"""
shell_layer.py — Narrow-subset shell parser in front of dispatch.

Real bash parses a grammar. We do not. We support a deliberately small set of
shell compositions that SSH automation reliably uses, and we reject everything
else with a plausible bash error. The explicit boundary means:
  - for inputs we support, output matches real shell physics
  - for inputs we do not, failure is consistent and bash-like (not fallthrough)

Public API:
  analyze(cmd)                 -> Analysis
  execute(cmd, state, router)  -> (response, source)

`router` is `dispatch.route_simple` — a callable that takes (cmd, state) and
returns (response, level). We call it for each simple sub-command and stitch
results together. No recursion into shell_layer from within execute.

Supported compositions (see workingplan.md § "Explicitly supported"):
  - sequences      cmd1 ; cmd2 ; cmd3
  - conditionals   cmd1 && cmd2   /   cmd1 || cmd2       (no short-circuit)
  - pipelines      cmd | head [-n N]
                   cmd | tail [-n N]
                   cmd | wc [-l|-c|-w]
                   cmd | grep [-i|-v|-E] PATTERN
                   cmd | sort
                   cmd | uniq [-c]
                   cmd | awk 'NR==N' | awk '{print $N}'   (narrow)
  - redirects      cmd > /tmp/file       (captures into session files)
                   cmd >> /tmp/file
                   cmd 2>/dev/null       (suffix stripped)
                   cmd >/dev/null
                   cmd 2>&1
  - env prefix     LANG=C cmd   TZ=UTC cmd  (prefix stripped)

Unsupported -> bash-style error response.
"""
from __future__ import annotations
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


# ==============================================================================
# Analysis
# ==============================================================================

# Metachars that trigger the compound path. Quoted occurrences are handled by
# shlex; regex detection is a fast-path to avoid shlex on the common-simple case.
_META_RX = re.compile(r"""
    (?<!\\)              # not escaped
    (
        \|\||&&|         # conditionals first (||, &&)
        [|;&<>]|          # single metas
        \$\(|`|          # command substitution
        <<                # heredoc
    )
""", re.X)

_PIPE_TOOL_RX = re.compile(r"^\s*(head|tail|wc|grep|sort|uniq|awk|cat)\b")

_ENV_PREFIX_RX = re.compile(r"^\s*([A-Z_][A-Z0-9_]*=\S+\s+)+")


@dataclass
class Analysis:
    type: str                       # simple | sequence | conditional | pipeline | redirect | env_prefix | unsupported
    parts: List[str] = field(default_factory=list)
    op: Optional[str] = None        # for conditional: "&&" or "||"
    pipe_tool: Optional[str] = None # for pipeline: filter tool name
    pipe_args: List[str] = field(default_factory=list)
    redirect_target: Optional[str] = None
    redirect_op: Optional[str] = None
    reason: str = ""


def analyze(command: str) -> Analysis:
    """Classify a command into one of the supported categories or 'unsupported'."""
    cmd = command.strip()
    if not cmd:
        return Analysis(type="simple", parts=[""])

    # Always strip env prefix (LANG=C ...) regardless of path
    cmd = _strip_env_prefix(cmd)

    # Fast path: no metacharacters anywhere → simple
    if not _META_RX.search(cmd):
        return Analysis(type="simple", parts=[cmd])

    # Heredoc and command substitution: hard-reject early
    if "<<" in cmd:
        return Analysis(type="unsupported", reason="heredoc")
    if "$(" in cmd or "`" in cmd:
        return Analysis(type="unsupported", reason="command substitution")

    # Strip trailing known-safe I/O redirects before further parsing so we don't
    # confuse a pipe with a stray `>/dev/null`
    core, redir = _split_trailing_redirect(cmd)

    # If the redirect target is not a write-side redirect we recognize, stop.
    if redir and redir.get("type") == "unsupported":
        return Analysis(type="unsupported", reason=redir["reason"])

    # Strip env prefix (LANG=C foo  -> foo)
    core = _strip_env_prefix(core)

    # Re-check meta on the stripped core. If nothing compound remains, it's simple +
    # possibly a redirect.
    if not _META_RX.search(core):
        if redir:
            return Analysis(
                type="redirect",
                parts=[core.strip()],
                redirect_op=redir["op"],
                redirect_target=redir["target"],
            )
        return Analysis(type="simple", parts=[core.strip()])

    # Conditionals (handle first because '||' / '&&' contain metachars)
    if "||" in core or "&&" in core:
        op = "&&" if "&&" in core else "||"
        split = _safe_split(core, op)
        if split and all(s.strip() for s in split):
            return Analysis(type="conditional", parts=[s.strip() for s in split], op=op)
        return Analysis(type="unsupported", reason=f"malformed {op}")

    # Background trailing & (but not '&&' which is handled above)
    if re.search(r"(?<!&)&\s*$", core):
        return Analysis(type="unsupported", reason="background &")

    # Pipeline — single-stage only (cmd | tool [args])
    if "|" in core:
        segments = _safe_split(core, "|")
        if segments and len(segments) == 2:
            inner, tool_expr = segments[0].strip(), segments[1].strip()
            m = _PIPE_TOOL_RX.match(tool_expr)
            if m and inner:
                tool = m.group(1)
                try:
                    tool_args = shlex.split(tool_expr)[1:]
                except ValueError:
                    tool_args = tool_expr.split()[1:]
                return Analysis(
                    type="pipeline",
                    parts=[inner],
                    pipe_tool=tool,
                    pipe_args=tool_args,
                )
        return Analysis(type="unsupported", reason="pipeline (unsupported tool or >2 stages)")

    # Sequence
    if ";" in core:
        parts = _safe_split(core, ";")
        if parts and all(p.strip() for p in parts):
            return Analysis(type="sequence", parts=[p.strip() for p in parts])
        return Analysis(type="unsupported", reason="malformed sequence")

    # Stray < or > we didn't match
    return Analysis(type="unsupported", reason="unrecognized composition")


# ==============================================================================
# Executor
# ==============================================================================

Router = Callable[[str, object], Tuple[str, object]]


def execute(cmd: str, state, router: Router) -> Tuple[str, str]:
    """
    Route a (possibly compound) command. Returns (response, reason_tag).
    `router` must be dispatch.route_simple(cmd, state) -> (response, level).
    reason_tag is a human-readable source annotation for metrics ("sequence",
    "pipeline:head", etc).
    """
    a = analyze(cmd)

    if a.type == "simple":
        resp, _ = router(a.parts[0] or "", state)
        return resp, "simple"

    if a.type == "sequence":
        outs = []
        for sub in a.parts:
            resp, _ = router(sub, state)
            if resp:
                outs.append(resp)
        return "\n".join(outs), "sequence"

    if a.type == "conditional":
        # No short-circuit semantics. Emit both, because attacker probes usually
        # want to see the second result regardless.
        outs = []
        for sub in a.parts:
            resp, _ = router(sub, state)
            if resp:
                outs.append(resp)
        return "\n".join(outs), f"conditional:{a.op}"

    if a.type == "pipeline":
        inner_resp, _ = router(a.parts[0], state)
        filtered = _apply_pipe(inner_resp or "", a.pipe_tool, a.pipe_args)
        return filtered, f"pipeline:{a.pipe_tool}"

    if a.type == "redirect":
        inner_resp, _ = router(a.parts[0], state)
        # /dev/null is the universal discard — silence without writing anywhere
        if a.redirect_target == "/dev/null":
            return "", f"redirect:/dev/null"
        # Write to session filesystem if the state supports it
        if a.redirect_target and hasattr(state, "create_session_file"):
            try:
                existing = ""
                if a.redirect_op == ">>":
                    prior = state.get_file_info(a.redirect_target) if hasattr(state, "get_file_info") else None
                    if prior and "content" in prior:
                        existing = prior["content"] + "\n"
                state.create_session_file(a.redirect_target, existing + (inner_resp or ""))
            except Exception:
                pass
        # Real shell: redirect steals stdout, returns empty
        return "", f"redirect:{a.redirect_op}"

    # unsupported
    return _reject(cmd, a.reason), f"unsupported:{a.reason}"


# ==============================================================================
# Pipe filters
# ==============================================================================

def _apply_pipe(text: str, tool: Optional[str], args: List[str]) -> str:
    """Apply a single-stage filter. Intentionally limited; matches real tool output."""
    if not text:
        return ""
    lines = text.splitlines()

    if tool == "head":
        n = _numeric_flag(args, "-n", 10)
        return "\n".join(lines[:n])

    if tool == "tail":
        n = _numeric_flag(args, "-n", 10)
        return "\n".join(lines[-n:])

    if tool == "wc":
        if "-l" in args:
            return str(len(lines))
        if "-c" in args:
            return str(len(text) + (0 if text.endswith("\n") else 0))
        if "-w" in args:
            return str(sum(len(l.split()) for l in lines))
        # default wc: lines, words, bytes
        return f"{len(lines):>7} {sum(len(l.split()) for l in lines):>7} {len(text):>7}"

    if tool == "grep":
        pattern = args[-1] if args else ""
        flags = 0
        if "-i" in args: flags |= re.I
        invert = "-v" in args
        try:
            rx = re.compile(pattern, flags)
        except re.error:
            return ""
        out = [l for l in lines if bool(rx.search(l)) != invert]
        return "\n".join(out)

    if tool == "sort":
        return "\n".join(sorted(lines))

    if tool == "uniq":
        out = []
        prev = object()
        counts = {}
        for l in lines:
            if l != prev:
                out.append(l)
                prev = l
            counts[l] = counts.get(l, 0) + 1
        if "-c" in args:
            return "\n".join(f"{counts[l]:>7} {l}" for l in out)
        return "\n".join(out)

    if tool == "awk":
        # We implement exactly one idiom: awk 'NR==N' or awk '{print $N}'
        script = args[0] if args else ""
        m = re.match(r"^NR==(\d+)$", script)
        if m:
            idx = int(m.group(1)) - 1
            return lines[idx] if 0 <= idx < len(lines) else ""
        m = re.match(r"^\{print\s+\$(\d+)\}$", script)
        if m:
            col = int(m.group(1)) - 1
            return "\n".join(
                (l.split()[col] if col < len(l.split()) else "") for l in lines
            )
        return text  # passthrough unknown awk — safer than empty

    if tool == "cat":
        return text

    return text


def _numeric_flag(args: List[str], flag: str, default: int) -> int:
    for i, a in enumerate(args):
        if a == flag and i + 1 < len(args):
            try:
                return int(args[i + 1])
            except ValueError:
                return default
        if a.startswith(flag) and len(a) > len(flag):
            try:
                return int(a[len(flag):])
            except ValueError:
                return default
        # bare -N (head -5)
        if a.startswith("-") and a[1:].isdigit() and flag in ("-n",):
            return int(a[1:])
    return default


# ==============================================================================
# Rejections
# ==============================================================================

def _reject(cmd: str, reason: str) -> str:
    """Produce a plausible bash error for an unsupported construct."""
    if reason == "heredoc":
        return "bash: syntax error: unexpected end of file"
    if reason == "command substitution":
        return "bash: syntax error near unexpected token `('"
    if reason == "background &":
        return "bash: syntax error: backgrounding not supported in this session"
    if reason.startswith("pipeline"):
        return "bash: syntax error near unexpected token `|'"
    if reason.startswith("malformed"):
        return f"bash: syntax error near unexpected token `{reason.split()[-1]}'"
    return "bash: syntax error near unexpected token `newline'"


# ==============================================================================
# Tokenizer helpers
# ==============================================================================

def _safe_split(s: str, delim: str) -> List[str]:
    """
    Split a string on a delimiter while respecting quotes. Returns [] on
    unbalanced quotes. Treats the delim as literal (no escape handling beyond
    respecting simple single/double quotes).
    """
    parts: List[str] = []
    buf: List[str] = []
    i = 0
    in_s = in_d = False
    dlen = len(delim)
    while i < len(s):
        c = s[i]
        if c == "'" and not in_d:
            in_s = not in_s
            buf.append(c); i += 1; continue
        if c == '"' and not in_s:
            in_d = not in_d
            buf.append(c); i += 1; continue
        if not in_s and not in_d and s[i:i+dlen] == delim:
            parts.append("".join(buf))
            buf = []
            i += dlen
            continue
        buf.append(c); i += 1
    if in_s or in_d:
        return []
    parts.append("".join(buf))
    return parts


def _strip_env_prefix(cmd: str) -> str:
    m = _ENV_PREFIX_RX.match(cmd)
    if m:
        return cmd[m.end():]
    return cmd


def _split_trailing_redirect(cmd: str):
    """
    Peel off trailing I/O redirects we recognize. Returns (core, info|None).
    info keys: type ("sink" | "unsupported"), op (">", ">>"), target (path).
    """
    # Strip off one or more of: 2>&1, 2>/dev/null, >/dev/null, >/path, >>/path
    core = cmd
    info = None
    while True:
        stripped = False
        # 2>&1 — pure dup, no target
        m = re.search(r"\s+2>&1\s*$", core)
        if m:
            core = core[:m.start()]
            stripped = True
            continue
        # 2>/dev/null or 2>FILE
        m = re.search(r"\s+2>\S+\s*$", core)
        if m:
            target = m.group(0).split(">", 1)[1].strip()
            if target == "/dev/null":
                core = core[:m.start()]
                stripped = True
                continue
            else:
                # 2>real-file — unsupported for simplicity
                return cmd, {"type": "unsupported", "reason": "stderr redirect to file"}
        # >> FILE
        m = re.search(r"\s+(>>)\s*(\S+)\s*$", core)
        if m:
            target = m.group(2)
            core = core[:m.start()]
            info = {"type": "sink", "op": ">>", "target": target}
            stripped = True
            continue
        # > FILE (but not 2>)
        m = re.search(r"(?<!2)(?<!&)\s+(>)\s*(\S+)\s*$", core)
        if m:
            target = m.group(2)
            core = core[:m.start()]
            # /dev/null is a sink too — flagged with target=/dev/null so
            # execute() silences output without creating a session file.
            info = {"type": "sink", "op": ">", "target": target}
            stripped = True
            continue
        if not stripped:
            break
    return core, info


# ==============================================================================
# __main__ — tiny self-test
# ==============================================================================

if __name__ == "__main__":
    cases = [
        "whoami",
        "cat /etc/os-release | head -5",
        "ps aux | wc -l",
        "cd /tmp; pwd",
        "true && echo ok",
        "echo hi > /tmp/foo",
        "echo $(whoami)",
        "cmd1 <<EOF",
        "cmd | unknown_tool",
        "LANG=C uname -a",
        "uname -a 2>/dev/null",
    ]
    for c in cases:
        a = analyze(c)
        print(f"  {c:<40}  type={a.type:<14} parts={a.parts!r:<40} reason={a.reason!r}")
