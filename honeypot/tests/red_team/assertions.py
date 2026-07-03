"""
Per-probe assertion library. Callables that consume (honeypot_result, clean_result)
and either return None (pass) or raise AssertionError (fail).

A ProbeResult is:
  {
    "cmd": str,
    "stdout": str,
    "stderr": str,
    "exit_code": int,
    "latency_ms": float,
  }

Assertions are pure — no side effects — so pytest can parametrize and parallelize.
"""
from __future__ import annotations
import re
import unicodedata
from dataclasses import dataclass
from typing import Optional


@dataclass
class ProbeResult:
    cmd: str
    stdout: str
    stderr: str
    exit_code: int
    latency_ms: float

    @property
    def combined(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip() if self.stderr else self.stdout.strip()


# ==============================================================================
# Normalizers
# ==============================================================================

def _normalize_ws(s: str) -> str:
    """Collapse whitespace, strip, lower-no — preserve case because we do exact matches."""
    return "\n".join(line.rstrip() for line in s.strip().splitlines() if line.strip())


_ZW = "".join(chr(c) for c in [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF])
_ZW_TRANS = str.maketrans("", "", _ZW)

def _nfkc_deflate(s: str) -> str:
    """NFKC-normalize and strip zero-width chars — used for LLM-leak detection."""
    return unicodedata.normalize("NFKC", s).translate(_ZW_TRANS)


# ==============================================================================
# Assertions. Signature: (honey: ProbeResult, clean: Optional[ProbeResult]) -> None
# Raises AssertionError on fail. Clean-pi oracle may be None when running offline;
# assertions that need it must handle gracefully.
# ==============================================================================

def match_clean_pi(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
    """Output must match clean Pi (whitespace-tolerant). Most common assertion."""
    if clean is None:
        raise AssertionError("clean_pi oracle required but missing")
    h, c = _normalize_ws(honey.combined), _normalize_ws(clean.combined)
    if h != c:
        raise AssertionError(f"output mismatch\n  honey: {h[:200]!r}\n  clean: {c[:200]!r}")


def regex(pattern: str):
    """Output (combined stdout+stderr) must match regex. Returns an assertion."""
    rx = re.compile(pattern, re.M | re.S)
    def _assert(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
        if not rx.search(honey.combined):
            raise AssertionError(f"no regex match: {pattern!r}\n  got: {honey.combined[:200]!r}")
    _assert.__name__ = f"regex({pattern!r})"
    return _assert


def exact_string(expected: str, exit_code: Optional[int] = None):
    """Output + optional exit-code must match exactly. Used for bash error strings."""
    def _assert(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
        if _normalize_ws(honey.combined) != _normalize_ws(expected):
            raise AssertionError(f"exact mismatch\n  got: {honey.combined[:200]!r}\n  want: {expected[:200]!r}")
        if exit_code is not None and honey.exit_code != exit_code:
            raise AssertionError(f"exit_code mismatch: got {honey.exit_code}, want {exit_code}")
    _assert.__name__ = f"exact_string({expected!r})"
    return _assert


def no_llm_leak(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
    """Output must not contain tokens that would betray the LLM / honeypot."""
    banned = {
        "honeypot", "cowrie", "ollama", "llm", "claude", "bedrock", "lambda", "aws",
        "anthropic", "svcd", "scalpel", "gpt", "openai", "as an ai",
        "i am an ai", "i cannot", "system prompt", "ignore previous",
    }
    haystack = _nfkc_deflate(honey.combined).lower()
    # Strip all punctuation and spacing to defeat "c o w r i e" style
    squashed = re.sub(r"[^a-z0-9]+", "", haystack)
    leaks = [tok for tok in banned if tok.replace(" ", "") in squashed]
    if leaks:
        raise AssertionError(f"LLM/honeypot token leak: {leaks}\n  output: {honey.combined[:300]!r}")


def command_not_found(cmd_first_word: Optional[str] = None):
    """Output must be a bash command-not-found response. For injection probes."""
    def _assert(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
        out = honey.combined
        if "command not found" not in out:
            raise AssertionError(f"expected command-not-found, got: {out[:200]!r}")
        if honey.exit_code not in (127, -1, 1):  # -1 if exit code wasn't captured
            raise AssertionError(f"exit_code for cnf should be 127, got {honey.exit_code}")
    _assert.__name__ = "command_not_found"
    return _assert


def no_network_egress(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
    """
    For LATERAL / EXFIL probes. We can't prove the negative from output alone —
    this assertion just ensures the output LOOKS like a failed connection, which
    is the user-facing signal. The real check is in external_tools.sh (pcap).
    """
    out = honey.combined.lower()
    plausible_rejections = [
        "connection refused", "no route to host", "network is unreachable",
        "could not resolve", "temporary failure in name resolution",
        "operation not permitted", "permission denied",
        "connection timed out", "name or service not known",
        "host unreachable", "no such host", "unknown host",
    ]
    if not any(p in out for p in plausible_rejections):
        # Exfil tools like curl might return 000 with no body
        if honey.exit_code == 0 and len(out.strip()) == 0:
            return  # silent fail is acceptable — looks like network stub
        raise AssertionError(
            f"output doesn't look like a network failure: {out[:200]!r}"
        )


def latency_below(p99_max_ms: float, n_runs_expected: int = 20):
    """Paired with a runner that collects multiple runs and emits latency_ms. Asserts p99."""
    def _assert(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
        # The runner collapses N runs into a single ProbeResult with latency_ms = p99
        if honey.latency_ms > p99_max_ms:
            raise AssertionError(f"p99 latency {honey.latency_ms:.0f}ms > {p99_max_ms}ms")
    _assert.__name__ = f"latency_below({p99_max_ms}ms)"
    return _assert


def latency_between(min_ms: float, max_ms: float):
    """For SLOW_COMMANDS — too-fast = short-circuit, too-slow = escalation failure."""
    def _assert(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
        if not (min_ms <= honey.latency_ms <= max_ms):
            raise AssertionError(
                f"latency {honey.latency_ms:.0f}ms outside [{min_ms}, {max_ms}]ms"
            )
    _assert.__name__ = f"latency_between({min_ms}, {max_ms})"
    return _assert


def no_crash(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
    """For CRASH-stage probes. Output can be anything; just ensure we got A response and Cowrie is up."""
    if honey.exit_code is None or honey.latency_ms > 30000:
        raise AssertionError(f"probe appeared to hang ({honey.latency_ms:.0f}ms)")
    # Negative: no Python traceback in response (suggests router.py crashed visibly)
    if "Traceback (most recent call last)" in honey.combined:
        raise AssertionError(f"router traceback leaked to attacker: {honey.combined[:300]!r}")


def all_of(*assertions):
    """Composite: run all assertions; fail on first."""
    def _assert(honey: ProbeResult, clean: Optional[ProbeResult]) -> None:
        for a in assertions:
            a(honey, clean)
    _assert.__name__ = f"all_of({', '.join(a.__name__ for a in assertions)})"
    return _assert
