#!/usr/bin/env python3
"""
dispatch.py — Sensor Network Node Agent
FAU Team - eMERGE 2026 Hackathon

This is the only place that knows about all four tiers. Each command is
classified into EXACTLY ONE tier — no fall-through chain. If the chosen
tier fails, we either (a) try a designated backup tier, or (b) return a
safe stub response. We never "try T1, then T2, then T3, then T4."

Why not fall-through? Two reasons:
  1. Metrics integrity — every command has one authoritative tier.
     If we fall through, Edge Efficiency accounting becomes fiction.
  2. Latency consistency — the hints doc warns that latency variance
     between commands is how the red team detects cloud calls. A
     command that falls through T1→T2→T3 takes measurably longer
     than one handled directly in T2.

CLASSIFICATION APPROACH:
  Each incoming command is examined by a classifier that returns a
  LevelAssignment. The classifier uses:
    - Tier 1 coverage check (exact match on static table)
    - Tier 2 dispatcher registry (known command handlers)
    - Pattern rules for T3 vs T4 (complexity, context-dependence)
    - Security rules (escalate attacker recon to T4 for richer handling)

ESCALATION POLICY (conservative — hints doc recommends this):
  Commands are sent to Tier 4 (cloud) ONLY when:
    - The command is naturally slow on real systems (hides latency)
    - The command requires multi-turn reasoning or complex output
    - Tier 3 has already failed and the router decides escalation is worth it

  Commands NEVER escalated (even if T3 fails — use safe stub instead):
    - Anything time-sensitive (date, uptime, ps) — users notice the lag
    - Anything invariant (whoami) — cloud call would be absurd here
    - Anything a script would run repeatedly — budget concern
"""

import time
import json
import re
import logging
import os
from typing import Tuple, Optional
from enum import Enum
from dataclasses import dataclass, asdict

import telemetry_cache
import node_runtime
from node_context import SessionState

# T3/T4 imported lazily — only needed when actually invoked
_tier3 = None
_tier4 = None

def _lazy_import_tier3():
    global _tier3
    if _tier3 is None:
        import edge_inference
        _tier3 = edge_inference
    return _tier3

def _lazy_import_tier4():
    global _tier4
    if _tier4 is None:
        import upstream_sync
        _tier4 = upstream_sync
    return _tier4


log = logging.getLogger(__name__)


# ==============================================================================
# Tier assignment
# ==============================================================================

class DispatchLevel(Enum):
    LOCAL_CACHE    = 1
    LOCAL_RUNTIME  = 2
    EDGE_INFER    = 3
    CLOUD_SYNC   = 4
    FALLBACK         = 5   # Hardcoded safe fallback (never tries LLM/cloud)


@dataclass
class LevelAssignment:
    level: DispatchLevel
    reason: str                       # Why we picked this tier
    backup: Optional[DispatchLevel] = None     # If primary fails, try this — then stub


# ==============================================================================
# Classification rules
# ==============================================================================

# Commands that are naturally slow on real systems. Cloud calls here are
# masked by expected latency — attackers won't flag them.
SLOW_COMMANDS_PATTERNS = [
    r"^find\s+/",
    r"^find\s+\.\s",
    r"^locate\s+",
    r"^updatedb",
    r"^apt(-get)?\s+update",
    r"^apt(-get)?\s+upgrade",
    r"^apt(-get)?\s+install",
    r"^pip\s+install",
    r"^pip3\s+install",
    r"^npm\s+install",
    r"^git\s+clone",
    r"^wget\s+http",
    r"^curl.*http",
    r"^nmap\s+",                # not installed anyway — ensure T1 shows "not found"
    r"^ping\s+-[^c]",           # continuous ping
    r"^tcpdump\s+",
    r"^rsync\s+",
]

# Commands that are RECON or show-me-everything. These deserve the best
# possible response quality because they're often the red team's probes.
HIGH_VALUE_RECON_PATTERNS = [
    r"^find\s.*passwd",
    r"^find\s.*shadow",
    r"^find\s.*config",
    r"^find\s.*\.ssh",
    r"^grep\s+-r",
    r"^grep\s+-R",
    r"^awk\s+",
    r"^sed\s+.*/",             # sed on files
]

# Commands that should never go to the cloud — output is trivially small
# and latency would stand out badly.
NEVER_ESCALATE_PATTERNS = [
    r"^whoami\b",
    r"^hostname\b",
    r"^id\b",
    r"^pwd\b",
    r"^date\b",
    r"^uptime\b",
    r"^true\b",
    r"^false\b",
    r"^echo\s",
    r"^true\s?$",
    r"^:\s?$",
]

# Dangerous/malicious patterns — route to T4 for careful handling so we
# return plausible "success" output instead of crashing Cowrie or tipping off.
ADVERSARIAL_PATTERNS = [
    r"/dev/tcp/",                    # bash TCP reverse shell
    r"bash\s+-i\s+>",                # interactive bash to fd
    r"nc\s+-[le]",                   # netcat listener/exec
    r"python\s+-c\s+.*socket",       # python reverse shell
    r"perl\s+-e\s+.*socket",
    r"base64\s+-d\s*\|",             # decoded payload into shell
    r"xxd\s+-r\s*\|",
    r"\$\(curl",                     # inline curl exec
    r"wget.*-O-\s*\|",               # wget piped to shell
]


# ==============================================================================
# Main classifier
# ==============================================================================

def classify(command: str, state: SessionState) -> LevelAssignment:
    """
    Decide which tier handles this command. Returns a LevelAssignment.
    This function is the single source of truth for dispatch decisions.
    """
    cmd = command.strip()
    if not cmd:
        return LevelAssignment(DispatchLevel.LOCAL_RUNTIME, "empty command")

    cmd_lower = cmd.lower()

    # --- RULE 1: Never-escalate commands MUST be T1 or T2 ---
    # These commands are so common that cloud latency would betray us instantly.
    for pattern in NEVER_ESCALATE_PATTERNS:
        if re.match(pattern, cmd_lower):
            if telemetry_cache.covers(cmd):
                return LevelAssignment(DispatchLevel.LOCAL_CACHE, f"invariant command (T1): {pattern}")
            return LevelAssignment(DispatchLevel.LOCAL_RUNTIME, f"time-sensitive (T2, no escalation): {pattern}",
                                  backup=DispatchLevel.FALLBACK)

    # --- RULE 2: Tier 1 exact match wins when available ---
    if telemetry_cache.covers(cmd):
        return LevelAssignment(DispatchLevel.LOCAL_CACHE, "exact match in static table")

    # --- RULE 3: Adversarial commands get T4 for careful handling ---
    # We want a plausible "it worked" response, not a crash or obvious fake.
    for pattern in ADVERSARIAL_PATTERNS:
        if re.search(pattern, cmd):
            return LevelAssignment(DispatchLevel.CLOUD_SYNC,
                                  f"adversarial pattern — needs careful handling: {pattern}",
                                  backup=DispatchLevel.FALLBACK)

    # --- RULE 4: Tier 2 dispatcher coverage ---
    # Check if the command head is in Tier 2's registry.
    head = cmd.split()[0] if cmd.split() else ""
    if head in _tier2_heads():
        return LevelAssignment(DispatchLevel.LOCAL_RUNTIME, f"T2 has dispatcher for '{head}'",
                              backup=DispatchLevel.EDGE_INFER)

    # --- RULE 5: Slow commands can safely hit cloud (latency hidden) ---
    for pattern in SLOW_COMMANDS_PATTERNS:
        if re.match(pattern, cmd_lower):
            # High-value recon gets T4 directly (best quality)
            for hv in HIGH_VALUE_RECON_PATTERNS:
                if re.match(hv, cmd_lower):
                    return LevelAssignment(DispatchLevel.CLOUD_SYNC,
                                          f"high-value recon command: {hv}",
                                          backup=DispatchLevel.EDGE_INFER)
            # Otherwise Tier 3 first, escalate to T4 if T3 fails
            return LevelAssignment(DispatchLevel.EDGE_INFER, f"naturally slow — T3 first: {pattern}",
                                  backup=DispatchLevel.CLOUD_SYNC)

    # --- RULE 6: Default — try Tier 3 (local LLM) ---
    # Unknown command with no slow-latency cover. Best handled locally.
    # If T3 fails, fall back to stub (not T4) because cloud latency would betray us.
    return LevelAssignment(DispatchLevel.EDGE_INFER, "default path — unknown command to local LLM",
                          backup=DispatchLevel.FALLBACK)


def _tier2_heads() -> set:
    """Pull the set of command heads that Tier 2 handles."""
    # Import here to avoid circular issues; this is the set from node_runtime.handle()
    return {
        "date", "uptime", "w", "who", "last", "lastlog",
        "ps", "top", "pgrep", "pidof",
        "netstat", "ss", "ifconfig", "ip", "arp", "route",
        "ls", "ll", "dir", "stat", "file", "cd", "pwd",
        "echo", "printf", "history", "env", "set", "printenv", "export",
        "free", "df", "du", "mount", "lsblk",
        "cat", "head", "tail", "wc", "grep",
        "touch", "mkdir", "rm", "cp", "mv",
        "systemctl", "service", "journalctl", "dmesg",
        "dpkg", "apt", "apt-get", "crontab",
        "sudo", "su", "ulimit", "sleep",
        "clear", "exit", "logout", "reset",
    }


# ==============================================================================
# Safe stub — last resort when everything fails
# ==============================================================================

def _stub_response(command: str, state: SessionState) -> str:
    """
    Never-fail fallback. Must ALWAYS return a plausible string, never raise.
    Used when Tier 3 is down AND Tier 4 is down/not configured.
    """
    cmd = command.strip()
    if not cmd:
        return ""
    head = cmd.split()[0]
    # Known-safe generic responses
    if head in ("cd", "export", "set", "unset", "alias", "unalias", "shopt",
                "bind", "declare", "readonly", "local", "function"):
        return ""
    if head in ("cat", "less", "more", "tail", "head"):
        if len(cmd.split()) > 1:
            target = cmd.split()[1]
            return f"{head}: {target}: No such file or directory"
        return ""
    if head in ("wget", "curl"):
        return f"{head}: unable to resolve host"
    if head in ("ssh", "scp", "rsync"):
        return f"ssh: connect to host ... port 22: Connection refused"
    if head == "ping":
        return "ping: connect: Network is unreachable"
    # Default — plausible command-not-found
    return f"bash: {head}: command not found"


# ==============================================================================
# Metrics
# ==============================================================================

class Metrics:
    def __init__(self, log_path=None):
        self.counts = {t.name: 0 for t in DispatchLevel}
        self.latencies_ms = {t.name: [] for t in DispatchLevel}
        self.failures = {t.name: 0 for t in DispatchLevel}
        self.total = 0
        self.log_path = log_path or os.path.expanduser(
            "~/cowrie/var/log/cowrie/sensor_health.json"
        )

    def record(self, level: DispatchLevel, latency_ms: float, failed: bool = False):
        self.counts[level.name] += 1
        self.latencies_ms[level.name].append(latency_ms)
        if failed:
            self.failures[level.name] += 1
        self.total += 1
        self._flush()

    def _flush(self):
        try:
            data = {
                "total_commands": self.total,
                "counts": self.counts,
                "failures": self.failures,
                "avg_latency_ms": {
                    t: (sum(ls)/len(ls) if ls else 0) for t, ls in self.latencies_ms.items()
                },
                "cloud_rate": (
                    self.counts["CLOUD_SYNC"] / max(self.total, 1)
                ),
                "local_rate": (
                    (self.counts["LOCAL_CACHE"] + self.counts["LOCAL_RUNTIME"] + self.counts["EDGE_INFER"])
                    / max(self.total, 1)
                ),
            }
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
            with open(self.log_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def summary(self) -> str:
        total = max(self.total, 1)
        lines = [f"=== Sensor Health (n={self.total}) ==="]
        for t in DispatchLevel:
            c = self.counts[t.name]
            pct = 100 * c / total
            avg_lat = sum(self.latencies_ms[t.name]) / len(self.latencies_ms[t.name]) if self.latencies_ms[t.name] else 0
            lines.append(f"  {t.name:<14} {c:>4} ({pct:>5.1f}%)   avg {avg_lat:>6.1f}ms   failures={self.failures[t.name]}")
        lines.append(f"  cloud_rate = {100 * self.counts['CLOUD_SYNC'] / total:.1f}%   "
                     f"local_rate = {100 * (self.counts['LOCAL_CACHE'] + self.counts['LOCAL_RUNTIME'] + self.counts['EDGE_INFER']) / total:.1f}%")
        return "\n".join(lines)


metrics = Metrics()


def safe_response(command: str) -> str:
    """
    Never-raise fallback used by shell_broker when the router itself fails.
    Callable with no session — purely a function of the command string.
    """
    try:
        return _stub_response(command, None)
    except Exception:
        head = (command.split() or [""])[0]
        return f"bash: {head}: command not found" if head else ""


# ==============================================================================
# Main dispatch function
# ==============================================================================

def route(command: str, state: SessionState) -> Tuple[str, DispatchLevel]:
    """
    Route a command. Compound shell constructs (pipes, sequences, conditionals,
    redirects) are pre-processed by shell_layer; each simple sub-command goes
    through _route_simple below. This keeps compound behavior consistent instead
    of letting the dispatcher see only the first token.
    """
    try:
        import shell_layer
        response, source = shell_layer.execute(command, state, _route_simple)
        # shell_layer already picked the logical "source" — we still record a
        # top-level metric at LOCAL_RUNTIME granularity so the dashboard stays
        # meaningful for compound commands.
        metrics.record(DispatchLevel.LOCAL_RUNTIME, 0.0)
        return response, DispatchLevel.LOCAL_RUNTIME
    except Exception as e:
        log.error(f"[sensor-agent] shell_layer failed on {command!r}: {e}")
        # Last-resort stub — never raise past this point
        return safe_response(command), DispatchLevel.FALLBACK


def _route_simple(command: str, state: SessionState) -> Tuple[str, DispatchLevel]:
    """
    Route a non-compound command to exactly one tier. Returns (response, tier).
    If primary tier fails, tries backup once, then falls back to stub.
    """
    start = time.time()
    assignment = classify(command, state)
    primary = assignment.level
    backup = assignment.backup

    log.debug(f"[sensor-agent] cmd={command!r} primary={primary.name} backup={backup.name if backup else None} reason={assignment.reason}")

    # --- Try primary tier ---
    resp, succeeded, level_used = _invoke(primary, command, state)
    if succeeded:
        metrics.record(level_used, (time.time() - start) * 1000)
        return resp, level_used

    # --- Primary failed, record it ---
    metrics.record(primary, (time.time() - start) * 1000, failed=True)

    # --- Try backup if any ---
    if backup is not None:
        bstart = time.time()
        resp, succeeded, level_used = _invoke(backup, command, state)
        if succeeded:
            metrics.record(level_used, (time.time() - bstart) * 1000)
            return resp, level_used
        metrics.record(backup, (time.time() - bstart) * 1000, failed=True)

    # --- Everything failed — stub ---
    stub = _stub_response(command, state)
    metrics.record(DispatchLevel.FALLBACK, (time.time() - start) * 1000)
    return stub, DispatchLevel.FALLBACK


def _invoke(level: DispatchLevel, command: str, state: SessionState) -> Tuple[str, bool, DispatchLevel]:
    """Invoke a specific dispatch level. Returns (response, succeeded, level_used)."""
    if level == DispatchLevel.LOCAL_CACHE:
        resp = telemetry_cache.lookup(command)
        if resp is not None:
            return resp, True, DispatchLevel.LOCAL_CACHE
        return "", False, DispatchLevel.LOCAL_CACHE

    if level == DispatchLevel.LOCAL_RUNTIME:
        handled, resp = node_runtime.handle(command, state)
        if handled:
            return resp, True, DispatchLevel.LOCAL_RUNTIME
        return "", False, DispatchLevel.LOCAL_RUNTIME

    if level == DispatchLevel.EDGE_INFER:
        t3 = _lazy_import_tier3()
        success, resp, _ = t3.handle(command, state)
        return resp, success, DispatchLevel.EDGE_INFER

    if level == DispatchLevel.CLOUD_SYNC:
        t4 = _lazy_import_tier4()
        success, resp, _ = t4.handle(command, state)
        return resp, success, DispatchLevel.CLOUD_SYNC

    if level == DispatchLevel.FALLBACK:
        return _stub_response(command, state), True, DispatchLevel.FALLBACK

    return "", False, level


# ==============================================================================
# Startup
# ==============================================================================

def startup():
    """Warm up Tier 3 (loads Ollama model into memory). Call on Cowrie boot."""
    try:
        t3 = _lazy_import_tier3()
        print("[sensor-agent] Warming up Tier 3 (Ollama)...")
        if t3.warm_up():
            print("[sensor-agent] Tier 3 ready.")
        else:
            print("[sensor-agent] Tier 3 unavailable — will stub on T3 requests.")
    except Exception as e:
        print(f"[sensor-agent] Tier 3 warm-up skipped: {e}")

    try:
        t4 = _lazy_import_tier4()
        if t4.is_configured():
            print("[sensor-agent] Tier 4 credentials present.")
        else:
            print("[sensor-agent] Tier 4 NOT configured — set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars.")
    except Exception:
        pass


if __name__ == "__main__":
    from node_context import get_session
    s = get_session("test", "1.2.3.4")

    test_commands = [
        "whoami",                                 # T1
        "uname -a",                               # T1
        "date",                                   # T2 (time-sensitive)
        "uptime",                                 # T2
        "ps aux",                                 # T2
        "cd /tmp",                                # T2
        "pwd",                                    # T2
        "ls",                                     # T2
        "systemctl status apache2",               # T2
        "find / -name '*.conf'",                  # T3 (slow, can mask)
        "find / -name '*passwd*'",                # T4 (high-value recon)
        "python3 -c 'import socket;s=socket.socket()'",  # T4 (adversarial)
        "apt-get update",                         # T3 backup T4
        "cat /proc/version",                      # T1
        "xyzblah",                                # T3 default
    ]

    for cmd in test_commands:
        assignment = classify(cmd, s)
        print(f"{assignment.level.name:<14} backup={assignment.backup.name if assignment.backup else '-':<14} $ {cmd}")
        print(f"               reason: {assignment.reason}")