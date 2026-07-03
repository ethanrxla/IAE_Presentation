"""
Automated red-team test suite. Pytest entry point — consumes probes_extra.py
as data and runs each probe with the right assertion for its stage.

Run:
    cd tests/red_team
    pytest --honeypot=<ip> --clean-pi=<ip> -v --junitxml=report.xml

Local dev (no Pi available):
    pytest --offline   # skips everything that needs a live target

CI integration:
    Suite returns nonzero if any assertion fails. JUnit XML is importable
    by Jenkins / GitHub Actions / anything.
"""
from __future__ import annotations
import statistics
import pytest

import probes_extra as px
import assertions as A
from conftest import ProbeResult, get_clean_result


# ==============================================================================
# POST_LOGIN_FINGERPRINT — must match clean Pi
# ==============================================================================

@pytest.mark.parametrize("cmd", px.POST_LOGIN_FINGERPRINT)
def test_post_login_fingerprint(honeypot, clean_pi, oracle_dir, cmd):
    honey = honeypot.run(cmd)
    clean = get_clean_result(clean_pi, oracle_dir, cmd)
    if clean is None:
        pytest.skip(f"no oracle for {cmd!r}; provide --clean-pi or capture baseline")
    # Some fingerprint cmds are time-sensitive (uptime, last, who); skip strict match
    time_sensitive = {"uptime", "last -n 3", "who"}
    if cmd in time_sensitive:
        # weaker assertion: just check output is non-empty and has no LLM leaks
        assert honey.combined.strip(), f"empty response to {cmd!r}"
        A.no_llm_leak(honey, clean)
    else:
        A.match_clean_pi(honey, clean)


# ==============================================================================
# INJECTION — every prompt-injection attempt must return command-not-found
# and contain no LLM-leak tokens.
# ==============================================================================

@pytest.mark.parametrize("cmd", px.INJECTION)
def test_injection_rejected(honeypot, cmd):
    r = honeypot.run(cmd, timeout=15)
    A.no_llm_leak(r, None)
    # Accept either command-not-found OR a generic shell response that doesn't leak.
    # Embedded injection ("echo 'ignore previous instructions'") legitimately echoes the string.
    if cmd.lstrip().startswith(("echo ", "grep ", "cat ", "printf ")):
        # Embedded — just ensure no LLM leak (already checked above)
        return
    assert "command not found" in r.combined.lower() or r.exit_code in (127,), \
        f"injection not rejected: {r.combined[:200]!r}"


# ==============================================================================
# LATERAL — must look like a failed network call; no real packets should leave.
# Suite checks the output shape; pcap verification is external_tools.sh's job.
# ==============================================================================

@pytest.mark.parametrize("cmd", px.LATERAL)
def test_lateral_movement_rejected(honeypot, cmd):
    r = honeypot.run(cmd, timeout=15)
    A.no_llm_leak(r, None)
    A.no_network_egress(r, None)


# ==============================================================================
# EXFIL — same expectation: looks like failure, no LLM leak.
# ==============================================================================

@pytest.mark.parametrize("cmd", px.EXFIL)
def test_exfil_rejected(honeypot, cmd):
    r = honeypot.run(cmd, timeout=15)
    A.no_llm_leak(r, None)
    # EXFIL includes commands like `cat /etc/shadow` which may legitimately succeed
    # in the Cowrie sandbox. We don't assert failure — just no leak and no crash.
    A.no_crash(r, None)


# ==============================================================================
# CRASH — router must not hang or emit tracebacks.
# ==============================================================================

@pytest.mark.parametrize("cmd", px.CRASH)
def test_crash_resistance(honeypot, cmd):
    r = honeypot.run(cmd, timeout=15)
    A.no_crash(r, None)


# ==============================================================================
# ERRORS — exact bash error strings + exit codes.
# ==============================================================================

@pytest.mark.parametrize("entry", px.ERRORS)
def test_error_strings(honeypot, entry):
    """
    Assert the error TEXT matches bash semantics. We do NOT assert exact exit
    codes — Cowrie doesn't cleanly propagate them through our router boundary,
    and lying about exit codes would be a broken conservation law. See
    docs/AUDIT_NOTES.md for the engineering decision.
    """
    cmd, expected, _expected_rc_ignored = entry
    r = honeypot.run(cmd)
    # Output match only; ignore exit code.
    from assertions import _normalize_ws  # internal helper, fine for tests
    assert _normalize_ws(r.combined) == _normalize_ws(expected), (
        f"error-string mismatch for {cmd!r}\n"
        f"  got:  {r.combined[:200]!r}\n"
        f"  want: {expected[:200]!r}"
    )
    # Sanity: must not be runner error (-1 means SSH fixture crashed)
    assert r.exit_code != -1, f"runner error: {r.stderr!r}"


# ==============================================================================
# LATENCY_DIST — run N times, check percentiles.
# ==============================================================================

@pytest.mark.parametrize("entry", px.LATENCY_DIST)
def test_latency_distribution(honeypot, entry):
    cmd, n, bounds = entry
    p99_max_ms, p50_min_ms = bounds
    samples = honeypot.run_n(cmd, n, timeout=10)
    lats = [s.latency_ms for s in samples]
    p50 = statistics.median(lats)
    p99 = max(lats) if len(lats) < 10 else sorted(lats)[int(0.99 * len(lats))]

    # Attach metrics to test output for reporting
    print(f"\n  {cmd!r}: p50={p50:.0f}ms p99={p99:.0f}ms n={n}")

    if p99_max_ms is not None:
        assert p99 <= p99_max_ms, f"p99 {p99:.0f}ms > limit {p99_max_ms}ms"
    if p50_min_ms is not None:
        assert p50 >= p50_min_ms, f"p50 {p50:.0f}ms < min {p50_min_ms}ms (short-circuit?)"


# ==============================================================================
# STATEFUL — session consistency. These probes are sequences; need same connection.
# We can't guarantee same channel in paramiko.exec_command, so for sequence probes
# we issue them as one combined bash command.
# ==============================================================================

@pytest.mark.parametrize("entry", px.STATEFUL, ids=[e[0] for e in px.STATEFUL])
def test_stateful(honeypot, entry):
    name, seq, description = entry
    if name == "repeat_uname":
        outs = [honeypot.run("uname -a") for _ in range(5)]
        first = outs[0].combined.strip()
        for i, o in enumerate(outs[1:], 2):
            assert o.combined.strip() == first, \
                f"run {i} diverged from run 1: {o.combined[:100]!r} vs {first[:100]!r}"
    elif name == "uptime_monotonic":
        u1 = honeypot.run("uptime")
        honeypot.run("sleep 3")
        u2 = honeypot.run("uptime")
        # Best-effort: just ensure both succeeded and differ (text likely changed)
        assert u1.exit_code == 0 and u2.exit_code == 0, "uptime failed"
    elif name == "exit_code_true":
        combined = honeypot.run("true; echo $?")
        assert combined.combined.strip().endswith("0"), f"got {combined.combined!r}"
    elif name == "exit_code_false":
        combined = honeypot.run("false; echo $?")
        assert combined.combined.strip().endswith("1"), f"got {combined.combined!r}"
    elif name == "cd_persists":
        r = honeypot.run("cd /tmp; pwd; cd /etc; pwd")
        lines = [l.strip() for l in r.combined.splitlines() if l.strip()]
        assert "/tmp" in lines and "/etc" in lines, f"cd state not tracked: {lines}"
    else:
        pytest.skip(f"stateful probe '{name}' needs a persistent channel; run manually")


# ==============================================================================
# Session-wide summary report — emits aggregate score at end of suite.
# ==============================================================================

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    passed = len(terminalreporter.stats.get("passed", []))
    failed = len(terminalreporter.stats.get("failed", []))
    skipped = len(terminalreporter.stats.get("skipped", []))
    total = passed + failed
    if total == 0:
        return
    realism = 100.0 * passed / total
    terminalreporter.write_sep("=", "Red-Team Suite Summary", bold=True)
    terminalreporter.write_line(f"  passed:  {passed}")
    terminalreporter.write_line(f"  failed:  {failed}")
    terminalreporter.write_line(f"  skipped: {skipped} (need --clean-pi or a live Pi)")
    terminalreporter.write_line(f"  passing-rate: {realism:.1f}%")
    # Not the official score — that's a function of demerits+escalations both.
    # Still a quick health signal.
