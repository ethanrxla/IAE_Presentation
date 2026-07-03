"""
Fatigue tests: many short-lived SSH sessions. The scorer's automation may
open N separate connections rather than one long one. We need:
  - no hangs
  - no leaks in _sessions
  - consistent output across connections
"""
from __future__ import annotations
import sys
import time
from pathlib import Path

import pytest


# In-process: stress the session registry without needing SSH
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from node_context import (                         # noqa: E402
    get_session, clear_session, session_count, _SESSION_CAP,
)
from dispatch import route                         # noqa: E402


class TestInProcessBurst:
    def test_session_cap_holds_under_burst(self):
        """Create 2x cap sessions; ensure count never exceeds cap."""
        start_count = session_count()
        # Clear any prior leftovers by using unique IDs
        for i in range(_SESSION_CAP * 2):
            get_session(f"burst-{i}", f"10.0.{i // 256}.{i % 256}")
        assert session_count() <= _SESSION_CAP, (
            f"session count {session_count()} exceeded cap {_SESSION_CAP}"
        )

    def test_short_connections_are_independent(self):
        """Each 'connection' (unique session_id) has independent state."""
        s1 = get_session("iso-a", "1.1.1.1")
        s2 = get_session("iso-b", "2.2.2.2")
        route("cd /tmp", s1)
        r2, _ = route("pwd", s2)
        assert r2.strip() == "/root", f"session B saw session A's cd: {r2!r}"
        clear_session("iso-a")
        clear_session("iso-b")

    def test_reconnect_same_id_restores_state(self):
        """Clearing and reconnecting with the same id drops old state cleanly."""
        get_session("rec", "5.5.5.5").current_dir = "/etc"
        clear_session("rec")
        fresh = get_session("rec", "5.5.5.5")
        assert fresh.current_dir == "/root", "state leaked across clear+recreate"
        clear_session("rec")


class TestLiveBurst:
    """Tests that actually open paramiko connections — skip without honeypot."""

    @pytest.mark.parametrize("n", [20])
    def test_n_short_connections_dont_hang(self, honeypot_target, n):
        if honeypot_target is None:
            pytest.skip("no --honeypot configured")
        try:
            import paramiko
        except ImportError:
            pytest.skip("paramiko not installed")

        t0 = time.time()
        for i in range(n):
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(
                hostname=honeypot_target.host,
                port=honeypot_target.port,
                username=honeypot_target.user,
                password=honeypot_target.password,
                timeout=5, allow_agent=False, look_for_keys=False,
            )
            _, stdout, _ = cli.exec_command("whoami", timeout=5)
            out = stdout.read().decode()
            cli.close()
            assert "root" in out or out.strip(), f"iter {i}: bad response {out!r}"
        elapsed = time.time() - t0
        assert elapsed < 60, f"{n} short connections took {elapsed:.1f}s (>60s = likely hang)"
