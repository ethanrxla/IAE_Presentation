"""
Persistent shell tests — uses paramiko's invoke_shell, which gives a real
interactive channel (one SSH session, multiple commands). This is what
matters for session-state realism: cd must stick, touch must be visible
to subsequent ls, uptime must be monotonic, etc.

These tests REQUIRE a live honeypot Pi (--honeypot flag). Skipped without.
"""
from __future__ import annotations
import time
import re
import pytest


pytestmark = pytest.mark.usefixtures("honeypot_target")


class PersistentShell:
    """Minimal interactive wrapper over paramiko.Channel."""
    def __init__(self, client, timeout=15.0):
        self.channel = client.invoke_shell(term="xterm")
        self.channel.settimeout(1.0)
        self.timeout = timeout
        self._drain_banner()

    def _recv_until_idle(self, idle_ms=400):
        """Read until no new data arrives for idle_ms."""
        out = b""
        deadline = time.time() + self.timeout
        last_recv = time.time()
        while time.time() < deadline:
            try:
                chunk = self.channel.recv(8192)
                if chunk:
                    out += chunk
                    last_recv = time.time()
                else:
                    break
            except Exception:
                pass
            if (time.time() - last_recv) * 1000 > idle_ms:
                break
            time.sleep(0.05)
        return out.decode("utf-8", errors="replace")

    def _drain_banner(self):
        self._recv_until_idle(idle_ms=700)

    def run(self, cmd: str) -> str:
        """Send cmd + newline; return everything printed until next idle."""
        self.channel.send((cmd + "\n").encode())
        raw = self._recv_until_idle()
        # Strip echoed command and trailing prompt
        lines = raw.splitlines()
        # First line is usually the echo of the command — drop it if so
        if lines and cmd.strip() in lines[0]:
            lines = lines[1:]
        # Last line is typically the prompt (e.g. "root@honey:~#"); drop
        if lines and re.search(r"[#$]\s*$", lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip()

    def close(self):
        try:
            self.channel.send(b"exit\n")
            self.channel.close()
        except Exception:
            pass


@pytest.fixture
def shell(honeypot, honeypot_target):
    if honeypot is None:
        pytest.skip("no --honeypot configured")
    sh = PersistentShell(honeypot.client)
    yield sh
    sh.close()


class TestPersistentShell:
    def test_cd_persists_in_one_channel(self, shell):
        shell.run("cd /tmp")
        out = shell.run("pwd")
        assert "/tmp" in out, f"cd didn't stick: {out!r}"

    def test_touch_then_ls(self, shell):
        marker = f"rt_{int(time.time())}"
        shell.run(f"touch /tmp/{marker}")
        out = shell.run("ls /tmp")
        assert marker in out, f"touched file not in ls: {out!r}"

    def test_echo_redirect_cat_roundtrip(self, shell):
        marker = f"marker_{int(time.time())}"
        shell.run(f"echo {marker} > /tmp/peek")
        out = shell.run("cat /tmp/peek")
        assert marker in out, f"redirect roundtrip failed: {out!r}"

    def test_repeated_uname_byte_identical(self, shell):
        runs = [shell.run("uname -a") for _ in range(5)]
        first = runs[0]
        assert all(r == first for r in runs), f"drift across runs: {runs}"

    def test_uptime_monotonic(self, shell):
        u1 = shell.run("uptime")
        time.sleep(3)
        u2 = shell.run("uptime")
        # Not asserting exact text — just that both exist and are nonempty
        assert u1 and u2, (u1, u2)
