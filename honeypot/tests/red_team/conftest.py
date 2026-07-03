"""
Pytest fixtures for the automated red-team suite.

Two SSH targets:
  - honeypot: root@<pi>:2222  password root   (our system under test)
  - clean_pi: pi@<pi>:22       password raspberry  (oracle — optional)

Config via env vars OR pytest CLI flags:
  PYTEST_HONEYPOT_IP    (required)
  PYTEST_CLEAN_PI_IP    (optional — some assertions skip without it)
  PYTEST_HONEYPOT_USER  default "root"
  PYTEST_HONEYPOT_PASS  default "root"
  PYTEST_HONEYPOT_PORT  default 2222
  PYTEST_CLEAN_PI_USER  default "pi"
  PYTEST_CLEAN_PI_PASS  default "raspberry"
  PYTEST_CLEAN_PI_PORT  default 22

Or:
  pytest --honeypot=1.2.3.4 --clean-pi=1.2.3.5

Fixtures are session-scoped so one connection is reused across all tests.
"""
from __future__ import annotations
import os
import time
from dataclasses import dataclass
from typing import Optional

import pytest

try:
    import paramiko
except ImportError:  # pragma: no cover
    paramiko = None

from assertions import ProbeResult


# ==============================================================================
# CLI flags
# ==============================================================================

def pytest_addoption(parser):
    parser.addoption("--honeypot", action="store", default=None, help="Honeypot Pi IP")
    parser.addoption("--honeypot-port", action="store", default=None, help="Honeypot SSH port (default 2222)")
    parser.addoption("--honeypot-user", action="store", default=None)
    parser.addoption("--honeypot-pass", action="store", default=None)
    parser.addoption("--clean-pi", action="store", default=None, help="Clean Pi IP (oracle)")
    parser.addoption("--clean-pi-port", action="store", default=None)
    parser.addoption("--clean-pi-user", action="store", default=None)
    parser.addoption("--clean-pi-pass", action="store", default=None)
    parser.addoption("--offline", action="store_true", help="Skip tests that need live targets")


# ==============================================================================
# Target config
# ==============================================================================

@dataclass
class Target:
    host: str
    port: int
    user: str
    password: str
    label: str


def _env_or_opt(request, opt_name, env_name, default=None):
    v = request.config.getoption(opt_name)
    if v is not None:
        return v
    return os.environ.get(env_name, default)


@pytest.fixture(scope="session")
def honeypot_target(request) -> Optional[Target]:
    host = _env_or_opt(request, "--honeypot", "PYTEST_HONEYPOT_IP")
    if not host:
        return None
    return Target(
        host=host,
        port=int(_env_or_opt(request, "--honeypot-port", "PYTEST_HONEYPOT_PORT", 2222)),
        user=_env_or_opt(request, "--honeypot-user", "PYTEST_HONEYPOT_USER", "root"),
        password=_env_or_opt(request, "--honeypot-pass", "PYTEST_HONEYPOT_PASS", "root"),
        label="honeypot",
    )


@pytest.fixture(scope="session")
def clean_pi_target(request) -> Optional[Target]:
    host = _env_or_opt(request, "--clean-pi", "PYTEST_CLEAN_PI_IP")
    if not host:
        return None
    return Target(
        host=host,
        port=int(_env_or_opt(request, "--clean-pi-port", "PYTEST_CLEAN_PI_PORT", 22)),
        user=_env_or_opt(request, "--clean-pi-user", "PYTEST_CLEAN_PI_USER", "pi"),
        password=_env_or_opt(request, "--clean-pi-pass", "PYTEST_CLEAN_PI_PASS", "raspberry"),
        label="clean_pi",
    )


# ==============================================================================
# SSH connections
# ==============================================================================

class SSHRunner:
    """Thin wrapper around paramiko for per-probe exec_command with timing."""
    def __init__(self, target: Target):
        if paramiko is None:
            pytest.skip("paramiko not installed: pip install paramiko")
        self.target = target
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            hostname=target.host, port=target.port,
            username=target.user, password=target.password,
            timeout=10, allow_agent=False, look_for_keys=False,
            banner_timeout=10,
        )

    def run(self, cmd: str, timeout: float = 10.0) -> ProbeResult:
        t0 = time.perf_counter()
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout, get_pty=False)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
        except Exception as e:
            return ProbeResult(cmd=cmd, stdout="", stderr=f"[runner error] {e}",
                               exit_code=-1, latency_ms=(time.perf_counter() - t0) * 1000)
        return ProbeResult(cmd=cmd, stdout=out, stderr=err, exit_code=rc,
                           latency_ms=(time.perf_counter() - t0) * 1000)

    def run_n(self, cmd: str, n: int, timeout: float = 10.0) -> "list[ProbeResult]":
        return [self.run(cmd, timeout) for _ in range(n)]

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass


@pytest.fixture(scope="session")
def honeypot(honeypot_target, request):
    if honeypot_target is None:
        pytest.skip("--honeypot not set; pass --honeypot=<ip> or set PYTEST_HONEYPOT_IP")
    r = SSHRunner(honeypot_target)
    yield r
    r.close()


@pytest.fixture(scope="session")
def clean_pi(clean_pi_target):
    if clean_pi_target is None:
        return None   # allow tests to proceed; assertions skip gracefully
    r = SSHRunner(clean_pi_target)
    yield r
    r.close()


# ==============================================================================
# Oracle fixtures dir — cached clean-Pi captures (fallback when clean_pi offline)
# ==============================================================================

@pytest.fixture(scope="session")
def oracle_dir(request):
    from pathlib import Path
    d = Path(__file__).parent / "baselines"
    d.mkdir(exist_ok=True)
    return d


# ==============================================================================
# Per-probe helper: run on honeypot, fetch-or-capture from oracle
# ==============================================================================

def get_clean_result(clean_pi, oracle_dir, cmd: str) -> Optional[ProbeResult]:
    """
    Live oracle if clean_pi fixture available; else look up a cached JSON fixture.
    Cache key is a filename-safe hash of the cmd.
    """
    import hashlib, json
    key = hashlib.sha1(cmd.encode()).hexdigest()[:12]
    cache = oracle_dir / f"{key}.json"
    if clean_pi is not None:
        r = clean_pi.run(cmd)
        try:
            cache.write_text(json.dumps({
                "cmd": cmd, "stdout": r.stdout, "stderr": r.stderr,
                "exit_code": r.exit_code, "latency_ms": r.latency_ms,
            }))
        except OSError:
            pass
        return r
    if cache.exists():
        d = json.loads(cache.read_text())
        return ProbeResult(**{k: d[k] for k in ("cmd", "stdout", "stderr", "exit_code", "latency_ms")})
    return None
