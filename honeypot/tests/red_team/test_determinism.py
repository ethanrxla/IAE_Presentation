"""
Repeated-probe determinism. The scorer will run the same command multiple
times and diff. Random jumps = instant finding.

Runs in-process; no live Pi required.
"""
from __future__ import annotations
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from node_context import get_session, clear_session  # noqa: E402
from dispatch import route                           # noqa: E402


@pytest.fixture
def fresh_state(request):
    sid = f"det-{request.node.name}"
    s = get_session(sid, "10.0.0.42")
    yield s
    clear_session(sid)


DETERMINISTIC_PROBES = [
    "whoami",
    "hostname",
    "uname -a",
    "uname -r",
    "id",
    "ps aux",
    "ps -ef",
    "stat /etc/passwd",
    "stat /etc/hostname",
    "systemctl status apache2",
    "systemctl status mysql",
    "ls /etc",
    "ls /",
    "env",
    "cat /etc/os-release",
]


@pytest.mark.parametrize("cmd", DETERMINISTIC_PROBES)
def test_repeated_probe_byte_identical(fresh_state, cmd):
    """Same probe 5× in one session → all outputs byte-identical."""
    outs = [route(cmd, fresh_state)[0] for _ in range(5)]
    first = outs[0]
    for i, out in enumerate(outs[1:], 2):
        assert out == first, (
            f"run {i} diverged for {cmd!r}:\n"
            f"  first: {first[:200]!r}\n"
            f"  this:  {out[:200]!r}"
        )


def test_stat_stable_across_sessions_same_path(fresh_state):
    """
    stat output can legitimately differ between sessions (different inode seeds),
    but it MUST stay stable within a session across arbitrarily many calls.
    """
    path = "/etc/passwd"
    r1 = route(f"stat {path}", fresh_state)[0]
    # Interleave with other commands; stat must still match
    route("whoami", fresh_state)
    route("ls /", fresh_state)
    r2 = route(f"stat {path}", fresh_state)[0]
    assert r1 == r2
