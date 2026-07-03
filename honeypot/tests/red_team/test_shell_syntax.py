"""
In-process tests for shell_layer. No SSH needed — these exercise the router
directly against a synthetic SessionState, so they run in CI and on any laptop.

Why in-process: the shell parser is pure logic; running it on a live Pi
wastes time and adds flakiness. Persistent-shell tests cover the Pi side
separately (test_persistent_shell.py).
"""
from __future__ import annotations
import sys
from pathlib import Path

import pytest

# Make the repo-root modules importable when pytest runs from tests/red_team
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from node_context import get_session                # noqa: E402
from dispatch import route                          # noqa: E402
import shell_layer                                  # noqa: E402


@pytest.fixture
def state():
    s = get_session(f"shelltest-{id(object())}", "10.0.0.99")
    s.current_dir = "/root"
    yield s


# ==============================================================================
# Sequences
# ==============================================================================

class TestSequences:
    def test_cd_then_pwd_is_stateful(self, state):
        out, _ = route("cd /tmp; pwd", state)
        assert out.strip() == "/tmp", f"expected /tmp, got {out!r}"

    def test_multi_cd(self, state):
        out, _ = route("cd /etc; pwd; cd /tmp; pwd", state)
        assert out.splitlines() == ["/etc", "/tmp"], out

    def test_sequence_empties_dropped(self, state):
        # true has empty output; pwd has output
        out, _ = route("true; pwd", state)
        assert out.strip() == "/root", out


# ==============================================================================
# Conditionals — no short-circuit, both sides run
# ==============================================================================

class TestConditionals:
    def test_and_runs_both(self, state):
        out, _ = route("true && pwd", state)
        assert out.strip() == "/root", out

    def test_or_runs_both(self, state):
        out, _ = route("false || pwd", state)
        assert out.strip() == "/root", out


# ==============================================================================
# Pipelines — narrow subset
# ==============================================================================

class TestPipelines:
    def test_head(self, state):
        out, _ = route("ps aux | head -3", state)
        assert len(out.splitlines()) == 3, out

    def test_head_short_flag(self, state):
        out, _ = route("ps aux | head -5", state)
        assert len(out.splitlines()) == 5, out

    def test_tail(self, state):
        out, _ = route("ps aux | tail -2", state)
        assert len(out.splitlines()) == 2, out

    def test_wc_l(self, state):
        full, _ = route("ps aux", state)
        expected = len(full.splitlines())
        out, _ = route("ps aux | wc -l", state)
        assert out.strip() == str(expected), f"{out!r} vs {expected}"

    def test_grep(self, state):
        out, _ = route("ps aux | grep apache", state)
        for line in out.splitlines():
            assert "apache" in line.lower(), line

    def test_grep_invert(self, state):
        out, _ = route("ps aux | grep -v apache", state)
        for line in out.splitlines():
            assert "apache" not in line.lower(), line

    def test_sort(self, state):
        out, _ = route("ls / | sort", state)
        lines = out.splitlines()
        assert lines == sorted(lines), out


# ==============================================================================
# Redirects
# ==============================================================================

class TestRedirects:
    def test_write_then_read(self, state):
        out1, _ = route("echo hello > /tmp/greet", state)
        assert out1 == "", "redirect should eat stdout"
        out2, _ = route("cat /tmp/greet", state)
        assert out2.strip() == "hello", out2

    def test_null_redirect_silenced(self, state):
        out, _ = route("whoami >/dev/null", state)
        assert out == ""

    def test_stderr_null(self, state):
        out, _ = route("whoami 2>/dev/null", state)
        assert out.strip() == "root"


# ==============================================================================
# Env prefix
# ==============================================================================

class TestEnvPrefix:
    def test_lang_prefix_ignored(self, state):
        bare, _ = route("whoami", state)
        pre, _ = route("LANG=C whoami", state)
        assert bare.strip() == pre.strip() == "root", (bare, pre)

    def test_multi_env(self, state):
        out, _ = route("LANG=C TZ=UTC whoami", state)
        assert out.strip() == "root"


# ==============================================================================
# Rejections — unsupported constructs emit plausible bash errors
# ==============================================================================

class TestRejections:
    def test_cmd_substitution_dollar(self, state):
        out, _ = route("echo $(whoami)", state)
        assert "syntax error" in out.lower(), out

    def test_cmd_substitution_backtick(self, state):
        out, _ = route("echo `whoami`", state)
        assert "syntax error" in out.lower(), out

    def test_heredoc(self, state):
        out, _ = route("cat <<EOF", state)
        assert "syntax error" in out.lower() or "unexpected end" in out.lower(), out

    def test_background_ampersand(self, state):
        out, _ = route("sleep 1 &", state)
        # either an error, or benign empty — just MUST NOT run a real sleep
        assert out == "" or "syntax error" in out.lower() or "backgrounding" in out.lower(), out

    def test_three_stage_pipeline_rejected(self, state):
        out, _ = route("cat /etc/passwd | head -5 | wc -l", state)
        assert "syntax error" in out.lower() or "unexpected token" in out.lower(), out

    def test_unknown_pipe_tool(self, state):
        out, _ = route("ls | xxd", state)
        assert "syntax error" in out.lower() or "unexpected token" in out.lower(), out


# ==============================================================================
# analyze() classifier — pure function tests
# ==============================================================================

class TestAnalyzer:
    @pytest.mark.parametrize("cmd,expected_type", [
        ("whoami", "simple"),
        ("LANG=C whoami", "simple"),
        ("cd /tmp; pwd", "sequence"),
        ("true && pwd", "conditional"),
        ("ls | head", "pipeline"),
        ("echo x > /tmp/f", "redirect"),
        ("echo $(whoami)", "unsupported"),
        ("cmd <<EOF", "unsupported"),
        ("echo `date`", "unsupported"),
        ("cat /etc/passwd | unknown_tool", "unsupported"),
    ])
    def test_analyze_classification(self, cmd, expected_type):
        assert shell_layer.analyze(cmd).type == expected_type
