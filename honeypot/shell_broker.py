#!/usr/bin/env python3
"""
shell_broker.py — Cowrie Integration Hook
Distributed Sensor Network - Node Agent

Thin wrapper that hooks Cowrie's command dispatch and routes every attacker
command through dispatch.route().

INSTALL:
  1. Copy all .py files to ~/cowrie/src/cowrie/commands/sensor_agent/
     (or wherever your Cowrie install keeps its command modules — check
     ~/cowrie/bin/cowrie to see the src layout)
  2. In ~/cowrie/etc/cowrie.cfg under [honeypot]:
       enable_sensor_agent = true
  3. ~/cowrie/bin/cowrie restart
  4. Verify hook: tail -f ~/cowrie/var/log/cowrie/cowrie.log and look for
       [sensor-agent] lines.

If Cowrie's hook points change between versions, the integration function
install_hook() below is the one-stop shop to update.
"""

import sys
import os
import logging
import traceback

# Make sibling modules importable regardless of where Cowrie imports this from
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import dispatch
    from node_context import get_session
    READY = True
except Exception as e:
    READY = False
    print(f"[sensor-agent] Tier modules failed to load: {e}", file=sys.stderr)

log = logging.getLogger(__name__)


# ==============================================================================
# Main hook — called once per attacker command
# ==============================================================================

def handle_command(command: str, session_id: str, attacker_ip: str = "unknown") -> str:
    """
    The one public function Cowrie should call.

    Args:
        command:     the raw command line the attacker typed
        session_id:  Cowrie's session identifier (stable per SSH connection)
        attacker_ip: source IP (for session state seeding)

    Returns:
        the string to write back to the attacker's terminal.
        If empty, Cowrie's default handler should run (e.g., exit).
    """
    if not READY:
        # Modules didn't import. Still answer with something plausible; do NOT
        # return "" and let Cowrie's default shell kick in — that causes a
        # visible behavior change (different "physics") mid-session.
        try:
            import dispatch as _d
            return _d.safe_response(command)
        except Exception:
            head = (command.split() or [""])[0]
            return f"bash: {head}: command not found" if head else ""

    try:
        state = get_session(session_id, attacker_ip)
        response, level = dispatch.route(command, state)
        log.info(f"[sensor-agent] session={session_id} ip={attacker_ip} level={level.name} cmd={command!r}")
        return response
    except Exception as e:
        log.error(f"[sensor-agent] routing error for {command!r}: {e}\n{traceback.format_exc()}")
        # Controlled fallback — plausible bash response, keeps our fake-shell
        # behavior consistent instead of phase-changing into raw Cowrie.
        return dispatch.safe_response(command)


def end_session(session_id: str) -> None:
    """Call from Cowrie's session-end hook to release state."""
    if not READY:
        return
    try:
        from node_context import clear_session
        clear_session(session_id)
    except Exception:
        pass


# ==============================================================================
# Startup — call from Cowrie boot
# ==============================================================================

def startup():
    """Call this when Cowrie service starts. Warms up Ollama, etc."""
    if not READY:
        print("[sensor-agent] startup skipped — tier modules not loaded")
        return
    print("[sensor-agent] Starting intelligence stack...")
    dispatch.startup()
    print("[sensor-agent] Ready.")


# ==============================================================================
# Cowrie command class — catch-all for unknown commands
# (Used when hook-patching isn't available; register in cowrie commands dir)
# ==============================================================================

try:
    from cowrie.shell.command import HoneyPotCommand

    class Command_scalpel(HoneyPotCommand):
        """Catch-all command handler."""
        def call(self):
            full_cmd = " ".join([self.cmd] + list(self.args or []))
            session_id = getattr(self.protocol, "transportId", "unknown")
            attacker_ip = getattr(self.protocol, "src_ip", "unknown")
            response = handle_command(full_cmd, session_id, attacker_ip)
            if response:
                self.write(response + "\n")

        def handle_CTRL_D(self):
            session_id = getattr(self.protocol, "transportId", "unknown")
            end_session(session_id)
            super().handle_CTRL_D()

    # Cowrie will pick up this dict when loading custom commands
    commands = {"*": Command_scalpel}
except ImportError:
    # Running outside Cowrie (tests) — that's fine
    pass


if __name__ == "__main__":
    # Standalone test
    startup()
    print()
    for cmd in ["whoami", "date", "uptime", "ps aux", "ls /"]:
        print(f"$ {cmd}")
        resp = handle_command(cmd, session_id="test", attacker_ip="1.2.3.4")
        for line in resp.split("\n")[:5]:
            print(f"  {line}")
    print()
    print(dispatch.metrics.summary())