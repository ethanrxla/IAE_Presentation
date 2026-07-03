#!/usr/bin/env python3
"""
edge_inference.py — Tier 3: Local Ollama LLM (ONLY)
Distributed Sensor Network - Node Agent

DESIGN PRINCIPLE: This tier is ONLY the local LLM. If Ollama fails or is too
slow, Tier 3 returns (success=False, ...). The router decides whether to
escalate to Tier 4 or use a safe fallback. Tier 3 does NOT call the cloud.

This separation matters because:
  - Cloud escalation is a scored decision — it must be explicit
  - Mixing local + cloud inside one function makes metrics ambiguous
  - Different timeouts/budgets apply to each tier

Latency target: < 3s for real-time attacker interaction.
Latency budget: 5s hard timeout, after which router decides.

Keep-alive: model stays resident for 60 minutes via `keep_alive` param.
This avoids the 30-40s cold-reload penalty documented in hints.
"""

import json
import time
import urllib.request
import urllib.error
from typing import Tuple

from node_context import SessionState


# ==============================================================================
# Config
# ==============================================================================

OLLAMA_HOST = "http://localhost:11434"
OLLAMA_MODEL = "qwen2.5:1.5b"  # Switch to qwen2.5:0.5b if too slow, phi3:mini if more quality needed

# Hard timeout — after this, Tier 3 gives up and router can escalate
OLLAMA_TIMEOUT = 5.0

# Keep model resident for 60 min (hints doc recommends this to avoid cold start)
KEEP_ALIVE = "60m"


# ==============================================================================
# System prompt — shapes the LLM's behavior
# ==============================================================================

def build_system_prompt(state: SessionState) -> str:
    """Build a dynamic system prompt that reflects current session state."""
    return f"""You are a Debian GNU/Linux 11 (bullseye) shell simulator running on a Raspberry Pi 4.
You must respond EXACTLY as a real terminal would — raw command output only, no explanations.

System facts (be consistent with these):
- Hostname: pi-sensor-gateway
- IP: 10.1.10.20  (eth0, MAC b8:27:eb:12:34:56)
- Gateway: 10.1.10.1
- Other nodes: 10.1.10.21 (node-beta), 10.1.10.22 (node-gamma), 10.1.10.55 (admin)
- OS: Debian 11 bullseye, Linux 5.15.84-v7l+ armv7l
- RAM: 3.7G total, ~1.7G used
- Disk: /dev/mmcblk0p2 30G mounted on /, 17% used
- Services running: apache2, mariadb, sshd, cron, rsyslog, sensor collector
- Web root: /var/www/html (has config.php with DB creds, admin panel, robots.txt)
- User logged in: root (from {state.attacker_ip})
- Current dir: {state.current_dir}
- System uptime: {state.uptime_seconds() // 86400} days

Installed: bash, python3 (3.9.2), perl, curl, wget, git, gcc, apache2, mariadb-server, openssh-server
NOT installed: docker, kubectl, nmap, nginx, postgresql

Output rules:
1. Output ONLY what the terminal would print. No markdown, no code fences, no preamble.
2. If command would produce no output (cd, export, touch), return empty string.
3. If command doesn't exist, return: bash: <cmd>: command not found
4. Be concise — real commands don't write essays.
5. Numbers/paths/PIDs should look realistic and consistent."""


# ==============================================================================
# Core Ollama call
# ==============================================================================

def _call_ollama(prompt: str, system: str, timeout: float = OLLAMA_TIMEOUT) -> Tuple[bool, str, float]:
    """
    Call Ollama API. Returns (success, response, latency_seconds).
    success=False means Ollama failed/timed out — router should escalate.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "system": system,
        "stream": False,
        "keep_alive": KEEP_ALIVE,
        "options": {
            "temperature": 0.25,    # Low temp = consistent, realistic output
            "num_predict": 512,     # Cap output length
            "top_p": 0.9,
            "repeat_penalty": 1.1,
            "stop": ["\n$", "\n#", "\n>"],  # Stop at next prompt
        }
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            latency = time.time() - start
            text = result.get("response", "").strip()
            return True, text, latency
    except urllib.error.URLError:
        return False, "", time.time() - start
    except (TimeoutError, Exception):
        return False, "", time.time() - start


# ==============================================================================
# Public interface
# ==============================================================================

def handle(command: str, state: SessionState) -> Tuple[bool, str, float]:
    """
    Attempt to generate a response via local LLM.

    Returns: (success, response, latency_seconds)
      success=True  -> use response
      success=False -> Ollama failed; router will call Tier 4 or fallback

    This function NEVER calls the cloud. That's Tier 4's job.
    """
    # Build prompt with recent command history for context consistency
    context_lines = []
    if state.command_history:
        recent = state.command_history[-3:-1]  # Last few commands (excluding current)
        if recent:
            context_lines.append("Recent commands in this session:")
            for c in recent:
                context_lines.append(f"  $ {c}")
            context_lines.append("")
    context_lines.append(f"$ {command}")
    prompt = "\n".join(context_lines)

    system = build_system_prompt(state)
    return _call_ollama(prompt, system)


def warm_up() -> bool:
    """
    Pre-load the model into memory. Call this on Cowrie startup so the first
    real attacker command doesn't pay the cold-start penalty (30-40s).
    Returns True if model is loaded and responsive.
    """
    success, _, latency = _call_ollama(
        prompt="echo warm",
        system="Respond with: warm",
        timeout=60.0,  # Allow long timeout for initial load
    )
    return success


def is_loaded() -> bool:
    """Check if the model is currently resident in memory."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/ps", method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = data.get("models", [])
            return any(m.get("name", "").startswith(OLLAMA_MODEL.split(":")[0]) for m in models)
    except Exception:
        return False


if __name__ == "__main__":
    from node_context import get_session
    print(f"[edge-inference] Warming up {OLLAMA_MODEL}...")
    if warm_up():
        print(f"[edge-inference] Model loaded (resident: {is_loaded()})")
        s = get_session("test")
        for cmd in ["ls /var/www/html", "cat /opt/sensor/collect.sh", "ping -c 1 10.1.10.21"]:
            print(f"\n$ {cmd}")
            ok, resp, lat = handle(cmd, s)
            print(f"[{'OK' if ok else 'FAIL'} {lat:.2f}s] {resp[:200]}")
    else:
        print("[edge-inference] Ollama not available — this is expected if running outside Pi")