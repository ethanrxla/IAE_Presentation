#!/usr/bin/env python3
"""
upstream_sync.py — Tier 4: AWS Bedrock Cloud Escalation (ONLY)
Distributed Sensor Network - Node Agent

DESIGN PRINCIPLE: This tier is ONLY the cloud call. It does NOT fall back
to Tier 3 or any local handler. The router handles failures.

Every call to this tier costs points on the Edge Efficiency score (40%).
It should be the LAST resort, invoked only when:
  - Tier 1/2/3 genuinely cannot produce a convincing response, AND
  - The command is one where the red team would expect real complexity

Latency: ~1.5s typical. This is naturally detectable, so the router only
sends commands here where attackers would tolerate slow responses anyway
(find / -name ..., apt-get update, pip install ..., large file reads).

CLIENT: direct AWS Bedrock call via boto3 (Claude Haiku 4.5). boto3 resolves
credentials from the environment (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY,
sourced into the Cowrie service env) or an instance role. boto3 is imported
lazily so this module loads even where boto3 isn't installed (e.g. CI).
"""

import json
import time
import os
from typing import Tuple

from node_context import SessionState


# ==============================================================================
# Configuration — EDIT THESE DAY-OF
# ==============================================================================

# Bedrock region — whatever AWS tells you to use
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Bedrock model ID — Claude Haiku 4.5 is fast + cheap, good for this use case.
# Other options:
#   us.anthropic.claude-haiku-4-5-20251001-v1:0   (recommended — fast, cheap)
#   us.anthropic.claude-sonnet-4-5-20250929-v1:0  (higher quality, slower)
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

# Credentials — resolved by boto3 from the environment / instance role.
# Presence of these env vars is how the router decides Tier 4 is "configured".
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

# Hard timeout — cloud calls must complete within this or the router gives up
BEDROCK_TIMEOUT = 8.0

# Max tokens per response — shell commands don't need long essays
MAX_TOKENS = 512


# ==============================================================================
# Lazy boto3 client (kept out of import time so CI without boto3 still loads)
# ==============================================================================

_client = None


def _get_client():
    """Create (once) and return a boto3 bedrock-runtime client."""
    global _client
    if _client is None:
        import boto3
        from botocore.config import Config
        _client = boto3.client(
            "bedrock-runtime",
            region_name=AWS_REGION,
            config=Config(read_timeout=BEDROCK_TIMEOUT, retries={"max_attempts": 1}),
        )
    return _client


# ==============================================================================
# Prompt construction
# ==============================================================================

def build_bedrock_prompt(command: str, state: SessionState) -> dict:
    """Build the Bedrock Messages API payload (Claude format)."""
    system_context = f"""You are simulating a real Debian 13 (trixie) shell on a Raspberry Pi 5 (pi-sensor-gateway, 10.1.10.20, aarch64).
You are logged in as root from {state.attacker_ip}. Current directory: {state.current_dir}.
System has been up {state.uptime_seconds() // 86400} days.
Services running: apache2, mariadb, sshd, cron, sensor collector.
Respond with ONLY the raw terminal output — no markdown, no explanations, no code fences.
If command would produce no output, return an empty string.
If command not found, return: bash: <cmd>: command not found"""

    # Include last 3 commands for consistency
    history_context = ""
    if state.command_history:
        recent = state.command_history[-4:-1]
        if recent:
            history_context = "Recent session commands:\n" + "\n".join(f"  $ {c}" for c in recent) + "\n\n"

    return {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": MAX_TOKENS,
        "temperature": 0.2,
        "system": system_context,
        "messages": [
            {
                "role": "user",
                "content": f"{history_context}Produce realistic terminal output for this command:\n\n$ {command}"
            }
        ],
    }


# ==============================================================================
# Public interface
# ==============================================================================

def handle(command: str, state: SessionState) -> Tuple[bool, str, float]:
    """
    Escalate to AWS Bedrock (Claude Haiku 4.5 via boto3).
    Returns (success, response, latency_seconds). success=False means the cloud
    call failed — the router handles that with its own fallback.

    This function NEVER touches local Ollama. That's Tier 3's job.
    """
    # Fail loud if not configured — better than silent fallback
    if not is_configured():
        return False, "", 0.0

    try:
        client = _get_client()
    except Exception as e:
        return False, f"[bedrock error: boto3 unavailable: {e}]", 0.0

    payload = json.dumps(build_bedrock_prompt(command, state))

    start = time.time()
    try:
        resp = client.invoke_model(
            modelId=MODEL_ID,
            body=payload,
            contentType="application/json",
            accept="application/json",
        )
        body = json.loads(resp["body"].read())
        latency = time.time() - start

        # Claude on Bedrock returns content as a list of blocks
        content = body.get("content", [])
        text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
        response_text = "\n".join(text_parts).strip()
        return True, response_text, latency
    except Exception as e:
        # Most common: auth error (bad/absent creds), throttling, or timeout
        return False, f"[bedrock error: {e}]", time.time() - start


def is_configured() -> bool:
    """Check if Tier 4 is ready to use (credentials present in the env)."""
    return bool(AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)


def health_check() -> Tuple[bool, str]:
    """Quick sanity check — try a tiny call and see if it works."""
    if not is_configured():
        return False, "Credentials not set (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)"
    state = SessionState()
    success, resp, latency = handle("echo ok", state)
    if success:
        return True, f"OK — Bedrock responded in {latency:.2f}s"
    return False, f"Failed: {resp}"


if __name__ == "__main__":
    print(f"Tier 4 — Bedrock region={AWS_REGION} model={MODEL_ID}")
    print(f"Configured: {is_configured()}")
    if is_configured():
        ok, msg = health_check()
        print(f"Health: {'OK' if ok else 'FAIL'} — {msg}")
    else:
        print("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env vars before testing.")
