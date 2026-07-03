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

Latency: 3-10s typical. This is naturally detectable, so the router only
sends commands here where attackers would tolerate slow responses anyway
(find / -name ..., apt-get update, pip install ..., large file reads).

!! CONFIGURATION !!
Fill in BEDROCK_ENDPOINT, MODEL_ID, and credentials BEFORE the gauntlet.
See bedrock_setup.md for step-by-step AWS configuration.
"""

import json
import time
import urllib.request
import urllib.error
import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Tuple

from node_context import SessionState


# ==============================================================================
# Configuration — EDIT THESE DAY-OF
# ==============================================================================

# Bedrock region — whatever AWS tells you to use
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Bedrock model ID — Claude Haiku is fast + cheap, good for this use case.
# Other options:
#   anthropic.claude-3-haiku-20240307-v1:0      (recommended — fast, cheap)
#   anthropic.claude-3-5-sonnet-20241022-v2:0   (higher quality, slower)
#   amazon.titan-text-express-v1                (Amazon's own, very cheap)
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")

# Credentials — prefer environment variables, never hard-code
AWS_ACCESS_KEY_ID     = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
AWS_SESSION_TOKEN     = os.environ.get("AWS_SESSION_TOKEN", "")

# Hard timeout — cloud calls must complete within this or router gives up
BEDROCK_TIMEOUT = 8.0

# Max tokens per response — shell commands don't need long essays
MAX_TOKENS = 512


# ==============================================================================
# AWS SigV4 signing (vanilla stdlib — no boto3 dependency on Pi)
# ==============================================================================

def _sigv4_sign_request(method, host, path, payload, access_key, secret_key, session_token, region, service="bedrock"):
    """
    Sign an HTTPS request for AWS SigV4. Returns headers dict.
    Using stdlib only (no boto3) to keep Pi install minimal.
    """
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = path
    canonical_querystring = ""
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    if session_token:
        canonical_headers += f"x-amz-security-token:{session_token}\n"
        signed_headers += ";x-amz-security-token"

    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

    def sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    auth_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    headers = {
        "Content-Type": "application/json",
        "X-Amz-Date": amz_date,
        "Authorization": auth_header,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token
    return headers


# ==============================================================================
# Prompt construction
# ==============================================================================

def build_bedrock_prompt(command: str, state: SessionState) -> dict:
    """Build the Bedrock Messages API payload (Claude format)."""
    system_context = f"""You are simulating a real Debian 11 shell on a Raspberry Pi 4 (pi-sensor-gateway, 10.1.10.20).
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
    Escalate to AWS Bedrock. Returns (success, response, latency_seconds).
    success=False means the cloud call failed — router handles with fallback.

    This function NEVER touches local Ollama. That's Tier 3's job.
    """
    # Fail loud if not configured — better than silent fallback
    if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY:
        return False, "", 0.0

    host = f"bedrock-runtime.{AWS_REGION}.amazonaws.com"
    path = f"/model/{MODEL_ID}/invoke"
    url  = f"https://{host}{path}"

    payload_dict = build_bedrock_prompt(command, state)
    payload = json.dumps(payload_dict)

    headers = _sigv4_sign_request(
        method="POST",
        host=host,
        path=path,
        payload=payload,
        access_key=AWS_ACCESS_KEY_ID,
        secret_key=AWS_SECRET_ACCESS_KEY,
        session_token=AWS_SESSION_TOKEN,
        region=AWS_REGION,
    )

    req = urllib.request.Request(
        url,
        data=payload.encode("utf-8"),
        headers=headers,
        method="POST",
    )

    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=BEDROCK_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            latency = time.time() - start

            # Claude on Bedrock returns content as list of blocks
            content = body.get("content", [])
            text_parts = [b.get("text", "") for b in content if b.get("type") == "text"]
            response_text = "\n".join(text_parts).strip()
            return True, response_text, latency
    except urllib.error.HTTPError as e:
        # Most common: auth error (bad creds) or throttling
        try:
            err_body = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            err_body = str(e)
        return False, f"[bedrock error: {e.code} {err_body}]", time.time() - start
    except Exception as e:
        return False, f"[bedrock error: {e}]", time.time() - start


def is_configured() -> bool:
    """Check if Tier 4 is ready to use."""
    return bool(AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY)


def health_check() -> Tuple[bool, str]:
    """Quick sanity check — try a tiny call and see if it works."""
    if not is_configured():
        return False, "Credentials not set (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)"
    from node_context import SessionState
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