"""
SCALPEL self-gauntlet runner — production-ready SSH harness.

Runs all probes against your honeypot AND the clean ground truth Pi,
diffs them, scores you using the official formula.

USAGE:
    pip install paramiko
    python3 runner.py --honeypot 192.168.1.42 --truth 192.168.1.43

OUTPUT:
    Console report + JSON saved to gauntlet_report_<timestamp>.json

This is your dress rehearsal. Run it Day 1 evening + Day 2 morning.
"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional

# Add red_team dir to path so probes/scoring imports work standalone
sys.path.insert(0, str(Path(__file__).parent))

import paramiko

import probes
import scoring


# ============================================================
# SSH client with connection reuse
# ============================================================

class SSHRunner:
    """Persistent SSH connection. Reuse across many commands for accuracy."""

    def __init__(self, host: str, user: str, password: str, port: int = 22):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.client: Optional[paramiko.SSHClient] = None

    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )

    def run(self, command: str, timeout: int = 10) -> tuple[str, float]:
        """Returns (combined_output, elapsed_seconds)."""
        if self.client is None:
            self.connect()
        start = time.perf_counter()
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            elapsed = time.perf_counter() - start
            return (out + err).rstrip("\n"), elapsed
        except Exception as e:
            elapsed = time.perf_counter() - start
            return f"<SSH_ERROR: {e}>", elapsed

    def close(self):
        if self.client:
            self.client.close()
            self.client = None


# ============================================================
# Comparison
# ============================================================

# Tokens that legitimately differ between the two Pis
VOLATILE_PATTERNS = [
    re.compile(r"\b\d+:\d+:\d+\b"),                  # times
    re.compile(r"\b\d+ days?, \d+:\d+\b"),           # uptime
    re.compile(r"up \d+ \w+,? "),                    # uptime -p
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),  # IPs
    re.compile(r"load average: [\d., ]+"),
    re.compile(r"\d+%\s+/"),                         # df % usage
    re.compile(r"\b\d+M\s+used\b"),                  # free memory
    re.compile(r"\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\?"),  # ps stats
]


def normalize(text: str) -> str:
    """Collapse volatile values so timing/load doesn't cause false demerits."""
    n = text
    for p in VOLATILE_PATTERNS:
        n = p.sub("<VOL>", n)
    n = re.sub(r"\s+", " ", n).strip().lower()
    return n


def compare(honey: str, truth: str, strict: bool = False) -> bool:
    """True if outputs are semantically equivalent."""
    if strict:
        return honey == truth
    return normalize(honey) == normalize(truth)


def categorize_finding(cmd: str, honey: str, truth: str) -> str:
    """Why did this fail?"""
    if not honey or honey.startswith("<SSH_ERROR"):
        return "no_response"
    if "command not found" in honey.lower() and "command not found" not in truth.lower():
        return "missing_command"  # Tier 1 doesn't cover this; Tier 2 returned not-found
    if "permission denied" in honey.lower() and "permission denied" not in truth.lower():
        return "permission_diff"
    if any(k in cmd for k in ["/etc/", "/proc/", "/sys/", "cat ", "ls "]):
        return "filesystem_mismatch"
    if "uname" in cmd or "version" in cmd or "release" in cmd:
        return "version_string_mismatch"
    return "wrong_output"


# ============================================================
# Latency analysis
# ============================================================

# A probe in this category that exceeds this threshold = predicted escalation finding.
LATENCY_THRESHOLDS = {
    "easy": 0.3,         # 300ms — easy commands should be sub-100ms ideally
    "intermediate": 1.0, # 1s — Ollama budget
    "complex": 3.0,      # 3s — cloud is OK here
    "latency": 0.2,      # 200ms — anything slower is a tell
}


def is_escalation_finding(category: str, elapsed: float) -> bool:
    threshold = LATENCY_THRESHOLDS.get(category, 1.0)
    return elapsed > threshold


# ============================================================
# Main harness
# ============================================================

def run_gauntlet(honeypot_ip: str, truth_ip: str, save_path: Optional[Path] = None):
    print(f"Connecting to honeypot at {honeypot_ip}:2222...")
    honey = SSHRunner(honeypot_ip, "root", "root", 2222)
    honey.connect()
    print(f"Connecting to ground truth at {truth_ip}:22...")
    truth = SSHRunner(truth_ip, "pi", "raspberry", 22)
    truth.connect()

    all_probes = probes.all_probes()
    print(f"Running {len(all_probes)} probes...\n")

    results = []
    demerits = 0
    escalations = 0
    findings = []

    for i, (category, cmd) in enumerate(all_probes, 1):
        try:
            h_out, h_t = honey.run(cmd)
        except Exception as e:
            h_out, h_t = f"<SSH_ERROR: {e}>", 0.0
        try:
            t_out, t_t = truth.run(cmd)
        except Exception as e:
            t_out, t_t = f"<SSH_ERROR: {e}>", 0.0

        match = compare(h_out, t_out)
        esc = is_escalation_finding(category, h_t)

        if not match:
            demerits += 1
            kind = categorize_finding(cmd, h_out, t_out)
            findings.append({"cmd": cmd, "kind": kind, "category": category,
                            "honey": h_out[:200], "truth": t_out[:200]})
        if esc:
            escalations += 1

        results.append({
            "category": category,
            "cmd": cmd,
            "match": match,
            "escalation": esc,
            "honey_t": round(h_t * 1000, 1),
            "truth_t": round(t_t * 1000, 1),
            "honey_out": h_out[:300],
            "truth_out": t_out[:300],
        })

        status = "✓" if match else "✗"
        latency_flag = " [SLOW]" if esc else ""
        print(f"  {i:3d}. [{category[:4]}] {status} {cmd:<40s} {h_t*1000:5.0f}ms{latency_flag}")

    honey.close()
    truth.close()

    # Score
    score = scoring.compute_score(
        total_probes=len(results),
        demerits=demerits,
        escalations=escalations,
        presentation=90.0,  # placeholder
    )

    print()
    scoring.print_report(score, findings)

    # Save
    if save_path:
        save_path.write_text(json.dumps({
            "score": score,
            "results": results,
            "findings": findings,
        }, indent=2))
        print(f"\nReport saved: {save_path}")

    return score, results, findings


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--honeypot", required=True, help="Honeypot Pi IP")
    p.add_argument("--truth", required=True, help="Ground truth Pi IP")
    p.add_argument("--save", help="Path to save JSON report", default=None)
    args = p.parse_args()

    save_path = Path(args.save) if args.save else Path(f"gauntlet_report_{int(time.time())}.json")
    run_gauntlet(args.honeypot, args.truth, save_path)
