#!/bin/bash
# Runs the automated tools the Red Team will use, against BOTH Pis, and diffs.
# This is the part pytest can't do — network-layer fingerprinting, not shell output.
#
# Run from your laptop on the venue network:
#   ./external_tools.sh <honeypot_ip> <clean_pi_ip> [output_dir]
#
# Produces:
#   $OUT/diff.txt       — side-by-side diff of every tool output
#   $OUT/honey_*.txt    — honeypot outputs
#   $OUT/clean_*.txt    — clean Pi outputs
#   $OUT/report.md      — summary with pass/fail per tool
#
# A non-empty diff.txt for any probe = a fingerprint the Red Team can detect.

set -uo pipefail

HONEY="${1:-}"
CLEAN="${2:-}"
OUT="${3:-./external_tools_out}"

if [ -z "$HONEY" ] || [ -z "$CLEAN" ]; then
    echo "Usage: $0 <honeypot_ip> <clean_pi_ip> [output_dir]"
    exit 1
fi
mkdir -p "$OUT"

# ------------------------------------------------------------------------------
# Utility: run cmd against both targets, record, diff
# ------------------------------------------------------------------------------
compare() {
    local label="$1"
    local honey_cmd="$2"
    local clean_cmd="$3"
    local honey_out="$OUT/honey_${label}.txt"
    local clean_out="$OUT/clean_${label}.txt"
    echo "─── $label ───"
    eval "$honey_cmd" > "$honey_out" 2>&1
    eval "$clean_cmd" > "$clean_out" 2>&1
    if diff -q "$honey_out" "$clean_out" >/dev/null 2>&1; then
        echo "  ✓ identical"
    else
        echo "  ✗ DIFFERENT — see $OUT/diff.txt"
        {
            echo ""
            echo "=== $label ==="
            diff -u "$clean_out" "$honey_out"
        } >> "$OUT/diff.txt"
    fi
}

# Truncate prior diff
: > "$OUT/diff.txt"

echo "━━━ Network-layer fingerprint diff ━━━"
echo "honeypot: $HONEY:2222"
echo "clean_pi: $CLEAN:22"
echo "output:   $OUT/"
echo ""

# ------------------------------------------------------------------------------
# 1. Raw banner
# ------------------------------------------------------------------------------
compare "banner" \
    "timeout 3 bash -c 'exec 3<>/dev/tcp/$HONEY/2222; head -1 <&3'" \
    "timeout 3 bash -c 'exec 3<>/dev/tcp/$CLEAN/22;   head -1 <&3'"

# ------------------------------------------------------------------------------
# 2. ssh -vvv (client-side verbose handshake)
# ------------------------------------------------------------------------------
# Stable subset of the handshake output — rest is timing/random
SSH_CLEAN='ssh -vvv -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=5 -p $PORT $USER@$IP exit 2>&1 | grep -E "remote software version|kex: algorithm|server host key type|server_host_key_algorithms" | sort'
compare "ssh_verbose" \
    "PORT=2222 USER=root IP=$HONEY $SSH_CLEAN" \
    "PORT=22   USER=pi   IP=$CLEAN $SSH_CLEAN"

# ------------------------------------------------------------------------------
# 3. nmap -sV (service-version detection)
# ------------------------------------------------------------------------------
if command -v nmap >/dev/null; then
    compare "nmap_sV" \
        "nmap -Pn -sV -p 2222 $HONEY | grep -E '^2222|SF:|SSH'" \
        "nmap -Pn -sV -p 22   $CLEAN | grep -E '^22|SF:|SSH'"
else
    echo "  · nmap not installed, skipping service-version diff"
fi

# ------------------------------------------------------------------------------
# 4. nmap NSE ssh-hostkey
# ------------------------------------------------------------------------------
if command -v nmap >/dev/null; then
    # Compare hostkey format (type, length, comment lines) — actual key bytes differ,
    # so strip the base64 portions before diff.
    compare "nmap_hostkey_format" \
        "nmap -Pn -p 2222 --script ssh-hostkey $HONEY | grep -E '^\\|' | sed 's/[A-Za-z0-9+/]\\{20,\\}//g'" \
        "nmap -Pn -p 22   --script ssh-hostkey $CLEAN | grep -E '^\\|' | sed 's/[A-Za-z0-9+/]\\{20,\\}//g'"
fi

# ------------------------------------------------------------------------------
# 5. nmap NSE ssh2-enum-algos (kex, cipher, mac, compression advertisements)
# ------------------------------------------------------------------------------
if command -v nmap >/dev/null; then
    compare "nmap_enum_algos" \
        "nmap -Pn -p 2222 --script ssh2-enum-algos $HONEY | grep -E '^\\|'" \
        "nmap -Pn -p 22   --script ssh2-enum-algos $CLEAN | grep -E '^\\|'"
fi

# ------------------------------------------------------------------------------
# 6. ssh-audit (if installed)
# ------------------------------------------------------------------------------
if command -v ssh-audit >/dev/null; then
    compare "ssh_audit" \
        "ssh-audit -j $HONEY:2222 2>/dev/null | jq -S 'del(.banner.raw, .fingerprints)'" \
        "ssh-audit -j $CLEAN:22   2>/dev/null | jq -S 'del(.banner.raw, .fingerprints)'"
else
    echo "  · ssh-audit not installed (pip install ssh-audit), skipping"
fi

# ------------------------------------------------------------------------------
# 7. Port-scan sanity — only 22 and 2222 should be open on honeypot
# ------------------------------------------------------------------------------
if command -v nmap >/dev/null; then
    echo "─── honeypot port scan (expect only 22 + 2222 open) ───"
    HONEY_PORTS=$(nmap -Pn --open -p 22,2222,8080,11434,3000,5000,8000 "$HONEY" | grep "open" | awk '{print $1}')
    echo "$HONEY_PORTS"
    if echo "$HONEY_PORTS" | grep -qE "8080|11434"; then
        echo "  ✗ FAIL: dashboard (8080) or Ollama (11434) is externally reachable!"
        echo "exposed: $HONEY_PORTS" >> "$OUT/diff.txt"
    else
        echo "  ✓ only 22/2222 exposed"
    fi
fi

# ------------------------------------------------------------------------------
# Report
# ------------------------------------------------------------------------------
{
    echo "# External-tools diff report"
    echo ""
    echo "Date: $(date)"
    echo "Honeypot: $HONEY:2222"
    echo "Clean Pi: $CLEAN:22"
    echo ""
    if [ -s "$OUT/diff.txt" ]; then
        echo "## Divergences found ($(grep -c '^=== ' $OUT/diff.txt) tool(s))"
        echo ""
        echo '```diff'
        head -200 "$OUT/diff.txt"
        echo '```'
    else
        echo "## ✓ No divergences — honeypot is byte-identical on all tools tested"
    fi
} > "$OUT/report.md"

echo ""
echo "━━━ Done ━━━"
echo "Summary: $OUT/report.md"
echo "Full diff: $OUT/diff.txt"
[ -s "$OUT/diff.txt" ] && exit 1 || exit 0
