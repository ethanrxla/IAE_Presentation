#!/bin/bash
# Failure drills — run Day 1 evening on the honeypot Pi.
#
# Simulates the three failure modes from docs/COMMANDERS_INTENT.md:
#   1. Ollama unreachable (network drop)
#   2. Bedrock unreachable (DNS null)
#   3. Cowrie killed (watchdog recovery)
#   4. Ollama model unloaded (keepalive recovery)
#   5. Rapid-fire input storm (no traceback)
#
# Each drill times the recovery and prints PASS/FAIL. Run from the honeypot Pi
# as the cowrie user. Needs sudo for iptables drills.
#
# Usage:
#   bash failure_drills.sh [drill_number]
#   bash failure_drills.sh         # runs all
#   bash failure_drills.sh 3       # runs only drill 3 (Cowrie kill)

set -uo pipefail

PASS=0
FAIL=0
DRILL_ONLY="${1:-all}"

pass()  { echo "  ✓ PASS: $*"; PASS=$((PASS+1)); }
fail()  { echo "  ✗ FAIL: $*"; FAIL=$((FAIL+1)); }
info()  { echo "  · $*"; }
section() { echo ""; echo "━━━ $* ━━━"; }

run_if()  { [ "$DRILL_ONLY" = "all" ] || [ "$DRILL_ONLY" = "$1" ]; }

# Probe over localhost loopback into Cowrie port 2222.
# Requires sshpass installed (apt install sshpass).
PROBE_HONEY() {
    local cmd="$1"
    local timeout_s="${2:-5}"
    timeout "$timeout_s" sshpass -p root ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -p 2222 root@127.0.0.1 "$cmd" 2>&1
}

need_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 not installed — apt install $1"
        exit 2
    fi
}

need_cmd sshpass
need_cmd iptables
need_cmd curl
need_cmd jq

# ==============================================================================
# Drill 1 — Ollama unreachable
# ==============================================================================
if run_if 1; then
section "Drill 1 — Ollama unreachable"
info "dropping 127.0.0.1:11434 traffic via iptables"
sudo iptables -I OUTPUT -o lo -p tcp --dport 11434 -j DROP

started=$(date +%s)
N_OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    t0=$(date +%s%N)
    out=$(PROBE_HONEY "whoami" 6)
    t1=$(date +%s%N)
    elapsed_ms=$(( (t1 - t0) / 1000000 ))
    if [ "$elapsed_ms" -lt 5000 ] && [ -n "$out" ]; then
        N_OK=$((N_OK+1))
    fi
done

sudo iptables -D OUTPUT -o lo -p tcp --dport 11434 -j DROP
info "restored iptables"

if [ "$N_OK" -ge 9 ]; then
    pass "10 probes under 5s with Ollama dead ($N_OK/10 OK)"
else
    fail "only $N_OK/10 probes completed in <5s — dispatch.py has a hang path"
fi
fi

# ==============================================================================
# Drill 2 — Bedrock unreachable
# Null-route bedrock DNS; SLOW_COMMANDS should fall through to Ollama.
# ==============================================================================
if run_if 2; then
section "Drill 2 — Bedrock unreachable"
HOSTS_LINE="127.0.0.1 bedrock-runtime.us-east-1.amazonaws.com"
if grep -qF "$HOSTS_LINE" /etc/hosts; then
    info "null-route already present"
else
    echo "$HOSTS_LINE" | sudo tee -a /etc/hosts >/dev/null
    info "null-routed bedrock-runtime.us-east-1.amazonaws.com"
fi

t0=$(date +%s%N)
out=$(PROBE_HONEY "find / -name '*.conf' 2>/dev/null | head -5" 8)
t1=$(date +%s%N)
elapsed_ms=$(( (t1 - t0) / 1000000 ))

sudo sed -i.bak "/bedrock-runtime\.us-east-1\.amazonaws\.com/d" /etc/hosts
info "restored /etc/hosts"

if [ "$elapsed_ms" -lt 6000 ] && [ -n "$out" ]; then
    pass "SLOW_COMMAND fell back to Tier 3 in ${elapsed_ms}ms"
else
    fail "fallback took ${elapsed_ms}ms (target <6000) or returned empty"
fi
fi

# ==============================================================================
# Drill 3 — Cowrie killed (watchdog recovery)
# ==============================================================================
if run_if 3; then
section "Drill 3 — Cowrie kill + watchdog recovery"

# Make sure watchdog is running in a tmux pane before starting this drill
if ! pgrep -f "watchdog.sh" >/dev/null; then
    fail "watchdog.sh not running — start it first in tmux: bash scripts/watchdog.sh"
else
    info "watchdog running (pid $(pgrep -f watchdog.sh | head -1))"
    COWRIE_PID=$(pgrep -f "twistd.*cowrie" | head -1)
    if [ -z "$COWRIE_PID" ]; then
        fail "Cowrie not running — bring it up first"
    else
        info "killing Cowrie pid $COWRIE_PID"
        kill -9 "$COWRIE_PID"
        t0=$(date +%s)
        for try in {1..30}; do
            sleep 1
            if ~/cowrie/bin/cowrie status >/dev/null 2>&1; then
                t1=$(date +%s)
                pass "watchdog restarted Cowrie in $((t1-t0))s"
                break
            fi
            [ "$try" = "30" ] && fail "Cowrie did not return within 30s"
        done
    fi
fi
fi

# ==============================================================================
# Drill 4 — Model unload + keepalive recovery
# ==============================================================================
if run_if 4; then
section "Drill 4 — model unload + keepalive re-warm"
info "unloading qwen2.5:1.5b via keep_alive=0"
curl -s -X POST http://localhost:11434/api/generate \
    -d '{"model":"qwen2.5:1.5b","prompt":"a","keep_alive":0,"stream":false,"options":{"num_predict":1}}' \
    >/dev/null

sleep 2
loaded=$(curl -s http://localhost:11434/api/ps | jq -r '.models | length' 2>/dev/null || echo 0)
if [ "$loaded" -gt 0 ]; then
    fail "model still loaded after keep_alive=0 — Ollama didn't honor unload"
else
    info "model unloaded; running keepalive.sh"
    t0=$(date +%s)
    bash "$(dirname "$0")/../../scripts/keepalive.sh"
    sleep 3
    loaded=$(curl -s http://localhost:11434/api/ps | jq -r '.models | length' 2>/dev/null || echo 0)
    t1=$(date +%s)
    if [ "$loaded" -gt 0 ]; then
        pass "keepalive re-warmed model in $((t1-t0))s"
    else
        fail "model did not re-load after keepalive"
    fi
fi
fi

# ==============================================================================
# Drill 5 — Rapid-fire probe storm
# ==============================================================================
if run_if 5; then
section "Drill 5 — 100-probe burst in one session"
OUT=$(mktemp)
t0=$(date +%s)
{
    echo "set -e"
    for i in $(seq 1 100); do echo "whoami"; done
    echo "exit"
} | timeout 60 sshpass -p root ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 root@127.0.0.1 > "$OUT" 2>&1
t1=$(date +%s)

OK=$(grep -c "^root$" "$OUT" || true)
HEALTH_LOG="$HOME/cowrie/var/log/cowrie/sensor_health.json"
TRACEBACKS=0
if [ -f "$HEALTH_LOG" ]; then
    TRACEBACKS=$(grep -c "Traceback\|Exception" "$HEALTH_LOG" 2>/dev/null || echo 0)
fi
rm -f "$OUT"

info "100 probes in $((t1-t0))s; got $OK valid responses; tracebacks=$TRACEBACKS"
if [ "$OK" -ge 95 ] && [ "$TRACEBACKS" -eq 0 ]; then
    pass "burst completed without crashes"
else
    fail "burst returned only $OK/100, tracebacks=$TRACEBACKS"
fi
fi

# ==============================================================================
echo ""
echo "═══════════════════════════════════════════════════"
echo " FAILURE DRILLS: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════"
exit $((FAIL > 0 ? 1 : 0))
