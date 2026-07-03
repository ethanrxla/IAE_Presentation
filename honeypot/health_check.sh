#!/bin/bash

# ==============================================================================
# Health Check — Sensor Network Node Agent
# Pre-Deployment Verification for Distributed Sensor Network nodes.
#
# Run this before the gauntlet starts to confirm everything is up.
# Green = good. Red = fix it NOW.
#
# Usage: bash health_check.sh
# ==============================================================================

PASS=0
FAIL=0
WARN=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

echo ""
echo "================================================================"
echo " Sensor Agent Pre-Deployment Check"
echo " $(date)"
echo "================================================================"
echo ""

# --- Cowrie ---
echo "--- Cowrie ---"
if systemctl is-active --quiet cowrie 2>/dev/null || pgrep -f "cowrie" > /dev/null; then
    ok "Cowrie is running"
else
    fail "Cowrie is NOT running — start it: ~/cowrie/bin/cowrie start"
fi

if ss -tlnp 2>/dev/null | grep -q ":2222"; then
    ok "Cowrie listening on port 2222"
else
    fail "Nothing listening on port 2222"
fi

if command -v sshpass &>/dev/null; then
    if sshpass -p root timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
            -p 2222 root@localhost "exit" 2>/dev/null; then
        ok "SSH root/root on port 2222 works"
    else
        fail "Cannot SSH as root/root — RED TEAM CANNOT SCORE YOU"
    fi
else
    warn "sshpass not installed — manually verify: ssh root@<pi_ip> -p 2222"
fi

if grep -q "hostname = pi-sensor-gateway" ~/cowrie/etc/cowrie.cfg 2>/dev/null; then
    ok "Hostname set to pi-sensor-gateway"
else
    warn "Hostname not set — run bait.sh"
fi

if [ -f ~/cowrie/share/cowrie/fs.pickle ]; then
    ok "Filesystem pickle present"
else
    fail "Filesystem pickle missing — bad for realism"
fi

echo ""

# --- Edge inference (Ollama) ---
echo "--- Edge Inference ---"
if systemctl is-active --quiet ollama 2>/dev/null; then
    ok "Inference service running"
else
    fail "Inference service not running — systemctl start ollama"
fi

if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    ok "Inference API responsive"
else
    fail "Inference API unreachable on localhost:11434"
fi

LOADED=$(curl -s http://localhost:11434/api/ps 2>/dev/null | python3 -c "
import json, sys
try:
    models = json.load(sys.stdin).get('models', [])
    print(models[0]['name'] if models else 'none')
except: print('error')
" 2>/dev/null)

if [ -z "$LOADED" ] || [ "$LOADED" = "none" ] || [ "$LOADED" = "error" ]; then
    warn "No model resident in memory — cold start will be slow"
else
    ok "Model resident: $LOADED"
fi

echo -n "    Inference latency test... "
START=$(date +%s%N)
curl -s -X POST http://localhost:11434/api/generate \
    -H "Content-Type: application/json" \
    -d '{"model":"qwen2.5:1.5b","prompt":"ok","stream":false,"keep_alive":"60m","options":{"num_predict":8}}' \
    > /dev/null 2>&1
END=$(date +%s%N)
LAT=$(( (END - START) / 1000000 ))

if [ $LAT -lt 3000 ]; then ok "Latency ${LAT}ms (good)"
elif [ $LAT -lt 8000 ]; then warn "Latency ${LAT}ms (acceptable)"
else fail "Latency ${LAT}ms (too slow — try qwen2.5:0.5b)"; fi

echo ""

# --- Agent files ---
echo "--- Agent Files ---"
AGENT_DIR=~/cowrie/src/cowrie/commands/sensor_agent
[ ! -d "$AGENT_DIR" ] && AGENT_DIR=~/cowrie/cowrie/commands/sensor_agent

if [ -d "$AGENT_DIR" ]; then
    ok "Agent directory: $AGENT_DIR"
    for f in node_context.py telemetry_cache.py node_runtime.py \
             edge_inference.py upstream_sync.py dispatch.py shell_broker.py; do
        if [ -f "$AGENT_DIR/$f" ]; then ok "  $f"
        else fail "  $f MISSING"; fi
    done

    if [ -f /etc/sensor-sync.env ] || [ -n "$AWS_ACCESS_KEY_ID" ]; then
        ok "Cloud sync credentials configured"
    else
        warn "Cloud sync credentials not set (fill in once organizers provide)"
    fi
else
    fail "Agent directory not found — copy files to $AGENT_DIR"
fi

echo ""

# --- Network ---
echo "--- Network ---"
PI_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
if [ -n "$PI_IP" ]; then
    ok "Pi IP: $PI_IP"
    echo "    >>> POST IN SLACK BY 10:20 AM: $PI_IP <<<"
else
    fail "Could not determine Pi IP"
fi

if ping -c 1 -W 2 8.8.8.8 > /dev/null 2>&1; then
    ok "Internet connectivity OK"
else
    warn "No internet — cloud sync will fail"
fi

echo ""

# --- Logs ---
echo "--- Logs ---"
LOG_DIR=~/cowrie/var/log/cowrie
if [ -d "$LOG_DIR" ]; then ok "Cowrie log dir exists"
else fail "Cowrie log dir missing"; fi

if [ -f "$LOG_DIR/cowrie.log" ]; then
    ok "cowrie.log exists ($(wc -l < $LOG_DIR/cowrie.log) lines)"
else
    warn "cowrie.log not yet written — normal before first connection"
fi

if [ -f "$LOG_DIR/sensor_health.json" ]; then
    ok "Agent telemetry file exists"
else
    warn "sensor_health.json not yet written"
fi

echo ""
echo "================================================================"
printf " ${GREEN}PASS: $PASS${NC}  ${RED}FAIL: $FAIL${NC}  ${YELLOW}WARN: $WARN${NC}\n"
echo "================================================================"

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}[!] Fix the $FAIL failures before the gauntlet${NC}"; exit 1
elif [ $WARN -gt 0 ]; then
    echo -e "${YELLOW}[!] $WARN warnings — will function but may not score optimally${NC}"
else
    echo -e "${GREEN}[+] Ready for gauntlet${NC}"
fi