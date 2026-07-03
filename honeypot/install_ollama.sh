#!/bin/bash

# ==============================================================================
# Ollama Install & Model Setup — Distributed Sensor Network
# FAU Team - eMERGE 2026 Hackathon
#
# Installs Ollama and pulls the recommended model for Pi 5 hardware.
# Keeps model resident in memory to avoid 30-40s cold start penalty.
#
# Run as root AFTER Cowrie is confirmed working.
# ==============================================================================

set -e

# Model to use — qwen2.5:1.5b is the recommended speed/quality balance for Pi 5
# Options from hints doc:
#   qwen2.5:0.5b  — fastest, lowest RAM, lower quality
#   qwen2.5:1.5b  — RECOMMENDED starting point
#   phi3:mini     — higher quality, slower
#   gemma2:2b     — good instruction following, moderate speed
MODEL="qwen2.5:1.5b"

echo "================================================================"
echo " sensor-agent Ollama Setup"
echo " Model: $MODEL"
echo "================================================================"

# ==============================================================================
# 1. Install Ollama
# ==============================================================================
echo "[*] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh

# ==============================================================================
# 2. Start Ollama service
# ==============================================================================
echo "[*] Starting Ollama service..."
systemctl enable ollama
systemctl start ollama

# Wait for Ollama to be ready
echo "[*] Waiting for Ollama to be ready..."
for i in {1..15}; do
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "[+] Ollama is ready"
        break
    fi
    echo "    Waiting... ($i/15)"
    sleep 2
done

# ==============================================================================
# 3. Pull the model
# ==============================================================================
echo "[*] Pulling model: $MODEL"
echo "    This may take a few minutes on first run..."
ollama pull $MODEL

# ==============================================================================
# 4. Warm up — load model into memory now so first attacker command is fast
# ==============================================================================
echo "[*] Loading model into memory (warm up)..."
curl -s -X POST http://localhost:11434/api/generate \
    -H "Content-Type: application/json" \
    -d "{
        \"model\": \"$MODEL\",
        \"prompt\": \"echo ready\",
        \"stream\": false,
        \"keep_alive\": \"60m\"
    }" > /dev/null

echo "[+] Model loaded and resident in memory"

# ==============================================================================
# 5. Verify model is loaded
# ==============================================================================
echo "[*] Verifying model is resident in memory..."
LOADED=$(curl -s http://localhost:11434/api/ps | python3 -c "
import json, sys
data = json.load(sys.stdin)
models = data.get('models', [])
print(models[0]['name'] if models else 'none')
" 2>/dev/null)

if [ "$LOADED" != "none" ] && [ -n "$LOADED" ]; then
    echo "[+] Confirmed: $LOADED is loaded in memory"
else
    echo "[!] Model may not be in memory yet — run warm up manually:"
    echo "    curl -s -X POST http://localhost:11434/api/generate -H 'Content-Type: application/json' -d '{\"model\":\"$MODEL\",\"prompt\":\"echo ready\",\"stream\":false,\"keep_alive\":\"60m\"}'"
fi

# ==============================================================================
# 6. Quick benchmark — measure response latency
# ==============================================================================
echo ""
echo "[*] Running latency benchmark..."
echo "    (This tells you how fast your Pi handles commands)"
echo ""

benchmark_cmd() {
    local prompt="$1"
    local start=$(date +%s%N)
    curl -s -X POST http://localhost:11434/api/generate \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"$MODEL\",
            \"prompt\": \"$prompt\",
            \"stream\": false,
            \"keep_alive\": \"60m\",
            \"options\": {\"num_predict\": 64}
        }" > /tmp/ollama_bench.json
    local end=$(date +%s%N)
    local ms=$(( (end - start) / 1000000 ))
    local response=$(python3 -c "import json; d=json.load(open('/tmp/ollama_bench.json')); print(d.get('response','').strip()[:60])" 2>/dev/null)
    echo "  [$ms ms] '$prompt' -> '$response'"
}

benchmark_cmd "whoami"
benchmark_cmd "uname -a"
benchmark_cmd "ls /etc"

echo ""
echo "================================================================"
echo " Ollama Setup Complete"
echo "================================================================"
echo ""
echo "  Model     : $MODEL"
echo "  Service   : systemctl status ollama"
echo "  Logs      : journalctl -u ollama -f"
echo "  Check RAM : curl http://localhost:11434/api/ps"
echo "  Models    : ollama list"
echo ""
echo "[!] If latency is too high (>5s), consider switching to qwen2.5:0.5b"
echo "    Run: ollama pull qwen2.5:0.5b"
echo "    Then update OLLAMA_MODEL in edge_inference.py"