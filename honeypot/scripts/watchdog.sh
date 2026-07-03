#!/bin/bash
# Service watchdog with exponential backoff to prevent restart storms.
#
# After 3 restarts in 60s, waits 5 min before next attempt and logs loudly.
# This prevents a misconfigured Cowrie from burning the SD card.
#
# Usage:
#   tmux new -s w
#   ./watchdog.sh
#   (Ctrl+B then D to detach)

set -uo pipefail

LOG="/var/log/journal/svcd/watchdog.log"
STATE="/tmp/.svcd_watchdog_state"
mkdir -p "$(dirname $LOG)"
chmod 700 "$(dirname $LOG)" 2>/dev/null || true

restart_count=0
backoff_until=0

log_line() {
    echo "[$(date)] $*" | tee -a "$LOG"
}

log_line "watchdog started (pid $$)"

while true; do
    NOW=$(date +%s)

    # Respect backoff window
    if [ "$NOW" -lt "$backoff_until" ]; then
        sleep 30
        continue
    fi

    # Check Cowrie
    if ! ~/cowrie/bin/cowrie status > /dev/null 2>&1; then
        # Track restart in last 60s
        restart_count=$((restart_count + 1))

        if [ "$restart_count" -ge 3 ]; then
            log_line "🛑 CRASH STORM: 3 restarts in <60s. Backing off 5 min."
            log_line "   Cowrie config likely broken. Check ~/cowrie/var/log/cowrie/cowrie.log"
            log_line "   Consider: bash ~/scalpel-kit/src/backup/panic.sh"
            backoff_until=$((NOW + 300))
            restart_count=0
            continue
        fi

        log_line "Cowrie down (restart #$restart_count), restarting"
        ~/cowrie/bin/cowrie start 2>&1 | tee -a "$LOG"
        sleep 5
    else
        # Decay restart counter on healthy intervals
        if [ "$restart_count" -gt 0 ] && [ "$NOW" -gt "$((backoff_until + 60))" ]; then
            restart_count=0
        fi
    fi

    # Check Ollama
    LOADED=$(curl -s http://localhost:11434/api/ps 2>/dev/null | grep -c "qwen2.5" 2>/dev/null || true)
    LOADED=${LOADED:-0}
    if [ "$LOADED" = "0" ]; then
        log_line "LLM model unloaded, re-warming"
        bash "$(dirname $0)/keepalive.sh" 2>&1 | tee -a "$LOG" || \
            log_line "keepalive failed"
    fi

    sleep 5
done
