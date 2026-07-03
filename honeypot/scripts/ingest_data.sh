#!/bin/bash
# Ingest ground truth captures into SVCD's data dir.
# Run on the honeypot Pi as the cowrie user.
#
# Usage: ./ingest_data.sh [path/to/groundtruth.tgz]

set -e

ARCHIVE="${1:-$HOME/groundtruth.tgz}"
DATA_DIR="$HOME/.local/lib/svcd/data"
COWRIE_HONEYFS="$HOME/cowrie/honeyfs"

if [ ! -f "$ARCHIVE" ]; then
    echo "ERROR: $ARCHIVE not found"
    echo "Usage: $0 [path/to/groundtruth.tgz]"
    exit 1
fi

# 1. Extract to disguised data dir
echo "[1/4] Extracting captures to ~/.local/lib/svcd/data/ ..."
mkdir -p "$DATA_DIR"
rm -rf "$DATA_DIR"/*
TMP=$(mktemp -d)
tar xzf "$ARCHIVE" -C "$TMP"
mv "$TMP"/groundtruth/* "$DATA_DIR/"
rm -rf "$TMP"

count=$(ls "$DATA_DIR"/cmd_*.txt 2>/dev/null | wc -l)
echo "    → Extracted $count command captures"

# 2. Verify manifest
if [ ! -f "$DATA_DIR/manifest.json" ]; then
    echo "ERROR: manifest.json missing"
    exit 1
fi
echo "[2/4] Manifest OK"

# 3. Populate honeyfs with file contents (so cat works correctly)
echo "[3/4] Populating Cowrie honeyfs..."
if [ -d "$DATA_DIR/files" ]; then
    for f in os-release passwd hostname debian_version issue group shells timezone; do
        src=$(find "$DATA_DIR/files" -name "*${f}*" 2>/dev/null | head -1)
        if [ -n "$src" ]; then
            mkdir -p "$COWRIE_HONEYFS/etc"
            cp "$src" "$COWRIE_HONEYFS/etc/$f"
            echo "    → honeyfs/etc/$f"
        fi
    done

    src=$(find "$DATA_DIR/files" -name "*config.txt*" 2>/dev/null | head -1)
    if [ -n "$src" ]; then
        mkdir -p "$COWRIE_HONEYFS/boot/firmware"
        cp "$src" "$COWRIE_HONEYFS/boot/firmware/config.txt"
        echo "    → honeyfs/boot/firmware/config.txt"
    fi
fi

# 4. Drop a believable bash_history
mkdir -p "$COWRIE_HONEYFS/home/pi"
cat > "$COWRIE_HONEYFS/home/pi/.bash_history" <<'EOF'
sudo apt update
sudo apt upgrade -y
df -h
free -h
htop
sudo systemctl status nginx
sudo systemctl restart nginx
tail -f /var/log/nginx/error.log
nano /etc/nginx/sites-available/default
sudo nginx -t
sudo systemctl reload nginx
git pull
cd /opt/app
ls -la
sudo journalctl -u nginx -n 50
ip a
ping -c 3 8.8.8.8
sudo apt install -y vim curl wget
crontab -l
ls /var/log/
sudo tail /var/log/auth.log
exit
EOF
echo "    → honeyfs/home/pi/.bash_history"

echo ""
echo "[4/4] Data ingested."
echo "Restart Cowrie: ~/cowrie/bin/cowrie restart"
