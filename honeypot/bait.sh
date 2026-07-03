#!/bin/bash

# ==============================================================================
# Cowrie Deception Configurator v4 — Distributed Sensor Network
# FAU Team - eMERGE 2026 Hackathon
#
# Run as the COWRIE USER (not root):
#   ssh cowrie@<pi_ip>    password: honeypot
#   bash bait.sh
#
# The Pi comes with Cowrie PRE-INSTALLED. This script only:
#   - Updates cowrie.cfg (hostname, SSH banner)
#   - Populates honeyfs with realistic fake files
#   - Does NOT install, reinstall, or touch the Cowrie service
#
# DAY-OF CHECKLIST:
#   Nothing to change in this file — it runs as-is.
#   The pickle file is already at ~/cowrie/share/cowrie/fs.pickle (pre-installed).
# ==============================================================================

if [ -d "$HOME/cowrie" ]; then
    COWRIE_DIR="$HOME/cowrie"
else
    echo "[!] Cannot find cowrie directory at $HOME/cowrie"
    exit 1
fi

if [ -f "$COWRIE_DIR/etc/cowrie.cfg" ]; then
    COWRIE_CFG="$COWRIE_DIR/etc/cowrie.cfg"
elif [ -f "$COWRIE_DIR/cowrie.cfg" ]; then
    COWRIE_CFG="$COWRIE_DIR/cowrie.cfg"
else
    echo "[!] cowrie.cfg not found — copying from template"
    cp "$COWRIE_DIR/etc/cowrie.cfg.dist" "$COWRIE_DIR/etc/cowrie.cfg"
    COWRIE_CFG="$COWRIE_DIR/etc/cowrie.cfg"
fi

NEW_HOSTNAME="pi-sensor-gateway"
SSH_BANNER="SSH-2.0-OpenSSH_10.0p1 Debian-5"

echo "[*] Starting Cowrie Deception Setup v4..."

# ==============================================================================
# 1. Update cowrie.cfg
# ==============================================================================
echo "[+] Setting hostname: $NEW_HOSTNAME"
sed -i "s/^hostname =.*/hostname = $NEW_HOSTNAME/" "$COWRIE_CFG"
grep -q "^hostname" "$COWRIE_CFG" || echo "hostname = $NEW_HOSTNAME" >> "$COWRIE_CFG"

echo "[+] Setting SSH banner: $SSH_BANNER"
sed -i "s/^version =.*/version = $SSH_BANNER/" "$COWRIE_CFG"
grep -q "^version" "$COWRIE_CFG" || echo "version = $SSH_BANNER" >> "$COWRIE_CFG"

# ==============================================================================
# 2. HoneyFS directories
# ==============================================================================
echo "[+] Creating honeyfs structure..."
mkdir -p "$COWRIE_DIR/honeyfs/etc/cron.d"
mkdir -p "$COWRIE_DIR/honeyfs/var/www/html"
mkdir -p "$COWRIE_DIR/honeyfs/var/log"
mkdir -p "$COWRIE_DIR/honeyfs/proc/net"
mkdir -p "$COWRIE_DIR/honeyfs/root/.aws"
mkdir -p "$COWRIE_DIR/honeyfs/root/.ssh"
mkdir -p "$COWRIE_DIR/honeyfs/home/pi"
mkdir -p "$COWRIE_DIR/honeyfs/opt/sensor"

# ==============================================================================
# 3. Core system files
# ==============================================================================
echo "[+] Writing core system files..."

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
pi:x:1000:1000:,,,:/home/pi:/bin/bash
webadmin:x:1001:1001:,,,:/home/webadmin:/bin/bash
mysql:x:1002:1002:MySQL Server,,,:/nonexistent:/bin/false
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/shadow"
root:$6$rounds=656000$rAnDoMsAlT123$fakehashedpassword123456789abcdef:19200:0:99999:7:::
pi:$6$rounds=656000$aNothErSaLt456$fakehashedpassword987654321zyxwvu:19200:0:99999:7:::
webadmin:$6$rounds=656000$yEtAnOtHeR789$fakehashedpasswordabcdef123456789:19200:0:99999:7:::
EOF

echo "pi-sensor-gateway" > "$COWRIE_DIR/honeyfs/etc/hostname"

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/hosts"
127.0.0.1       localhost
127.0.1.1       pi-sensor-gateway
10.1.10.20      node-alpha.sensor.local     node-alpha
10.1.10.21      node-beta.sensor.local      node-beta
10.1.10.22      node-gamma.sensor.local     node-gamma
10.1.10.1       gateway.sensor.local        gateway
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/os-release"
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
EOF

# ==============================================================================
# 4. Crontabs
# ==============================================================================
echo "[+] Writing crontabs..."

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/crontab"
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
*/5 *   * * *   pi      /opt/sensor/collect.sh >> /var/log/sensor.log 2>&1
0   2   * * *   root    /usr/local/bin/db_backup.sh
30  3   * * *   root    rsync -az /var/sensor-data/ admin@10.1.10.55:/backup/node-alpha/
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/cron.d/sensor-sync"
# Sensor network sync - DO NOT REMOVE
*/10 * * * * root /opt/sensor/sync_nodes.sh 2>/dev/null
0 4 * * * root scp -i /root/.ssh/id_rsa /var/www/html/config.php webadmin@10.1.10.55:/tmp/cfg_backup
EOF

# ==============================================================================
# 5. /proc entries
# ==============================================================================
echo "[+] Writing /proc entries..."

cat << 'EOF' > "$COWRIE_DIR/honeyfs/proc/cpuinfo"
processor	: 0
BogoMIPS	: 108.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x4
CPU part	: 0xd0b
CPU revision	: 1

processor	: 1
BogoMIPS	: 108.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x4
CPU part	: 0xd0b
CPU revision	: 1

processor	: 2
BogoMIPS	: 108.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x4
CPU part	: 0xd0b
CPU revision	: 1

processor	: 3
BogoMIPS	: 108.00
Features	: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint
CPU implementer	: 0x41
CPU architecture: 8
CPU variant	: 0x4
CPU part	: 0xd0b
CPU revision	: 1

Hardware	: BCM2712
Revision	: d04170
Serial		: 10000000b1234567
Model		: Raspberry Pi 5 Model B Rev 1.0
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/proc/version"
Linux version 6.12.34+rpt-rpi-2712 (dom@buildhost) (aarch64-linux-gnu-gcc-14 (Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP PREEMPT Debian 1:6.12.34-1+rpt1 (2025-06-15)
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/proc/meminfo"
MemTotal:        3884968 kB
MemFree:          234156 kB
MemAvailable:    1823456 kB
Buffers:          124892 kB
Cached:          1654320 kB
SwapCached:            0 kB
Active:          2341872 kB
Inactive:         987654 kB
SwapTotal:        102396 kB
SwapFree:         102396 kB
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/proc/net/arp"
IP address       HW type     Flags       HW address            Mask     Device
10.1.10.1        0x1         0x2         b8:27:eb:12:34:56     *        eth0
10.1.10.21       0x1         0x2         b8:27:eb:ab:cd:ef     *        eth0
10.1.10.22       0x1         0x2         b8:27:eb:98:76:54     *        eth0
10.1.10.55       0x1         0x2         dc:a6:32:11:22:33     *        eth0
EOF

# ==============================================================================
# 6. Bait files
# ==============================================================================
echo "[+] Writing bait files..."

cat << 'EOF' > "$COWRIE_DIR/honeyfs/var/www/html/config.php"
<?php
// Auto-generated by Ansible
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'FAU_cyber_db_admin_99!');
define('DB_NAME', 'sensor_data_metrics');
?>
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/etc/motd"

====================================================================
WARNING: UNAUTHORIZED ACCESS PROHIBITED
Property of Distributed Sensor Network - Node Alpha
All connections are monitored and recorded.
====================================================================
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/root/.bash_history"
ping 8.8.8.8
apt update && apt upgrade -y
nano /var/www/html/config.php
systemctl restart mariadb
systemctl status apache2
ssh admin@10.1.10.55
ssh -i /root/.ssh/id_rsa webadmin@10.1.10.21
rsync -az /var/sensor-data/ admin@10.1.10.55:/backup/
cat /etc/passwd
crontab -l
mysql -u root -pFAU_cyber_db_admin_99! sensor_data_metrics
exit
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/home/pi/.bash_history"
ls -la
cd /var/www/html
cat config.php
python3 collect.py
sudo systemctl status sensor
ping 10.1.10.1
exit
EOF

# Plausible AWS key — NOT the AWS docs example (AKIAIOSFODNN7EXAMPLE)
cat << 'EOF' > "$COWRIE_DIR/honeyfs/root/.aws/credentials"
[default]
aws_access_key_id = AKIAQX3LM7NP2RSTVW84
aws_secret_access_key = Jx7vK2mPqR9nL4wT6yB3hF8cZ1dA5eG0iUoYsNj
region = us-east-1
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/root/.aws/config"
[default]
region = us-east-1
output = json
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/root/.ssh/known_hosts"
10.1.10.21 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vX fake_key_node_beta==
10.1.10.22 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD3wY fake_key_node_gamma==
10.1.10.55 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQE4xZ fake_key_admin==
EOF

cat << 'EOF' > "$COWRIE_DIR/honeyfs/var/log/auth.log"
Apr 20 03:12:45 pi-sensor-gateway sshd[1234]: Accepted publickey for pi from 10.1.10.55 port 51234 ssh2
Apr 20 03:12:46 pi-sensor-gateway sshd[1234]: pam_unix(sshd:session): session opened for user pi
Apr 20 03:18:22 pi-sensor-gateway sshd[1234]: pam_unix(sshd:session): session closed for user pi
Apr 21 02:00:01 pi-sensor-gateway cron[892]: (root) CMD (/usr/local/bin/db_backup.sh)
Apr 22 03:15:01 pi-sensor-gateway sshd[2891]: Accepted publickey for root from 10.1.10.1 port 49823 ssh2
Apr 22 03:22:17 pi-sensor-gateway sshd[2891]: pam_unix(sshd:session): session closed for user root
EOF

# ==============================================================================
# 7. Restart Cowrie
# ==============================================================================
echo "[+] Restarting Cowrie..."
if [ -f "$COWRIE_DIR/bin/cowrie" ]; then
    "$COWRIE_DIR/bin/cowrie" restart
    sleep 2
    "$COWRIE_DIR/bin/cowrie" status
else
    echo "[!] Restart manually: ~/cowrie/bin/cowrie restart"
fi

echo ""
echo "=== Deception Setup Complete ==="
echo "  Hostname : $NEW_HOSTNAME"
echo "  Banner   : $SSH_BANNER"
echo "  HoneyFS  : passwd, shadow, hosts, crontab, proc, auth.log, .aws, .bash_history"
echo ""
echo "  Verify: ssh root@<pi_ip> -p 2222   password: root"