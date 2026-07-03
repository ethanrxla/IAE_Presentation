#!/usr/bin/env python3
"""
telemetry_cache.py — Tier 1: Pure Static Dispatch
Distributed Sensor Network - Node Agent

DESIGN PRINCIPLE: Only commands whose output NEVER changes between calls on a
real system belong here. If the output depends on time, session, filesystem
state, or anything else — it belongs in Tier 2.

Tier 1 is a pure dictionary lookup. No logic, no state, no generation.
Latency: ~0.05ms (measured)

What qualifies for Tier 1:
  - Kernel/hardware identity: uname -r, arch, hardware model
  - OS release info: /etc/os-release, /etc/debian_version
  - Static config files that never change on a running system
  - Shell builtin behavior: echo, true, false, :

What does NOT qualify:
  - date, uptime, who, w, last (time-based)
  - ps, top, netstat (process/connection state)
  - ls, stat, find (filesystem state)
  - env, set, history (session-based)
  - cat on files that could be modified (handle in Tier 2)
"""

from typing import Optional


# ==============================================================================
# TRULY STATIC COMMANDS — outputs are invariant given our honeyfs config
# ==============================================================================

STATIC_TABLE = {

    # --- Identity (the Pi identity never changes during a session) ---
    "hostname":                 "pi-sensor-gateway",
    "hostname -f":              "pi-sensor-gateway.sensor.local",
    "hostname -s":              "pi-sensor-gateway",
    "hostname -d":              "sensor.local",
    "hostname -i":              "10.1.10.20",
    "hostname -I":              "10.1.10.20",
    "dnsdomainname":            "sensor.local",
    "domainname":               "(none)",

    # --- Kernel / architecture ---
    "uname":                    "Linux",
    "uname -s":                 "Linux",
    "uname -r":                 "5.15.84-v7l+",
    "uname -v":                 "#1613 SMP Thu Jan 5 12:01:26 GMT 2023",
    "uname -m":                 "armv7l",
    "uname -p":                 "unknown",
    "uname -i":                 "unknown",
    "uname -o":                 "GNU/Linux",
    "uname -n":                 "pi-sensor-gateway",
    "uname -a":                 "Linux pi-sensor-gateway 5.15.84-v7l+ #1613 SMP Thu Jan 5 12:01:26 GMT 2023 armv7l GNU/Linux",
    "arch":                     "armv7l",

    # --- OS release (these files never change on a running system) ---
    "cat /etc/os-release": (
        'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\n'
        'NAME="Debian GNU/Linux"\n'
        'VERSION_ID="11"\n'
        'VERSION="11 (bullseye)"\n'
        'VERSION_CODENAME=bullseye\n'
        'ID=debian\n'
        'HOME_URL="https://www.debian.org/"\n'
        'SUPPORT_URL="https://www.debian.org/support"\n'
        'BUG_REPORT_URL="https://bugs.debian.org/"'
    ),
    "cat /etc/debian_version":  "11.6",
    "cat /etc/issue":           "Debian GNU/Linux 11 \\n \\l\n",
    "cat /etc/issue.net":       "Debian GNU/Linux 11",
    "lsb_release -a": (
        "No LSB modules are available.\n"
        "Distributor ID: Debian\n"
        "Description:    Debian GNU/Linux 11 (bullseye)\n"
        "Release:        11\n"
        "Codename:       bullseye"
    ),
    "lsb_release -d":           "Description:    Debian GNU/Linux 11 (bullseye)",
    "lsb_release -r":           "Release:        11",
    "lsb_release -c":           "Codename:       bullseye",
    "lsb_release -i":           "Distributor ID: Debian",

    # --- Hardware (Pi identity is constant) ---
    "cat /proc/cpuinfo": (
        "processor\t: 0\n"
        "model name\t: ARMv7 Processor rev 3 (v7l)\n"
        "BogoMIPS\t: 108.00\n"
        "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32\n"
        "CPU implementer\t: 0x41\n"
        "CPU architecture: 7\n"
        "CPU variant\t: 0x0\n"
        "CPU part\t: 0xd08\n"
        "CPU revision\t: 3\n\n"
        "processor\t: 1\n"
        "model name\t: ARMv7 Processor rev 3 (v7l)\n"
        "BogoMIPS\t: 108.00\n"
        "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae evtstrm crc32\n"
        "CPU implementer\t: 0x41\n"
        "CPU architecture: 7\n"
        "CPU variant\t: 0x0\n"
        "CPU part\t: 0xd08\n"
        "CPU revision\t: 3\n\n"
        "Hardware\t: BCM2711\n"
        "Revision\t: c03114\n"
        "Serial\t\t: 10000000b1234567\n"
        "Model\t\t: Raspberry Pi 4 Model B Rev 1.4"
    ),
    "cat /proc/version": (
        "Linux version 5.15.84-v7l+ (dom@buildhost) "
        "(arm-linux-gnueabihf-gcc-8 (Ubuntu/Linaro 8.4.0-3ubuntu1) 8.4.0, "
        "GNU ld (GNU Binutils for Ubuntu) 2.34) "
        "#1613 SMP Thu Jan 5 12:01:26 GMT 2023"
    ),
    "cat /sys/firmware/devicetree/base/model": "Raspberry Pi 4 Model B Rev 1.4\x00",
    "cat /proc/device-tree/model":             "Raspberry Pi 4 Model B Rev 1.4\x00",

    # --- Network config (IPs, MACs don't change mid-session) ---
    "cat /etc/hostname":        "pi-sensor-gateway",
    "cat /etc/hosts": (
        "127.0.0.1       localhost\n"
        "127.0.1.1       pi-sensor-gateway\n"
        "10.1.10.20      node-alpha.sensor.local     node-alpha\n"
        "10.1.10.21      node-beta.sensor.local      node-beta\n"
        "10.1.10.22      node-gamma.sensor.local     node-gamma\n"
        "10.1.10.1       gateway.sensor.local        gateway"
    ),
    "cat /etc/resolv.conf": (
        "nameserver 8.8.8.8\n"
        "nameserver 8.8.4.4\n"
        "search sensor.local"
    ),
    "cat /etc/nsswitch.conf": (
        "passwd:         files\n"
        "group:          files\n"
        "shadow:         files\n"
        "hosts:          files dns\n"
        "networks:       files\n"
        "protocols:      db files\n"
        "services:       db files"
    ),

    # --- User/group database files ---
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
        "pi:x:1000:1000:,,,:/home/pi:/bin/bash\n"
        "webadmin:x:1001:1001:,,,:/home/webadmin:/bin/bash\n"
        "mysql:x:1002:1002:MySQL Server,,,:/nonexistent:/bin/false"
    ),
    "cat /etc/shadow": (
        "root:$6$rounds=656000$rAnDoMsAlT123$fakehashedpassword123456789abcdef:19200:0:99999:7:::\n"
        "daemon:*:19200:0:99999:7:::\n"
        "bin:*:19200:0:99999:7:::\n"
        "sys:*:19200:0:99999:7:::\n"
        "sync:*:19200:0:99999:7:::\n"
        "www-data:*:19200:0:99999:7:::\n"
        "sshd:*:19200:0:99999:7:::\n"
        "pi:$6$rounds=656000$aNothErSaLt456$fakehashedpassword987654321zyxwvu:19200:0:99999:7:::\n"
        "webadmin:$6$rounds=656000$yEtAnOtHeR789$fakehashedpasswordabcdef123456789:19200:0:99999:7:::\n"
        "mysql:!:19200:0:99999:7:::"
    ),
    "cat /etc/group": (
        "root:x:0:\n"
        "daemon:x:1:\n"
        "bin:x:2:\n"
        "sys:x:3:\n"
        "adm:x:4:pi\n"
        "tty:x:5:\n"
        "disk:x:6:\n"
        "sudo:x:27:pi\n"
        "www-data:x:33:\n"
        "mysql:x:1002:\n"
        "pi:x:1000:\n"
        "webadmin:x:1001:"
    ),
    "cat /etc/gshadow":         "cat: /etc/gshadow: Permission denied",  # Realistic failure

    # --- Identity (root session) — these don't change until `su` ---
    # NOTE: if we later support user-switching, move these to Tier 2
    "whoami":                   "root",
    "id":                       "uid=0(root) gid=0(root) groups=0(root)",
    "id -u":                    "0",
    "id -g":                    "0",
    "id -un":                   "root",
    "id -gn":                   "root",
    "id -G":                    "0",
    "groups":                   "root",
    "logname":                  "root",

    # --- Shell builtin trivial outputs ---
    "true":                     "",
    "false":                    "",
    ":":                        "",
    # pwd deliberately absent: it's stateful (depends on cd). Handled by T2.

    # --- Locale / timezone (constant for our config) ---
    "locale": (
        "LANG=en_GB.UTF-8\n"
        "LANGUAGE=\n"
        "LC_CTYPE=\"en_GB.UTF-8\"\n"
        "LC_NUMERIC=\"en_GB.UTF-8\"\n"
        "LC_TIME=\"en_GB.UTF-8\"\n"
        "LC_COLLATE=\"en_GB.UTF-8\"\n"
        "LC_MONETARY=\"en_GB.UTF-8\"\n"
        "LC_MESSAGES=\"en_GB.UTF-8\"\n"
        "LC_PAPER=\"en_GB.UTF-8\"\n"
        "LC_NAME=\"en_GB.UTF-8\"\n"
        "LC_ADDRESS=\"en_GB.UTF-8\"\n"
        "LC_TELEPHONE=\"en_GB.UTF-8\"\n"
        "LC_MEASUREMENT=\"en_GB.UTF-8\"\n"
        "LC_IDENTIFICATION=\"en_GB.UTF-8\"\n"
        "LC_ALL="
    ),
    "cat /etc/timezone":        "Etc/UTC",

    # --- Which on installed binaries (these are present, paths never change) ---
    "which bash":               "/bin/bash",
    "which sh":                 "/bin/sh",
    "which python3":            "/usr/bin/python3",
    "which python":             "/usr/bin/python3",
    "which perl":               "/usr/bin/perl",
    "which curl":               "/usr/bin/curl",
    "which wget":               "/usr/bin/wget",
    "which nc":                 "/bin/nc",
    "which ncat":               "/usr/bin/ncat",
    "which ssh":                "/usr/bin/ssh",
    "which mysql":              "/usr/bin/mysql",
    "which apache2":            "/usr/sbin/apache2",
    "which git":                "/usr/bin/git",
    "which make":               "/usr/bin/make",
    "which gcc":                "/usr/bin/gcc",
    "which php":                "/usr/bin/php",

    # --- Which on binaries NOT installed — attackers probe for these ---
    "which docker":             "",
    "which kubectl":            "",
    "which podman":             "",
    "which iptables-save":      "/usr/sbin/iptables-save",
    "which tcpdump":            "/usr/sbin/tcpdump",
    "which nmap":               "",  # Not installed — avoid giving attackers recon tools
    "which netstat":            "/bin/netstat",
    "which ss":                 "/usr/sbin/ss",

    # --- command -v (same semantics as which, different syntax) ---
    "command -v bash":          "/bin/bash",
    "command -v python3":       "/usr/bin/python3",
    "command -v docker":        "",

    # --- Version strings (programs ship with fixed versions) ---
    "python3 --version":        "Python 3.9.2",
    "python --version":         "Python 3.9.2",
    "bash --version": (
        "GNU bash, version 5.1.4(1)-release (arm-unknown-linux-gnueabihf)\n"
        "Copyright (C) 2020 Free Software Foundation, Inc.\n"
        "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n\n"
        "This is free software; you are free to change and redistribute it.\n"
        "There is NO WARRANTY, to the extent permitted by law."
    ),
    "perl --version": (
        "\nThis is perl 5, version 32, subversion 1 (v5.32.1) built for arm-linux-gnueabihf-thread-multi\n\n"
        "Copyright 1987-2021, Larry Wall\n\n"
        "Perl may be copied only under the terms of either the Artistic License or the\n"
        "GNU General Public License, which may be found in the Perl 5 source kit."
    ),
    "curl --version":           "curl 7.74.0 (arm-unknown-linux-gnueabihf) libcurl/7.74.0 GnuTLS/3.7.1 zlib/1.2.11",
    "wget --version":           "GNU Wget 1.21 built on linux-gnueabihf.",
    "gcc --version": (
        "gcc (Debian 10.2.1-6) 10.2.1 20210110\n"
        "Copyright (C) 2020 Free Software Foundation, Inc.\n"
        "This is free software; see the source for copying conditions.  There is NO\n"
        "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
    ),
    "ssh -V":                   "OpenSSH_8.4p1 Debian-5+deb11u1, OpenSSL 1.1.1w  11 Sep 2023",
    "openssl version":          "OpenSSL 1.1.1w  11 Sep 2023",
    "php --version":            "PHP 7.4.33 (cli) (built: Dec  7 2022 22:43:05) ( NTS )",
    "mysql --version":          "mysql  Ver 15.1 Distrib 10.5.19-MariaDB, for debian-linux-gnueabihf (armhf) using readline 5.2",

    # --- Shell builtin help/env (fixed for our shell) ---
    "echo $SHELL":              "/bin/bash",
    "echo $0":                  "-bash",
    "echo $TERM":               "xterm-256color",

    # --- Commands that should error — emulate real errors ---
    "cat /etc/gshadow-":        "cat: /etc/gshadow-: Permission denied",
    "cat /etc/shadow-":         "cat: /etc/shadow-: Permission denied",
}


# ==============================================================================
# EXPANDED STATIC CORPUS
# ------------------------------------------------------------------------------
# Folded in from the earlier tier-based lineage (was `tier1_static.py`) and
# re-written to THIS node's identity: pi-sensor-gateway / 10.1.10.20 (eth0,
# b8:27:eb:12:34:56) / Debian 11 bullseye / Raspberry Pi 4 / armv7l.
#
# Only TRULY STATIC entries live here. Anything time- or connection-dependent
# (date, uptime, w/who/last, free, df, ifconfig, ip, arp, netstat, ss, env,
# printenv) is intentionally NOT included — Tier 2 (node_runtime) renders those
# dynamically so they reflect the live session. The router checks Tier 1 first,
# so any key added here would shadow the dynamic handler; that is why the list
# below is restricted to invariant file reads and version/identity strings.
# ==============================================================================

_EXPANDED = {

    # --- Session identity (invariant while logged in as root) ---
    "tty":                      "/dev/pts/0",
    "users":                    "root",
    "cat /etc/machine-id":      "b9d1c4e27f8a4d3ea1c60f9b2d7e4a51",

    # --- Invariant env-var echoes (values never change; PATH/HOME/etc.) ---
    "echo $PATH":               "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "echo $HOME":               "/root",
    "echo $USER":               "root",
    "echo $LOGNAME":            "root",
    "echo $HOSTNAME":           "pi-sensor-gateway",
    "echo $LANG":               "en_GB.UTF-8",
    "echo $PWD":                "/root",

    # --- Version strings for tools not covered above ---
    "python3 -V":               "Python 3.9.2",
    "git --version":            "git version 2.30.2",
    "apache2 -v": (
        "Server version: Apache/2.4.62 (Debian)\n"
        "Server built:   2024-09-02T10:42:00"
    ),
    "rsync --version":          "rsync  version 3.2.3  protocol version 31",
    "vi --version":             "VIM - Vi IMproved 8.2 (2019 Dec 12, compiled Sep 25 2021 08:19:05)",
    "vim --version":            "VIM - Vi IMproved 8.2 (2019 Dec 12, compiled Sep 25 2021 08:19:05)",
    "nano --version":           "GNU nano, version 5.4",
    "dpkg --version":           "Debian 'dpkg' package management program version 1.20.13 (armhf).",
    "apt --help": (
        "apt 2.2.4 (armhf)\n"
        "Usage: apt [options] command\n\n"
        "apt is a commandline package manager and provides commands for\n"
        "searching and managing as well as querying information about packages."
    ),
    "crontab -l":               "no crontab for root",
    "cat /proc/loadavg":        "0.12 0.08 0.05 1/234 9823",

    # ==========================================================================
    # Static /etc config files (never change on a running system)
    # ==========================================================================
    "cat /etc/fstab": (
        "# /etc/fstab: static file system information.\n"
        "#\n"
        "# Use 'blkid' to print the universally unique identifier for a device; this\n"
        "# may be used with UUID= as a more robust way to name devices that works even\n"
        "# if disks are added and removed. See fstab(5).\n"
        "#\n"
        "# <file system> <mount point>   <type>  <options>       <dump>  <pass>\n"
        "proc            /proc           proc    defaults          0       0\n"
        "PARTUUID=738a4d67-01  /boot           vfat    defaults          0       2\n"
        "PARTUUID=738a4d67-02  /               ext4    defaults,noatime  0       1\n"
        "# a swapfile is not a swap partition, no line here\n"
        "#   use  dphys-swapfile swap[on|off]  for that"
    ),
    "cat /etc/shells": (
        "# /etc/shells: valid login shells\n"
        "/bin/sh\n"
        "/usr/bin/sh\n"
        "/bin/bash\n"
        "/usr/bin/bash\n"
        "/bin/rbash\n"
        "/usr/bin/rbash\n"
        "/usr/bin/dash\n"
        "/bin/dash"
    ),
    "cat /etc/sudoers": (
        "#\n"
        "# This file MUST be edited with the 'visudo' command as root.\n"
        "#\n"
        "# Please consider adding local content in /etc/sudoers.d/ instead of\n"
        "# directly modifying this file.\n"
        "#\n"
        "# See the man page for details on how to write a sudoers file.\n"
        "#\n"
        "Defaults\tenv_reset\n"
        "Defaults\tmail_badpass\n"
        "Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n\n"
        "# Host alias specification\n\n"
        "# User alias specification\n\n"
        "# Cmnd alias specification\n\n"
        "# User privilege specification\n"
        "root\tALL=(ALL:ALL) ALL\n\n"
        "# Allow members of group sudo to execute any command\n"
        "%sudo\tALL=(ALL:ALL) ALL\n\n"
        "# See sudoers(5) for more information on \"#include\" directives:\n\n"
        "@includedir /etc/sudoers.d"
    ),
    "cat /etc/login.defs": (
        "# /etc/login.defs - Configuration control definitions for the login package.\n\n"
        "MAIL_DIR\t/var/mail\n"
        "FAILLOG_ENAB\t\tyes\n"
        "LOG_UNKFAIL_ENAB\tno\n"
        "LOG_OK_LOGINS\t\tno\n"
        "SYSLOG_SU_ENAB\t\tyes\n"
        "SYSLOG_SG_ENAB\t\tyes\n"
        "FTMP_FILE\t/var/log/btmp\n"
        "SU_NAME\t\tsu\n"
        "HUSHLOGIN_FILE\t.hushlogin\n"
        "ENV_SUPATH\tPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "ENV_PATH\tPATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games\n"
        "TTYGROUP\ttty\n"
        "TTYPERM\t\t0600\n"
        "UMASK\t\t022\n"
        "HOME_MODE\t0755\n"
        "PASS_MAX_DAYS\t99999\n"
        "PASS_MIN_DAYS\t0\n"
        "PASS_WARN_AGE\t7\n"
        "UID_MIN\t\t\t 1000\n"
        "UID_MAX\t\t\t60000\n"
        "SYS_UID_MIN\t\t  100\n"
        "SYS_UID_MAX\t\t  999\n"
        "GID_MIN\t\t\t 1000\n"
        "GID_MAX\t\t\t60000\n"
        "SYS_GID_MIN\t\t  100\n"
        "SYS_GID_MAX\t\t  999\n"
        "LOGIN_RETRIES\t\t5\n"
        "LOGIN_TIMEOUT\t\t60\n"
        "CHFN_RESTRICT\t\trwh\n"
        "DEFAULT_HOME\tyes\n"
        "USERGROUPS_ENAB yes\n"
        "ENCRYPT_METHOD YESCRYPT"
    ),
    # Bullseye APT sources (normalized from the newer-release lineage).
    "cat /etc/apt/sources.list": (
        "deb http://deb.debian.org/debian bullseye main contrib non-free\n"
        "deb http://security.debian.org/debian-security bullseye-security main contrib non-free\n"
        "deb http://deb.debian.org/debian bullseye-updates main contrib non-free"
    ),
    "cat /etc/network/interfaces": (
        "# interfaces(5) file used by ifup(8) and ifdown(8)\n"
        "# Include files from /etc/network/interfaces.d:\n"
        "source /etc/network/interfaces.d/*\n\n"
        "# The loopback network interface\n"
        "auto lo\n"
        "iface lo inet loopback"
    ),
    "cat /etc/sysctl.conf": (
        "#\n"
        "# /etc/sysctl.conf - Configuration file for setting system variables\n"
        "# See /etc/sysctl.d/ for additional system variables.\n"
        "# See sysctl.conf (5) for information.\n"
        "#\n\n"
        "#kernel.domainname = example.com\n\n"
        "#net.ipv4.conf.default.rp_filter=2\n"
        "#net.ipv4.conf.all.rp_filter=2\n\n"
        "#net.ipv4.tcp_syncookies=1\n\n"
        "#net.ipv4.ip_forward=1"
    ),
    "cat /etc/motd": (
        "\n"
        "====================================================================\n"
        "WARNING: UNAUTHORIZED ACCESS PROHIBITED\n"
        "Property of Distributed Sensor Network - Node Alpha\n"
        "All connections are monitored and recorded.\n"
        "===================================================================="
    ),

    # --- Cron (lateral-movement bait; targets are on this node's subnet) ---
    "cat /etc/crontab": (
        "SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        "# m h dom mon dow user  command\n"
        "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "*/5 *   * * *   pi      /opt/sensor/collect.sh >> /var/log/sensor.log 2>&1\n"
        "0   2   * * *   root    /usr/local/bin/db_backup.sh\n"
        "30  3   * * *   root    rsync -az /var/sensor-data/ admin@10.1.10.55:/backup/node-alpha/"
    ),
    "cat /etc/cron.d/sensor-sync": (
        "# Sensor network sync - DO NOT REMOVE\n"
        "*/10 * * * * root /opt/sensor/sync_nodes.sh 2>/dev/null\n"
        "0 4 * * * root scp -i /root/.ssh/id_rsa /var/www/html/config.php webadmin@10.1.10.55:/tmp/cfg_backup"
    ),

    # ==========================================================================
    # Static /proc + /boot files (invariant identity/config)
    # ==========================================================================
    # Memory totals match Tier 2 `free` (3884968 kB total, 102396 kB swap).
    "cat /proc/meminfo": (
        "MemTotal:        3884968 kB\n"
        "MemFree:         1998248 kB\n"
        "MemAvailable:    3210132 kB\n"
        "Buffers:           38560 kB\n"
        "Cached:           432464 kB\n"
        "SwapCached:            0 kB\n"
        "Active:           248528 kB\n"
        "Inactive:         286448 kB\n"
        "Unevictable:           0 kB\n"
        "Mlocked:               0 kB\n"
        "SwapTotal:        102396 kB\n"
        "SwapFree:         102396 kB\n"
        "Dirty:                 0 kB\n"
        "Writeback:             0 kB\n"
        "AnonPages:         64144 kB\n"
        "Mapped:            44528 kB\n"
        "Shmem:             13152 kB\n"
        "KReclaimable:      36640 kB\n"
        "Slab:              80288 kB\n"
        "SReclaimable:      36640 kB\n"
        "SUnreclaim:        43648 kB\n"
        "KernelStack:        2912 kB\n"
        "PageTables:         3808 kB\n"
        "CommitLimit:     2044880 kB\n"
        "Committed_AS:     137344 kB\n"
        "VmallocTotal:   68447887360 kB\n"
        "VmallocUsed:       65904 kB\n"
        "CmaTotal:          65536 kB\n"
        "CmaFree:           55296 kB"
    ),
    "cat /proc/filesystems": (
        "nodev\tsysfs\n"
        "nodev\ttmpfs\n"
        "nodev\tbdev\n"
        "nodev\tproc\n"
        "nodev\tcgroup\n"
        "nodev\tcgroup2\n"
        "nodev\tcpuset\n"
        "nodev\tdevtmpfs\n"
        "nodev\tdebugfs\n"
        "nodev\ttracefs\n"
        "nodev\tsockfs\n"
        "nodev\tpipefs\n"
        "nodev\tramfs\n"
        "nodev\thugetlbfs\n"
        "nodev\tdevpts\n"
        "\text3\n"
        "\text2\n"
        "\text4\n"
        "\tsquashfs\n"
        "\tvfat\n"
        "nodev\tmqueue\n"
        "\tfuseblk\n"
        "nodev\tfuse\n"
        "nodev\tfusectl\n"
        "nodev\tautofs"
    ),
    "cat /proc/mounts": (
        "/dev/mmcblk0p2 / ext4 rw,noatime 0 0\n"
        "devtmpfs /dev devtmpfs rw,relatime,size=1823456k,nr_inodes=227932,mode=755 0 0\n"
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "proc /proc proc rw,relatime 0 0\n"
        "tmpfs /run tmpfs rw,nosuid,nodev,size=388496k,mode=755 0 0\n"
        "devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0\n"
        "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
        "tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0\n"
        "/dev/mmcblk0p1 /boot vfat rw,relatime,fmask=0022,dmask=0022,codepage=437,iocharset=ascii,shortname=mixed,errors=remount-ro 0 0\n"
        "tmpfs /run/user/0 tmpfs rw,nosuid,nodev,relatime,size=388492k,mode=700 0 0"
    ),
    "cat /proc/net/arp": (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "10.1.10.1        0x1         0x2         b8:27:eb:12:34:56     *        eth0\n"
        "10.1.10.55       0x1         0x2         dc:a6:32:11:22:33     *        eth0"
    ),
    "cat /proc/net/route": (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t010A0A0A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t000A0A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0"
    ),
    "cat /proc/1/cmdline":      "/sbin/init",
    "cat /proc/1/comm":         "systemd",
    "cat /boot/cmdline.txt": (
        "console=serial0,115200 console=tty1 root=PARTUUID=738a4d67-02 "
        "rootfstype=ext4 fsck.repair=yes rootwait quiet splash "
        "plymouth.ignore-serial-consoles"
    ),
    "cat /boot/config.txt": (
        "# For more options and information see\n"
        "# http://rptl.io/configtxt\n"
        "# Some settings may impact device functionality. See link above for details\n\n"
        "#dtparam=i2c_arm=on\n"
        "#dtparam=i2s=on\n"
        "#dtparam=spi=on\n\n"
        "# Enable audio (loads snd_bcm2835)\n"
        "dtparam=audio=on\n\n"
        "camera_auto_detect=1\n"
        "display_auto_detect=1\n\n"
        "# Enable DRM VC4 V3D driver\n"
        "dtoverlay=vc4-kms-v3d\n"
        "max_framebuffers=2\n\n"
        "disable_overscan=1\n\n"
        "[cm4]\n"
        "otg_mode=1\n\n"
        "[all]"
    ),

    # ==========================================================================
    # Bait file reads — lateral-movement lures (consistent with bait.sh honeyfs)
    # ==========================================================================
    "cat /root/.bash_history": (
        "ping 8.8.8.8\n"
        "apt update && apt upgrade -y\n"
        "nano /var/www/html/config.php\n"
        "systemctl restart mariadb\n"
        "systemctl status apache2\n"
        "ssh admin@10.1.10.55\n"
        "ssh -i /root/.ssh/id_rsa webadmin@10.1.10.21\n"
        "rsync -az /var/sensor-data/ admin@10.1.10.55:/backup/\n"
        "cat /etc/passwd\n"
        "crontab -l\n"
        "mysql -u root -pFAU_cyber_db_admin_99! sensor_data_metrics\n"
        "exit"
    ),
    "cat /home/pi/.bash_history": (
        "ls -la\n"
        "cd /var/www/html\n"
        "cat config.php\n"
        "python3 collect.py\n"
        "sudo systemctl status sensor\n"
        "ping 10.1.10.1\n"
        "exit"
    ),
    "cat /var/www/html/config.php": (
        "<?php\n"
        "// Auto-generated by Ansible\n"
        "define('DB_SERVER', 'localhost');\n"
        "define('DB_USERNAME', 'root');\n"
        "define('DB_PASSWORD', 'FAU_cyber_db_admin_99!');\n"
        "define('DB_NAME', 'sensor_data_metrics');\n"
        "?>"
    ),
    "cat /root/.aws/credentials": (
        "[default]\n"
        "aws_access_key_id = AKIAQX3LM7NP2RSTVW84\n"
        "aws_secret_access_key = Jx7vK2mPqR9nL4wT6yB3hF8cZ1dA5eG0iUoYsNj\n"
        "region = us-east-1"
    ),
    "cat /root/.aws/config": (
        "[default]\n"
        "region = us-east-1\n"
        "output = json"
    ),
    "cat /root/.ssh/known_hosts": (
        "10.1.10.21 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vX fake_key_node_beta==\n"
        "10.1.10.22 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD3wY fake_key_node_gamma==\n"
        "10.1.10.55 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQE4xZ fake_key_admin=="
    ),
    "cat /root/.ssh/id_rsa.pub": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vX9nM4cR7pT5sH3bY8wQ1uL6jF2"
        "aK4eM8dS7gV0xJ6yW5pC3qN9iO1rT2hB4vU7kL0xE5sD8fG3mR9aP2cW6tY4zI1qN7"
        "mK8vB3dH5nQ9oL4pX2wR6sT7fC1yE5uJ8aN0zI3qM4kG7hD2bV9cS6tW8oR1pL3nF5yX2"
        " root@pi-sensor-gateway"
    ),
    # Prime lateral-movement bait: real-looking OpenSSH PEM, garbage key material.
    "cat /root/.ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n"
        "cnNhAAAAAwEAAQAAAYEAtvX9nM4cR7pT5sH3bY8wQ1uL6jF2aK4eM8dS7gV0xJ6yW5pC\n"
        "3qN9iO1rT2hB4vU7kL0xE5sD8fG3mR9aP2cW6tY4zI1qN7mK8vB3dH5nQ9oL4pX2wR6s\n"
        "T7fC1yE5uJ8aN0zI3qM4kG7hD2bV9cS6tW8oR1pL3nF5yX2dK9pT7mW4cL2bV5xR8fQ3\n"
        "AAAAwQDJm2H8nK5pT4cR9sN3bY7wQ1uL6jF2aK4eM8dS7gV0xJ6yW5pC3qN9iO1rT2hB\n"
        "-----END OPENSSH PRIVATE KEY-----"
    ),
    "cat /home/pi/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmK2nP8vR4cT7sL9xH3bY1wQ5uN6jF"
        "4aE2kM0dS9gV7xJ8yW3pC5qN1iO6rT2hB9vU4kL7xE3sD0fG8mR5aP6cW2tY9zI4qN1"
        " pi@workstation"
    ),
    "cat /var/log/auth.log": (
        "Apr 20 03:12:45 pi-sensor-gateway sshd[1234]: Accepted publickey for pi from 10.1.10.55 port 51234 ssh2\n"
        "Apr 20 03:12:46 pi-sensor-gateway sshd[1234]: pam_unix(sshd:session): session opened for user pi\n"
        "Apr 20 03:18:22 pi-sensor-gateway sshd[1234]: pam_unix(sshd:session): session closed for user pi\n"
        "Apr 21 02:00:01 pi-sensor-gateway cron[892]: (root) CMD (/usr/local/bin/db_backup.sh)\n"
        "Apr 22 03:15:01 pi-sensor-gateway sshd[2891]: Accepted publickey for root from 10.1.10.1 port 49823 ssh2\n"
        "Apr 22 03:22:17 pi-sensor-gateway sshd[2891]: pam_unix(sshd:session): session closed for user root"
    ),

    # ==========================================================================
    # SSH server/client config + host public keys
    # ==========================================================================
    "cat /etc/ssh/sshd_config": (
        "# $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $\n\n"
        "# This is the sshd server system-wide configuration file.  See\n"
        "# sshd_config(5) for more information.\n\n"
        "Include /etc/ssh/sshd_config.d/*.conf\n\n"
        "#Port 22\n"
        "#AddressFamily any\n"
        "#ListenAddress 0.0.0.0\n\n"
        "#LoginGraceTime 2m\n"
        "PermitRootLogin yes\n"
        "#StrictModes yes\n"
        "#MaxAuthTries 6\n\n"
        "PubkeyAuthentication yes\n"
        "PasswordAuthentication yes\n"
        "PermitEmptyPasswords no\n\n"
        "ChallengeResponseAuthentication no\n"
        "UsePAM yes\n\n"
        "X11Forwarding yes\n"
        "PrintMotd no\n"
        "AcceptEnv LANG LC_*\n"
        "Subsystem\tsftp\t/usr/lib/openssh/sftp-server"
    ),
    "cat /etc/ssh/ssh_config": (
        "# This is the ssh client system-wide configuration file.  See\n"
        "# ssh_config(5) for more information.\n\n"
        "Include /etc/ssh/ssh_config.d/*.conf\n\n"
        "Host *\n"
        "#   ForwardAgent no\n"
        "#   IdentityFile ~/.ssh/id_rsa\n"
        "#   Port 22\n"
        "    SendEnv LANG LC_*\n"
        "    HashKnownHosts yes\n"
        "    GSSAPIAuthentication yes"
    ),
    "cat /etc/ssh/ssh_host_rsa_key.pub": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ7f8k2vH3pT5cX9nQ2wR4sM6vB1aL"
        "x8KjF7yW3mE5nT2pQ4cV9uL0xJ5kR6sY1bN3mC8hF2dA7gU4eK9pO6tW0iE3qJ5zX4vB7nM1"
        " root@pi-sensor-gateway"
    ),
    "cat /etc/ssh/ssh_host_ed25519_key.pub": (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKx8W4nR7mQ2pT3cH9vX6zB5uL1aK8jF4sM2yE3wN7rQ"
        " root@pi-sensor-gateway"
    ),
    "cat /etc/ssh/ssh_host_ecdsa_key.pub": (
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKj7vN2m"
        "Q4cX8hR5pT6wL9yB1fA3eK7sM4nU2iH6zJ8dG0uV5tE3yW7pC9qN1bO4xR6mD8jS5vK2hL9aT"
        " root@pi-sensor-gateway"
    ),
    "cat /root/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCk9vX2mT4cR7pH5sN3bY8wQ1uL6jF"
        "2aK4eM8dS7gV0xJ6yW5pC3qN9iO1rT2hB4vU7kL0xE5sD8fG3mR9aP2cW6tY4zI1qN7"
        " ansible@deploy-01\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM4nP2wR7vK9sT3cH6xB1uL8jF4eK5yQ2mE3aN7rT9dW"
        " admin@10.1.10.55"
    ),

    # ==========================================================================
    # Dotfiles — root and pi (standard Debian bullseye skeletons)
    # ==========================================================================
    "cat /root/.bashrc": (
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
        "# Note: PS1 and umask are already set in /etc/profile. You should not\n"
        "# need this unless you want different defaults for root.\n"
        "# PS1='${debian_chroot:+($debian_chroot)}\\h:\\w\\$ '\n"
        "# umask 022\n\n"
        "export LS_OPTIONS='--color=auto'\n"
        "eval \"$(dircolors)\"\n"
        "alias ls='ls $LS_OPTIONS'\n"
        "alias ll='ls $LS_OPTIONS -l'\n"
        "alias l='ls $LS_OPTIONS -lA'\n\n"
        "alias rm='rm -i'\n"
        "alias cp='cp -i'\n"
        "alias mv='mv -i'"
    ),
    "cat /root/.profile": (
        "# ~/.profile: executed by Bourne-compatible login shells.\n\n"
        "if [ \"$BASH\" ]; then\n"
        "  if [ -f ~/.bashrc ]; then\n"
        "    . ~/.bashrc\n"
        "  fi\n"
        "fi\n\n"
        "mesg n 2> /dev/null || true"
    ),
    "cat /home/pi/.bashrc": (
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
        "case $- in\n"
        "    *i*) ;;\n"
        "      *) return;;\n"
        "esac\n\n"
        "HISTCONTROL=ignoreboth\n"
        "HISTSIZE=1000\n"
        "HISTFILESIZE=2000\n\n"
        "shopt -s checkwinsize\n\n"
        "alias ll='ls -alF'\n"
        "alias la='ls -A'\n"
        "alias l='ls -CF'"
    ),
    "cat /home/pi/.profile": (
        "# ~/.profile: executed by the command interpreter for login shells.\n\n"
        "if [ -n \"$BASH_VERSION\" ]; then\n"
        "    if [ -f \"$HOME/.bashrc\" ]; then\n"
        "\t. \"$HOME/.bashrc\"\n"
        "    fi\n"
        "fi\n\n"
        "if [ -d \"$HOME/bin\" ] ; then\n"
        "    PATH=\"$HOME/bin:$PATH\"\n"
        "fi"
    ),
    "cat /etc/bash.bashrc": (
        "# System-wide .bashrc file for interactive bash(1) shells.\n\n"
        "# If not running interactively, don't do anything\n"
        "[ -z \"$PS1\" ] && return\n\n"
        "shopt -s checkwinsize\n\n"
        "PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '"
    ),
    "cat /etc/profile": (
        "# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))\n"
        "# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).\n\n"
        "if [ \"$(id -u)\" -eq 0 ]; then\n"
        "  PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
        "else\n"
        "  PATH=\"/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games\"\n"
        "fi\n"
        "export PATH\n\n"
        "if [ -d /etc/profile.d ]; then\n"
        "  for i in /etc/profile.d/*.sh; do\n"
        "    if [ -r $i ]; then\n"
        "      . $i\n"
        "    fi\n"
        "  done\n"
        "  unset i\n"
        "fi"
    ),
}

STATIC_TABLE.update(_EXPANDED)


# Commands that produce an error on a real system. Tier 1 returns these exactly.
STATIC_ERRORS = {
    "docker":                   "bash: docker: command not found",
    "docker ps":                "bash: docker: command not found",
    "kubectl":                  "bash: kubectl: command not found",
    "kubectl get pods":         "bash: kubectl: command not found",
    "podman":                   "bash: podman: command not found",
    "nmap":                     "bash: nmap: command not found",
    "nmap localhost":           "bash: nmap: command not found",
}


def lookup(command: str) -> Optional[str]:
    """
    Pure dictionary lookup. Returns the response string or None if not found.
    None means "this command is not in Tier 1 — pass to router for re-dispatch".
    """
    cmd = command.strip()

    # Exact match on success table
    if cmd in STATIC_TABLE:
        return STATIC_TABLE[cmd]

    # Exact match on error table
    if cmd in STATIC_ERRORS:
        return STATIC_ERRORS[cmd]

    return None


def covers(command: str) -> bool:
    """Does Tier 1 claim this command? Used by router for dispatch decision."""
    cmd = command.strip()
    return cmd in STATIC_TABLE or cmd in STATIC_ERRORS


if __name__ == "__main__":
    tests = ["whoami", "uname -a", "cat /etc/os-release", "docker ps",
             "ps aux", "date", "ls /"]
    for t in tests:
        r = lookup(t)
        if r is None:
            print(f"[MISS ] {t!r}  (pass to router)")
        else:
            print(f"[HIT  ] {t!r}")
            print(f"        -> {r[:60]}")