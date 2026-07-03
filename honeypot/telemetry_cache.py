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