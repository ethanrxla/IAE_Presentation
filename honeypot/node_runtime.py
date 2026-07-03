#!/usr/bin/env python3
"""
node_runtime.py — Tier 2: Stateful Response Engine
Distributed Sensor Network - Node Agent

DESIGN PRINCIPLE: Commands whose output changes between calls on a real system,
but whose changes follow deterministic rules given session + wall-clock state.

This is fundamentally different from Tier 1. Tier 1 is a constant lookup.
Tier 2 generates responses from SessionState so that:
  - `uptime` advances over time consistently
  - `date` returns real wall clock
  - `ps aux` shows the attacker's own bash process
  - `ls` reflects files the attacker has created this session
  - `cd` actually changes the working directory for subsequent commands
  - `last` shows this attacker's login

The red team will probe for consistency. This tier defeats that.

Latency: ~1-5ms (dominated by string formatting, not I/O).

Returns: (handled: bool, response: str)
  handled=False -> router should dispatch to Tier 3
"""

import re
import shlex
import random
from typing import Tuple, Optional

from node_context import SessionState


# ==============================================================================
# Handler registry — maps command patterns to generator functions
# ==============================================================================

def handle(command: str, state: SessionState) -> Tuple[bool, str]:
    """
    Main entry point. Returns (handled, response).
    If handled=False, router falls through to Tier 3.
    """
    cmd = command.strip()
    if not cmd:
        return True, ""

    # Record for history
    state.record_command(cmd)

    # Strip common prefixes like `LANG=C ls`, `sudo -S cmd`, etc.
    # For honeypot realism we keep sudo prefix handling minimal.
    parts = shlex.split(cmd, posix=True) if _shellsafe(cmd) else cmd.split()
    if not parts:
        return True, ""
    head = parts[0]

    # Dispatch on first token
    dispatchers = {
        "date":         _cmd_date,
        "uptime":       _cmd_uptime,
        "w":            _cmd_w,
        "who":          _cmd_who,
        "last":         _cmd_last,
        "lastlog":      _cmd_lastlog,
        "ps":           _cmd_ps,
        "top":          _cmd_top,
        "pgrep":        _cmd_pgrep,
        "pidof":        _cmd_pidof,
        "netstat":      _cmd_netstat,
        "ss":           _cmd_ss,
        "ifconfig":     _cmd_ifconfig,
        "ip":           _cmd_ip,
        "arp":          _cmd_arp,
        "route":        _cmd_route,
        "ls":           _cmd_ls,
        "ll":           _cmd_ls_long,
        "dir":          _cmd_ls,
        "stat":         _cmd_stat,
        "file":         _cmd_file,
        "cd":           _cmd_cd,
        "pwd":          _cmd_pwd,
        "echo":         _cmd_echo,
        "printf":       _cmd_printf,
        "history":      _cmd_history,
        "env":          _cmd_env,
        "set":          _cmd_env,
        "printenv":     _cmd_printenv,
        "export":       _cmd_export,
        "free":         _cmd_free,
        "df":           _cmd_df,
        "du":           _cmd_du,
        "mount":        _cmd_mount,
        "lsblk":        _cmd_lsblk,
        "cat":          _cmd_cat,
        "head":         _cmd_headtail,
        "tail":         _cmd_headtail,
        "wc":           _cmd_wc,
        "grep":         _cmd_grep,
        "touch":        _cmd_touch,
        "mkdir":        _cmd_mkdir,
        "rm":           _cmd_rm,
        "cp":           _cmd_cp,
        "mv":           _cmd_mv,
        "systemctl":    _cmd_systemctl,
        "service":      _cmd_service,
        "journalctl":   _cmd_journalctl,
        "dmesg":        _cmd_dmesg,
        "dpkg":         _cmd_dpkg,
        "apt":          _cmd_apt,
        "apt-get":      _cmd_apt,
        "crontab":      _cmd_crontab,
        "sudo":         _cmd_sudo,
        "su":           _cmd_su,
        "ulimit":       _cmd_ulimit,
        "sleep":        _cmd_sleep,
        "clear":        lambda p, s: (True, ""),
        "exit":         lambda p, s: (True, ""),
        "logout":       lambda p, s: (True, ""),
        "reset":        lambda p, s: (True, ""),
    }

    if head in dispatchers:
        return dispatchers[head](parts, state)

    return False, ""  # Not handled -> DispatchLevel 3


# ==============================================================================
# Helper: safe shell tokenization
# ==============================================================================

def _shellsafe(cmd: str) -> bool:
    """Avoid shlex on commands with unbalanced quotes."""
    return cmd.count('"') % 2 == 0 and cmd.count("'") % 2 == 0


# ==============================================================================
# TIME COMMANDS — date, uptime, w, who, last
# ==============================================================================

def _cmd_date(parts, state):
    # Handle common `date` flags
    if len(parts) == 1:
        return True, state.format_date()
    if "+%s" in parts:
        from datetime import datetime, timezone
        return True, str(int(datetime.now(timezone.utc).timestamp()))
    # Accept arbitrary format strings: date "+%Y-%m-%d"
    for p in parts[1:]:
        if p.startswith("+"):
            fmt = p[1:].replace("%Y-%m-%d", "%Y-%m-%d")
            try:
                return True, state.format_date(fmt)
            except Exception:
                pass
    return True, state.format_date()


def _cmd_uptime(parts, state):
    if "-p" in parts:
        s = state.uptime_seconds()
        days = s // 86400
        hours = (s % 86400) // 3600
        mins = (s % 3600) // 60
        return True, f"up {days} days, {hours} hours, {mins} minutes"
    if "-s" in parts:
        return True, state.SYSTEM_BOOT_TIME.strftime("%Y-%m-%d %H:%M:%S")
    return True, state.format_uptime()


def _cmd_w(parts, state):
    header = state.format_uptime()
    body = (
        "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        f"root     pts/0    {state.attacker_ip:<16} {state.format_login_time():<8} 0.00s  0.02s  0.00s w"
    )
    return True, header + "\n" + body


def _cmd_who(parts, state):
    return True, f"root     pts/0        {state.login_time.strftime('%Y-%m-%d %H:%M')} ({state.attacker_ip})"


def _cmd_last(parts, state):
    login_line = f"root     pts/0        {state.attacker_ip:<16} {state.format_login_date_verbose()}   still logged in"
    history = (
        f"pi       pts/0        10.1.10.55       Tue Apr 21 03:12 - 03:18  (00:05)\n"
        f"root     pts/0        10.1.10.1        Mon Apr 20 03:15 - 03:22  (00:07)\n"
        f"reboot   system boot  6.12.34+rpt-rpi-2712     Sun Apr 19 11:52"
    )
    return True, login_line + "\n" + history + "\n\nwtmp begins Sun Apr 19 11:52:58 2026"


def _cmd_lastlog(parts, state):
    return True, (
        "Username         Port     From             Latest\n"
        f"root             pts/0    {state.attacker_ip:<16} {state.format_login_date_verbose()}\n"
        "daemon                                      **Never logged in**\n"
        "bin                                         **Never logged in**\n"
        "sys                                         **Never logged in**\n"
        "pi               pts/0    10.1.10.55       Tue Apr 21 03:12:45 +0000 2026\n"
        "webadmin                                    **Never logged in**"
    )


# ==============================================================================
# PROCESS COMMANDS — ps, top, pgrep, pidof
# ==============================================================================

def _cmd_ps(parts, state):
    # ps with various flag combos — all return the consistent process table
    flags = " ".join(parts[1:]) if len(parts) > 1 else ""
    if "ef" in flags or "-ef" in parts or "-e" in parts:
        return True, "\n".join(state.get_ps_ef())
    # Default ps aux or ps -aux
    return True, "\n".join(state.get_process_list())


def _cmd_top(parts, state):
    # top -bn1 is the scriptable form attackers use
    header = (
        f"top - {state.format_date('%H:%M:%S')} up {state.uptime_seconds()//86400} days,  "
        f"{(state.uptime_seconds()%86400)//3600:2}:{(state.uptime_seconds()%3600)//60:02}, 1 user, load average: 0.12, 0.08, 0.05\n"
        "Tasks:  98 total,   1 running,  97 sleeping,   0 stopped,   0 zombie\n"
        "%Cpu(s):  1.2 us,  0.8 sy,  0.0 ni, 97.5 id,  0.3 wa,  0.0 hi,  0.2 si,  0.0 st\n"
        "MiB Mem :   3793.1 total,    228.7 free,   1780.2 used,   1784.2 buff/cache\n"
        "MiB Swap:     99.0 total,     99.0 free,      0.0 used.   1715.3 avail Mem\n\n"
        "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"
    )
    procs = [
        "  521 mysql     20   0 1234567  82M    14M S   0.7   2.1   1:23.01 mysqld",
        "  512 root      20   0   65432   8M     4M S   0.2   0.2   0:12.43 apache2",
        "  489 root      20   0   14892   4M     3M S   0.0   0.1   0:00.04 sshd",
        "  534 root      20   0   14232   3M     2M S   0.0   0.1   0:00.00 cron",
        "  312 root      20   0   15328   3M     2M S   0.0   0.1   0:01.23 systemd-journal",
        "    1 root      20   0   22340   4M     3M S   0.0   0.1   0:08.41 systemd",
    ]
    return True, header + "\n" + "\n".join(procs)


def _cmd_pgrep(parts, state):
    if len(parts) < 2:
        return True, ""
    pattern = parts[-1]
    matches = [str(p[0]) for p in state.BOOT_PROCESSES if pattern in p[2]]
    return True, "\n".join(matches) if matches else ""


def _cmd_pidof(parts, state):
    if len(parts) < 2:
        return True, ""
    target = parts[1]
    matches = [str(p[0]) for p in state.BOOT_PROCESSES if target in p[2]]
    return True, " ".join(matches) if matches else ""


# ==============================================================================
# NETWORK COMMANDS — dynamic because they show THIS attacker's connection
# ==============================================================================

def _cmd_netstat(parts, state):
    flags = "".join(parts[1:])
    listeners = (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN"
    )
    # Show the attacker's own connection — consistency requirement
    attacker_conn = (
        f"\ntcp        0    128 10.1.10.20:2222         {state.attacker_ip}:51234        ESTABLISHED"
    )
    if "a" in flags or not flags:
        return True, listeners + attacker_conn
    return True, listeners


def _cmd_ss(parts, state):
    output = (
        "Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port\n"
        "tcp    LISTEN  0       128          0.0.0.0:22           0.0.0.0:*\n"
        "tcp    LISTEN  0       128          0.0.0.0:80           0.0.0.0:*\n"
        "tcp    LISTEN  0       128        127.0.0.1:3306         0.0.0.0:*\n"
        "tcp    LISTEN  0       128          0.0.0.0:2222         0.0.0.0:*\n"
        f"tcp    ESTAB   0       0       10.1.10.20:2222      {state.attacker_ip}:51234"
    )
    return True, output


def _cmd_ifconfig(parts, state):
    return True, (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.1.10.20  netmask 255.255.255.0  broadcast 10.1.10.255\n"
        "        ether b8:27:eb:12:34:56  txqueuelen 1000  (Ethernet)\n"
        f"        RX packets {45231 + state.uptime_seconds()//60}  bytes {12453821 + state.uptime_seconds()*100}\n"
        f"        TX packets {31982 + state.uptime_seconds()//90}  bytes {4821045 + state.uptime_seconds()*50}\n\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        loop  txqueuelen 1000  (Local Loopback)"
    )


def _cmd_ip(parts, state):
    if len(parts) < 2:
        return True, "Usage: ip [OPTIONS] OBJECT { COMMAND | help }"
    obj = parts[1]
    if obj in ("a", "addr", "address"):
        return True, (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "       valid_lft forever preferred_lft forever\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
            "    link/ether b8:27:eb:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 10.1.10.20/24 brd 10.1.10.255 scope global eth0\n"
            "       valid_lft forever preferred_lft forever"
        )
    if obj in ("r", "route"):
        return True, (
            "default via 10.1.10.1 dev eth0\n"
            "10.1.10.0/24 dev eth0 proto kernel scope link src 10.1.10.20"
        )
    if obj in ("n", "neigh", "neighbour"):
        return True, (
            "10.1.10.1 dev eth0 lladdr b8:27:eb:12:34:56 REACHABLE\n"
            "10.1.10.21 dev eth0 lladdr b8:27:eb:ab:cd:ef STALE\n"
            "10.1.10.22 dev eth0 lladdr b8:27:eb:98:76:54 STALE\n"
            "10.1.10.55 dev eth0 lladdr dc:a6:32:11:22:33 REACHABLE"
        )
    return False, ""


def _cmd_arp(parts, state):
    return True, (
        "Address                  HWtype  HWaddress           Flags Mask            Iface\n"
        "gateway                  ether   b8:27:eb:12:34:56   C                     eth0\n"
        "node-beta                ether   b8:27:eb:ab:cd:ef   C                     eth0\n"
        "node-gamma               ether   b8:27:eb:98:76:54   C                     eth0\n"
        "10.1.10.55               ether   dc:a6:32:11:22:33   C                     eth0"
    )


def _cmd_route(parts, state):
    return True, (
        "Kernel IP routing table\n"
        "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
        "default         gateway         0.0.0.0         UG    0      0        0 eth0\n"
        "10.1.10.0       0.0.0.0         255.255.255.0   U     0      0        0 eth0"
    )


# ==============================================================================
# FILESYSTEM COMMANDS — ls, stat, cd, pwd, touch, rm, etc.
# ==============================================================================

def _cmd_ls(parts, state, long=False):
    # Parse flags and paths
    flags = set()
    paths = []
    for p in parts[1:]:
        if p.startswith("-"):
            for c in p[1:]:
                flags.add(c)
        else:
            paths.append(p)

    show_long = "l" in flags or long
    show_hidden = "a" in flags or "A" in flags

    if not paths:
        paths = [state.current_dir]

    output = []
    for path in paths:
        path = _resolve_path(path, state)
        entries = state.list_directory(path)
        if entries is None:
            # Check if it's a file — ls on a file returns that filename
            info = state.get_file_info(path)
            if info:
                if show_long:
                    output.append(_format_ls_line(path.split("/")[-1], info))
                else:
                    output.append(path.split("/")[-1])
            else:
                output.append(f"ls: cannot access '{path}': No such file or directory")
            continue

        if not show_hidden:
            entries = [e for e in entries if not e.startswith(".")]
        if show_hidden and "a" in flags:
            # Include . and ..
            entries = [".", ".."] + entries

        if show_long:
            output.append(f"total {len(entries) * 4}")
            for e in entries:
                full = f"{path.rstrip('/')}/{e}" if path != "/" else f"/{e}"
                info = state.get_file_info(full)
                if info:
                    output.append(_format_ls_line(e, info))
                else:
                    # Directory or unknown — fake dir entry
                    is_dir = e in (".", "..") or state.list_directory(full) is not None
                    mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                    from datetime import datetime, timezone
                    mtime = state.SYSTEM_BOOT_TIME
                    output.append(f"{mode} 2 root root 4096 {mtime.strftime('%b %d  %Y')} {e}")
        else:
            output.append("  ".join(entries))

    return True, "\n".join(output)


def _cmd_ls_long(parts, state):
    return _cmd_ls(["ll", "-la"] + parts[1:], state, long=True)


def _format_ls_line(name, info):
    from datetime import datetime
    mtime = info["mtime"]
    # Format like real ls: "Apr 22 14:23" for this year, "Apr 22  2025" for older
    now_year = datetime.now(info["mtime"].tzinfo).year
    if mtime.year == now_year:
        date_str = mtime.strftime("%b %d %H:%M")
    else:
        date_str = mtime.strftime("%b %d  %Y")
    owner = "root" if info["uid"] == 0 else "pi"
    return f"{info['mode']} 1 {owner} {owner} {info['size']:>6} {date_str} {name}"


def _cmd_stat(parts, state):
    if len(parts) < 2:
        return True, "stat: missing operand"
    path = _resolve_path(parts[1], state)
    info = state.get_file_info(path)
    if not info:
        return True, f"stat: cannot statx '{path}': No such file or directory"
    mtime = info["mtime"]
    inode = state.rand_int(f"stat_inode:{path}", 100000, 999999)
    return True, (
        f"  File: {path}\n"
        f"  Size: {info['size']}          Blocks: {(info['size']+511)//512}     "
        f"IO Block: 4096   {'regular file' if not info['mode'].startswith('d') else 'directory'}\n"
        f"Device: b302h/45826d    Inode: {inode}    Links: 1\n"
        f"Access: (0644/{info['mode']})  Uid: ({info['uid']:>4}/    root)   "
        f"Gid: ({info['uid']:>4}/    root)\n"
        f"Access: {mtime.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000')}\n"
        f"Modify: {mtime.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000')}\n"
        f"Change: {mtime.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000')}\n"
        f" Birth: -"
    )


def _cmd_file(parts, state):
    if len(parts) < 2:
        return True, "file: missing operand"
    path = _resolve_path(parts[1], state)
    info = state.get_file_info(path)
    if not info:
        if state.list_directory(path) is not None:
            return True, f"{path}: directory"
        return True, f"{path}: cannot open (No such file or directory)"
    # Guess file type from path
    if path.endswith(".sh"):
        return True, f"{path}: Bourne-Again shell script, ASCII text executable"
    if path.endswith(".py"):
        return True, f"{path}: Python script, ASCII text executable"
    if path.endswith(".php"):
        return True, f"{path}: PHP script, ASCII text"
    if path.endswith(".log"):
        return True, f"{path}: ASCII text"
    if path.endswith(".html"):
        return True, f"{path}: HTML document, ASCII text"
    return True, f"{path}: ASCII text"


def _cmd_cd(parts, state):
    if len(parts) == 1:
        state.current_dir = state.env_vars["HOME"]
        state.env_vars["PWD"] = state.current_dir
        return True, ""
    target = _resolve_path(parts[1], state)
    if state.list_directory(target) is not None:
        state.current_dir = target
        state.env_vars["PWD"] = target
        return True, ""
    return True, f"bash: cd: {parts[1]}: No such file or directory"


def _cmd_pwd(parts, state):
    return True, state.current_dir


def _resolve_path(path, state):
    """Resolve relative paths against current_dir."""
    if path.startswith("/"):
        return path.rstrip("/") or "/"
    if path == ".":
        return state.current_dir
    if path == "..":
        parent = "/".join(state.current_dir.rstrip("/").split("/")[:-1])
        return parent or "/"
    if path.startswith("~"):
        return state.env_vars["HOME"] + path[1:]
    base = state.current_dir.rstrip("/")
    return f"{base}/{path}" if base else f"/{path}"


def _cmd_touch(parts, state):
    for p in parts[1:]:
        if not p.startswith("-"):
            full = _resolve_path(p, state)
            state.create_session_file(full, "")
    return True, ""


def _cmd_mkdir(parts, state):
    # Track created dirs in session_files with directory mode
    for p in parts[1:]:
        if not p.startswith("-"):
            full = _resolve_path(p, state)
            state.session_files[full] = {
                "size": 4096, "mtime": __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                "mode": "drwxr-xr-x", "uid": 0,
            }
    return True, ""


def _cmd_rm(parts, state):
    """Attacker trying to delete honeyfs files. Refuse realistically for system files."""
    for p in parts[1:]:
        if p.startswith("-"):
            continue
        full = _resolve_path(p, state)
        # Allow deletion of session-created files; refuse system files
        if full in state.session_files:
            del state.session_files[full]
        elif state.file_exists(full):
            return True, f"rm: cannot remove '{p}': Permission denied"
    return True, ""


def _cmd_cp(parts, state):
    return True, ""  # Silent success — attacker doesn't get real feedback


def _cmd_mv(parts, state):
    return True, ""


# ==============================================================================
# FILE CONTENT — cat, head, tail, wc, grep (stateful: reads session files)
# ==============================================================================

def _cmd_cat(parts, state):
    if len(parts) < 2:
        return False, ""  # Tier 3 handles interactive cat
    # Multiple files concatenated
    output_parts = []
    for p in parts[1:]:
        if p.startswith("-"):
            continue
        full = _resolve_path(p, state)
        if full in state.session_files and "content" in state.session_files[full]:
            output_parts.append(state.session_files[full]["content"])
            continue
        # Defer to Tier 1 for known static files (like /etc/passwd)
        # That happens at router level — if cat /etc/passwd got here, it's not in Tier 1
        if not state.file_exists(full):
            output_parts.append(f"cat: {p}: No such file or directory")
            continue
        # Tier 2 doesn't know the content — pass to Tier 3
        return False, ""
    return True, "\n".join(output_parts) if output_parts else ""


def _cmd_headtail(parts, state):
    return False, ""  # Let Tier 3 handle these with LLM awareness


def _cmd_wc(parts, state):
    return False, ""


def _cmd_grep(parts, state):
    return False, ""  # Grep is too context-sensitive — let LLM handle


# ==============================================================================
# ENVIRONMENT / SHELL
# ==============================================================================

def _cmd_echo(parts, state):
    if len(parts) == 1:
        return True, ""
    args = parts[1:]
    # Handle -n (no newline) and -e (escape interpretation) minimally
    suppress_newline = False
    if args and args[0] == "-n":
        suppress_newline = True
        args = args[1:]
    # Variable expansion
    text = " ".join(args)
    for var, val in state.env_vars.items():
        text = text.replace(f"${var}", val)
        text = text.replace(f"${{{var}}}", val)
    return True, text


def _cmd_printf(parts, state):
    if len(parts) < 2:
        return True, ""
    # Minimal printf — just strip quotes and print
    text = " ".join(parts[1:]).strip('"').strip("'")
    return True, text


def _cmd_history(parts, state):
    lines = []
    for i, h in enumerate(state.command_history, 1):
        lines.append(f"{i:>5}  {h}")
    return True, "\n".join(lines)


def _cmd_env(parts, state):
    lines = [f"{k}={v}" for k, v in state.env_vars.items()]
    return True, "\n".join(lines)


def _cmd_printenv(parts, state):
    if len(parts) == 1:
        return _cmd_env(parts, state)
    var = parts[1]
    return True, state.env_vars.get(var, "")


def _cmd_export(parts, state):
    if len(parts) == 1:
        return True, "\n".join(f"declare -x {k}=\"{v}\"" for k, v in state.env_vars.items())
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            state.env_vars[k] = v.strip('"').strip("'")
    return True, ""


# ==============================================================================
# RESOURCE COMMANDS — free, df, du
# ==============================================================================

def _cmd_free(parts, state):
    # Vary slightly based on uptime to feel "alive"
    delta = state.uptime_seconds() % 1000
    used = 1780 + (delta % 50)
    free = 3793 - used - 1784
    if "-h" in parts:
        return True, (
            "              total        used        free      shared  buff/cache   available\n"
            f"Mem:           3.7G        {used/1024:.1f}G        {free}M         44M        1.7G        {free + 1500}M\n"
            "Swap:           99M          0B         99M"
        )
    if "-m" in parts:
        return True, (
            "              total        used        free      shared  buff/cache   available\n"
            f"Mem:           3793        {used}         {free}          44        1784        {free + 1500}\n"
            "Swap:            99           0          99"
        )
    return True, (
        "              total        used        free      shared  buff/cache   available\n"
        f"Mem:        3884968     {used*1024}      {free*1024}       45892     1827356     {(free+1500)*1024}\n"
        "Swap:        102396           0      102396"
    )


def _cmd_df(parts, state):
    if "-h" in parts:
        return True, (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "udev            1.7G     0  1.7G   0% /dev\n"
            "tmpfs           380M  1.8M  378M   1% /run\n"
            "/dev/mmcblk0p2   30G  4.6G   23G  17% /\n"
            "tmpfs           1.9G     0  1.9G   0% /dev/shm\n"
            "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            "/dev/mmcblk0p1  253M   48M  205M  19% /boot/firmware\n"
            "tmpfs           380M     0  380M   0% /run/user/0"
        )
    return True, (
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "udev             1823456       0   1823456   0% /dev\n"
        "tmpfs             388496    1832    386664   1% /run\n"
        "/dev/mmcblk0p2  30703044 4823456  24234456  17% /\n"
        "tmpfs            1942480       0   1942480   0% /dev/shm\n"
        "/dev/mmcblk0p1    258095   49024    209071  19% /boot/firmware"
    )


def _cmd_du(parts, state):
    return False, ""  # du output is very context-sensitive — defer


def _cmd_mount(parts, state):
    return True, (
        "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
        "udev on /dev type devtmpfs (rw,nosuid,relatime,size=1823456k,nr_inodes=227932,mode=755)\n"
        "devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)\n"
        "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=388496k,mode=755)\n"
        "/dev/mmcblk0p2 on / type ext4 (rw,noatime)\n"
        "/dev/mmcblk0p1 on /boot/firmware type vfat (rw,relatime)"
    )


def _cmd_lsblk(parts, state):
    return True, (
        "NAME         MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT\n"
        "mmcblk0      179:0    0  29.7G  0 disk\n"
        "├─mmcblk0p1  179:1    0   256M  0 part /boot/firmware\n"
        "└─mmcblk0p2  179:2    0  29.5G  0 part /"
    )


# ==============================================================================
# SERVICE / SYSTEMD
# ==============================================================================

SYSTEMCTL_SERVICES = {
    "apache2":  ("active", "The Apache HTTP Server",       512, "Mon 2026-04-19 11:53:02 UTC"),
    "mariadb":  ("active", "MariaDB 10.5.19 database server", 521, "Mon 2026-04-19 11:53:05 UTC"),
    "mysql":    ("active", "MariaDB 10.5.19 database server", 521, "Mon 2026-04-19 11:53:05 UTC"),
    "ssh":      ("active", "OpenBSD Secure Shell server",  489, "Mon 2026-04-19 11:52:58 UTC"),
    "sshd":     ("active", "OpenBSD Secure Shell server",  489, "Mon 2026-04-19 11:52:58 UTC"),
    "cron":     ("active", "Regular background program processing daemon", 534, "Mon 2026-04-19 11:53:00 UTC"),
    "rsyslog":  ("active", "System Logging Service",       891, "Mon 2026-04-19 11:53:05 UTC"),
    "networking": ("active", "Raise network interfaces",   None, "Mon 2026-04-19 11:52:55 UTC"),
    "systemd-journald": ("active", "Journal Service",      312, "Mon 2026-04-19 11:52:58 UTC"),
    "docker":   ("not-found", None, None, None),
    "nginx":    ("not-found", None, None, None),
}


def _cmd_systemctl(parts, state):
    if len(parts) < 2:
        return False, ""
    sub = parts[1]

    if sub == "status" and len(parts) >= 3:
        svc = parts[2]
        if svc in SYSTEMCTL_SERVICES:
            s, desc, pid, started = SYSTEMCTL_SERVICES[svc]
            if s == "not-found":
                return True, f"Unit {svc}.service could not be found."
            tasks = state.rand_int(f"sysctl_tasks:{svc}", 1, 30)
            mem_int = state.rand_int(f"sysctl_memint:{svc}", 3, 82)
            mem_frac = state.rand_int(f"sysctl_memfrac:{svc}", 0, 9)
            cpu_int = state.rand_int(f"sysctl_cpuint:{svc}", 0, 90)
            cpu_frac = state.rand_int(f"sysctl_cpufrac:{svc}", 0, 999)
            return True, (
                f"● {svc}.service - {desc}\n"
                f"     Loaded: loaded (/lib/systemd/system/{svc}.service; enabled; vendor preset: enabled)\n"
                f"     Active: {s} (running) since {started}; {state.uptime_seconds()//86400} days ago\n"
                + (f"   Main PID: {pid} ({svc})\n" if pid else "")
                + f"      Tasks: {tasks} (limit: 4915)\n"
                f"     Memory: {mem_int}.{mem_frac}M\n"
                f"        CPU: {cpu_int}.{cpu_frac:03d}s"
            )
        return True, f"Unit {svc}.service could not be found."

    if sub == "is-active" and len(parts) >= 3:
        svc = parts[2]
        if svc in SYSTEMCTL_SERVICES and SYSTEMCTL_SERVICES[svc][0] != "not-found":
            return True, "active"
        return True, "inactive"

    if sub == "is-enabled" and len(parts) >= 3:
        svc = parts[2]
        if svc in SYSTEMCTL_SERVICES and SYSTEMCTL_SERVICES[svc][0] != "not-found":
            return True, "enabled"
        return True, f"Failed to get unit file state for {svc}.service: No such file or directory"

    if sub == "list-units":
        lines = ["  UNIT                          LOAD   ACTIVE SUB     DESCRIPTION"]
        for svc, (s, desc, _, _) in SYSTEMCTL_SERVICES.items():
            if s == "active":
                lines.append(f"  {svc}.service".ljust(32) + f"loaded active running {desc}")
        lines.append("\nLEGEND: LOAD=Reflects whether the unit definition was properly loaded.")
        return True, "\n".join(lines)

    if sub in ("start", "stop", "restart", "reload"):
        # Permission-style refusal since attacker should think they need different creds
        return True, ""

    return False, ""


def _cmd_service(parts, state):
    if len(parts) < 3:
        return False, ""
    svc = parts[1]
    action = parts[2]
    if action == "status":
        return _cmd_systemctl(["systemctl", "status", svc], state)
    return True, ""


def _cmd_journalctl(parts, state):
    # Minimal journalctl — show recent fake entries
    lines = []
    boot = state.SYSTEM_BOOT_TIME.strftime("%b %d %H:%M:%S")
    lines.append(f"-- Logs begin at {boot}. --")
    lines.append(f"Apr 19 11:52:58 pi-sensor-gateway systemd[1]: Started Apache HTTP Server.")
    lines.append(f"Apr 19 11:53:00 pi-sensor-gateway systemd[1]: Started Regular background program processing daemon.")
    lines.append(f"Apr 22 14:00:01 pi-sensor-gateway CRON[534]: (root) CMD (/opt/sensor/collect.sh)")
    lines.append(f"Apr 22 14:05:01 pi-sensor-gateway CRON[534]: (root) CMD (/opt/sensor/collect.sh)")
    lines.append(f"{state.format_date('%b %d %H:%M:%S')} pi-sensor-gateway sshd[{state.attacker_bash_pid - 1}]: Accepted password for root from {state.attacker_ip} port 51234 ssh2")
    return True, "\n".join(lines)


def _cmd_dmesg(parts, state):
    # Real dmesg on a Pi shows boot messages. Return a plausible subset.
    return True, (
        "[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x414fd0b1]\n"
        "[    0.000000] Linux version 6.12.34+rpt-rpi-2712 (dom@buildhost) (aarch64-linux-gnu-gcc-14)\n"
        "[    0.000000] Machine model: Raspberry Pi 5 Model B Rev 1.0\n"
        "[    0.000000] Memory policy: Data cache writealloc\n"
        "[    0.000000] OF: reserved mem: 0x0000000038000000..0x000000003fffffff (131072 KiB) map reusable linux,cma\n"
        "[    1.234521] systemd[1]: System time before build time, advancing clock.\n"
        "[    2.456789] systemd[1]: systemd 257.2-3 running in system mode.\n"
        "[    3.123456] systemd[1]: Detected architecture arm64."
    )


def _cmd_dpkg(parts, state):
    if len(parts) >= 2 and parts[1] in ("-l", "--list"):
        return True, (
            "Desired=Unknown/Install/Remove/Purge/Hold\n"
            "| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n"
            "|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n"
            "||/ Name                 Version                 Architecture Description\n"
            "+++-====================-=======================-============-===============================\n"
            "ii  apache2              2.4.64-1        arm64        Apache HTTP Server\n"
            "ii  bash                 5.2.37-1           arm64        GNU Bourne Again SHell\n"
            "ii  coreutils            9.5-1               arm64        GNU core utilities\n"
            "ii  curl                 8.14.1-1      arm64        command line tool for URLs\n"
            "ii  mariadb-server       1:11.8.2-1     arm64        MariaDB database server\n"
            "ii  openssh-server       1:10.0p1-5       arm64        secure shell (SSH) server\n"
            "ii  openssl              3.5.1-1        arm64        Secure Sockets Layer toolkit\n"
            "ii  python3              3.13.5-1                 arm64        interactive high-level OO language\n"
            "ii  wget                 1.25.0-1          arm64        retrieves files from the web"
        )
    if len(parts) >= 2 and parts[1] in ("-s", "--status"):
        return True, ""
    return False, ""


def _cmd_apt(parts, state):
    if len(parts) >= 2 and parts[1] == "list":
        return _cmd_dpkg(["dpkg", "-l"], state)
    if len(parts) >= 2 and parts[1] in ("update", "upgrade", "install", "remove"):
        return True, (
            "Reading package lists... Done\n"
            "Building dependency tree... Done\n"
            "Reading state information... Done\n"
            "All packages are up to date."
        )
    return False, ""


def _cmd_crontab(parts, state):
    if "-l" in parts:
        return True, (
            "# Sensor data collection\n"
            "*/5 * * * * /opt/sensor/collect.sh >> /var/log/sensor.log 2>&1\n"
            "# Database backup\n"
            "0 2 * * * /usr/local/bin/db_backup.sh\n"
            "# Sync to remote node\n"
            "30 3 * * * rsync -az /var/sensor-data/ admin@10.1.10.55:/backup/node-alpha/"
        )
    return True, ""


# ==============================================================================
# PRIVILEGE
# ==============================================================================

def _cmd_sudo(parts, state):
    # Re-dispatch the command inside sudo
    if len(parts) < 2:
        return True, "sudo: a command is required"
    # As root, sudo is a no-op
    inner = parts[1:]
    # Recurse into handler
    return handle(" ".join(inner), state)


def _cmd_su(parts, state):
    # Attacker trying to switch users — we stay as root for session integrity
    if len(parts) >= 2 and parts[1] != "-":
        return True, "Password: \nsu: Authentication failure"
    return True, ""


def _cmd_ulimit(parts, state):
    if "-a" in parts:
        return True, (
            "real-time non-blocking time  (microseconds, -R) unlimited\n"
            "core file size              (blocks, -c) 0\n"
            "data seg size               (kbytes, -d) unlimited\n"
            "scheduling priority                 (-e) 0\n"
            "file size                   (blocks, -f) unlimited\n"
            "pending signals                     (-i) 15041\n"
            "max locked memory           (kbytes, -l) 65536\n"
            "max memory size             (kbytes, -m) unlimited\n"
            "open files                          (-n) 1024\n"
            "pipe size                (512 bytes, -p) 8\n"
            "POSIX message queues         (bytes, -q) 819200\n"
            "real-time priority                  (-r) 0\n"
            "stack size                  (kbytes, -s) 8192\n"
            "cpu time                   (seconds, -t) unlimited\n"
            "max user processes                  (-u) 15041\n"
            "virtual memory              (kbytes, -v) unlimited\n"
            "file locks                          (-x) unlimited"
        )
    return True, "unlimited"


def _cmd_sleep(parts, state):
    # Honor sleep for realism — red team will use this as timing check
    if len(parts) >= 2:
        try:
            secs = float(parts[1])
            if secs > 0 and secs <= 10:  # Cap at 10s to avoid DoS
                import time as _t
                _t.sleep(secs)
        except ValueError:
            return True, "sleep: invalid time interval"
    return True, ""


if __name__ == "__main__":
    from node_context import get_session
    s = get_session("test")

    tests = [
        "date", "uptime", "w", "last", "ps aux", "ifconfig", "netstat -tlnp",
        "ls /", "ls /etc", "ls -la /root", "stat /etc/passwd",
        "cd /tmp", "pwd", "touch newfile", "ls", "ls -la",
        "echo $HOME", "history", "env",
        "free -h", "df -h", "mount",
        "systemctl status apache2", "systemctl status docker",
        "dpkg -l", "crontab -l",
    ]
    for t in tests:
        handled, resp = handle(t, s)
        print(f"\n[{'OK' if handled else 'MISS'}] $ {t}")
        if resp:
            for line in resp.split("\n")[:5]:
                print(f"     {line}")
            if len(resp.split("\n")) > 5:
                print(f"     ... ({len(resp.split(chr(10))) - 5} more lines)")