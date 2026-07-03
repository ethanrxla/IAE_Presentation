#!/usr/bin/env python3
"""
node_context.py — Sensor Network Node Agent
FAU Team - eMERGE 2026 Hackathon

The red team probes for consistency across commands. If `uptime` shows 3 days,
then `last` must show a reboot 3 days ago. If the attacker creates a file with
`echo`, `ls` must show it. If they `cd /tmp`, subsequent commands must reflect it.

This module holds all live session state — consulted by Tier 2, Tier 3, and
Tier 4. Tier 1 does not use state (by design — its outputs are invariant).

Key design principle: every query to state is deterministic given the session.
Two calls to get_uptime() return values consistent with the elapsed wall time.
"""

import time
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional


class SessionState:
    """
    Per-session state. One instance per attacker connection.
    Seeded deterministically so same attacker gets consistent values.
    """

    # --- Persistent across ALL sessions (the "system" has been up for days) ---
    SYSTEM_BOOT_TIME = datetime(2026, 4, 19, 11, 52, 58, tzinfo=timezone.utc)

    # Fake processes that exist at boot. PIDs stable across session.
    # Format: (pid, user, command, cpu, mem_pct, vsz, rss, tty, stat, start_time_offset_seconds)
    BOOT_PROCESSES = [
        (1,    "root",     "/sbin/init",                           0.0, 0.1, 22340,  4012, "?",     "Ss",  0),
        (2,    "root",     "[kthreadd]",                           0.0, 0.0, 0,      0,    "?",     "S",   0),
        (312,  "root",     "/lib/systemd/systemd-journald",        0.0, 0.1, 15328,  3124, "?",     "Ss",  2),
        (341,  "root",     "/lib/systemd/systemd-udevd",           0.0, 0.1, 20244,  3892, "?",     "Ss",  3),
        (489,  "root",     "/usr/sbin/sshd -D",                    0.0, 0.1, 14892,  4231, "?",     "Ss",  12),
        (512,  "root",     "/usr/sbin/apache2 -k start",           0.0, 0.2, 65432,  8912, "?",     "Ss",  14),
        (513,  "www-data", "/usr/sbin/apache2 -k start",           0.0, 0.2, 65432,  6234, "?",     "S",   15),
        (514,  "www-data", "/usr/sbin/apache2 -k start",           0.0, 0.2, 65432,  6198, "?",     "S",   15),
        (521,  "mysql",    "/usr/sbin/mysqld",                     0.0, 2.1, 1234567, 82341, "?",   "Ssl", 17),
        (534,  "root",     "/usr/sbin/cron -f",                    0.0, 0.1, 14232,  3421, "?",     "Ss",  20),
        (891,  "root",     "/usr/sbin/rsyslogd -n",                0.0, 0.1, 13456,  2341, "?",     "Ss",  22),
        (1023, "pi",       "/opt/sensor/collect.sh",               0.0, 0.1, 8234,   2341, "?",     "S",   45),
        (1124, "root",     "/usr/bin/python3 /opt/sensor/sync_nodes.py", 0.0, 0.3, 45231, 9823, "?", "Ss", 60),
    ]

    # Files with realistic mtimes — must match across ls, stat, find
    # Format: path -> (size_bytes, mtime_offset_from_boot_hours, mode)
    FAKE_FILES = {
        "/etc/passwd":                  (823, 0, "-rw-r--r--"),
        "/etc/shadow":                  (546, 0, "-rw-------"),
        "/etc/hostname":                (18, 0, "-rw-r--r--"),
        "/etc/hosts":                   (312, 0, "-rw-r--r--"),
        "/etc/os-release":              (241, 0, "-rw-r--r--"),
        "/etc/crontab":                 (723, 12, "-rw-r--r--"),
        "/etc/ssh/sshd_config":         (3264, 24, "-rw-r--r--"),
        "/var/www/html/config.php":     (178, 48, "-rw-r--r--"),
        "/var/www/html/index.html":     (1823, 36, "-rw-r--r--"),
        "/var/log/auth.log":            (14823, 72, "-rw-r-----"),
        "/var/log/syslog":              (234891, 71, "-rw-r-----"),
        "/var/log/apache2/access.log":  (89234, 70, "-rw-r-----"),
        "/root/.bash_history":          (423, 2, "-rw-------"),
        "/root/.aws/credentials":       (187, 48, "-rw-------"),
        "/root/.aws/config":            (48, 48, "-rw-------"),
        "/root/.ssh/known_hosts":       (812, 36, "-rw-------"),
        "/home/pi/.bash_history":       (89, 2, "-rw-------"),
        "/opt/sensor/collect.sh":       (2341, 96, "-rwxr-xr-x"),
        "/opt/sensor/sync_nodes.py":    (5823, 96, "-rwxr-xr-x"),
    }

    def __init__(self, attacker_ip: str = "10.1.10.99", session_id: Optional[str] = None):
        self.attacker_ip = attacker_ip
        self.session_id = session_id or attacker_ip
        self.login_time = datetime.now(timezone.utc)
        self.last_touched = time.time()
        self.current_user = "root"
        self.current_dir = "/root"
        self.command_history: List[str] = []

        # Seeded RNG for per-session deterministic "random" values. Anything that
        # needs a stable pseudo-random number (inode, task count, memory figure)
        # goes through rand_int so repeated probes return identical output.
        import random as _r
        self._rng = _r.Random(hash(self.session_id) & 0xFFFFFFFF)
        self._rand_cache: Dict[str, int] = {}
        self.env_vars: Dict[str, str] = {
            "SHELL": "/bin/bash",
            "PWD": "/root",
            "LOGNAME": "root",
            "HOME": "/root",
            "USER": "root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "LANG": "en_GB.UTF-8",
        }
        # Files the attacker has created/modified during THIS session
        self.session_files: Dict[str, Dict] = {}
        # Track last-seen times for commands (used to detect rapid repeat probing)
        self.last_seen: Dict[str, float] = {}

        # Attacker session PID — shows up in ps for THIS session's bash
        self.attacker_bash_pid = 2340 + (hash(attacker_ip) % 100)
        self.attacker_cmd_pid = self.attacker_bash_pid + 1

    # --- Deterministic pseudo-random ---
    def rand_int(self, key: str, lo: int, hi: int) -> int:
        """
        Return a stable int in [lo, hi] for (session, key). First call populates
        the cache; later calls return the same value. Same key across sessions
        can still differ, because each session has its own seeded RNG.
        """
        if key not in self._rand_cache:
            self._rand_cache[key] = self._rng.randint(lo, hi)
        return self._rand_cache[key]

    # --- Time helpers ---
    def uptime_seconds(self) -> int:
        return int((datetime.now(timezone.utc) - self.SYSTEM_BOOT_TIME).total_seconds())

    def format_uptime(self) -> str:
        """Format like the real 'uptime' command: ' 14:23:01 up 3 days, 2:14, 1 user, load...'"""
        now = datetime.now(timezone.utc)
        delta = now - self.SYSTEM_BOOT_TIME
        days = delta.days
        hours = delta.seconds // 3600
        mins = (delta.seconds % 3600) // 60

        time_str = now.strftime("%H:%M:%S")
        if days > 0:
            up_str = f"{days} days, {hours:2d}:{mins:02d}"
        elif hours > 0:
            up_str = f"{hours:2d}:{mins:02d}"
        else:
            up_str = f"{mins} min"

        # Deterministic load averages — vary slightly over time
        base_load = 0.08 + (self.uptime_seconds() % 100) / 1000
        load1 = round(base_load + 0.04, 2)
        load5 = round(base_load, 2)
        load15 = round(base_load - 0.03, 2)

        return f" {time_str} up {up_str}, 1 user, load average: {load1:.2f}, {load5:.2f}, {load15:.2f}"

    def format_date(self, fmt: Optional[str] = None) -> str:
        """Return 'date' command output. Uses real wall clock time."""
        now = datetime.now(timezone.utc)
        if fmt:
            return now.strftime(fmt)
        return now.strftime("%a %b %d %H:%M:%S UTC %Y")

    def format_login_time(self) -> str:
        """When THIS attacker logged in (for `last`, `w`, `who`)"""
        return self.login_time.strftime("%H:%M")

    def format_login_date_verbose(self) -> str:
        """Verbose login line for `last`"""
        return self.login_time.strftime("%a %b %d %H:%M")

    # --- Process table ---
    def get_process_list(self, long_format: bool = False) -> List[str]:
        """
        Generate a realistic ps output. Times advance as session progresses.
        Includes the attacker's own bash and whatever they just ran.
        """
        lines = []
        if long_format:
            lines.append("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")
        else:
            lines.append("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND")

        boot_str = self.SYSTEM_BOOT_TIME.strftime("%b%d")
        login_str = self.login_time.strftime("%H:%M")

        for pid, user, cmd, cpu, mem, vsz, rss, tty, stat, start_offset in self.BOOT_PROCESSES:
            # Time accumulated = (uptime - start_offset) roughly, keep it small for most
            uptime_s = self.uptime_seconds()
            if cpu > 0:
                cpu_time_s = max(0, int((uptime_s - start_offset) * cpu / 100))
            else:
                cpu_time_s = self.rand_int(f"ps_cpu:{pid}", 0, 15)
            mins = cpu_time_s // 60
            secs = cpu_time_s % 60
            time_str = f"{mins}:{secs:02d}"
            lines.append(
                f"{user:<10} {pid:>5} {cpu:4.1f} {mem:4.1f} {vsz:>6} {rss:>5} {tty:<8} {stat:<5} {boot_str:<7} {time_str:>4} {cmd}"
            )

        # Attacker's own session
        lines.append(
            f"{'root':<10} {self.attacker_bash_pid:>5} {0.0:4.1f} {0.1:4.1f} {14234:>6} {3421:>5} {'pts/0':<8} {'Ss':<5} {login_str:<7} {'0:00':>4} -bash"
        )
        lines.append(
            f"{'root':<10} {self.attacker_cmd_pid:>5} {0.0:4.1f} {0.1:4.1f} {10234:>6} {2341:>5} {'pts/0':<8} {'R+':<5} {login_str:<7} {'0:00':>4} ps aux"
        )

        return lines

    def get_ps_ef(self) -> List[str]:
        """Generate ps -ef output."""
        lines = ["UID        PID  PPID  C STIME TTY          TIME CMD"]
        boot_str = self.SYSTEM_BOOT_TIME.strftime("%b%d")
        login_str = self.login_time.strftime("%H:%M")

        for pid, user, cmd, cpu, mem, vsz, rss, tty, stat, start_offset in self.BOOT_PROCESSES:
            ppid = 1 if pid > 10 else 0
            secs = self.rand_int(f"psef_secs:{pid}", 0, 59)
            lines.append(f"{user:<10} {pid:>5} {ppid:>5}  0 {boot_str:<7} {tty:<12} 00:00:{secs:02d} {cmd}")

        lines.append(f"{'root':<10} {self.attacker_bash_pid:>5} {self.attacker_bash_pid - 1:>5}  0 {login_str:<7} {'pts/0':<12} 00:00:00 -bash")
        lines.append(f"{'root':<10} {self.attacker_cmd_pid:>5} {self.attacker_bash_pid:>5}  0 {login_str:<7} {'pts/0':<12} 00:00:00 ps -ef")
        return lines

    # --- Filesystem ---
    def file_exists(self, path: str) -> bool:
        return path in self.FAKE_FILES or path in self.session_files

    def get_file_info(self, path: str) -> Optional[Dict]:
        """Return stat-like info for a file."""
        if path in self.session_files:
            return self.session_files[path]
        if path in self.FAKE_FILES:
            size, mtime_off_hours, mode = self.FAKE_FILES[path]
            mtime = self.SYSTEM_BOOT_TIME + timedelta(hours=mtime_off_hours)
            return {
                "size": size,
                "mtime": mtime,
                "mode": mode,
                "uid": 0 if mode.startswith("-rw-------") or "/root/" in path else 1000,
            }
        return None

    def create_session_file(self, path: str, content: str):
        """Attacker created a file via echo >, touch, etc."""
        self.session_files[path] = {
            "size": len(content),
            "mtime": datetime.now(timezone.utc),
            "mode": "-rw-r--r--",
            "uid": 0,
            "content": content,
        }

    # --- Directory contents ---
    DIRECTORY_CONTENTS = {
        "/": ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt",
              "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"],
        "/etc": ["apache2", "cron.d", "cron.daily", "crontab", "group", "hostname",
                 "hosts", "init.d", "mysql", "os-release", "passwd", "resolv.conf",
                 "shadow", "ssh", "sudoers", "systemd"],
        "/root": [".aws", ".bash_history", ".bashrc", ".profile", ".ssh"],
        "/root/.aws": ["config", "credentials"],
        "/root/.ssh": ["authorized_keys", "id_rsa", "id_rsa.pub", "known_hosts"],
        "/home": ["pi", "webadmin"],
        "/home/pi": [".bash_history", ".bashrc", ".profile"],
        "/var": ["backups", "cache", "lib", "local", "lock", "log", "mail", "opt",
                 "run", "spool", "tmp", "www"],
        "/var/www": ["html"],
        "/var/www/html": ["admin", "api", "backup", "config.php", "index.html", "robots.txt"],
        "/var/log": ["apache2", "auth.log", "daemon.log", "dpkg.log", "kern.log",
                     "lastlog", "mysql", "syslog", "wtmp"],
        "/opt": ["sensor"],
        "/opt/sensor": ["collect.sh", "sync_nodes.py", "config.ini"],
        "/tmp": [],  # starts empty
    }

    def list_directory(self, path: str) -> Optional[List[str]]:
        path = path.rstrip("/") or "/"
        if path in self.DIRECTORY_CONTENTS:
            # Add any session-created files in this directory
            contents = list(self.DIRECTORY_CONTENTS[path])
            for sp in self.session_files:
                parent = os.path.dirname(sp)
                if parent == path:
                    name = os.path.basename(sp)
                    if name not in contents:
                        contents.append(name)
            return sorted(contents)
        return None

    # --- Command history (for `history` command) ---
    def record_command(self, cmd: str):
        self.command_history.append(cmd)
        self.last_seen[cmd] = time.time()


# --- Global session registry ---
# Cowrie gives each SSH connection a unique identifier. We map them here.
#
# LRU cap prevents unbounded growth under reconnect storms (fatigue testing).
# Idle eviction drops sessions that haven't been touched in IDLE_TTL_SEC so
# long-running processes don't retain memory for disconnected attackers.
from collections import OrderedDict

_SESSION_CAP = 200
IDLE_TTL_SEC = 30 * 60  # 30 min

_sessions: "OrderedDict[str, SessionState]" = OrderedDict()


def _evict_idle(now: Optional[float] = None) -> None:
    """Drop any session untouched for more than IDLE_TTL_SEC."""
    now = now if now is not None else time.time()
    stale = [sid for sid, s in _sessions.items() if now - s.last_touched > IDLE_TTL_SEC]
    for sid in stale:
        _sessions.pop(sid, None)


def get_session(session_id: str, attacker_ip: str = "10.1.10.99") -> SessionState:
    """Get or create a session state for a given Cowrie session."""
    now = time.time()
    _evict_idle(now)
    s = _sessions.get(session_id)
    if s is None:
        # Enforce cap BEFORE insert so we never exceed
        while len(_sessions) >= _SESSION_CAP:
            _sessions.popitem(last=False)
        s = SessionState(attacker_ip=attacker_ip, session_id=session_id)
        _sessions[session_id] = s
    else:
        # Mark as most-recently-used
        _sessions.move_to_end(session_id)
    s.last_touched = now
    return s


def clear_session(session_id: str) -> None:
    _sessions.pop(session_id, None)


def session_count() -> int:
    """For tests and monitoring."""
    return len(_sessions)


if __name__ == "__main__":
    s = get_session("test", "1.2.3.4")
    print("=== uptime ===")
    print(s.format_uptime())
    print("\n=== date ===")
    print(s.format_date())
    print("\n=== ps aux (first 5 lines) ===")
    for line in s.get_process_list()[:5]:
        print(line)
    print("\n=== /etc contents ===")
    print(s.list_directory("/etc"))
    print("\n=== file info on /etc/passwd ===")
    print(s.get_file_info("/etc/passwd"))