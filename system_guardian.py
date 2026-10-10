#!/usr/bin/env python3
"""
=============================================================================
PANELX SYSTEM GUARDIAN — v2.0 Production Background Daemon
Automated Storage Protection, Disk Leak Guard & Smart Device Limiter
Powered by SG Home
=============================================================================
Key Features:
- 6-Hour Automated Storage Guard & Emergency Disk Full Preventer
- Journalctl Vacuum (Cap at 50MB) & Log Truncation (/var/log/syslog > 100MB)
- Automatic Removal of Orphaned .1, .gz, .old log archives
- Ultra-Low CPU Device Limiter (Non-blocking ss/proc socket telemetry)
- Graceful Disconnect of Newest Unauthorized Session (Allowed sessions stay online)
- Bandwidth Quota and Expiry Auto-Enforcement
- Fail2ban SSH Bot Defense Watchdog
=============================================================================
"""

import os
import re
import sys
import time
import glob
import json
import signal
import shutil
import sqlite3
import subprocess
from datetime import datetime
from typing import Dict, List, Set, Tuple, Any

# Reconfigure stdout for UTF-8 compatibility
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Configuration & Paths
# ---------------------------------------------------------------------------
DATA_DIR = "/etc/panelx"
if not os.path.exists(DATA_DIR) and not os.access("/etc", os.W_OK):
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

DB_PATH = os.path.join(DATA_DIR, "panelx.db")
BW_DIR = os.path.join(DATA_DIR, "bandwidth")
PID_TRACK_DIR = os.path.join(BW_DIR, "pidtrack")
LOG_DIR = "/var/log/panelx" if os.access("/var/log", os.W_OK) else DATA_DIR
GUARDIAN_LOG = os.path.join(LOG_DIR, "guardian.log")

ACTIVE_USERS_FILE = "/run/panelx/active_users.json"
if not os.path.exists("/run"):
    ACTIVE_USERS_FILE = os.path.join(DATA_DIR, "active_users.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BW_DIR, exist_ok=True)
os.makedirs(PID_TRACK_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(ACTIVE_USERS_FILE), exist_ok=True)

# Timers
FAST_LOOP_INTERVAL = 4          # Check connections every 4 seconds
STORAGE_CHECK_INTERVAL = 21600  # 6 hours in seconds
FAIL2BAN_CHECK_INTERVAL = 300   # 5 minutes

# ---------------------------------------------------------------------------
# Logging Helper
# ---------------------------------------------------------------------------
def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] [{level}] {msg}"
    print(formatted, flush=True)
    try:
        with open(GUARDIAN_LOG, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Database Helper (WAL & busy_timeout)
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

# ---------------------------------------------------------------------------
# 1. Storage Protection & Disk Leak Guard
# ---------------------------------------------------------------------------
def safe_truncate_log(file_path: str, max_size_bytes: int = 100 * 1024 * 1024, keep_lines: int = 15000):
    """
    Safely truncates a log file while preserving the open file descriptor / inode.
    Avoids breaking rsyslog or syslog-ng logging daemons.
    """
    if not os.path.exists(file_path):
        return

    try:
        size = os.path.getsize(file_path)
        if size > max_size_bytes:
            log(f"Log file {file_path} exceeded limit ({round(size / (1024**2), 1)} MB). Truncating...", "WARN")
            tmp_file = f"{file_path}.tmp_trunc"
            # Extract last N lines
            subprocess.run(f"tail -n {keep_lines} {file_path} > {tmp_file}", shell=True)
            # Copy back to preserve existing inode
            subprocess.run(f"cat {tmp_file} > {file_path} && rm -f {tmp_file}", shell=True)
            new_size = os.path.getsize(file_path)
            log(f"Successfully truncated {file_path} to {round(new_size / (1024**2), 1)} MB.")
    except Exception as e:
        log(f"Error truncating {file_path}: {e}", "ERROR")

def clean_orphaned_logs():
    """
    Removes unneeded rotated/compressed log archives (.1, .gz, .old) that fill up disk.
    """
    reclaimed_bytes = 0
    patterns = [
        "/var/log/*.gz",
        "/var/log/*.[0-9]",
        "/var/log/*.[0-9].gz",
        "/var/log/*.old",
        "/var/log/syslog.*",
        "/var/log/auth.log.*",
        "/var/log/journal/*/*.journal~"
    ]
    for pattern in patterns:
        for fpath in glob.glob(pattern):
            # Do not delete currently active log files
            if fpath in ["/var/log/syslog", "/var/log/auth.log", "/var/log/messages"]:
                continue
            try:
                sz = os.path.getsize(fpath)
                os.remove(fpath)
                reclaimed_bytes += sz
            except Exception:
                pass

    if reclaimed_bytes > 0:
        mb = round(reclaimed_bytes / (1024**2), 1)
        log(f"Reclaimed {mb} MB by purging orphaned rotated log archives.")

def run_storage_protection(is_emergency: bool = False):
    """
    Performs comprehensive storage maintenance:
    - Vacuum journalctl to 50M
    - Truncate /var/log/syslog & /var/log/auth.log if > 100M
    - Delete orphaned .gz / .1 log files
    - Emergency cleanup if disk > 85% full
    """
    mode = "EMERGENCY" if is_emergency else "SCHEDULED (6-Hour)"
    log(f"Running {mode} Storage Protection & Disk Leak Guard...")

    try:
        # 1. Vacuum systemd journal to max 50MB (or 20MB in emergency)
        vac_size = "20M" if is_emergency else "50M"
        subprocess.run(f"journalctl --vacuum-size={vac_size} 2>/dev/null", shell=True)
        log(f"Vacuumed systemd journal logs (cap: {vac_size}).")

        # 2. Check and truncate syslog & auth.log
        safe_truncate_log("/var/log/syslog", max_size_bytes=100 * 1024 * 1024)
        safe_truncate_log("/var/log/auth.log", max_size_bytes=100 * 1024 * 1024)
        safe_truncate_log("/var/log/messages", max_size_bytes=100 * 1024 * 1024)

        # 3. Clean orphaned archives
        clean_orphaned_logs()

        # 4. Check disk usage
        total, used, free = shutil.disk_usage("/")
        used_pct = round((used / total) * 100, 1)
        free_gb = round(free / (1024**3), 2)
        log(f"Current root disk usage: {used_pct}% ({free_gb} GB free).")

        # 5. Critical emergency actions if usage > 90%
        if used_pct > 90:
            log("Root filesystem is above 90%! Running deep package and temp cleanup...", "WARN")
            subprocess.run("apt-get clean 2>/dev/null", shell=True)
            subprocess.run("find /tmp -type f -atime +3 -delete 2>/dev/null", shell=True)
            subprocess.run("journalctl --vacuum-time=2d 2>/dev/null", shell=True)

    except Exception as e:
        log(f"Error during storage protection: {e}", "ERROR")

# ---------------------------------------------------------------------------
# 2. SSH Brute-Force Bot Defense Watchdog
# ---------------------------------------------------------------------------
def check_fail2ban_guard():
    """
    Ensures fail2ban is running with the SSH jail active to prevent CPU spikes
    from massive internet bot brute-force attacks.
    """
    try:
        res = subprocess.run("systemctl is-active fail2ban", shell=True, capture_output=True, text=True)
        if res.stdout.strip() != "active":
            log("fail2ban service is inactive. Attempting to start...", "WARN")
            subprocess.run("systemctl restart fail2ban 2>/dev/null", shell=True)
        else:
            # Check jail status
            jres = subprocess.run("fail2ban-client status sshd 2>/dev/null", shell=True, capture_output=True, text=True)
            if "Currently banned:" in jres.stdout:
                m = re.search(r"Currently banned:\s+(\d+)", jres.stdout)
                if m:
                    banned_count = m.group(1)
                    # Periodic heartbeat info
                    log(f"Fail2ban SSH Bot Defense: {banned_count} malicious IP(s) currently banned.")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 3. Efficient Live Socket & Device Limiter
# ---------------------------------------------------------------------------
def get_linux_users_map() -> Dict[int, str]:
    """Reads /etc/passwd once per cycle to map UID -> username in memory."""
    uid_map = {}
    try:
        with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 3 and parts[2].isdigit():
                    uid_map[int(parts[2])] = parts[0]
    except Exception:
        pass
    return uid_map

def get_process_start_time(pid: int) -> int:
    """Reads starttime (field 22) from /proc/<pid>/stat without spawning subshells."""
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            fields = f.read().split()
            # field 21 (0-indexed) is starttime in jiffies
            if len(fields) >= 22:
                return int(fields[21])
    except Exception:
        pass
    return int(time.time())

def get_process_io_bytes(pid: int) -> int:
    """Reads rchar + wchar from /proc/<pid>/io."""
    try:
        with open(f"/proc/{pid}/io", "r") as f:
            rchar = 0
            wchar = 0
            for line in f:
                if line.startswith("rchar:"):
                    rchar = int(line.split()[1])
                elif line.startswith("wchar:"):
                    wchar = int(line.split()[1])
            return rchar + wchar
    except Exception:
        return 0

def scan_active_ssh_sessions(uid_map: Dict[int, str]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Scans active SSH/VPN sessions using 'ss -tnp' with supplementary process validation.
    Accurately maps:
    username -> [
        {"pid": int, "remote_ip": str, "remote_port": str, "start_time": int},
        ...
    ]
    """
    user_sessions: Dict[str, List[Dict[str, Any]]] = {}
    seen_pids: Set[int] = set()

    # Query TCP established sockets on ports 22, 80, 8080, 443, 8880
    cmd = "ss -tnp '( sport = :22 or sport = :80 or sport = :8080 or sport = :443 or sport = :8880 )'"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception:
        res = None

    if res and res.stdout:
        lines = res.stdout.splitlines()
        for line in lines:
            if not ("ESTAB" in line and "sshd" in line):
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            peer_addr = parts[4]
            # Parse remote IP & port
            if ":" in peer_addr:
                remote_ip = peer_addr.rsplit(":", 1)[0].strip("[]")
                remote_port = peer_addr.rsplit(":", 1)[1]
            else:
                remote_ip = peer_addr
                remote_port = ""

            # Extract PID from users:(("sshd",pid=1234,fd=4))
            m = re.search(r"pid=(\d+)", line)
            if not m:
                continue
            pid = int(m.group(1))
            if pid in seen_pids:
                continue

            # Determine user associated with this SSH session PID
            username = None

            # Method A: Process UID from /proc/<pid>/status
            status_file = f"/proc/{pid}/status"
            if os.path.exists(status_file):
                try:
                    with open(status_file, "r") as sf:
                        for sline in sf:
                            if sline.startswith("Uid:"):
                                uids = sline.split()
                                if len(uids) >= 2 and uids[1].isdigit():
                                    r_uid = int(uids[1])
                                    if r_uid != 0 and r_uid in uid_map:
                                        username = uid_map[r_uid]
                                break
                except Exception:
                    pass

            # Method B: Process command line /proc/<pid>/cmdline (e.g. sshd: alice [priv] or sshd: alice@notty)
            if not username:
                cmdline_file = f"/proc/{pid}/cmdline"
                if os.path.exists(cmdline_file):
                    try:
                        with open(cmdline_file, "r", errors="ignore") as cf:
                            content = cf.read().replace("\x00", " ")
                            cm = re.search(r"sshd:\s+([a-zA-Z0-9_\-\.]+)", content)
                            if cm:
                                cand = cm.group(1).split("@")[0].strip().lower()
                                if cand not in ["root", "sshd", "privsep", "nobody", "listener", "accepted"]:
                                    username = cand
                    except Exception:
                        pass

            # Method C: Kernel loginuid (/proc/<pid>/loginuid)
            if not username:
                loginuid_file = f"/proc/{pid}/loginuid"
                if os.path.exists(loginuid_file):
                    try:
                        with open(loginuid_file, "r") as lf:
                            l_uid_str = lf.read().strip()
                            if l_uid_str.isdigit() and l_uid_str != "4294967295":
                                l_uid = int(l_uid_str)
                                if l_uid in uid_map:
                                    username = uid_map[l_uid]
                    except Exception:
                        pass

            if username and username not in ["root", "sshd", "nobody", "listener", "accepted"]:
                username = username.lower()
                seen_pids.add(pid)
                start_time = get_process_start_time(pid)
                sess_info = {
                    "pid": pid,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "start_time": start_time
                }
                if username not in user_sessions:
                    user_sessions[username] = []
                user_sessions[username].append(sess_info)

    # Method D: Fast process scan fallback for active OpenSSH user sessions
    try:
        ps_res = subprocess.run("ps -eo pid,user,args 2>/dev/null", shell=True, capture_output=True, text=True)
        if ps_res.stdout:
            for pline in ps_res.stdout.splitlines():
                if "sshd:" in pline:
                    pm = re.search(r"sshd:\s+([a-zA-Z0-9_\-\.]+)", pline)
                    if pm:
                        cand = pm.group(1).split("@")[0].strip().lower()
                        if cand not in ["root", "sshd", "privsep", "nobody", "listener", "accepted"]:
                            parts = pline.split()
                            if parts and parts[0].isdigit():
                                p_pid = int(parts[0])
                                if p_pid not in seen_pids:
                                    seen_pids.add(p_pid)
                                    if cand not in user_sessions:
                                        user_sessions[cand] = []
                                    # Add session if not priv process duplicate
                                    if "[priv]" not in pline or len(user_sessions[cand]) == 0:
                                        user_sessions[cand].append({
                                            "pid": p_pid,
                                            "remote_ip": "127.0.0.1",
                                            "remote_port": "",
                                            "start_time": get_process_start_time(p_pid)
                                        })
    except Exception:
        pass

    return user_sessions

def enforce_device_limits_and_bandwidth(user_sessions: Dict[str, List[Dict[str, Any]]], db_users: Dict[str, Dict[str, Any]]):
    """
    Evaluates each user:
    1. Simultaneous device limits (Default: 4):
       Gracefully disconnects only the newest unauthorized socket(s). Allowed sessions remain online!
    2. Bandwidth usage tracking & Quota locking.
    3. Expiry date evaluation & Account locking.
    """
    now_ts = int(time.time())

    for username, uinfo in db_users.items():
        clean_user = username.lower()
        sessions = user_sessions.get(clean_user, [])
        limit = int(uinfo.get("simultaneous_limit") or 4)
        bw_limit_gb = int(uinfo.get("bandwidth_gb") or 0)
        expiry_str = uinfo.get("expiry_date", "")
        status = uinfo.get("status", "Active")

        # -------------------------------------------------------------
        # 1. Expiry Check
        # -------------------------------------------------------------
        if expiry_str and expiry_str != "Never":
            try:
                exp_date = datetime.strptime(expiry_str, "%Y-%m-%d")
                if exp_date < datetime.now():
                    if status == "Active":
                        log(f"User '{clean_user}' expired on {expiry_str}. Locking account...", "WARN")
                        subprocess.run(f"usermod -L {clean_user} 2>/dev/null", shell=True)
                        subprocess.run(f"pkill -u {clean_user} -9 2>/dev/null", shell=True)
                        with get_db() as conn:
                            conn.execute("UPDATE users SET status = 'Expired' WHERE username = ?", (clean_user,))
                    continue
            except Exception:
                pass

        # -------------------------------------------------------------
        # 2. Bandwidth Tracking & Quota Check
        # -------------------------------------------------------------
        usage_file = os.path.join(BW_DIR, f"{clean_user}.usage")
        accumulated_bytes = 0
        if os.path.exists(usage_file):
            try:
                with open(usage_file, "r") as bf:
                    accumulated_bytes = int(bf.read().strip() or "0")
            except Exception:
                pass

        # If file is empty or missing, fallback to DB used_bytes (e.g. after database restore)
        if accumulated_bytes == 0 and uinfo.get("used_bytes"):
            accumulated_bytes = int(uinfo.get("used_bytes") or 0)
            if accumulated_bytes > 0:
                try:
                    with open(usage_file, "w") as bf:
                        bf.write(str(accumulated_bytes))
                except Exception:
                    pass

        # Calculate I/O delta for active session PIDs
        delta_bytes = 0
        for sess in sessions:
            pid = sess["pid"]
            cur_io = get_process_io_bytes(pid)
            track_file = os.path.join(PID_TRACK_DIR, f"{clean_user}__{pid}.io")
            prev_io = 0
            if os.path.exists(track_file):
                try:
                    with open(track_file, "r") as tf:
                        prev_io = int(tf.read().strip() or "0")
                except Exception:
                    pass

            if cur_io >= prev_io:
                delta_bytes += (cur_io - prev_io)
            else:
                delta_bytes += cur_io

            try:
                with open(track_file, "w") as tf:
                    tf.write(str(cur_io))
            except Exception:
                pass

        new_total_bytes = accumulated_bytes + delta_bytes
        if delta_bytes > 0:
            try:
                with open(usage_file, "w") as bf:
                    bf.write(str(new_total_bytes))
            except Exception:
                pass
            try:
                with get_db() as conn:
                    conn.execute("UPDATE users SET used_bytes = ? WHERE username = ?", (new_total_bytes, clean_user))
                    conn.commit()
            except Exception:
                pass

        # Clean dead tracking files
        for f in glob.glob(os.path.join(PID_TRACK_DIR, f"{clean_user}__*.io")):
            m = re.search(r"__(\d+)\.io$", f)
            if m:
                p = int(m.group(1))
                if not os.path.exists(f"/proc/{p}"):
                    try:
                        os.remove(f)
                    except Exception:
                        pass

        # Quota enforcement
        if bw_limit_gb > 0:
            quota_bytes = bw_limit_gb * (1024**3)
            if new_total_bytes >= quota_bytes:
                if status == "Active":
                    log(f"User '{clean_user}' exceeded data quota ({bw_limit_gb} GB). Locking account...", "WARN")
                    subprocess.run(f"usermod -L {clean_user} 2>/dev/null", shell=True)
                    subprocess.run(f"pkill -u {clean_user} -9 2>/dev/null", shell=True)
                    with get_db() as conn:
                        conn.execute("UPDATE users SET status = 'Quota Exceeded' WHERE username = ?", (clean_user,))
                continue

        # -------------------------------------------------------------
        # 3. Simultaneous Device Limit Enforcement (Smart Disconnect)
        # -------------------------------------------------------------
        if sessions:
            unique_ips = set(s["remote_ip"] for s in sessions if s.get("remote_ip") not in ["", "127.0.0.1"])
            device_count = len(sessions) if not unique_ips else max(len(unique_ips), len(sessions))

            if device_count > limit:
                # Sort sessions by start_time ascending (oldest first)
                sorted_sessions = sorted(sessions, key=lambda s: s["start_time"])
                excess_sessions = sorted_sessions[limit:]

                for s in excess_sessions:
                    extra_pid = s["pid"]
                    log(f"User '{clean_user}' device limit exceeded ({device_count}/{limit}). "
                        f"Gracefully terminating unauthorized session PID {extra_pid} (IP: {s.get('remote_ip', '127.0.0.1')}). Allowed sessions remain online.", "WARN")
                    try:
                        os.kill(extra_pid, signal.SIGTERM)
                        time.sleep(0.3)
                        if os.path.exists(f"/proc/{extra_pid}"):
                            os.kill(extra_pid, signal.SIGKILL)
                    except Exception as e:
                        log(f"Failed to kill extra PID {extra_pid}: {e}", "ERROR")

def write_active_telemetry(user_sessions: Dict[str, List[Dict[str, Any]]]):
    """
    Atomically writes live online user state to /run/panelx/active_users.json.
    panelx_server reads this file with 0ms latency.
    """
    telemetry: Dict[str, Any] = {}
    for username, sessions in user_sessions.items():
        unique_ips = list(set(s["remote_ip"] for s in sessions if s.get("remote_ip") not in ["", "127.0.0.1"]))
        active_conns = len(sessions) if not unique_ips else max(len(unique_ips), len(sessions))
        telemetry[username] = {
            "active_connections": active_conns,
            "total_sockets": len(sessions),
            "ips": unique_ips or ["127.0.0.1"],
            "last_seen": int(time.time())
        }

    tmp_file = f"{ACTIVE_USERS_FILE}.tmp"
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(telemetry, f)
        os.replace(tmp_file, ACTIVE_USERS_FILE)
    except Exception as e:
        log(f"Error saving active telemetry: {e}", "ERROR")

# ---------------------------------------------------------------------------
# Daemon Main Loop
# ---------------------------------------------------------------------------
def main():
    log("=" * 65)
    log("PANELX SYSTEM GUARDIAN v2.0 DAEMON STARTED")
    log("Storage Guard, Log Truncation & Device Limiter Online")
    log("=" * 65)

    last_storage_check = 0.0
    last_fail2ban_check = 0.0
    last_db_cache_time = 0.0
    db_users_cache: Dict[str, Dict[str, Any]] = {}

    # Run immediate storage and log health check on startup
    run_storage_protection(is_emergency=False)

    while True:
        try:
            now = time.time()

            # 1. 6-Hour Scheduled Storage Protection
            if (now - last_storage_check) >= STORAGE_CHECK_INTERVAL:
                run_storage_protection(is_emergency=False)
                last_storage_check = now

            # 2. Check for Emergency Disk Leak (if disk usage > 85%)
            try:
                tot, usd, _ = shutil.disk_usage("/")
                if (usd / tot) > 0.85 and (now - last_storage_check) > 300:
                    log("Disk usage exceeds 85%! Running immediate emergency storage protection...", "WARN")
                    run_storage_protection(is_emergency=True)
                    last_storage_check = now
            except Exception:
                pass

            # 3. Fail2ban SSH Bot Defense Watchdog (Every 5 mins)
            if (now - last_fail2ban_check) >= FAIL2BAN_CHECK_INTERVAL:
                check_fail2ban_guard()
                last_fail2ban_check = now

            # 4. Refresh DB Users in Memory (Every 30 seconds)
            if (now - last_db_cache_time) >= 30.0 or not db_users_cache:
                try:
                    with get_db() as conn:
                        rows = conn.execute("SELECT username, simultaneous_limit, bandwidth_gb, expiry_date, status, COALESCE(used_bytes, 0) as used_bytes FROM users").fetchall()
                        db_users_cache = {r["username"].lower(): dict(r) for r in rows}
                    last_db_cache_time = now
                except Exception as e:
                    log(f"Error refreshing database users cache: {e}", "ERROR")

            # 5. Live Connection Monitoring & Smart Device Limiting
            uid_map = get_linux_users_map()
            active_sessions = scan_active_ssh_sessions(uid_map)

            # Enforce limits & quotas
            if db_users_cache:
                enforce_device_limits_and_bandwidth(active_sessions, db_users_cache)

            # Write telemetry for FastAPI dashboard
            write_active_telemetry(active_sessions)

        except Exception as e:
            log(f"Unhandled exception in guardian loop: {e}", "ERROR")

        time.sleep(FAST_LOOP_INTERVAL)

if __name__ == "__main__":
    main()
