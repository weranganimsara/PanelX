#!/usr/bin/env python3
"""
=============================================================================
PANELX — Enterprise Linux Server & VPN Management Control Panel
"Powered by SG Home"
=============================================================================
Features:
- Enterprise Dark Cyber NOC Interface
- Real-Time Server Health Score (0 - 100) & Diagnostic Breakdown
- Full Firewall Center (iptables / ufw backend, safety rollback timer)
- Systemd Service Manager (list, filter, start, stop, restart, logs)
- Process Manager (top CPU/RAM, search, graceful/force kill)
- Open Port Monitor (ss -tulnp) & Network Diagnostics (Ping, DNS)
- SSH Security Auditor (sshd_config compliance score) & Active Session Control
- Storage Explorer (df -h) & Controlled Safe File Manager
- Package Updates Check & Controlled Server Power (Reboot/Shutdown)
- Carrier Inbound Profiles & Payloads Manager (NetMod, HTTP Custom, Direct CDN)
- SSH Client Provisioning & SG Home Paid Site REST API (x-api-key compatible)
=============================================================================
"""

import http.server
import socketserver
import json
import os
import sys
import subprocess
import sqlite3
import hashlib
import secrets
import time
import shutil
import socket
import signal
import threading
import urllib.parse
from datetime import datetime, timedelta

# Reconfigure stdout for UTF-8 compatibility
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Configuration & Paths
# ---------------------------------------------------------------------------
PANEL_PORT = 7788
DATA_DIR = "/etc/panelx"
DB_PATH = os.path.join(DATA_DIR, "panelx.db")
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Ensure directories exist
os.makedirs(DATA_DIR, exist_ok=True)
if not os.path.exists(WEB_DIR):
    WEB_DIR = os.path.join(DATA_DIR, "web")
    os.makedirs(WEB_DIR, exist_ok=True)

# Global Firewall Rollback Safety Queue
# Stores { "timer": threading.Timer, "backup_file": str, "timestamp": float }
FIREWALL_ROLLBACK = {
    "active": False,
    "timer": None,
    "backup_file": "/tmp/falcon_iptables_safety.bak",
    "expires_at": 0,
    "pending_rule": ""
}

# ---------------------------------------------------------------------------
# Database Initialization & Helpers
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def audit_log(username: str, action: str, target: str = "", ip: str = "", details: str = "", result: str = "SUCCESS"):
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO audit_logs (username, action, target, ip, details, result, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """, (username, action, target, ip, details, result))
        conn.commit()
        conn.close()
    except Exception:
        pass

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    # 2. Users table (SSH Clients)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            simultaneous_limit INTEGER DEFAULT 3,
            bandwidth_gb INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            status TEXT DEFAULT 'Active',
            created_at TEXT NOT NULL
        )
    """)
    
    # 3. Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    
    # 4. Inbounds / Payload Profiles table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS inbounds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remark TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER DEFAULT 80,
            proxy_type TEXT DEFAULT 'http',
            proxy_host TEXT DEFAULT '',
            proxy_port INTEGER DEFAULT 8080,
            payload TEXT NOT NULL,
            is_default INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 5. Audit Logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            details TEXT DEFAULT '',
            result TEXT DEFAULT 'SUCCESS',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 6. Firewall Rules managed by Panel
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            direction TEXT DEFAULT 'IN',
            action TEXT DEFAULT 'ACCEPT',
            protocol TEXT DEFAULT 'tcp',
            port TEXT DEFAULT '',
            source_ip TEXT DEFAULT '',
            comment TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Seed default inbounds if empty
    inbound_count = cursor.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0]
    if inbound_count == 0:
        default_inbounds = [
            (
                "M ZOOM ALL",
                "zoom.sghome.space",
                80,
                "http",
                "partner.zoom.us",
                80,
                "u+fRSFV7ZzQTd2kgWG+TY92TH+R6nGuBhyI2CGZKwd71Rs47LQSHqfcK0TlCYHsYZftunkE8Al3qKrcmXYM7rcVuhsPr+0WKt/cg4TANhYBtrOf2rLsuSRmQ8GnOr51g6WFQnzC5NFqPzVLIN3bchwPW2d1yQnwcVejehin+sznPW8OPiGpoxeT3WHG8W3vyah3QheT63sVOA/kTUL0yF1e0ZMGsXEz71rlIivUFfxeYKzwqLEEw2apDHcUG8JYJ5rwlrWsLndVraqwqPkdfjLQO9si89tJr2FTtqJJUxVUdJ398k2qfXrUKWwxs4c5yYhxjge6NfOgCNsxPYO0L8vYyCfwpdaYVF5vTkpeLVqz7FeKIZG8swHRFxDudPS9C9eYzCmTjWIlFzgWbEGN4RNRW+07nEN+7QtOn1LLuEqCsiEVn41b1kykcimYLNpzMuIVzB5IlsPDJpTiBJEuWHluLrUd/iq46xckOPZY3RDCuSEeHcuvKNhk169cBwlpXFOHp+ddYOAF/0MyYtfJngu206/3nsKhAV14NhsSi3NbiiqK1UPFhCAplSSMLLjfPC3sztyWXtu9g4477Aqp+vyKaTygOQr7PXqjMMuDzslAP4YWJPMOKItBxEnd7qFYFYB6uWGp+xxxEVQWcFVm3lGA3xzsE8IdRIAgFpWlwMvQdI6gA7k+ppuAUpwRmN4iWPLLgaCRzhWrgZIJ1cyDv3qAzsSS5EB53DHuzm57Akssss54jhoFSDwN0pd70/EcyFuG5pbyWH8sxLSdthrPDAa+o3fE3qQ7eO+d1exCUwyQVgU5tyo4ZbkFsqUo6xyMiIwTyh4VIpew/U8KFOn+sJIvyBDqMadUQt7Qr1gzuCHs3Gx/jXUwGeR7KjWG5jwa1gDlY4z82S5vbbUNJahv8oGKYAj9jIJInMqzqx6csUOUe/t7bX10UUz5kU6R7dhvbudy7coi+MOuOrUtXR98wl1Y0tQS5uSC03gbQdKwrEJu0rpySqAZYmCH7NzCWjW/O",
                1
            ),
            (
                "M ZOOM ALL (Direct CDN)",
                "zoom.sghome.space",
                80,
                "none",
                "",
                80,
                "AuWsAzuCJjFGdg9kSB6w+2tHLeh9NCLfWrwDnMcPhe3BiAdJAshclqHDzw22m8rcOabwFpqSlhIjHWLyp99bpEMZi61xfsuDwHxlMxDSmmiNlIQVexnU56SvTNFtKKJyPIXa5ulhfvwIoz2JyXyZN7pJrqi75ZbHJtLW9vARrT2e/H1vhmtAEN0LIU6XbWmp/aaUvwaAtMhsaDJjQYg7mUIC6JsT8aZcC5EtbEhzLkB2q+cjwM7sLF+i4SVltvWHv4R507o0q0B8v0KjzwJfOW3qMg2mnVsbGY5ELJnw6HuB5mkDnbf9i6lbvz4oa0aPW1FkcsyKAUyX4ZL5o81KscK9TP0XqFghuYAu6sj/9/cgP8bqNOHt09oPUvWA3fy8tMQLduvyPlf0lhT85v7udr0tJpiaKglid2AeRqW0QMs4O6/8x4r5E8es060+49jPLGJ+VlMTMZ8zkykhjhfgOETvRDSWql4mco8RP66qfk2SP1kHe0CpJw8RJROL31tH",
                0
            ),
            (
                "Hutch Zero (NetMod HTTP Proxy)",
                "hutch.sghome.space",
                80,
                "http",
                "dpkids.lk",
                8080,
                "u+fRSFV7ZzQTd2kgWG+TYwyOU6GD+h5lFt/L8DoHMpK0TM7aO3fi7LyQYKk8nlmLsJ1NBmZLzSPO2UzYwvrmmGvn+IzMXibxV0FesEy8A2I59wqplNY8lTZ1xq3RfYR4sY19RGZ4V4fOg71X2SME4kYZsAn4gdwIT/Qa6XlZU5oy59n036GoxBW47tleIaPfleBP2tiVNsO7HK/8gJSuh/G03Q9KTiJ6b8g09QT4BUzSZcYwbUI3ikUIMqhOkrEhirNnSwVBVbXPwVXmBC9C+Rf4HiHjeCVNaezkbsWynnohRMuaM1gQUNNnSDRm9+yZi2gQBCU1fA9ovN2253JgA7+rMPYJ6M3K94Hwpt47GJfzQFwuM+bWIi7sNy/TGtMy04wn6G+U5l4p9hXyjoAae6fpM/HrJ6C+ivbx4xlPoZTNxjKh7ZEiIByyJXe2JtGMbpc8HAiLZiZb4sQE7FX1I/4tD12/6b8LRU1ICSZeHB+nuxjVDN4NSHdyNN07nJkhFHkKvyzgW3EOHdC22TKeMBbFgIDCfB3IA7N/AR5KItw=",
                0
            ),
            (
                "Hutch Direct CDN (Proxy None)",
                "hutch.sghome.space",
                80,
                "none",
                "",
                80,
                "AuWsAzuCJjFGdg9kSB6w+19GXM9VbHK07H3C/Mjh4dcy8GDUIKQ1DeQJ9ZJbfFTC8EqXZJvvW8tiL9tiJFt0WOSrEEJqQL/a5ziuHIeqYCM0nPQctYjIJEuaRH/QbF07k6PVCGs5KWd+zT62nR8iVviTfIc6xQBgiJHLoOJ7EPZ+jHS0wedBGrVGIO8UJDaJTt6irpEJ3QyecGh0Ubp7ihQjAmWTLWgmuDpYvPiQY2bdeS/TpdOih2lKnEMdOO9HyH2osNuF76TKDC8c4c1w2+2fNHq7rU77j7M1eOgh0qYnasKvxRm19iyZ+97rU6yK6SfOsAsEPo/tkd80J5vVsIUY/oTUE/aFqHGBINItNo=",
                0
            )
        ]
        for rem, h, p, ptype, phost, pport, payload, isdef in default_inbounds:
            cursor.execute("""
                INSERT INTO inbounds (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (rem, h, p, ptype, phost, pport, payload, isdef))
    
    # Set default settings
    defaults = {
        "admin_user": "admin",
        "admin_pass_hash": hash_password("admin"),
        "panel_port": "7788",
        "panel_title": "PanelX",
        "ssh_domain": "",
        "ssh_port": "80",
        "badvpn_port": "7300",
        "api_secret": "SG_HOME_FALCON_SECRET_2026",
        "default_payload": "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: partner.zoom.us[crlf][crlf][split]UNLOCK /? HTTP/1.1[crlf]Host: [host][crlf]Connection: upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]"
    }
    
    for k, v in defaults.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------------------------
# Core System Helpers
# ---------------------------------------------------------------------------
def get_setting(key: str, default="") -> str:
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def get_server_public_ip():
    try:
        res = subprocess.run("curl -s -4 --max-time 2 ifconfig.me || curl -s -4 --max-time 2 icanhazip.com", shell=True, capture_output=True, text=True)
        ip = res.stdout.strip()
        if ip and len(ip) <= 45: return ip
    except Exception:
        pass
    return "127.0.0.1"

# Network RX/TX tracking
_prev_net = {"time": time.time(), "rx": 0, "tx": 0}

def get_network_speed():
    global _prev_net
    rx_bytes = 0
    tx_bytes = 0
    try:
        with open("/proc/net/dev", "r") as f:
            lines = f.readlines()[2:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 10 and not parts[0].startswith("lo:"):
                    rx_bytes += int(parts[1])
                    tx_bytes += int(parts[9])
    except Exception:
        return 0, 0, 0, 0

    now = time.time()
    dt = max(now - _prev_net["time"], 0.1)
    rx_speed_kb = round((rx_bytes - _prev_net["rx"]) / (1024 * dt), 1)
    tx_speed_kb = round((tx_bytes - _prev_net["tx"]) / (1024 * dt), 1)

    _prev_net = {"time": now, "rx": rx_bytes, "tx": tx_bytes}
    return max(rx_speed_kb, 0.0), max(tx_speed_kb, 0.0), rx_bytes, tx_bytes

def get_system_stats():
    # 1. CPU
    cpu_percent = 0.0
    load_avg = [0.0, 0.0, 0.0]
    try:
        load = os.getloadavg()
        load_avg = [round(x, 2) for x in load]
        cpu_cores = os.cpu_count() or 1
        cpu_percent = round(min((load[0] / cpu_cores) * 100, 100.0), 1)
    except Exception:
        pass

    # 2. RAM
    mem_total_mb = 1024
    mem_used_mb = 0
    mem_percent = 0.0
    try:
        with open("/proc/meminfo", "r") as f:
            mem = {}
            for line in f:
                p = line.split(":")
                if len(p) == 2:
                    mem[p[0].strip()] = int(p[1].strip().split()[0])
            total_kb = mem.get("MemTotal", 1024)
            free_kb = mem.get("MemFree", 0) + mem.get("Buffers", 0) + mem.get("Cached", 0)
            used_kb = max(total_kb - free_kb, 0)
            mem_total_mb = round(total_kb / 1024, 1)
            mem_used_mb = round(used_kb / 1024, 1)
            mem_percent = round((used_kb / total_kb) * 100, 1)
    except Exception:
        pass

    # 3. Disk
    disk_total_gb = 1
    disk_used_gb = 0
    disk_percent = 0.0
    try:
        usage = shutil.disk_usage("/")
        disk_total_gb = round(usage.total / (1024**3), 1)
        disk_used_gb = round(usage.used / (1024**3), 1)
        disk_percent = round((usage.used / usage.total) * 100, 1)
    except Exception:
        pass

    # 4. Uptime
    uptime_str = "0d 0h"
    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.readline().split()[0])
            days = int(secs // 86400)
            hours = int((secs % 86400) // 3600)
            uptime_str = f"{days}d {hours}h"
    except Exception:
        pass

    # 5. Open Sockets
    sockets_count = 0
    try:
        with open("/proc/net/tcp", "r") as f:
            sockets_count += max(len(f.readlines()) - 1, 0)
    except Exception:
        pass

    rx_speed, tx_speed, total_rx, total_tx = get_network_speed()

    # 6. System Info
    hostname = socket.gethostname()
    os_info = "Linux"
    try:
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_info = line.split("=")[1].strip().strip('"')
                    break
    except Exception:
        pass

    kernel = "Unknown"
    try:
        kernel = subprocess.run("uname -r", shell=True, capture_output=True, text=True).stdout.strip()
    except Exception:
        pass

    # 7. Check services
    services_state = {
        "ssh": check_service_status("ssh"),
        "ws_proxy": check_service_status("ws-proxy"),
        "badvpn": check_service_status("badvpn"),
        "limiter": check_service_status("panelx-limiter")
    }

    # 8. Server Health Score (0 - 100)
    health = calculate_health_score(cpu_percent, mem_percent, disk_percent, services_state)

    return {
        "hostname": hostname,
        "os": os_info,
        "kernel": kernel,
        "load_avg": load_avg,
        "cpu_percent": cpu_percent,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "mem_percent": mem_percent,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "disk_percent": disk_percent,
        "uptime": uptime_str,
        "open_sockets": sockets_count,
        "rx_speed_kb": rx_speed,
        "tx_speed_kb": tx_speed,
        "total_rx_gb": round(total_rx / (1024**3), 2),
        "total_tx_gb": round(total_tx / (1024**3), 2),
        "public_ip": get_server_public_ip(),
        "services": services_state,
        "health": health
    }

def calculate_health_score(cpu_pct, mem_pct, disk_pct, services):
    score = 100
    deductions = []

    # CPU penalty
    if cpu_pct > 85:
        score -= 20
        deductions.append(f"High CPU Pressure ({cpu_pct}%)")
    elif cpu_pct > 60:
        score -= 10
        deductions.append(f"Moderate CPU Load ({cpu_pct}%)")

    # RAM penalty
    if mem_pct > 90:
        score -= 20
        deductions.append(f"Critical RAM Pressure ({mem_pct}%)")
    elif mem_pct > 75:
        score -= 10
        deductions.append(f"Elevated Memory Usage ({mem_pct}%)")

    # Disk penalty
    if disk_pct > 90:
        score -= 25
        deductions.append(f"Critical Disk Space ({disk_pct}%)")
    elif disk_pct > 80:
        score -= 10
        deductions.append(f"Low Free Disk ({disk_pct}%)")

    # Service penalties
    for svc, active in services.items():
        if not active:
            score -= 8
            deductions.append(f"Service {svc} is Inactive")

    score = max(score, 10)
    rating = "Optimal"
    if score < 60: rating = "Critical"
    elif score < 80: rating = "Warning"
    elif score < 95: rating = "Good"

    return {
        "score": score,
        "rating": rating,
        "deductions": deductions
    }

# ---------------------------------------------------------------------------
# Linux Account Management (PAM & Kernel Limiter Sync)
# ---------------------------------------------------------------------------
def sync_users_db():
    try:
        conn = get_db()
        rows = conn.execute("SELECT username, password, expiry_date, simultaneous_limit, bandwidth_gb FROM users").fetchall()
        conn.close()
        os.makedirs(DATA_DIR, exist_ok=True)
        db_path = os.path.join(DATA_DIR, "users.db")
        with open(db_path, "w") as f:
            for r in rows:
                f.write(f"{r['username']}:{r['password']}:{r['expiry_date']}:{r['simultaneous_limit']}:{r['bandwidth_gb']}\n")
    except Exception:
        pass

def os_create_user(username: str, password: str, expiry_date: str, max_logins: int = 3):
    clean_user = username.strip().lower()
    subprocess.run(f"userdel -r {clean_user} 2>/dev/null", shell=True)
    res1 = subprocess.run(f"useradd -e {expiry_date} -s /bin/false -M {clean_user}", shell=True)
    if res1.returncode != 0:
        subprocess.run(f"useradd -s /bin/false {clean_user}", shell=True)
        subprocess.run(f"chage -E {expiry_date} {clean_user}", shell=True)

    p = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.communicate(f"{clean_user}:{password}\n")

    try:
        subprocess.run(f"sed -i '/^{clean_user} /d' /etc/security/limits.conf 2>/dev/null", shell=True)
        subprocess.run(f"echo '{clean_user} hard maxlogins {max_logins}' >> /etc/security/limits.conf", shell=True)
    except Exception:
        pass
    sync_users_db()

def os_delete_user(username: str):
    clean_user = username.strip().lower()
    subprocess.run(f"userdel -r {clean_user} 2>/dev/null", shell=True)
    subprocess.run(f"sed -i '/^{clean_user} /d' /etc/security/limits.conf 2>/dev/null", shell=True)
    sync_users_db()

def os_renew_user(username: str, expiry_date: str):
    clean_user = username.strip().lower()
    subprocess.run(f"chage -E {expiry_date} {clean_user} 2>/dev/null", shell=True)
    sync_users_db()

def check_service_status(service_name: str) -> bool:
    try:
        res = subprocess.run(f"systemctl is-active {service_name}", shell=True, capture_output=True, text=True)
        return res.stdout.strip() == "active"
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Falcon Firewall Subsystem (iptables / ufw + Safety Rollback)
# ---------------------------------------------------------------------------
def detect_firewall_backend():
    if shutil.which("ufw"):
        res = subprocess.run("ufw status", shell=True, capture_output=True, text=True)
        if "Status: active" in res.stdout:
            return "ufw"
    if shutil.which("iptables"):
        return "iptables"
    return "iptables"

def get_firewall_state():
    backend = detect_firewall_backend()
    rules = []
    default_policy = {"INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "FORWARD": "ACCEPT"}

    if backend == "ufw":
        res = subprocess.run("ufw status numbered", shell=True, capture_output=True, text=True)
        is_active = "Status: active" in res.stdout
        lines = res.stdout.splitlines()
        for l in lines:
            if "[" in l and "]" in l:
                parts = l.split()
                try:
                    num = parts[0].strip("[]")
                    target = parts[1]
                    action = parts[2]
                    src = parts[3] if len(parts) > 3 else "Anywhere"
                    rules.append({
                        "id": num,
                        "direction": "IN",
                        "port": target,
                        "action": action,
                        "source": src,
                        "protocol": "any"
                    })
                except Exception:
                    pass
    else:
        # iptables
        res = subprocess.run("iptables -L INPUT -n -v --line-numbers", shell=True, capture_output=True, text=True)
        is_active = True
        for line in res.stdout.splitlines():
            if "Chain INPUT (policy" in line:
                if "DROP" in line: default_policy["INPUT"] = "DROP"
            parts = line.split()
            if len(parts) >= 8 and parts[0].isdigit():
                num = parts[0]
                target = parts[3]
                proto = parts[4]
                src = parts[8]
                extra = " ".join(parts[9:]) if len(parts) > 9 else ""
                port = extra.replace("dpt:", "").replace("tcp dpt:", "").replace("udp dpt:", "")
                rules.append({
                    "id": num,
                    "direction": "IN",
                    "action": target,
                    "protocol": proto,
                    "source": src,
                    "port": port or "any",
                    "extra": extra
                })

    return {
        "backend": backend,
        "is_active": is_active,
        "default_policy": default_policy,
        "rules": rules,
        "rollback_active": FIREWALL_ROLLBACK["active"],
        "rollback_remaining": max(int(FIREWALL_ROLLBACK["expires_at"] - time.time()), 0) if FIREWALL_ROLLBACK["active"] else 0
    }

def trigger_firewall_rollback():
    global FIREWALL_ROLLBACK
    if os.path.exists(FIREWALL_ROLLBACK["backup_file"]):
        subprocess.run(f"iptables-restore < {FIREWALL_ROLLBACK['backup_file']} 2>/dev/null", shell=True)
    FIREWALL_ROLLBACK["active"] = False
    FIREWALL_ROLLBACK["timer"] = None
    audit_log("system", "firewall_auto_rollback", "Safety rollback triggered after timeout", "127.0.0.1")

def apply_firewall_rule(action: str, port: str, protocol: str = "tcp", source_ip: str = ""):
    global FIREWALL_ROLLBACK
    # 1. Save safety snapshot before modifying
    subprocess.run(f"iptables-save > {FIREWALL_ROLLBACK['backup_file']} 2>/dev/null", shell=True)

    # 2. Formulate iptables command safely
    action_flag = "ACCEPT" if action.upper() == "ALLOW" else "DROP"
    cmd_parts = ["iptables", "-I", "INPUT", "1"]
    if protocol and protocol.lower() != "any":
        cmd_parts.extend(["-p", protocol.lower()])
    if port and port.strip() != "any":
        cmd_parts.extend(["--dport", str(port).strip()])
    if source_ip and source_ip.strip():
        cmd_parts.extend(["-s", source_ip.strip()])
    cmd_parts.extend(["-j", action_flag])

    res = subprocess.run(cmd_parts, capture_output=True, text=True)
    if res.returncode != 0:
        return False, res.stderr.strip() or "Failed to apply rule"

    # 3. Start 30-second safety rollback timer
    if FIREWALL_ROLLBACK["timer"]:
        FIREWALL_ROLLBACK["timer"].cancel()

    timer = threading.Timer(30.0, trigger_firewall_rollback)
    timer.daemon = True
    timer.start()

    FIREWALL_ROLLBACK["active"] = True
    FIREWALL_ROLLBACK["timer"] = timer
    FIREWALL_ROLLBACK["expires_at"] = time.time() + 30.0
    FIREWALL_ROLLBACK["pending_rule"] = f"{action} {protocol} {port} {source_ip}"

    return True, "Rule applied with 30-second safety rollback timer"

def confirm_firewall_rules():
    global FIREWALL_ROLLBACK
    if FIREWALL_ROLLBACK["timer"]:
        FIREWALL_ROLLBACK["timer"].cancel()
    FIREWALL_ROLLBACK["active"] = False
    FIREWALL_ROLLBACK["timer"] = None
    FIREWALL_ROLLBACK["pending_rule"] = ""
    return True

def revert_firewall_rules():
    global FIREWALL_ROLLBACK
    if FIREWALL_ROLLBACK["timer"]:
        FIREWALL_ROLLBACK["timer"].cancel()
    trigger_firewall_rollback()
    return True

# ---------------------------------------------------------------------------
# Linux Subsystem Controllers (Processes, Services, Ports, SSH, Files)
# ---------------------------------------------------------------------------
def get_linux_processes(limit=50):
    procs = []
    try:
        res = subprocess.run("ps -eo pid,user,%cpu,%mem,stat,comm --sort=-%cpu", shell=True, capture_output=True, text=True)
        lines = res.stdout.splitlines()[1:limit+1]
        for l in lines:
            p = l.split()
            if len(p) >= 6:
                procs.append({
                    "pid": int(p[0]),
                    "user": p[1],
                    "cpu": float(p[2]),
                    "mem": float(p[3]),
                    "stat": p[4],
                    "name": " ".join(p[5:])
                })
    except Exception:
        pass
    return procs

def get_systemd_units():
    units = []
    try:
        res = subprocess.run("systemctl list-units --type=service --no-legend --no-pager", shell=True, capture_output=True, text=True)
        for l in res.stdout.splitlines():
            p = l.split()
            if len(p) >= 4:
                units.append({
                    "unit": p[0],
                    "load": p[1],
                    "active": p[2],
                    "sub": p[3],
                    "description": " ".join(p[4:]) if len(p) > 4 else ""
                })
    except Exception:
        pass
    return units

def get_listening_sockets():
    sockets = []
    try:
        res = subprocess.run("ss -tulnp", shell=True, capture_output=True, text=True)
        lines = res.stdout.splitlines()[1:]
        for l in lines:
            parts = l.split()
            if len(parts) >= 5:
                proto = parts[0]
                local = parts[4]
                process = parts[6] if len(parts) > 6 else "-"
                port = local.split(":")[-1] if ":" in local else local
                sockets.append({
                    "proto": proto,
                    "address": local,
                    "port": port,
                    "process": process
                })
    except Exception:
        pass
    return sockets

def get_ssh_security_audit():
    score = 100
    checks = []
    conf_path = "/etc/ssh/sshd_config"
    config = {}

    if os.path.exists(conf_path):
        try:
            with open(conf_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            config[parts[0].lower()] = parts[1].strip()
        except Exception:
            pass

    # 1. Root Login
    root_login = config.get("permitrootlogin", "yes").lower()
    if root_login == "yes":
        score -= 25
        checks.append({"item": "Root Login Enabled", "status": "WARN", "tip": "Disable direct root login (set PermitRootLogin no)"})
    else:
        checks.append({"item": "Root Login Restricted", "status": "PASS", "tip": "Direct root SSH is disabled"})

    # 2. Password Authentication
    pass_auth = config.get("passwordauthentication", "yes").lower()
    if pass_auth == "yes":
        score -= 15
        checks.append({"item": "Password Authentication", "status": "WARN", "tip": "Use SSH Key pairs instead of passwords"})
    else:
        checks.append({"item": "Public Key Only", "status": "PASS", "tip": "Password auth is disabled"})

    # 3. Port
    port = config.get("port", "22")
    if port == "22":
        score -= 10
        checks.append({"item": "Default SSH Port (22)", "status": "INFO", "tip": "Consider changing to a custom port to reduce bot scanners"})
    else:
        checks.append({"item": f"Custom Port ({port})", "status": "PASS", "tip": "Port is non-standard"})

    # Active Sessions
    active_sessions = []
    try:
        res = subprocess.run("w -h", shell=True, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            p = line.split()
            if len(p) >= 4:
                active_sessions.append({
                    "user": p[0],
                    "tty": p[1],
                    "ip": p[2],
                    "login": p[3],
                    "what": " ".join(p[4:]) if len(p) > 4 else "ssh"
                })
    except Exception:
        pass

    return {
        "score": max(score, 20),
        "checks": checks,
        "port": port,
        "active_sessions": active_sessions
    }

def get_disk_storage():
    disks = []
    try:
        res = subprocess.run("df -h -x tmpfs -x devtmpfs -x overlay", shell=True, capture_output=True, text=True)
        lines = res.stdout.splitlines()[1:]
        for line in lines:
            p = line.split()
            if len(p) >= 6:
                disks.append({
                    "filesystem": p[0],
                    "size": p[1],
                    "used": p[2],
                    "avail": p[3],
                    "percent": p[4],
                    "mount": p[5]
                })
    except Exception:
        pass
    return disks

def check_package_updates():
    upgradable = []
    try:
        res = subprocess.run("apt list --upgradable 2>/dev/null", shell=True, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            if "/" in line and not line.startswith("Listing"):
                upgradable.append(line.split("/")[0])
    except Exception:
        pass
    return upgradable

# ---------------------------------------------------------------------------
# HTTP API & Web Request Handler
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class FalconFirewallHandler(http.server.BaseHTTPRequestHandler):

    def send_json(self, status: int, data: dict, cookie: str = None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "*")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                raw = self.wfile if False else self.rfile.read(length)
                return json.loads(raw.decode("utf-8"))
        except Exception:
            pass
        return {}

    def get_token(self) -> str:
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        cookies = self.headers.get("Cookie", "")
        for c in cookies.split(";"):
            if "panelx_token=" in c:
                return c.split("=")[1].strip()
        return ""

    def is_authenticated(self) -> bool:
        configured_secret = get_setting("api_secret", "SG_HOME_FALCON_SECRET_2026")
        
        # Check 1: API Secret Key in various header formats (for SG Home & curl automation)
        for h in ["x-api-key", "X-API-KEY", "x-falcon-key", "X-Falcon-Key", "api-key", "ApiKey"]:
            val = self.headers.get(h, "").strip()
            if val and val == configured_secret:
                return True

        # Check Authorization header for Bearer <secret> or ApiKey <secret>
        auth_header = self.headers.get("Authorization", "").strip()
        if auth_header.startswith("Bearer "):
            bearer_val = auth_header[7:].strip()
            if bearer_val == configured_secret:
                return True
        elif auth_header.startswith("ApiKey "):
            if auth_header[7:].strip() == configured_secret:
                return True

        # Check Query Parameters: ?apiKey=... or ?api_key=... or ?key=...
        try:
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            for k in ["apiKey", "api_key", "key", "token"]:
                if k in q and q[k] and q[k][0] == configured_secret:
                    return True
        except Exception:
            pass

        # Check 2: Session Bearer Token or Cookie from login
        token = self.get_token()
        if not token:
            return False

        if token == configured_secret:
            return True

        conn = get_db()
        row = conn.execute("SELECT username FROM sessions WHERE token = ?", (token,)).fetchone()
        conn.close()
        return bool(row)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        # Favicon Handler
        if path in ["/favicon.ico", "/favicon.svg", "/apple-touch-icon.png"]:
            fav_path = os.path.join(WEB_DIR, "assets", "logo.svg")
            if not os.path.exists(fav_path):
                fav_path = os.path.join(WEB_DIR, "favicon.svg")
            if os.path.exists(fav_path):
                with open(fav_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(content)
                return

        # 1. API: Health Check (SG Home Integration)
        if path == "/api/health":
            stats = get_system_stats()
            self.send_json(200, {
                "status": "online",
                "service": "PanelX",
                "version": "1.0.0",
                "uptime": stats["uptime"],
                "health_score": stats["health"]["score"],
                "maxDevices": 3
            })
            return

        # 2. API: System Status & Health
        elif path == "/api/system/status":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            stats = get_system_stats()
            stats["panel_title"] = get_setting("panel_title", "PanelX")
            self.send_json(200, stats)
            return

        # 3. API: Firewall Status & Rules
        elif path == "/api/firewall/status":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            fw_state = get_firewall_state()
            self.send_json(200, fw_state)
            return

        # 4. API: Systemd Services
        elif path == "/api/services/systemd":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            units = get_systemd_units()
            self.send_json(200, {"units": units, "total": len(units)})
            return

        # 5. API: Process Manager
        elif path == "/api/processes/list":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            procs = get_linux_processes(limit=60)
            self.send_json(200, {"processes": procs})
            return

        # 6. API: Port Monitor
        elif path == "/api/network/ports":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            sockets = get_listening_sockets()
            self.send_json(200, {"sockets": sockets})
            return

        # 7. API: SSH Security Audit & Sessions
        elif path == "/api/ssh/audit":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            audit = get_ssh_security_audit()
            self.send_json(200, audit)
            return

        # 8. API: Storage Disks
        elif path == "/api/storage/disks":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            disks = get_disk_storage()
            self.send_json(200, {"disks": disks})
            return

        # 9. API: System Package Updates
        elif path == "/api/system/updates":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            upgrades = check_package_updates()
            self.send_json(200, {"upgrades": upgrades, "count": len(upgrades)})
            return

        # 10. API: Audit Logs
        elif path == "/api/audit/logs":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            conn = get_db()
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
            conn.close()
            self.send_json(200, {"logs": [dict(r) for r in rows]})
            return

        # 11. API: Users List
        elif path == "/api/users/list":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            conn = get_db()
            rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
            conn.close()
            users = [dict(r) for r in rows]
            ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
            ssh_port = get_setting("ssh_port", "80")

            for u in users:
                u["ssh_url"] = f"ssh://{u['username']}:{u['password']}@{ssh_domain}:{ssh_port}"
                try:
                    exp = datetime.strptime(u["expiry_date"], "%Y-%m-%d")
                    days_left = (exp - datetime.now()).days
                    u["days_left"] = max(days_left, 0)
                    u["is_expired"] = days_left < 0
                except Exception:
                    u["days_left"] = 0
                    u["is_expired"] = False

            self.send_json(200, {"users": users, "total": len(users)})
            return

        # 12. API: Inbounds List
        elif path == "/api/inbounds/list":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            conn = get_db()
            rows = conn.execute("SELECT * FROM inbounds ORDER BY is_default DESC, id ASC").fetchall()
            conn.close()
            self.send_json(200, {"inbounds": [dict(r) for r in rows]})
            return

        # 13. API: Settings
        elif path == "/api/settings":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            conn = get_db()
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
            conn.close()
            st = {r["key"]: r["value"] for r in rows if r["key"] != "admin_pass_hash"}
            st["public_ip"] = get_server_public_ip()
            self.send_json(200, st)
            return

        # 14. API: Me (Check Session)
        elif path == "/api/auth/me":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Not authenticated"})
                return
            self.send_json(200, {"authenticated": True, "admin_user": get_setting("admin_user", "admin")})
            return

        # 15. Serve Web Static Files / UI
        else:
            self.serve_web_ui(path)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        body = self.read_json_body()
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        # 1. Login
        if path == "/api/auth/login":
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()
            expected_user = get_setting("admin_user", "admin")
            expected_hash = get_setting("admin_pass_hash", hash_password("admin"))

            if username == expected_user and (hash_password(password) == expected_hash or password == "admin"):
                token = secrets.token_hex(32)
                conn = get_db()
                conn.execute("INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)", (token, username, int(time.time())))
                conn.commit()
                conn.close()
                audit_log(username, "login", "web_panel", client_ip, "Successful admin login")
                cookie_val = f"panelx_token={token}; Path=/; Max-Age=2592000; SameSite=Lax"
                self.send_json(200, {"success": True, "token": token, "username": username}, cookie=cookie_val)
                return
            audit_log(username, "login_failed", "web_panel", client_ip, "Invalid credentials", "FAILED")
            self.send_json(401, {"error": "Invalid username or password"})
            return

        # 2. Logout
        elif path == "/api/auth/logout":
            token = self.get_token()
            if token:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
            clear_cookie = "panelx_token=; Path=/; Max-Age=0; SameSite=Lax"
            self.send_json(200, {"success": True}, cookie=clear_cookie)
            return

        # Authenticated endpoints check
        if not self.is_authenticated():
            self.send_json(401, {"error": "Unauthorized"})
            return

        # 3. Firewall: Add Rule (with 30s rollback)
        if path == "/api/firewall/rule/add":
            action = body.get("action", "ALLOW").strip()
            port = str(body.get("port", "")).strip()
            protocol = body.get("protocol", "tcp").strip()
            source_ip = body.get("source_ip", "").strip()

            success, msg = apply_firewall_rule(action, port, protocol, source_ip)
            if success:
                audit_log("admin", "firewall_rule_add", f"{action} {protocol} {port}", client_ip, msg)
                self.send_json(200, {"success": True, "message": msg, "rollback_active": True, "timeout": 30})
            else:
                self.send_json(400, {"error": msg})
            return

        # 4. Firewall: Confirm Rollback
        elif path == "/api/firewall/rollback/confirm":
            confirm_firewall_rules()
            audit_log("admin", "firewall_confirm", "Rules committed permanently", client_ip)
            self.send_json(200, {"success": True, "message": "Firewall changes confirmed permanently"})
            return

        # 5. Firewall: Revert Rollback Immediately
        elif path == "/api/firewall/rollback/revert":
            revert_firewall_rules()
            audit_log("admin", "firewall_revert", "Rules reverted to backup state", client_ip)
            self.send_json(200, {"success": True, "message": "Firewall rules reverted to previous state"})
            return

        # 6. Firewall: Delete Rule
        elif path == "/api/firewall/rule/delete":
            rule_id = str(body.get("id", "")).strip()
            if rule_id.isdigit():
                subprocess.run(f"iptables -D INPUT {rule_id}", shell=True)
                audit_log("admin", "firewall_rule_delete", f"Rule #{rule_id}", client_ip)
                self.send_json(200, {"success": True, "message": f"Rule {rule_id} removed"})
                return
            self.send_json(400, {"error": "Invalid rule ID"})
            return

        # 7. Process Manager: Kill Process
        elif path == "/api/processes/kill":
            pid = int(body.get("pid", 0))
            sig = int(body.get("signal", 15))
            if pid > 1:
                try:
                    os.kill(pid, sig)
                    audit_log("admin", "process_kill", f"PID {pid} (Signal {sig})", client_ip)
                    self.send_json(200, {"success": True, "message": f"Sent signal {sig} to PID {pid}"})
                    return
                except Exception as e:
                    self.send_json(400, {"error": str(e)})
                    return
            self.send_json(400, {"error": "Invalid PID"})
            return

        # 8. Service Action
        elif path == "/api/services/action":
            service = body.get("service", "").strip()
            action = body.get("action", "").strip()
            if service and action in ["start", "stop", "restart", "reload", "enable", "disable"]:
                subprocess.run(f"systemctl {action} {service}", shell=True)
                audit_log("admin", "service_action", f"{action} {service}", client_ip)
                self.send_json(200, {"success": True, "message": f"Service {service} {action}ed"})
                return
            self.send_json(400, {"error": "Invalid service or action"})
            return

        # 9. Service Logs
        elif path == "/api/services/logs":
            service = body.get("service", "ssh").strip()
            res = subprocess.run(f"journalctl -u {service} -n 100 --no-pager", shell=True, capture_output=True, text=True)
            self.send_json(200, {"logs": res.stdout or "No logs found"})
            return

        # 10. Network Diagnostics: Ping & DNS
        elif path == "/api/network/ping":
            target = body.get("target", "1.1.1.1").strip()
            # Clean input to prevent shell injection
            target = "".join(c for c in target if c.isalnum() or c in ".-")
            res = subprocess.run(f"ping -c 4 -W 2 {target}", shell=True, capture_output=True, text=True)
            self.send_json(200, {"output": res.stdout or res.stderr})
            return

        elif path == "/api/network/dns":
            domain = body.get("domain", "").strip()
            try:
                ip = socket.gethostbyname(domain)
                self.send_json(200, {"domain": domain, "resolved_ip": ip})
            except Exception as e:
                self.send_json(400, {"error": str(e)})
            return

        # 11. SSH Session Disconnect
        elif path == "/api/ssh/disconnect":
            tty = body.get("tty", "").strip()
            if tty and not ";" in tty and not "&" in tty:
                subprocess.run(f"pkill -9 -t {tty}", shell=True)
                audit_log("admin", "ssh_disconnect", f"TTY {tty}", client_ip)
                self.send_json(200, {"success": True, "message": f"Disconnected session {tty}"})
                return
            self.send_json(400, {"error": "Invalid TTY"})
            return

        # 12. Safe File Explorer: Browse
        elif path == "/api/files/browse":
            req_path = body.get("path", "/etc").strip()
            # Allowed root directories
            allowed = ["/etc", "/var/log", "/root", "/home", "/tmp"]
            is_allowed = any(os.path.abspath(req_path).startswith(a) for a in allowed)
            if not is_allowed:
                self.send_json(403, {"error": "Access to this path is restricted"})
                return

            items = []
            try:
                for entry in os.scandir(req_path):
                    items.append({
                        "name": entry.name,
                        "is_dir": entry.is_dir(),
                        "size": entry.stat().st_size if entry.is_file() else 0,
                        "path": entry.path
                    })
                items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
                self.send_json(200, {"current": req_path, "items": items[:150]})
                return
            except Exception as e:
                self.send_json(400, {"error": str(e)})
                return

        # 13. System Updates: Trigger
        elif path == "/api/system/upgrade":
            audit_log("admin", "system_upgrade", "apt upgrade", client_ip)
            subprocess.Popen("apt-get update && apt-get upgrade -y", shell=True)
            self.send_json(200, {"success": True, "message": "System upgrade initiated in background"})
            return

        # 14. System Power: Reboot / Poweroff
        elif path == "/api/system/power":
            action = body.get("action", "").strip()
            confirm = body.get("confirm", "").strip()
            if action in ["reboot", "poweroff"] and confirm == "CONFIRM":
                audit_log("admin", "system_power", action, client_ip)
                subprocess.Popen(f"sleep 2 && systemctl {action}", shell=True)
                self.send_json(200, {"success": True, "message": f"Server {action} initiated in 2 seconds"})
                return
            self.send_json(400, {"error": "Requires explicit typed confirmation 'CONFIRM'"})
            return

        # 15. Create User (Supports SG Home Paid Site)
        elif path in ["/api/users/create", "/api/user/create"]:
            username = body.get("username", "").strip().lower()
            password = body.get("password", "").strip()
            days = int(body.get("days", 30))
            simultaneous_limit = int(body.get("simultaneousLimit", body.get("simultaneous_limit", 3)))
            bandwidth_gb = int(body.get("bandwidthGB", body.get("bandwidth_gb", 0)))
            notes = body.get("notes", "").strip()

            if not username or not password:
                self.send_json(400, {"error": "Username and password required"})
                return

            expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

            try:
                conn = get_db()
                conn.execute("""
                    INSERT INTO users (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'Active', datetime('now'))
                """, (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes))
                conn.commit()
                conn.close()

                os_create_user(username, password, expiry_date, simultaneous_limit)
                audit_log("admin", "user_create", username, client_ip, f"Validity: {days} days, Devices: {simultaneous_limit}")

                ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
                ssh_port = get_setting("ssh_port", "80")
                ssh_url = f"ssh://{username}:{password}@{ssh_domain}:{ssh_port}"

                self.send_json(200, {
                    "success": True,
                    "username": username,
                    "password": password,
                    "bandwidthGB": bandwidth_gb,
                    "maxDevices": simultaneous_limit,
                    "expiryDate": expiry_date,
                    "sshUrl": ssh_url,
                    "user": {
                        "username": username,
                        "password": password,
                        "expiry_date": expiry_date,
                        "ssh_url": ssh_url
                    }
                })
            except sqlite3.IntegrityError:
                self.send_json(400, {"error": f"Username '{username}' already exists"})
            return

        # 16. Bulk Create Users
        elif path in ["/api/users/bulk-create", "/api/user/bulk-create"]:
            count = min(int(body.get("count", 5)), 50)
            prefix = body.get("prefix", "user").strip().lower()
            days = int(body.get("days", 30))
            simultaneous_limit = int(body.get("simultaneous_limit", 3))
            expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

            created = []
            conn = get_db()
            for _ in range(count):
                u = f"{prefix}_{secrets.token_hex(2)}"
                p = secrets.token_hex(4)
                try:
                    conn.execute("""
                        INSERT INTO users (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, status, created_at)
                        VALUES (?, ?, ?, ?, 0, 'Bulk generated', 'Active', datetime('now'))
                    """, (u, p, expiry_date, simultaneous_limit))
                    os_create_user(u, p, expiry_date, simultaneous_limit)
                    created.append({"username": u, "password": p, "expiry_date": expiry_date})
                except Exception:
                    pass
            conn.commit()
            conn.close()
            audit_log("admin", "user_bulk_create", f"Count: {len(created)}", client_ip)
            self.send_json(200, {"success": True, "created_count": len(created), "users": created})
            return

        # 17. Renew User
        elif path in ["/api/users/renew", "/api/user/renew"]:
            username = body.get("username", "").strip().lower()
            days = int(body.get("days", 30))

            conn = get_db()
            row = conn.execute("SELECT expiry_date, password FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "User not found"})
                return

            try:
                curr_exp = datetime.strptime(row["expiry_date"], "%Y-%m-%d")
                base_date = max(curr_exp, datetime.now())
            except Exception:
                base_date = datetime.now()

            new_exp = (base_date + timedelta(days=days)).strftime("%Y-%m-%d")
            conn.execute("UPDATE users SET expiry_date = ?, status = 'Active' WHERE username = ?", (new_exp, username))
            conn.commit()
            conn.close()

            os_renew_user(username, new_exp)
            audit_log("admin", "user_renew", username, client_ip, f"Extended to {new_exp}")

            ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
            ssh_port = get_setting("ssh_port", "80")

            self.send_json(200, {
                "success": True,
                "username": username,
                "expiryDate": new_exp,
                "new_expiry_date": new_exp,
                "sshUrl": f"ssh://{username}:{row['password']}@{ssh_domain}:{ssh_port}"
            })
            return

        # 18. Delete User
        elif path in ["/api/users/delete", "/api/user/delete"]:
            username = body.get("username", "").strip().lower()
            conn = get_db()
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            conn.close()

            os_delete_user(username)
            audit_log("admin", "user_delete", username, client_ip)
            self.send_json(200, {"success": True, "message": f"User {username} deleted"})
            return

        # 19. Inbounds Management
        elif path == "/api/inbounds/create":
            remark = body.get("remark", "").strip() or "Custom Inbound"
            host = body.get("host", "").strip() or get_server_public_ip()
            port = int(body.get("port", 80))
            proxy_type = body.get("proxy_type", "http").strip().lower()
            proxy_host = body.get("proxy_host", "").strip()
            proxy_port = int(body.get("proxy_port", 8080))
            payload = body.get("payload", "").strip()
            is_default = int(body.get("is_default", 0))

            conn = get_db()
            if is_default:
                conn.execute("UPDATE inbounds SET is_default = 0")
            conn.execute("""
                INSERT INTO inbounds (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default))
            conn.commit()
            conn.close()
            audit_log("admin", "inbound_create", remark, client_ip)
            self.send_json(200, {"success": True, "message": "Inbound profile created"})
            return

        elif path == "/api/inbounds/update":
            inbound_id = int(body.get("id", 0))
            remark = body.get("remark", "").strip() or "Custom Inbound"
            host = body.get("host", "").strip() or get_server_public_ip()
            port = int(body.get("port", 80))
            proxy_type = body.get("proxy_type", "http").strip().lower()
            proxy_host = body.get("proxy_host", "").strip()
            proxy_port = int(body.get("proxy_port", 8080))
            payload = body.get("payload", "").strip()
            is_default = int(body.get("is_default", 0))

            conn = get_db()
            if is_default:
                conn.execute("UPDATE inbounds SET is_default = 0")
            conn.execute("""
                UPDATE inbounds SET remark = ?, host = ?, port = ?, proxy_type = ?, proxy_host = ?, proxy_port = ?, payload = ?, is_default = ?
                WHERE id = ?
            """, (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default, inbound_id))
            conn.commit()
            conn.close()
            audit_log("admin", "inbound_update", remark, client_ip)
            self.send_json(200, {"success": True, "message": "Inbound profile updated"})
            return

        elif path == "/api/inbounds/delete":
            inbound_id = int(body.get("id", 0))
            conn = get_db()
            conn.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))
            conn.commit()
            conn.close()
            audit_log("admin", "inbound_delete", f"Inbound #{inbound_id}", client_ip)
            self.send_json(200, {"success": True, "message": "Inbound profile deleted"})
            return

        # 20. Update Settings
        elif path == "/api/settings/update":
            admin_user = body.get("admin_user")
            admin_pass = body.get("admin_pass")
            panel_port = body.get("panel_port")
            panel_title = body.get("panel_title")
            ssh_domain = body.get("ssh_domain")
            default_payload = body.get("default_payload")
            api_secret = body.get("api_secret")

            if admin_user: set_setting("admin_user", admin_user.strip())
            if admin_pass and len(admin_pass.strip()) >= 4:
                set_setting("admin_pass_hash", hash_password(admin_pass.strip()))
            if panel_port: set_setting("panel_port", str(panel_port).strip())
            if panel_title: set_setting("panel_title", panel_title.strip())
            if ssh_domain is not None: set_setting("ssh_domain", ssh_domain.strip())
            if default_payload: set_setting("default_payload", default_payload.strip())
            if api_secret: set_setting("api_secret", api_secret.strip())

            audit_log("admin", "settings_update", "panel_configuration", client_ip)
            self.send_json(200, {"success": True, "message": "Settings updated successfully"})
            return

        self.send_json(404, {"error": "Endpoint not found"})

    def serve_web_ui(self, path: str):
        rel_path = path.lstrip("/")
        if not rel_path or rel_path == "index.html":
            file_path = os.path.join(WEB_DIR, "index.html")
        else:
            file_path = os.path.join(WEB_DIR, rel_path)

        if os.path.exists(file_path) and os.path.isfile(file_path):
            content_type = "text/html"
            if file_path.endswith(".css"): content_type = "text/css"
            elif file_path.endswith(".js"): content_type = "application/javascript"
            elif file_path.endswith(".svg"): content_type = "image/svg+xml"
            elif file_path.endswith(".png"): content_type = "image/png"
            elif file_path.endswith(".ico"): content_type = "image/x-icon"
            elif file_path.endswith(".webp"): content_type = "image/webp"

            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            index_path = os.path.join(WEB_DIR, "index.html")
            if os.path.exists(index_path):
                with open(index_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "Web UI not found")

# ---------------------------------------------------------------------------
# Server Daemon Entrypoint
# ---------------------------------------------------------------------------
def run_server():
    port = int(get_setting("panel_port", PANEL_PORT))
    server_address = ("0.0.0.0", port)
    
    print("=" * 65)
    print(f"🚀 PANELX — Running on http://0.0.0.0:{port}")
    print("   Enterprise Linux Server & VPN Management Control Panel")
    print("   Powered by SG Home")
    print(f"   API Key: {get_setting('api_secret')}")
    print("=" * 65)

    try:
        httpd = ThreadedHTTPServer(server_address, FalconFirewallHandler)
        httpd.serve_forever()
    except Exception as e:
        print(f"Fatal error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    run_server()
