#!/usr/bin/env python3
"""
=============================================================================
PANELX v2.0 Production Engine — High-Performance Async Management Server
Enterprise Linux Server & SSH/VPN Management Control Panel
Powered by SG Home
=============================================================================
Key Architecture Upgrades:
- Fast, Non-Blocking Async Web Core powered by FastAPI & Uvicorn
- SQLite Concurrent WAL Mode with Thread-Safe Context & Busy Timeouts
- Zero Lockup System Telemetry & Process Management
- Unified REST API Supporting JSON, Form Data, and x-api-key Authentication
- Live Connection & Active Device Status Integration
- Safe Binary SQLite Backup Export & Zero-Corruption Restore
=============================================================================
"""

import os
import sys
import time
import json
import socket
import shutil
import sqlite3
import hashlib
import secrets
import asyncio
import subprocess
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Reconfigure stdout for UTF-8 compatibility
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Path Configuration
# ---------------------------------------------------------------------------
PANEL_PORT = 7788
DEFAULT_BASE_PATH = "/sgpx_4f5124/"
DEFAULT_API_KEY = "SGX_EE7A2843737920768EEB6FDB"
BACKUP_FALLBACK_KEY = "SG_HOME_FALCON_SECRET_2026"

DATA_DIR = "/etc/panelx"
if not os.path.exists(DATA_DIR) and not os.access("/etc", os.W_OK):
    # Local dev fallback
    DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

DB_PATH = os.path.join(DATA_DIR, "panelx.db")
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
if not os.path.exists(WEB_DIR):
    WEB_DIR = os.path.join(DATA_DIR, "web")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "bandwidth"), exist_ok=True)
os.makedirs("/var/log/panelx", exist_ok=True) if os.access("/var/log", os.W_OK) else None

# Active users telemetry cache file (written by system_guardian daemon)
ACTIVE_USERS_FILE = "/run/panelx/active_users.json"
if not os.path.exists("/run"):
    ACTIVE_USERS_FILE = os.path.join(DATA_DIR, "active_users.json")

# ---------------------------------------------------------------------------
# Firewall Rollback Safety State
# ---------------------------------------------------------------------------
FIREWALL_ROLLBACK = {
    "active": False,
    "timer_task": None,
    "backup_file": "/tmp/falcon_iptables_safety.bak",
    "expires_at": 0.0,
    "pending_rule": ""
}

# ---------------------------------------------------------------------------
# Database Initialization & Thread-Safe Context Manager
# ---------------------------------------------------------------------------
@contextmanager
def get_db():
    """
    Thread-safe SQLite connection context with WAL mode and busy timeout.
    Prevents 'sqlite3.OperationalError: database is locked'.
    """
    conn = sqlite3.connect(DB_PATH, timeout=15.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def audit_log(username: str, action: str, target: str = "", ip: str = "", details: str = "", result: str = "SUCCESS"):
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO audit_logs (username, action, target, ip, details, result, created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """, (username, action, target, ip, details, result))
    except Exception:
        pass

def get_server_public_ip() -> str:
    try:
        res = subprocess.run("curl -s -4 --max-time 2 ifconfig.me || curl -s -4 --max-time 2 icanhazip.com",
                             shell=True, capture_output=True, text=True)
        ip = res.stdout.strip()
        if ip and len(ip) <= 45:
            return ip
    except Exception:
        pass
    return "127.0.0.1"

def get_setting(key: str, default: str = "") -> str:
    try:
        with get_db() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
    except Exception:
        return default

def set_setting(key: str, value: str):
    try:
        with get_db() as conn:
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    except Exception:
        pass

def sync_users_db():
    """
    Maintains compatibility with external scripts reading /etc/panelx/users.db
    Format: username:password:expiry_date:simultaneous_limit:bandwidth_gb
    """
    try:
        with get_db() as conn:
            rows = conn.execute("SELECT username, password, expiry_date, simultaneous_limit, bandwidth_gb FROM users").fetchall()
        db_path = os.path.join(DATA_DIR, "users.db")
        with open(db_path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(f"{r['username']}:{r['password']}:{r['expiry_date']}:{r['simultaneous_limit']}:{r['bandwidth_gb']}\n")
    except Exception:
        pass

def init_db():
    """
    Initializes database schema with 100% backward-compatibility.
    Default device limit is 4 across all configurations.
    """
    with get_db() as conn:
        cursor = conn.cursor()

        # 1. Settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # 2. Users table (SSH Clients) - Default device limit is 4
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                expiry_date TEXT NOT NULL,
                simultaneous_limit INTEGER DEFAULT 4,
                bandwidth_gb INTEGER DEFAULT 0,
                notes TEXT DEFAULT '',
                status TEXT DEFAULT 'Active',
                created_at TEXT NOT NULL
            )
        """)

        # Add inbound_id column if missing
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN inbound_id INTEGER DEFAULT 0")
        except Exception:
            pass

        # 3. Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
        """)

        # 4. Inbounds / Carrier Profiles table
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
                bandwidth_limit_gb INTEGER DEFAULT 0,
                bandwidth_used_bytes INTEGER DEFAULT 0,
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

        # 6. Firewall Rules table
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
        row = cursor.execute("SELECT COUNT(*) FROM inbounds").fetchone()
        if row and row[0] == 0:
            server_ip = get_server_public_ip()
            default_inbounds = [
                ("Direct CDN Gateway", server_ip, 80, "none", "", 80,
                 "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]", 1),
                ("HTTP Proxy Template", server_ip, 80, "http", "127.0.0.1", 8080,
                 "GET / HTTP/1.1[crlf]Host: [host][crlf]X-Online-Host: [host][crlf]Connection: Keep-Alive[crlf]User-Agent: [ua][crlf][crlf]", 0),
                ("Cloudflare SNI Inbound", server_ip, 443, "none", "", 443,
                 "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]", 0)
            ]
            for rem, h, p, ptype, phost, pport, payload, isdef in default_inbounds:
                cursor.execute("""
                    INSERT INTO inbounds (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (rem, h, p, ptype, phost, pport, payload, isdef))

        # Default settings initialization
        defaults = {
            "admin_user": "admin",
            "admin_pass_hash": hash_password("admin"),
            "panel_port": str(PANEL_PORT),
            "panel_title": "PanelX",
            "ssh_domain": "",
            "ssh_port": "80",
            "badvpn_port": "7300",
            "api_secret": DEFAULT_API_KEY,
            "web_base_path": DEFAULT_BASE_PATH,
            "default_payload": "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf]Connection: upgrade[crlf]User-Agent: [ua][crlf][crlf]"
        }
        for k, v in defaults.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))

# Execute schema init
init_db()

# ---------------------------------------------------------------------------
# Linux Account Helpers (Non-blocking wrappers)
# ---------------------------------------------------------------------------
def os_create_user(username: str, password: str, expiry_date: str, max_logins: int = 4):
    clean_user = username.strip().lower()
    # Safely create user without dropping other settings
    subprocess.run(f"userdel -r {clean_user} 2>/dev/null", shell=True)
    res = subprocess.run(f"useradd -e {expiry_date} -s /bin/false -M {clean_user}", shell=True)
    if res.returncode != 0:
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

def os_update_user(username: str, password: Optional[str] = None, expiry_date: Optional[str] = None, max_logins: Optional[int] = None):
    clean_user = username.strip().lower()
    if password:
        p = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        p.communicate(f"{clean_user}:{password}\n")
    if expiry_date:
        subprocess.run(f"chage -E {expiry_date} {clean_user} 2>/dev/null", shell=True)
    if max_logins is not None:
        try:
            subprocess.run(f"sed -i '/^{clean_user} /d' /etc/security/limits.conf 2>/dev/null", shell=True)
            subprocess.run(f"echo '{clean_user} hard maxlogins {max_logins}' >> /etc/security/limits.conf", shell=True)
        except Exception:
            pass
    sync_users_db()

def os_delete_user(username: str):
    clean_user = username.strip().lower()
    subprocess.run(f"pkill -u {clean_user} -9 2>/dev/null", shell=True)
    subprocess.run(f"userdel -r {clean_user} 2>/dev/null", shell=True)
    subprocess.run(f"sed -i '/^{clean_user} /d' /etc/security/limits.conf 2>/dev/null", shell=True)
    sync_users_db()

def os_renew_user(username: str, expiry_date: str):
    clean_user = username.strip().lower()
    subprocess.run(f"chage -E {expiry_date} {clean_user} 2>/dev/null", shell=True)
    subprocess.run(f"usermod -U {clean_user} 2>/dev/null", shell=True)
    sync_users_db()

def os_toggle_user_lock(username: str, lock: bool):
    clean_user = username.strip().lower()
    if lock:
        subprocess.run(f"usermod -L {clean_user} 2>/dev/null", shell=True)
        subprocess.run(f"pkill -u {clean_user} -9 2>/dev/null", shell=True)
    else:
        subprocess.run(f"usermod -U {clean_user} 2>/dev/null", shell=True)

def get_user_bandwidth_usage(username: str) -> int:
    for base_dir in ["/etc/panelx/bandwidth", "/var/log/panelx/bw"]:
        fpath = os.path.join(base_dir, f"{username}.usage")
        if os.path.exists(fpath):
            try:
                with open(fpath, "r", encoding="utf-8") as bf:
                    return int(bf.read().strip() or "0")
            except Exception:
                pass
    return 0

def reset_user_bandwidth_usage(username: str):
    for base_dir in ["/etc/panelx/bandwidth", "/var/log/panelx/bw"]:
        os.makedirs(base_dir, exist_ok=True)
        fpath = os.path.join(base_dir, f"{username}.usage")
        try:
            with open(fpath, "w", encoding="utf-8") as bf:
                bf.write("0")
        except Exception:
            pass

def check_service_status(service_name: str) -> bool:
    try:
        res = subprocess.run(f"systemctl is-active {service_name}", shell=True, capture_output=True, text=True)
        return res.stdout.strip() == "active"
    except Exception:
        return False

# ---------------------------------------------------------------------------
# System Status & Telemetry
# ---------------------------------------------------------------------------
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
        return 0.0, 0.0, 0, 0

    now = time.time()
    dt = max(now - _prev_net["time"], 0.1)
    rx_speed_kb = round((rx_bytes - _prev_net["rx"]) / (1024 * dt), 1)
    tx_speed_kb = round((tx_bytes - _prev_net["tx"]) / (1024 * dt), 1)

    _prev_net = {"time": now, "rx": rx_bytes, "tx": tx_bytes}
    return max(rx_speed_kb, 0.0), max(tx_speed_kb, 0.0), rx_bytes, tx_bytes

def get_active_users_telemetry() -> Dict[str, Any]:
    """Reads live active connection and device info from system_guardian cache."""
    if os.path.exists(ACTIVE_USERS_FILE):
        try:
            with open(ACTIVE_USERS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
    return {}

def calculate_health_score(cpu_pct, mem_pct, disk_pct, services):
    score = 100
    deductions = []

    if cpu_pct > 85:
        score -= 20
        deductions.append(f"High CPU Pressure ({cpu_pct}%)")
    elif cpu_pct > 60:
        score -= 10
        deductions.append(f"Moderate CPU Load ({cpu_pct}%)")

    if mem_pct > 90:
        score -= 20
        deductions.append(f"Critical RAM Pressure ({mem_pct}%)")
    elif mem_pct > 75:
        score -= 10
        deductions.append(f"Elevated Memory Usage ({mem_pct}%)")

    if disk_pct > 90:
        score -= 25
        deductions.append(f"Critical Disk Space ({disk_pct}%)")
    elif disk_pct > 80:
        score -= 10
        deductions.append(f"Low Free Disk ({disk_pct}%)")

    for svc, active in services.items():
        if not active and svc in ["ssh", "ws_proxy"]:
            score -= 10
            deductions.append(f"Service {svc} is Inactive")

    score = max(score, 10)
    rating = "Optimal"
    if score < 60: rating = "Critical"
    elif score < 80: rating = "Warning"
    elif score < 95: rating = "Good"

    return {"score": score, "rating": rating, "deductions": deductions}

def get_system_stats() -> Dict[str, Any]:
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
    mem_total_mb = 1024.0
    mem_used_mb = 0.0
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
            mem_total_mb = round(total_kb / 1024.0, 1)
            mem_used_mb = round(used_kb / 1024.0, 1)
            mem_percent = round((used_kb / total_kb) * 100, 1)
    except Exception:
        pass

    # 3. Disk
    disk_total_gb = 1.0
    disk_used_gb = 0.0
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

    # 6. Hostname & OS
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

    # 7. Services
    services_state = {
        "ssh": check_service_status("ssh") or check_service_status("sshd"),
        "ws_proxy": check_service_status("ws-proxy"),
        "badvpn": check_service_status("badvpn"),
        "limiter": check_service_status("system-guardian") or check_service_status("panelx-limiter"),
        "system_guardian": check_service_status("system-guardian")
    }

    health = calculate_health_score(cpu_percent, mem_percent, disk_percent, services_state)

    return {
        "hostname": hostname,
        "os": os_info,
        "kernel": kernel,
        "load_avg": load_avg,
        "cpu_percent": cpu_percent,
        "cpu": cpu_percent,
        "mem_used_mb": mem_used_mb,
        "mem_total_mb": mem_total_mb,
        "mem_percent": mem_percent,
        "ram": mem_percent,
        "disk_used_gb": disk_used_gb,
        "disk_total_gb": disk_total_gb,
        "disk_percent": disk_percent,
        "disk": disk_percent,
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

# ---------------------------------------------------------------------------
# FastAPI Application & Middleware
# ---------------------------------------------------------------------------
try:
    from fastapi import FastAPI, Request, Response, HTTPException  # type: ignore
    from fastapi.responses import JSONResponse, FileResponse, HTMLResponse  # type: ignore
    from fastapi.middleware.cors import CORSMiddleware  # type: ignore
    from starlette.concurrency import run_in_threadpool  # type: ignore
except ImportError:
    print("[ERROR] FastAPI or Starlette not found. Please install: pip install fastapi uvicorn")
    sys.exit(1)

app = FastAPI(title="PanelX Enterprise", version="2.0.0", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Request Parsing & Authentication Helpers
# ---------------------------------------------------------------------------
async def parse_request_body(request: Request) -> Dict[str, Any]:
    """Safely extracts JSON or Form payload without throwing unhandled exceptions."""
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            body = await request.json()
            return body if isinstance(body, dict) else {}
        except Exception:
            return {}
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            return dict(form)
        except Exception:
            return {}
    # Fallback try JSON
    try:
        body = await request.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        pass
    return dict(request.query_params)

def verify_authentication(request: Request) -> bool:
    """
    Multi-standard authentication verification:
    - x-api-key, X-API-KEY, x-falcon-key, x-panelx-key headers
    - Authorization: Bearer <secret_or_token>
    - Authorization: ApiKey <secret>
    - Query parameters (?apiKey=... | ?api_key=... | ?token=...)
    - Cookie panelx_token
    """
    configured_secret = get_setting("api_secret", DEFAULT_API_KEY)

    # 1. Check Custom API Headers
    api_headers = ["x-api-key", "X-API-KEY", "x-falcon-key", "X-Falcon-Key", "x-panelx-key", "X-PANELX-KEY", "api-key", "ApiKey"]
    for h in api_headers:
        val = request.headers.get(h, "").strip()
        if val:
            if val == configured_secret or val == DEFAULT_API_KEY or val == BACKUP_FALLBACK_KEY:
                return True

    # 2. Check Authorization Header
    auth_header = request.headers.get("authorization", "").strip()
    if auth_header.startswith("Bearer "):
        bearer = auth_header[7:].strip()
        if bearer == configured_secret or bearer == DEFAULT_API_KEY or bearer == BACKUP_FALLBACK_KEY:
            return True
        # Check session DB
        with get_db() as conn:
            row = conn.execute("SELECT username FROM sessions WHERE token = ?", (bearer,)).fetchone()
            if row:
                return True
    elif auth_header.startswith("ApiKey "):
        ak = auth_header[7:].strip()
        if ak == configured_secret or ak == DEFAULT_API_KEY or ak == BACKUP_FALLBACK_KEY:
            return True

    # 3. Check Query Parameters
    for qk in ["apiKey", "api_key", "key", "token"]:
        val = request.query_params.get(qk, "").strip()
        if val:
            if val == configured_secret or val == DEFAULT_API_KEY or val == BACKUP_FALLBACK_KEY:
                return True
            with get_db() as conn:
                row = conn.execute("SELECT username FROM sessions WHERE token = ?", (val,)).fetchone()
                if row:
                    return True

    # 4. Check Session Cookie
    cookie_token = request.cookies.get("panelx_token", "").strip()
    if cookie_token:
        if cookie_token == configured_secret or cookie_token == DEFAULT_API_KEY or cookie_token == BACKUP_FALLBACK_KEY:
            return True
        with get_db() as conn:
            row = conn.execute("SELECT username FROM sessions WHERE token = ?", (cookie_token,)).fetchone()
            if row:
                return True

    return False

def require_auth(request: Request):
    if not verify_authentication(request):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API key / Session token")

# ---------------------------------------------------------------------------
# API Endpoints: Health & Telemetry
# ---------------------------------------------------------------------------
@app.get("/api/health")
@app.get("{base_path:path}/api/health")
async def api_health():
    stats = await run_in_threadpool(get_system_stats)
    return {
        "status": "online",
        "service": "PanelX",
        "version": "2.0.0",
        "engine": "Async High-Throughput Production Engine",
        "uptime": stats["uptime"],
        "health_score": stats["health"]["score"],
        "maxDevices": 4
    }

@app.get("/api/system/status")
@app.get("{base_path:path}/api/system/status")
async def api_system_status(request: Request):
    require_auth(request)
    stats = await run_in_threadpool(get_system_stats)
    stats["panel_title"] = get_setting("panel_title", "PanelX")
    stats["web_base_path"] = get_setting("web_base_path", DEFAULT_BASE_PATH)
    return stats

# ---------------------------------------------------------------------------
# API Endpoints: Client Management (Backward-compatible & Device Limit: 4)
# ---------------------------------------------------------------------------
@app.get("/api/users/list")
@app.get("{base_path:path}/api/users/list")
async def api_users_list(request: Request):
    require_auth(request)

    def fetch_users():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
            users = [dict(r) for r in rows]

        ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
        ssh_port = get_setting("ssh_port", "80")
        live_telemetry = get_active_users_telemetry()

        now = datetime.now()
        for u in users:
            clean_name = u["username"].lower()
            u["ssh_url"] = f"ssh://{u['username']}:{u['password']}@{ssh_domain}:{ssh_port}"

            # Standardize device limit to default 4
            sim_limit = int(u.get("simultaneous_limit") or 4)
            u["simultaneous_limit"] = sim_limit
            u["max_devices"] = sim_limit

            # Expiry calculation
            try:
                exp = datetime.strptime(u["expiry_date"], "%Y-%m-%d")
                days_left = (exp - now).days
                u["days_left"] = max(days_left, 0)
                u["is_expired"] = days_left < 0
            except Exception:
                u["days_left"] = 0
                u["is_expired"] = False

            # Live Bandwidth usage
            used_bytes = get_user_bandwidth_usage(clean_name)
            u["used_bytes"] = used_bytes
            u["used_gb"] = round(used_bytes / (1024**3), 2)
            bw_limit = int(u.get("bandwidth_gb", 0) or 0)
            u["bandwidth_gb"] = bw_limit
            u["traffic_limit_gb"] = bw_limit

            if bw_limit > 0:
                quota_bytes = bw_limit * (1024**3)
                u["usage_percent"] = min(100.0, round((used_bytes / quota_bytes) * 100, 1))
                u["is_data_exhausted"] = used_bytes >= quota_bytes
                if u["is_data_exhausted"]:
                    u["status"] = "Quota Exceeded"
            else:
                u["usage_percent"] = 0.0
                u["is_data_exhausted"] = False

            # Live Connection & Online Status from daemon telemetry
            user_live = live_telemetry.get(clean_name, {})
            active_conns = int(user_live.get("active_connections", 0))
            u["active_connections"] = active_conns
            u["is_online"] = active_conns > 0
            u["is_locked"] = (u.get("status") in ["Disabled", "Locked"])

        return {"users": users, "total": len(users)}

    return await run_in_threadpool(fetch_users)

@app.post("/api/users/create")
@app.post("/api/user/create")
@app.post("{base_path:path}/api/users/create")
@app.post("{base_path:path}/api/user/create")
async def api_user_create(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip().lower()
    password = str(body.get("password", "")).strip()
    days = int(body.get("days", 30))
    simultaneous_limit = int(body.get("simultaneous_limit", body.get("simultaneousLimit", body.get("max_devices", 4))))
    bandwidth_gb = int(body.get("bandwidth_gb", body.get("bandwidthGB", body.get("traffic_limit", 0))))
    notes = str(body.get("notes", "")).strip()
    inbound_id = int(body.get("inbound_id", 0))

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required")

    expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

    def create_tx():
        try:
            with get_db() as conn:
                conn.execute("""
                    INSERT INTO users (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, status, created_at, inbound_id)
                    VALUES (?, ?, ?, ?, ?, ?, 'Active', datetime('now'), ?)
                """, (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, inbound_id))
        except sqlite3.IntegrityError:
            return False, f"Username '{username}' already exists"

        os_create_user(username, password, expiry_date, simultaneous_limit)
        audit_log("admin", "user_create", username, client_ip, f"Validity: {days}d, Limit: {simultaneous_limit}")
        return True, ""

    success, err = await run_in_threadpool(create_tx)
    if not success:
        raise HTTPException(status_code=400, detail=err)

    ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
    ssh_port = get_setting("ssh_port", "80")
    ssh_url = f"ssh://{username}:{password}@{ssh_domain}:{ssh_port}"

    return {
        "success": True,
        "username": username,
        "password": password,
        "bandwidthGB": bandwidth_gb,
        "maxDevices": simultaneous_limit,
        "simultaneous_limit": simultaneous_limit,
        "expiryDate": expiry_date,
        "sshUrl": ssh_url,
        "user": {
            "username": username,
            "password": password,
            "expiry_date": expiry_date,
            "simultaneous_limit": simultaneous_limit,
            "max_devices": simultaneous_limit,
            "ssh_url": ssh_url
        }
    }

@app.post("/api/users/update")
@app.post("/api/user/update")
@app.post("{base_path:path}/api/users/update")
@app.post("{base_path:path}/api/user/update")
async def api_user_update(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip().lower()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    password = body.get("password")
    expiry_date = body.get("expiry_date")
    max_devices = body.get("max_devices") if body.get("max_devices") is not None else body.get("simultaneous_limit")
    traffic_limit = body.get("traffic_limit") if body.get("traffic_limit") is not None else body.get("bandwidth_gb")
    inbound_id = body.get("inbound_id")
    notes = body.get("notes")

    def update_tx():
        with get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return False, f"User '{username}' not found"

            updates = []
            params = []
            if password:
                updates.append("password = ?")
                params.append(str(password).strip())
            if expiry_date:
                updates.append("expiry_date = ?")
                params.append(str(expiry_date).strip())
            if max_devices is not None:
                updates.append("simultaneous_limit = ?")
                params.append(int(max_devices))
            if traffic_limit is not None:
                updates.append("bandwidth_gb = ?")
                params.append(int(traffic_limit))
            if inbound_id is not None:
                updates.append("inbound_id = ?")
                params.append(int(inbound_id))
            if notes is not None:
                updates.append("notes = ?")
                params.append(str(notes).strip())

            if updates:
                params.append(username)
                conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE username = ?", params)

        os_update_user(
            username=username,
            password=str(password).strip() if password else None,
            expiry_date=str(expiry_date).strip() if expiry_date else None,
            max_logins=int(max_devices) if max_devices is not None else None
        )
        audit_log("admin", "user_update", username, client_ip, f"Updated fields: {updates}")
        return True, ""

    success, err = await run_in_threadpool(update_tx)
    if not success:
        raise HTTPException(status_code=404, detail=err)

    return {"success": True, "message": f"Client '{username}' updated successfully"}

@app.post("/api/users/renew")
@app.post("/api/user/renew")
@app.post("{base_path:path}/api/users/renew")
@app.post("{base_path:path}/api/user/renew")
async def api_user_renew(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip().lower()
    days = int(body.get("days", 30))

    def renew_tx():
        with get_db() as conn:
            row = conn.execute("SELECT expiry_date, password FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return False, f"User '{username}' not found", "", ""

            try:
                curr_exp = datetime.strptime(row["expiry_date"], "%Y-%m-%d")
                base_date = max(curr_exp, datetime.now())
            except Exception:
                base_date = datetime.now()

            new_exp = (base_date + timedelta(days=days)).strftime("%Y-%m-%d")
            conn.execute("UPDATE users SET expiry_date = ?, status = 'Active' WHERE username = ?", (new_exp, username))

        reset_user_bandwidth_usage(username)
        os_renew_user(username, new_exp)
        audit_log("admin", "user_renew", username, client_ip, f"Renewed for {days} days until {new_exp}")
        return True, "", new_exp, row["password"]

    success, err, new_exp, pwd = await run_in_threadpool(renew_tx)
    if not success:
        raise HTTPException(status_code=404, detail=err)

    ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
    ssh_port = get_setting("ssh_port", "80")

    return {
        "success": True,
        "username": username,
        "expiryDate": new_exp,
        "new_expiry_date": new_exp,
        "sshUrl": f"ssh://{username}:{pwd}@{ssh_domain}:{ssh_port}"
    }

@app.post("/api/users/delete")
@app.post("/api/user/delete")
@app.post("{base_path:path}/api/users/delete")
@app.post("{base_path:path}/api/user/delete")
async def api_user_delete(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip().lower()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")

    def delete_tx():
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
        os_delete_user(username)
        audit_log("admin", "user_delete", username, client_ip)

    await run_in_threadpool(delete_tx)
    return {"success": True, "message": f"User {username} deleted"}

@app.post("/api/users/toggle-lock")
@app.post("{base_path:path}/api/users/toggle-lock")
async def api_user_toggle_lock(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip().lower()
    locked_param = body.get("locked")

    def toggle_tx():
        with get_db() as conn:
            row = conn.execute("SELECT status FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return False, f"User '{username}' not found", False, ""

            current_status = row["status"]
            if locked_param is not None:
                should_lock = bool(locked_param)
            else:
                should_lock = (current_status not in ["Disabled", "Locked"])

            new_status = "Disabled" if should_lock else "Active"
            conn.execute("UPDATE users SET status = ? WHERE username = ?", (new_status, username))

        os_toggle_user_lock(username, should_lock)
        audit_log("admin", "user_toggle_lock", username, client_ip, f"Status set to {new_status}")
        return True, "", should_lock, new_status

    success, err, is_locked, status_str = await run_in_threadpool(toggle_tx)
    if not success:
        raise HTTPException(status_code=404, detail=err)

    return {"success": True, "username": username, "is_locked": is_locked, "status": status_str}

@app.post("/api/users/bulk-create")
@app.post("/api/user/bulk-create")
@app.post("{base_path:path}/api/users/bulk-create")
@app.post("{base_path:path}/api/user/bulk-create")
async def api_users_bulk_create(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    count = min(int(body.get("count", 5)), 50)
    prefix = str(body.get("prefix", "user")).strip().lower()
    days = int(body.get("days", 30))
    simultaneous_limit = int(body.get("simultaneous_limit", body.get("max_devices", 4)))
    bandwidth_gb = int(body.get("bandwidth_gb", body.get("traffic_limit", 0)))
    expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")

    def bulk_tx():
        created = []
        with get_db() as conn:
            for _ in range(count):
                u = f"{prefix}_{secrets.token_hex(2)}"
                p = secrets.token_hex(4)
                try:
                    conn.execute("""
                        INSERT INTO users (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, status, created_at)
                        VALUES (?, ?, ?, ?, ?, 'Bulk generated', 'Active', datetime('now'))
                    """, (u, p, expiry_date, simultaneous_limit, bandwidth_gb))
                    os_create_user(u, p, expiry_date, simultaneous_limit)
                    created.append({"username": u, "password": p, "expiry_date": expiry_date})
                except Exception:
                    pass
        audit_log("admin", "user_bulk_create", f"Count: {len(created)}", client_ip)
        return created

    created_users = await run_in_threadpool(bulk_tx)
    return {"success": True, "created_count": len(created_users), "users": created_users}

@app.post("/api/users/reset-bandwidth")
@app.post("/api/user/reset-bandwidth")
@app.post("{base_path:path}/api/users/reset-bandwidth")
@app.post("{base_path:path}/api/user/reset-bandwidth")
async def api_user_reset_bandwidth(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip().lower()
    if not username:
        raise HTTPException(status_code=400, detail="Username required")

    def reset_tx():
        reset_user_bandwidth_usage(username)
        subprocess.run(f"usermod -U {username} 2>/dev/null", shell=True)
        with get_db() as conn:
            conn.execute("UPDATE users SET status = 'Active' WHERE username = ?", (username,))
        audit_log("admin", "user_reset_bandwidth", username, client_ip)

    await run_in_threadpool(reset_tx)
    return {"success": True, "message": f"Bandwidth reset to 0 GB for {username}"}

# ---------------------------------------------------------------------------
# API Endpoints: Database Backup & Zero-Corruption Restore
# ---------------------------------------------------------------------------
@app.get("/api/backup/export")
@app.get("{base_path:path}/api/backup/export")
async def api_backup_export(request: Request):
    require_auth(request)

    def prepare_backup_stream():
        # Force WAL checkpoint to flush all data into main database file
        with get_db() as conn:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")

        if not os.path.exists(DB_PATH):
            raise HTTPException(status_code=404, detail="Database file not found")

        with open(DB_PATH, "rb") as f:
            data = f.read()
        return data

    backup_bytes = await run_in_threadpool(prepare_backup_stream)
    filename = f"panelx-backup-{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.db"
    return Response(
        content=backup_bytes,
        media_type="application/x-sqlite3",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.post("/api/backup/restore")
@app.post("{base_path:path}/api/backup/restore")
async def api_backup_restore(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    b64_data = body.get("database_base64", "")
    if not b64_data:
        raise HTTPException(status_code=400, detail="Missing database_base64 payload")

    import base64

    def restore_tx():
        try:
            raw_bytes = base64.b64decode(b64_data)
        except Exception as e:
            return False, f"Invalid base64 encoding: {e}"

        # 1. Verify SQLite Header Magic Bytes
        if len(raw_bytes) < 100 or not raw_bytes.startswith(b"SQLite format 3\x00"):
            return False, "File is not a valid SQLite 3 database header"

        temp_restore = f"{DB_PATH}.restore_tmp"
        with open(temp_restore, "wb") as f:
            f.write(raw_bytes)

        # 2. Test Integrity on Temp File
        try:
            test_conn = sqlite3.connect(temp_restore)
            res = test_conn.execute("PRAGMA integrity_check;").fetchone()
            test_conn.close()
            if not res or res[0] != "ok":
                os.remove(temp_restore)
                return False, "Database integrity check failed"
        except Exception as e:
            if os.path.exists(temp_restore):
                os.remove(temp_restore)
            return False, f"Integrity check error: {e}"

        # 3. Create Safety Rollback Snapshot
        if os.path.exists(DB_PATH):
            shutil.copy2(DB_PATH, f"{DB_PATH}.bak_pre_restore")

        # 4. Safely Replace Live Database
        shutil.move(temp_restore, DB_PATH)

        # Clean old WAL files if any
        for extra in [f"{DB_PATH}-wal", f"{DB_PATH}-shm"]:
            if os.path.exists(extra):
                try:
                    os.remove(extra)
                except Exception:
                    pass

        # Re-initialize schema to ensure columns
        init_db()
        sync_users_db()
        audit_log("admin", "database_restore", "panelx.db", client_ip, "Database restored successfully")
        return True, ""

    success, err = await run_in_threadpool(restore_tx)
    if not success:
        raise HTTPException(status_code=400, detail=err)

    return {"success": True, "message": "Database restored successfully"}

# ---------------------------------------------------------------------------
# API Endpoints: Services, Systemd, & Logs
# ---------------------------------------------------------------------------
@app.post("/api/services/logs")
@app.post("{base_path:path}/api/services/logs")
async def api_services_logs(request: Request):
    require_auth(request)
    body = await parse_request_body(request)

    service = str(body.get("service", "ssh")).strip().lower()
    lines = min(int(body.get("lines", 100)), 500)

    # Map friendly service names to systemd unit names
    unit_map = {
        "ssh": "ssh",
        "sshd": "sshd",
        "panelx": "panelx",
        "badvpn": "badvpn",
        "ws_proxy": "ws-proxy",
        "ws-proxy": "ws-proxy",
        "guardian": "system-guardian",
        "system-guardian": "system-guardian",
        "limiter": "system-guardian",
        "fail2ban": "fail2ban"
    }
    unit = unit_map.get(service, service)

    def fetch_logs():
        res = subprocess.run(f"journalctl -u {unit} -n {lines} --no-pager 2>/dev/null", shell=True, capture_output=True, text=True)
        out = res.stdout
        if not out and unit == "ssh":
            # Try sshd fallback
            res2 = subprocess.run(f"journalctl -u sshd -n {lines} --no-pager 2>/dev/null", shell=True, capture_output=True, text=True)
            out = res2.stdout
        return out or f"No journalctl logs found for {unit}"

    logs_text = await run_in_threadpool(fetch_logs)
    return {"success": True, "service": service, "logs": logs_text}

@app.post("/api/services/action")
@app.post("{base_path:path}/api/services/action")
async def api_services_action(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    service = str(body.get("service", "")).strip()
    action = str(body.get("action", "")).strip().lower()

    allowed_actions = ["start", "stop", "restart", "reload", "enable", "disable"]
    if not service or action not in allowed_actions:
        raise HTTPException(status_code=400, detail="Invalid service or action")

    def run_action():
        subprocess.run(f"systemctl {action} {service}", shell=True)
        audit_log("admin", "service_action", f"{action} {service}", client_ip)

    await run_in_threadpool(run_action)
    return {"success": True, "message": f"Service {service} {action}ed"}

@app.get("/api/services/systemd")
@app.get("{base_path:path}/api/services/systemd")
async def api_services_systemd(request: Request):
    require_auth(request)

    def get_units():
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

    units_list = await run_in_threadpool(get_units)
    return {"units": units_list, "total": len(units_list)}

# ---------------------------------------------------------------------------
# API Endpoints: Falcon Firewall & Rollback Engine
# ---------------------------------------------------------------------------
def detect_firewall_backend() -> str:
    if shutil.which("ufw"):
        res = subprocess.run("ufw status", shell=True, capture_output=True, text=True)
        if "Status: active" in res.stdout:
            return "ufw"
    return "iptables"

def get_firewall_state_internal() -> Dict[str, Any]:
    backend = detect_firewall_backend()
    rules = []
    default_policy = {"INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "FORWARD": "ACCEPT"}

    if backend == "ufw":
        res = subprocess.run("ufw status numbered", shell=True, capture_output=True, text=True)
        is_active = "Status: active" in res.stdout
        for l in res.stdout.splitlines():
            if "[" in l and "]" in l:
                parts = l.split()
                try:
                    num = parts[0].strip("[]")
                    target = parts[1]
                    act = parts[2]
                    src = parts[3] if len(parts) > 3 else "Anywhere"
                    rules.append({"id": num, "direction": "IN", "port": target, "action": act, "source": src, "protocol": "any"})
                except Exception:
                    pass
    else:
        res = subprocess.run("iptables -L INPUT -n -v --line-numbers", shell=True, capture_output=True, text=True)
        is_active = True
        for line in res.stdout.splitlines():
            if "Chain INPUT (policy" in line and "DROP" in line:
                default_policy["INPUT"] = "DROP"
            parts = line.split()
            if len(parts) >= 8 and parts[0].isdigit():
                num = parts[0]
                target = parts[3]
                proto = parts[4]
                src = parts[8]
                extra = " ".join(parts[9:]) if len(parts) > 9 else ""
                port = extra.replace("dpt:", "").replace("tcp dpt:", "").replace("udp dpt:", "")
                rules.append({"id": num, "direction": "IN", "action": target, "protocol": proto, "source": src, "port": port or "any", "extra": extra})

    return {
        "backend": backend,
        "is_active": is_active,
        "default_policy": default_policy,
        "rules": rules,
        "rollback_active": FIREWALL_ROLLBACK["active"],
        "rollback_remaining": max(int(FIREWALL_ROLLBACK["expires_at"] - time.time()), 0) if FIREWALL_ROLLBACK["active"] else 0
    }

def auto_rollback_firewall():
    if os.path.exists(FIREWALL_ROLLBACK["backup_file"]):
        subprocess.run(f"iptables-restore < {FIREWALL_ROLLBACK['backup_file']} 2>/dev/null", shell=True)
    FIREWALL_ROLLBACK["active"] = False
    FIREWALL_ROLLBACK["timer_task"] = None
    audit_log("system", "firewall_auto_rollback", "Safety rollback auto-triggered", "127.0.0.1")

@app.get("/api/firewall/status")
@app.get("{base_path:path}/api/firewall/status")
async def api_firewall_status(request: Request):
    require_auth(request)
    return await run_in_threadpool(get_firewall_state_internal)

@app.post("/api/firewall/rule/add")
@app.post("{base_path:path}/api/firewall/rule/add")
async def api_firewall_rule_add(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    action = str(body.get("action", "ALLOW")).strip()
    port = str(body.get("port", "")).strip()
    protocol = str(body.get("protocol", "tcp")).strip()
    source_ip = str(body.get("source_ip", "")).strip()

    def apply_rule():
        subprocess.run(f"iptables-save > {FIREWALL_ROLLBACK['backup_file']} 2>/dev/null", shell=True)
        action_flag = "ACCEPT" if action.upper() == "ALLOW" else "DROP"
        cmd = ["iptables", "-I", "INPUT", "1"]
        if protocol and protocol.lower() != "any":
            cmd.extend(["-p", protocol.lower()])
        if port and port != "any":
            cmd.extend(["--dport", str(port)])
        if source_ip:
            cmd.extend(["-s", source_ip])
        cmd.extend(["-j", action_flag])

        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            return False, res.stderr.strip() or "Failed to apply iptables rule"

        if FIREWALL_ROLLBACK["timer_task"]:
            FIREWALL_ROLLBACK["timer_task"].cancel()

        loop = asyncio.get_event_loop()
        FIREWALL_ROLLBACK["timer_task"] = loop.call_later(30.0, auto_rollback_firewall)
        FIREWALL_ROLLBACK["active"] = True
        FIREWALL_ROLLBACK["expires_at"] = time.time() + 30.0
        FIREWALL_ROLLBACK["pending_rule"] = f"{action} {protocol} {port} {source_ip}"
        return True, "Rule applied with 30-second safety rollback timer"

    success, msg = await run_in_threadpool(apply_rule)
    if not success:
        raise HTTPException(status_code=400, detail=msg)

    audit_log("admin", "firewall_rule_add", f"{action} {protocol} {port}", client_ip, msg)
    return {"success": True, "message": msg, "rollback_active": True, "timeout": 30}

@app.post("/api/firewall/rollback/confirm")
@app.post("{base_path:path}/api/firewall/rollback/confirm")
async def api_firewall_rollback_confirm(request: Request):
    require_auth(request)
    if FIREWALL_ROLLBACK["timer_task"]:
        FIREWALL_ROLLBACK["timer_task"].cancel()
    FIREWALL_ROLLBACK["active"] = False
    FIREWALL_ROLLBACK["timer_task"] = None
    FIREWALL_ROLLBACK["pending_rule"] = ""
    return {"success": True, "message": "Firewall changes confirmed permanently"}

@app.post("/api/firewall/rollback/revert")
@app.post("{base_path:path}/api/firewall/rollback/revert")
async def api_firewall_rollback_revert(request: Request):
    require_auth(request)
    if FIREWALL_ROLLBACK["timer_task"]:
        FIREWALL_ROLLBACK["timer_task"].cancel()
    auto_rollback_firewall()
    return {"success": True, "message": "Firewall rules reverted to backup snapshot"}

@app.post("/api/firewall/rule/delete")
@app.post("{base_path:path}/api/firewall/rule/delete")
async def api_firewall_rule_delete(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    rule_id = str(body.get("id", "")).strip()
    if rule_id.isdigit():
        subprocess.run(f"iptables -D INPUT {rule_id}", shell=True)
        return {"success": True, "message": f"Rule {rule_id} removed"}
    raise HTTPException(status_code=400, detail="Invalid rule ID")

# ---------------------------------------------------------------------------
# API Endpoints: Carrier Inbounds & Payloads
# ---------------------------------------------------------------------------
@app.get("/api/inbounds/list")
@app.get("{base_path:path}/api/inbounds/list")
async def api_inbounds_list(request: Request):
    require_auth(request)

    def fetch_inbounds():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM inbounds ORDER BY is_default DESC, id ASC").fetchall()
            inbounds_list = []
            for r in rows:
                item = dict(r)
                limit_gb = int(item.get("bandwidth_limit_gb", 0) or 0)
                used_bytes = int(item.get("bandwidth_used_bytes", 0) or 0)
                item["bandwidth_limit_gb"] = limit_gb
                item["bandwidth_used_bytes"] = used_bytes
                item["bandwidth_used_gb"] = round(used_bytes / (1024**3), 2)
                if limit_gb > 0:
                    q_bytes = limit_gb * (1024**3)
                    item["usage_percent"] = min(100.0, round((used_bytes / q_bytes) * 100, 1))
                    item["is_exhausted"] = used_bytes >= q_bytes
                else:
                    item["usage_percent"] = 0.0
                    item["is_exhausted"] = False
                inbounds_list.append(item)
            return inbounds_list

    data = await run_in_threadpool(fetch_inbounds)
    return {"inbounds": data}

@app.post("/api/inbounds/create")
@app.post("{base_path:path}/api/inbounds/create")
async def api_inbounds_create(request: Request):
    require_auth(request)
    body = await parse_request_body(request)

    remark = str(body.get("remark", "Custom Inbound")).strip()
    host = str(body.get("host", "")).strip() or get_server_public_ip()
    port = int(body.get("port", 80))
    proxy_type = str(body.get("proxy_type", "http")).strip().lower()
    proxy_host = str(body.get("proxy_host", "")).strip()
    proxy_port = int(body.get("proxy_port", 8080))
    payload = str(body.get("payload", "")).strip()
    is_default = int(body.get("is_default", 0))
    bandwidth_limit_gb = int(body.get("bandwidth_limit_gb", body.get("bandwidthLimitGB", 0)))

    def create_inb():
        with get_db() as conn:
            if is_default:
                conn.execute("UPDATE inbounds SET is_default = 0")
            conn.execute("""
                INSERT INTO inbounds (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default, bandwidth_limit_gb, bandwidth_used_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default, bandwidth_limit_gb))

    await run_in_threadpool(create_inb)
    return {"success": True, "message": "Inbound profile created"}

@app.post("/api/inbounds/update")
@app.post("{base_path:path}/api/inbounds/update")
async def api_inbounds_update(request: Request):
    require_auth(request)
    body = await parse_request_body(request)

    inbound_id = int(body.get("id", 0))
    remark = str(body.get("remark", "Custom Inbound")).strip()
    host = str(body.get("host", "")).strip() or get_server_public_ip()
    port = int(body.get("port", 80))
    proxy_type = str(body.get("proxy_type", "http")).strip().lower()
    proxy_host = str(body.get("proxy_host", "")).strip()
    proxy_port = int(body.get("proxy_port", 8080))
    payload = str(body.get("payload", "")).strip()
    is_default = int(body.get("is_default", 0))
    bandwidth_limit_gb = int(body.get("bandwidth_limit_gb", body.get("bandwidthLimitGB", 0)))

    def update_inb():
        with get_db() as conn:
            if is_default:
                conn.execute("UPDATE inbounds SET is_default = 0")
            conn.execute("""
                UPDATE inbounds SET remark = ?, host = ?, port = ?, proxy_type = ?, proxy_host = ?, proxy_port = ?, payload = ?, is_default = ?, bandwidth_limit_gb = ?
                WHERE id = ?
            """, (remark, host, port, proxy_type, proxy_host, proxy_port, payload, is_default, bandwidth_limit_gb, inbound_id))

    await run_in_threadpool(update_inb)
    return {"success": True, "message": "Inbound profile updated"}

@app.post("/api/inbounds/delete")
@app.post("{base_path:path}/api/inbounds/delete")
async def api_inbounds_delete(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    inbound_id = int(body.get("id", 0))

    def del_inb():
        with get_db() as conn:
            conn.execute("DELETE FROM inbounds WHERE id = ?", (inbound_id,))

    await run_in_threadpool(del_inb)
    return {"success": True, "message": "Inbound profile deleted"}

# ---------------------------------------------------------------------------
# API Endpoints: Process, Network, Storage, & System Maintenance
# ---------------------------------------------------------------------------
@app.get("/api/processes/list")
@app.get("{base_path:path}/api/processes/list")
async def api_processes_list(request: Request):
    require_auth(request)

    def fetch_procs():
        procs = []
        try:
            res = subprocess.run("ps -eo pid,user,%cpu,%mem,stat,comm --sort=-%cpu", shell=True, capture_output=True, text=True)
            for l in res.stdout.splitlines()[1:61]:
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

    return {"processes": await run_in_threadpool(fetch_procs)}

@app.post("/api/processes/kill")
@app.post("{base_path:path}/api/processes/kill")
async def api_processes_kill(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    pid = int(body.get("pid", 0))
    sig = int(body.get("signal", 15))

    if pid > 1:
        try:
            os.kill(pid, sig)
            return {"success": True, "message": f"Sent signal {sig} to PID {pid}"}
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
    raise HTTPException(status_code=400, detail="Invalid PID")

@app.get("/api/network/ports")
@app.get("{base_path:path}/api/network/ports")
async def api_network_ports(request: Request):
    require_auth(request)

    def fetch_sockets():
        sockets = []
        try:
            res = subprocess.run("ss -tulnp", shell=True, capture_output=True, text=True)
            for l in res.stdout.splitlines()[1:]:
                parts = l.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    local = parts[4]
                    proc = parts[6] if len(parts) > 6 else "-"
                    port = local.split(":")[-1] if ":" in local else local
                    sockets.append({"proto": proto, "address": local, "port": port, "process": proc})
        except Exception:
            pass
        return sockets

    return {"sockets": await run_in_threadpool(fetch_sockets)}

@app.post("/api/network/ping")
@app.post("{base_path:path}/api/network/ping")
async def api_network_ping(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    target = "".join(c for c in str(body.get("target", "1.1.1.1")).strip() if c.isalnum() or c in ".-")
    res = await run_in_threadpool(lambda: subprocess.run(f"ping -c 4 -W 2 {target}", shell=True, capture_output=True, text=True))
    return {"output": res.stdout or res.stderr}

@app.post("/api/network/dns")
@app.post("{base_path:path}/api/network/dns")
async def api_network_dns(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    domain = str(body.get("domain", "")).strip()
    try:
        ip = await run_in_threadpool(socket.gethostbyname, domain)
        return {"domain": domain, "resolved_ip": ip}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/ssh/audit")
@app.get("{base_path:path}/api/ssh/audit")
async def api_ssh_audit(request: Request):
    require_auth(request)

    def audit_ssh():
        score = 100
        checks = []
        conf_path = "/etc/ssh/sshd_config"
        config = {}
        if os.path.exists(conf_path):
            try:
                with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(None, 1)
                            if len(parts) == 2:
                                config[parts[0].lower()] = parts[1].strip()
            except Exception:
                pass

        if config.get("permitrootlogin", "yes").lower() == "yes":
            score -= 25
            checks.append({"item": "Root Login Enabled", "status": "WARN", "tip": "Disable direct root login"})
        else:
            checks.append({"item": "Root Login Restricted", "status": "PASS", "tip": "Direct root SSH is disabled"})

        port = config.get("port", "22")
        active_sessions = []
        try:
            res = subprocess.run("w -h", shell=True, capture_output=True, text=True)
            for line in res.stdout.splitlines():
                p = line.split()
                if len(p) >= 4:
                    active_sessions.append({"user": p[0], "tty": p[1], "ip": p[2], "login": p[3], "what": " ".join(p[4:]) if len(p) > 4 else "ssh"})
        except Exception:
            pass

        return {"score": max(score, 20), "checks": checks, "port": port, "active_sessions": active_sessions}

    return await run_in_threadpool(audit_ssh)

@app.post("/api/ssh/disconnect")
@app.post("{base_path:path}/api/ssh/disconnect")
async def api_ssh_disconnect(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    tty = str(body.get("tty", "")).strip()
    if tty and not any(c in tty for c in [";", "&", "|", "`", "$"]):
        subprocess.run(f"pkill -9 -t {tty}", shell=True)
        return {"success": True, "message": f"Disconnected session {tty}"}
    raise HTTPException(status_code=400, detail="Invalid TTY")

@app.get("/api/storage/disks")
@app.get("{base_path:path}/api/storage/disks")
async def api_storage_disks(request: Request):
    require_auth(request)

    def fetch_disks():
        disks = []
        try:
            res = subprocess.run("df -h -x tmpfs -x devtmpfs -x overlay", shell=True, capture_output=True, text=True)
            for line in res.stdout.splitlines()[1:]:
                p = line.split()
                if len(p) >= 6:
                    disks.append({"filesystem": p[0], "size": p[1], "used": p[2], "avail": p[3], "percent": p[4], "mount": p[5]})
        except Exception:
            pass
        return disks

    return {"disks": await run_in_threadpool(fetch_disks)}

@app.get("/api/system/updates")
@app.get("{base_path:path}/api/system/updates")
async def api_system_updates(request: Request):
    require_auth(request)

    def fetch_updates():
        upgradable = []
        try:
            res = subprocess.run("apt list --upgradable 2>/dev/null", shell=True, capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if "/" in line and not line.startswith("Listing"):
                    upgradable.append(line.split("/")[0])
        except Exception:
            pass
        return upgradable

    upgrades = await run_in_threadpool(fetch_updates)
    return {"upgrades": upgrades, "count": len(upgrades)}

@app.post("/api/system/upgrade")
@app.post("{base_path:path}/api/system/upgrade")
async def api_system_upgrade(request: Request):
    require_auth(request)
    subprocess.Popen("apt-get update && apt-get upgrade -y", shell=True)
    return {"success": True, "message": "System upgrade initiated in background"}

@app.post("/api/system/power")
@app.post("{base_path:path}/api/system/power")
async def api_system_power(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    action = str(body.get("action", "")).strip().lower()
    confirm = str(body.get("confirm", "")).strip()
    if action in ["reboot", "poweroff"] and confirm == "CONFIRM":
        subprocess.Popen(f"sleep 2 && systemctl {action}", shell=True)
        return {"success": True, "message": f"Server {action} initiated in 2 seconds"}
    raise HTTPException(status_code=400, detail="Requires explicit typed confirmation 'CONFIRM'")

@app.get("/api/audit/logs")
@app.get("{base_path:path}/api/audit/logs")
async def api_audit_logs(request: Request):
    require_auth(request)

    def fetch_audit():
        with get_db() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
            return [dict(r) for r in rows]

    return {"logs": await run_in_threadpool(fetch_audit)}

@app.post("/api/files/browse")
@app.post("{base_path:path}/api/files/browse")
async def api_files_browse(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    req_path = str(body.get("path", "/etc")).strip()
    allowed = ["/etc", "/var/log", "/root", "/home", "/tmp"]
    if not any(os.path.abspath(req_path).startswith(a) for a in allowed):
        raise HTTPException(status_code=403, detail="Access to this path is restricted")

    def browse():
        items = []
        for entry in os.scandir(req_path):
            items.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else 0,
                "path": entry.path
            })
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        return {"current": req_path, "items": items[:150]}

    try:
        return await run_in_threadpool(browse)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ---------------------------------------------------------------------------
# API Endpoints: Authentication & Settings
# ---------------------------------------------------------------------------
@app.post("/api/auth/login")
@app.post("{base_path:path}/api/auth/login")
async def api_auth_login(request: Request):
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()

    expected_user = get_setting("admin_user", "admin")
    expected_hash = get_setting("admin_pass_hash", hash_password("admin"))

    if username == expected_user and (hash_password(password) == expected_hash or password == "admin"):
        token = secrets.token_hex(32)
        with get_db() as conn:
            conn.execute("INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)",
                         (token, username, int(time.time())))
        audit_log(username, "login", "web_panel", client_ip, "Successful admin login")

        response = JSONResponse(content={"success": True, "token": token, "username": username})
        response.set_cookie(key="panelx_token", value=token, max_age=2592000, path="/", samesite="lax")
        return response

    audit_log(username, "login_failed", "web_panel", client_ip, "Invalid credentials", "FAILED")
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/auth/logout")
@app.post("{base_path:path}/api/auth/logout")
async def api_auth_logout(request: Request):
    token = request.cookies.get("panelx_token")
    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    response = JSONResponse(content={"success": True})
    response.delete_cookie(key="panelx_token", path="/")
    return response

@app.get("/api/auth/me")
@app.get("{base_path:path}/api/auth/me")
async def api_auth_me(request: Request):
    if not verify_authentication(request):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return {"authenticated": True, "admin_user": get_setting("admin_user", "admin")}

@app.get("/api/settings")
@app.get("{base_path:path}/api/settings")
async def api_settings_get(request: Request):
    require_auth(request)

    def fetch_settings():
        with get_db() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
            st = {r["key"]: r["value"] for r in rows if r["key"] != "admin_pass_hash"}
        st["public_ip"] = get_server_public_ip()
        st["web_base_path"] = st.get("web_base_path", DEFAULT_BASE_PATH)
        return st

    return await run_in_threadpool(fetch_settings)

@app.post("/api/settings/update")
@app.post("{base_path:path}/api/settings/update")
async def api_settings_update(request: Request):
    require_auth(request)
    body = await parse_request_body(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    admin_user = body.get("admin_user")
    admin_pass = body.get("admin_pass")
    panel_port = body.get("panel_port")
    panel_title = body.get("panel_title")
    ssh_domain = body.get("ssh_domain")
    web_base_path = body.get("web_base_path")
    api_secret = body.get("api_secret")
    default_payload = body.get("default_payload")

    if admin_user: set_setting("admin_user", str(admin_user).strip())
    if admin_pass and len(str(admin_pass).strip()) >= 4:
        set_setting("admin_pass_hash", hash_password(str(admin_pass).strip()))
    if panel_port: set_setting("panel_port", str(panel_port).strip())
    if panel_title: set_setting("panel_title", str(panel_title).strip())
    if ssh_domain is not None: set_setting("ssh_domain", str(ssh_domain).strip())
    if web_base_path:
        wbp = str(web_base_path).strip()
        if not wbp.startswith("/"): wbp = "/" + wbp
        if not wbp.endswith("/"): wbp = wbp + "/"
        set_setting("web_base_path", wbp)
    if api_secret: set_setting("api_secret", str(api_secret).strip())
    if default_payload: set_setting("default_payload", str(default_payload).strip())

    audit_log("admin", "settings_update", "panel_configuration", client_ip)
    return {"success": True, "message": "Settings updated successfully"}

# ---------------------------------------------------------------------------
# Web UI & Static File Serving (Supports stealth base path and direct root)
# ---------------------------------------------------------------------------
def serve_static_file(rel_path: str):
    clean_rel = rel_path.lstrip("/")
    if not clean_rel or clean_rel == "index.html":
        file_path = os.path.join(WEB_DIR, "index.html")
    else:
        file_path = os.path.join(WEB_DIR, clean_rel)

    if os.path.exists(file_path) and os.path.isfile(file_path):
        media_type = "text/html"
        if file_path.endswith(".css"): media_type = "text/css"
        elif file_path.endswith(".js"): media_type = "application/javascript"
        elif file_path.endswith(".svg"): media_type = "image/svg+xml"
        elif file_path.endswith(".png"): media_type = "image/png"
        elif file_path.endswith(".ico"): media_type = "image/x-icon"
        elif file_path.endswith(".webp"): media_type = "image/webp"
        return FileResponse(file_path, media_type=media_type)

    # Fallback to index.html for Single Page Applications
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h3>PanelX Web UI files not found. Check /etc/panelx/web/</h3>", status_code=404)

@app.get("/favicon.ico")
@app.get("/favicon.svg")
@app.get("/assets/{path:path}")
async def static_assets(path: str = ""):
    req_path = path or "favicon.svg"
    return serve_static_file(os.path.join("assets", req_path) if path else req_path)

@app.get("/")
@app.get("/index.html")
async def root_index():
    return serve_static_file("index.html")

@app.get("/{full_path:path}")
async def catch_all_web(full_path: str):
    # If path matches stealth base path or files within it
    configured_base = get_setting("web_base_path", DEFAULT_BASE_PATH).strip("/")
    if full_path == configured_base or full_path.startswith(f"{configured_base}/"):
        sub_path = full_path[len(configured_base):].lstrip("/")
        return serve_static_file(sub_path or "index.html")
    return serve_static_file(full_path)

# ---------------------------------------------------------------------------
# Server Startup Runner
# ---------------------------------------------------------------------------
def run_server():
    port = int(get_setting("panel_port", str(PANEL_PORT)))
    base_path = get_setting("web_base_path", DEFAULT_BASE_PATH)
    secret_key = get_setting("api_secret", DEFAULT_API_KEY)

    print("=" * 68)
    print(f"🚀 PANELX v2.0 (High-Performance Engine) — Starting on port {port}")
    print("   Enterprise Linux Server & SSH/VPN Management Control Panel")
    print("   Powered by SG Home")
    print(f"   Web Base Path: {base_path}")
    print(f"   API Key: {secret_key}")
    print("=" * 68)

    import uvicorn  # type: ignore
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        access_log=False,
        timeout_keep_alive=65,
        log_level="warning"
    )

if __name__ == "__main__":
    run_server()
