#!/usr/bin/env python3
"""
=============================================================================
PanelX - Modern Open-Source SSH & WebSocket VPN Management Panel
Author: Weranga Nimsara (SG Home) & Open-Source Contributors
Version: 1.0.0
=============================================================================
"""

import http.server
import socketserver
import json
import sqlite3
import hashlib
import os
import sys
import subprocess
import time
import shutil
import urllib.parse
import secrets
from datetime import datetime, timedelta

# Configuration Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = "/etc/panelx" if os.path.exists("/etc") and os.access("/etc", os.W_OK) else BASE_DIR
DB_FILE = os.path.join(DATA_DIR, "panelx.db")
WEB_DIR = os.path.join(BASE_DIR, "web")
os.makedirs(DATA_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Database Initialization & Management
# ---------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Settings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    
    # Users table
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
    
    # Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    
    # Set default settings if not exists
    defaults = {
        "admin_user": "admin",
        "admin_pass_hash": hash_password("admin"),
        "panel_port": "7788",
        "panel_title": "PanelX Manager",
        "ssh_domain": "",
        "ssh_port": "80",
        "badvpn_port": "7300",
        "api_secret": secrets.token_hex(24),
        "default_payload": "GET /cdn-cgi/trace HTTP/1.1[crlf]Host: partner.zoom.us[crlf][crlf][split]UNLOCK /? HTTP/1.1[crlf]Host: [host][crlf]Connection: upgrade[crlf]User-Agent: [ua][crlf]Upgrade: websocket[crlf][crlf]"
    }
    
    for k, v in defaults.items():
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
        
    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------------------------
# System Helpers
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
        res = subprocess.run("curl -s -4 ifconfig.me || curl -s -4 icanhazip.com", shell=True, capture_output=True, text=True, timeout=3)
        ip = res.stdout.strip()
        if ip: return ip
    except:
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
    except:
        return 0, 0, 0, 0

    now = time.time()
    dt = max(now - _prev_net["time"], 0.1)
    rx_speed_kb = round((rx_bytes - _prev_net["rx"]) / (1024 * dt), 1)
    tx_speed_kb = round((tx_bytes - _prev_net["tx"]) / (1024 * dt), 1)

    _prev_net = {"time": now, "rx": rx_bytes, "tx": tx_bytes}
    return rx_speed_kb, tx_speed_kb, rx_bytes, tx_bytes

def get_system_stats():
    # 1. CPU
    cpu_percent = 0.0
    try:
        load = os.getloadavg()
        cpu_cores = os.cpu_count() or 1
        cpu_percent = round(min((load[0] / cpu_cores) * 100, 100.0), 1)
    except:
        pass

    # 2. RAM
    mem_total_mb = 1
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
    except:
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
    except:
        pass

    # 4. Uptime
    uptime_str = "0d 0h"
    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.readline().split()[0])
            days = int(secs // 86400)
            hours = int((secs % 86400) // 3600)
            uptime_str = f"{days}d {hours}h"
    except:
        pass

    # 5. Open Sockets
    sockets_count = 0
    try:
        with open("/proc/net/tcp", "r") as f:
            sockets_count += max(len(f.readlines()) - 1, 0)
    except:
        pass

    rx_speed, tx_speed, total_rx, total_tx = get_network_speed()

    return {
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
        "public_ip": get_server_public_ip()
    }

# ---------------------------------------------------------------------------
# Linux Account Management (System Enforcements)
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
    except:
        pass

def os_create_user(username: str, password: str, expiry_date: str, max_logins: int = 3):
    clean_user = username.strip().lower()
    # 1. Delete if previously exists
    subprocess.run(f"userdel -r {clean_user} 2>/dev/null", shell=True)
    
    # 2. Add with expiration date and disabled shell
    res1 = subprocess.run(f"useradd -e {expiry_date} -s /bin/false -M {clean_user}", shell=True)
    if res1.returncode != 0:
        # Retry with minimal flags
        subprocess.run(f"useradd -s /bin/false {clean_user}", shell=True)
        subprocess.run(f"chage -E {expiry_date} {clean_user}", shell=True)

    # 3. Set password
    p = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.communicate(f"{clean_user}:{password}\n")

    # 4. Limit simultaneous logins
    try:
        subprocess.run(f"sed -i '/^{clean_user} /d' /etc/security/limits.conf 2>/dev/null", shell=True)
        subprocess.run(f"echo '{clean_user} hard maxlogins {max_logins}' >> /etc/security/limits.conf", shell=True)
    except:
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
    except:
        return False

# ---------------------------------------------------------------------------
# HTTP API & Web Request Handler
# ---------------------------------------------------------------------------
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class PanelXHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy standard request logging
        pass

    def send_json(self, status_code: int, data: dict):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key")
        self.end_headers()

    def get_auth_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth.split(" ")[1].strip()
        # Check cookie
        cookie_header = self.headers.get("Cookie", "")
        if "panelx_token=" in cookie_header:
            for c in cookie_header.split(";"):
                if "panelx_token=" in c:
                    return c.split("panelx_token=")[1].strip()
        return ""

    def is_authenticated(self) -> bool:
        # Check API key header
        api_key = self.headers.get("x-api-key")
        if api_key and api_key == get_setting("api_secret"):
            return True

        token = self.get_auth_token()
        if not token:
            return False
        conn = get_db()
        row = conn.execute("SELECT username FROM sessions WHERE token = ?", (token,)).fetchone()
        conn.close()
        return row is not None

    def read_json_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0: return {}
            body = self.rfile.read(length)
            return json.loads(body.decode("utf-8"))
        except:
            return {}

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        # 1. API: System Status
        if path == "/api/system/status":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Unauthorized"})
                return
            stats = get_system_stats()
            stats["services"] = {
                "ssh": check_service_status("ssh") or check_service_status("sshd"),
                "ws_proxy": check_service_status("ws-proxy") or check_service_status("panelx-ws"),
                "badvpn": check_service_status("badvpn") or check_service_status("badvpn-udpgw")
            }
            stats["panel_title"] = get_setting("panel_title", "PanelX Manager")
            self.send_json(200, stats)
            return

        # 2. API: Users List
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

            # Enrich with generated SSH URL
            for u in users:
                u["ssh_url"] = f"ssh://{u['username']}:{u['password']}@{ssh_domain}:{ssh_port}"
                try:
                    exp = datetime.strptime(u["expiry_date"], "%Y-%m-%d")
                    days_left = (exp - datetime.now()).days
                    u["days_left"] = max(days_left, 0)
                    u["is_expired"] = days_left < 0
                except:
                    u["days_left"] = 0
                    u["is_expired"] = False

            self.send_json(200, {"users": users, "total": len(users)})
            return

        # 3. API: Settings
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

        # 4. API: Me (Check Session)
        elif path == "/api/auth/me":
            if not self.is_authenticated():
                self.send_json(401, {"error": "Not authenticated"})
                return
            self.send_json(200, {"authenticated": True, "admin_user": get_setting("admin_user", "admin")})
            return

        # 5. Serve Web Static Files / UI
        else:
            self.serve_web_ui(path)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        body = self.read_json_body()

        # 1. Login
        if path == "/api/auth/login":
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()

            expected_user = get_setting("admin_user", "admin")
            expected_hash = get_setting("admin_pass_hash", hash_password("admin"))

            if username == expected_user and hash_password(password) == expected_hash:
                token = secrets.token_hex(32)
                conn = get_db()
                conn.execute("INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)", (token, username, int(time.time())))
                conn.commit()
                conn.close()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"panelx_token={token}; Path=/; HttpOnly; Max-Age=2592000")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "token": token}).encode("utf-8"))
                return
            else:
                self.send_json(401, {"error": "Invalid username or password"})
                return

        # 2. Logout
        elif path == "/api/auth/logout":
            token = self.get_auth_token()
            if token:
                conn = get_db()
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
            self.send_json(200, {"success": True})
            return

        # All other POST routes require auth
        if not self.is_authenticated():
            self.send_json(401, {"error": "Unauthorized"})
            return

        # 3. Create Single User
        if path == "/api/users/create":
            username = body.get("username", "").strip().lower().replace(" ", "")
            password = body.get("password", "").strip()
            days = int(body.get("days", 30))
            max_logins = int(body.get("simultaneous_limit", 3))
            bandwidth_gb = int(body.get("bandwidth_gb", 0))
            notes = body.get("notes", "").strip()

            if not username or not password:
                self.send_json(400, {"error": "Username and password required"})
                return

            expiry_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            conn = get_db()
            try:
                conn.execute("""
                    INSERT INTO users (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'Active', ?)
                """, (username, password, expiry_date, max_logins, bandwidth_gb, notes, created_at))
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                self.send_json(400, {"error": f"Username '{username}' already exists"})
                return
            conn.close()

            # Execute Linux User Creation
            os_create_user(username, password, expiry_date, max_logins)

            ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
            ssh_port = get_setting("ssh_port", "80")

            self.send_json(200, {
                "success": True,
                "user": {
                    "username": username,
                    "password": password,
                    "expiry_date": expiry_date,
                    "ssh_url": f"ssh://{username}:{password}@{ssh_domain}:{ssh_port}"
                }
            })
            return

        # 4. Bulk Create Users
        elif path == "/api/users/bulk-create":
            count = min(int(body.get("count", 5)), 50)
            prefix = body.get("prefix", "user").strip().lower()
            days = int(body.get("days", 30))
            max_logins = int(body.get("simultaneous_limit", 3))

            created = []
            conn = get_db()
            ssh_domain = get_setting("ssh_domain") or get_server_public_ip()
            ssh_port = get_setting("ssh_port", "80")

            for _ in range(count):
                u_name = f"{prefix}_{secrets.token_hex(2)}"
                u_pass = secrets.token_hex(4)
                exp_date = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
                created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                try:
                    conn.execute("""
                        INSERT INTO users (username, password, expiry_date, simultaneous_limit, bandwidth_gb, notes, status, created_at)
                        VALUES (?, ?, ?, ?, 0, 'Bulk Created', 'Active', ?)
                    """, (u_name, u_pass, exp_date, max_logins, created_at))
                    conn.commit()

                    os_create_user(u_name, u_pass, exp_date, max_logins)
                    created.append({
                        "username": u_name,
                        "password": u_pass,
                        "expiry_date": exp_date,
                        "ssh_url": f"ssh://{u_name}:{u_pass}@{ssh_domain}:{ssh_port}"
                    })
                except:
                    continue

            conn.close()
            self.send_json(200, {"success": True, "created_count": len(created), "users": created})
            return

        # 5. Renew User
        elif path == "/api/users/renew":
            username = body.get("username", "").strip().lower()
            days = int(body.get("days", 30))

            conn = get_db()
            row = conn.execute("SELECT expiry_date FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                conn.close()
                self.send_json(404, {"error": "User not found"})
                return

            try:
                curr_exp = datetime.strptime(row["expiry_date"], "%Y-%m-%d")
                start_date = curr_exp if curr_exp > datetime.now() else datetime.now()
            except:
                start_date = datetime.now()

            new_exp = (start_date + timedelta(days=days)).strftime("%Y-%m-%d")
            conn.execute("UPDATE users SET expiry_date = ?, status = 'Active' WHERE username = ?", (new_exp, username))
            conn.commit()
            conn.close()

            os_renew_user(username, new_exp)
            self.send_json(200, {"success": True, "username": username, "new_expiry_date": new_exp})
            return

        # 6. Delete User
        elif path == "/api/users/delete":
            username = body.get("username", "").strip().lower()
            conn = get_db()
            conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            conn.close()

            os_delete_user(username)
            self.send_json(200, {"success": True, "message": f"User {username} deleted"})
            return

        # 7. Service Action (Start / Stop / Restart)
        elif path == "/api/services/action":
            service = body.get("service", "").strip()
            action = body.get("action", "").strip()
            if service in ["ssh", "ws-proxy", "badvpn"] and action in ["start", "stop", "restart"]:
                subprocess.run(f"systemctl {action} {service}", shell=True)
                self.send_json(200, {"success": True, "message": f"Service {service} {action}ed"})
                return
            self.send_json(400, {"error": "Invalid service or action"})
            return

        # 8. Update Settings
        elif path == "/api/settings/update":
            admin_user = body.get("admin_user")
            admin_pass = body.get("admin_pass")
            panel_port = body.get("panel_port")
            panel_title = body.get("panel_title")
            ssh_domain = body.get("ssh_domain")
            default_payload = body.get("default_payload")

            if admin_user: set_setting("admin_user", admin_user.strip())
            if admin_pass: set_setting("admin_pass_hash", hash_password(admin_pass.strip()))
            if panel_port: set_setting("panel_port", str(panel_port).strip())
            if panel_title: set_setting("panel_title", panel_title.strip())
            if ssh_domain is not None: set_setting("ssh_domain", ssh_domain.strip())
            if default_payload: set_setting("default_payload", default_payload.strip())

            self.send_json(200, {"success": True, "message": "Settings updated successfully"})
            return

        self.send_json(404, {"error": "Endpoint not found"})

    def serve_web_ui(self, path: str):
        # Clean path
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

            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            # Fallback to index.html for Single-Page Application routing
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
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"PanelX Web UI files not found in web/ directory.")

# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------
def main():
    port = int(get_setting("panel_port", "7788"))
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])

    server_address = ("0.0.0.0", port)
    httpd = ThreadedHTTPServer(server_address, PanelXHandler)

    pub_ip = get_server_public_ip()
    print("=" * 60)
    print("🚀 PanelX Manager - SSH & WebSocket Control Panel")
    print(f"📡 Web Interface: http://{pub_ip}:{port}")
    print(f"🔑 Default Admin: admin / admin")
    print(f"💾 SQLite Database: {DB_FILE}")
    print("=" * 60)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[PanelX] Shutting down...")
        httpd.server_close()

if __name__ == "__main__":
    main()
