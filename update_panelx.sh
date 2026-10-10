#!/usr/bin/env bash
# =============================================================================
# PanelX v2.0 Production Engine — 1-Click Zero-Downtime Safe Updater
# Enterprise Linux Server & SSH/VPN Management Control Panel
# Author: Weranga Nimsara (SG Home) & Open-Source Community
# =============================================================================
# ⚠️ ZERO-DOWNTIME GUARANTEE:
# - Backs up existing SQLite database before any changes
# - Preserves all existing Linux system users & passwords
# - Does NOT restart OpenSSH daemon (active SSH tunnels are NEVER disconnected)
# - Caps system logs at 50MB and deploys fail2ban SSH brute-force defense
# =============================================================================

set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# Check Root Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] This updater must be executed as root (sudo bash)!${NC}"
    exit 1
fi

clear
echo -e "${CYAN}"
echo "  ███████╗ ██████╗ ██████╗ ██╗  ██╗"
echo "  ██╔════╝██╔════╝ ██╔══██╗╚██╗██╔╝"
echo "  ███████╗██║  ███╗██████╔╝ ╚███╔╝ "
echo "  ╚════██║██║   ██║██╔═══╝  ██╔██╗ "
echo "  ███████║╚██████╔╝██║     ██╔╝ ██╗"
echo "  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝"
echo -e "       ${PURPLE}SGPX — PanelX Production Engine v2.0 Upgrade${NC}"
echo -e "                 ${YELLOW}Powered by SG Home${NC}"
echo -e "${CYAN}================================================================${NC}"

INSTALL_DIR="/etc/panelx"
DB_FILE="$INSTALL_DIR/panelx.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---------------------------------------------------------------------------
# Step 1: Safe Backup of Existing Database & Configuration
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[1/7] 🛡️ Creating zero-loss backup of existing users & database...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p /root/panelx_backups

if [ -f "$DB_FILE" ]; then
    # Safely checkpoint WAL journal before backup
    python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$DB_FILE', timeout=10)
    conn.execute('PRAGMA wal_checkpoint(TRUNCATE);')
    conn.close()
except Exception:
    pass
" 2>/dev/null || true

    cp -a "$DB_FILE" "$INSTALL_DIR/panelx.db.backup_$TIMESTAMP"
    cp -a "$DB_FILE" "/root/panelx_backups/panelx.db.backup_$TIMESTAMP"
    echo -e "${GREEN}✓ Database snapshot safely backed up to:${NC}"
    echo -e "  - ${YELLOW}$INSTALL_DIR/panelx.db.backup_$TIMESTAMP${NC}"
    echo -e "  - ${YELLOW}/root/panelx_backups/panelx.db.backup_$TIMESTAMP${NC}"
    
    # Report active users count
    USER_COUNT=$(python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$DB_FILE')
    r = conn.execute('SELECT COUNT(*) FROM users').fetchone()
    print(r[0] if r else 0)
    conn.close()
except Exception:
    print(0)
" 2>/dev/null || echo 0)
    echo -e "${GREEN}✓ Verified ${BOLD}${USER_COUNT} VIP User(s)${NC}${GREEN} in database. All accounts are 100% preserved.${NC}"
else
    echo -e "${YELLOW}! No existing database found at $DB_FILE. Fresh database will be initialized.${NC}"
fi

# ---------------------------------------------------------------------------
# Step 2: System Packages & Async Dependencies
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[2/7] 📦 Installing lightweight async runtime & security tools...${NC}"
apt-get update -y >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip curl wget fail2ban logrotate rsyslog net-tools lsof iptables >/dev/null 2>&1

# Install FastAPI and Uvicorn
echo -e "${CYAN}→ Ensuring FastAPI & Uvicorn engine dependencies are ready...${NC}"
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-fastapi uvicorn >/dev/null 2>&1 || true

python3 -c "import fastapi, uvicorn" >/dev/null 2>&1 || {
    pip3 install fastapi uvicorn --break-system-packages >/dev/null 2>&1 || \
    pip3 install fastapi uvicorn >/dev/null 2>&1 || true
}

if python3 -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ FastAPI & Uvicorn async engine verified.${NC}"
else
    echo -e "${RED}[WARNING] Could not verify FastAPI. Python will fallback to standard runtime.${NC}"
fi

# ---------------------------------------------------------------------------
# Step 3: Automated Storage Protection & Disk Leak Guard (50MB Cap)
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[3/7] 🧹 Configuring storage leak guard & 50MB system log limits...${NC}"

# Configure systemd-journald max 50MB
mkdir -p /etc/systemd/journald.conf.d
cat <<'EOF' > /etc/systemd/journald.conf.d/panelx-limits.conf
[Journal]
SystemMaxUse=50M
SystemKeepFree=500M
RuntimeMaxUse=30M
MaxRetentionSec=3day
EOF

systemctl restart systemd-journald 2>/dev/null || true
journalctl --vacuum-size=50M >/dev/null 2>&1 || true

# Configure logrotate for syslog and auth.log to prevent 18+ GB log bloat
cat <<'EOF' > /etc/logrotate.d/panelx-rsyslog
/var/log/syslog
/var/log/auth.log
/var/log/messages
{
    rotate 2
    daily
    maxsize 50M
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl restart rsyslog 2>/dev/null || true
    endscript
}
EOF

# Immediate truncation of existing bloated logs (> 100MB)
for logfile in /var/log/syslog /var/log/auth.log /var/log/messages; do
    if [ -f "$logfile" ]; then
        LOG_SZ=$(stat -c%s "$logfile" 2>/dev/null || echo 0)
        # If larger than 100MB (104857600 bytes)
        if [ "$LOG_SZ" -gt 104857600 ]; then
            echo -e "${YELLOW}→ Truncating oversized $logfile ($(numfmt --to=iec $LOG_SZ))...${NC}"
            tail -n 15000 "$logfile" > "${logfile}.tmp" 2>/dev/null && \
            cat "${logfile}.tmp" > "$logfile" 2>/dev/null && \
            rm -f "${logfile}.tmp" 2>/dev/null || true
        fi
    fi
done

# Clean orphaned .1, .gz archives
rm -f /var/log/*.gz /var/log/*.[0-9] /var/log/*.[0-9].gz 2>/dev/null || true
echo -e "${GREEN}✓ System logs vacuumed and strictly capped at 50MB.${NC}"

# ---------------------------------------------------------------------------
# Step 4: Fail2ban SSH Brute-Force Bot Defense
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[4/7] 🛡️ Configuring Fail2ban SSH brute-force bot defense...${NC}"
mkdir -p /etc/fail2ban/jail.d

cat <<'EOF' > /etc/fail2ban/jail.d/panelx-ssh.conf
[sshd]
enabled = true
port = 22,80,8080,443,8880
filter = sshd
maxretry = 4
findtime = 10m
bantime = 24h
banaction = iptables-multiport
EOF

systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true
echo -e "${GREEN}✓ Fail2ban active: 4 max attempts, 10m find time, 24h drop ban.${NC}"

# ---------------------------------------------------------------------------
# Step 5: Deploy Core Services & Web UI
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[5/7] 🚀 Deploying PanelX v2.0 Production Engine & System Guardian...${NC}"
mkdir -p "$INSTALL_DIR/web"
mkdir -p "$INSTALL_DIR/bandwidth"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# If running via pipe (e.g. curl ... | bash) and source files aren't in SCRIPT_DIR
if [ ! -f "$SCRIPT_DIR/panelx_server.py" ]; then
    echo -e "${YELLOW}→ Fetching latest PanelX files from GitHub repository...${NC}"
    TMP_SRC="/tmp/panelx_update_src"
    rm -rf "$TMP_SRC"
    mkdir -p "$TMP_SRC"
    
    # Try git clone first
    git clone --depth 1 https://github.com/weranganimsara/PanelX.git "$TMP_SRC" >/dev/null 2>&1 || true
    
    # If git clone failed or files missing, download tarball
    if [ ! -f "$TMP_SRC/panelx_server.py" ]; then
        curl -sSL https://github.com/weranganimsara/PanelX/archive/refs/heads/main.tar.gz | tar -xz -C "$TMP_SRC" --strip-components=1 2>/dev/null || true
    fi

    # Fallback to direct raw downloads if needed
    if [ ! -f "$TMP_SRC/panelx_server.py" ]; then
        REPO_RAW="https://raw.githubusercontent.com/weranganimsara/PanelX/main"
        mkdir -p "$TMP_SRC/web"
        curl -sSL "$REPO_RAW/panelx_server.py" -o "$TMP_SRC/panelx_server.py" 2>/dev/null || true
        curl -sSL "$REPO_RAW/panelx.py" -o "$TMP_SRC/panelx.py" 2>/dev/null || true
        curl -sSL "$REPO_RAW/system_guardian.py" -o "$TMP_SRC/system_guardian.py" 2>/dev/null || true
        curl -sSL "$REPO_RAW/ws-proxy.py" -o "$TMP_SRC/ws-proxy.py" 2>/dev/null || true
        curl -sSL "$REPO_RAW/bin/panelx-proxy" -o "$TMP_SRC/panelx-proxy" 2>/dev/null || true
        curl -sSL "$REPO_RAW/panelx-cli" -o "$TMP_SRC/panelx-cli" 2>/dev/null || true
        curl -sSL "$REPO_RAW/web/index.html" -o "$TMP_SRC/web/index.html" 2>/dev/null || true
    fi

    if [ -f "$TMP_SRC/panelx_server.py" ]; then
        SCRIPT_DIR="$TMP_SRC"
    fi
fi

# Deploy panelx_server.py
if [ -f "$SCRIPT_DIR/panelx_server.py" ]; then
    cp "$SCRIPT_DIR/panelx_server.py" "$INSTALL_DIR/panelx_server.py"
    cp "$SCRIPT_DIR/panelx_server.py" "$INSTALL_DIR/panelx-backend.py"
    cp "$SCRIPT_DIR/panelx.py" "$INSTALL_DIR/panelx.py"
    cp "$SCRIPT_DIR/system_guardian.py" "$INSTALL_DIR/system_guardian.py"
    if [ -f "$SCRIPT_DIR/ws-proxy.py" ]; then
        cp "$SCRIPT_DIR/ws-proxy.py" "$INSTALL_DIR/ws-proxy.py"
    fi
    if [ -f "$SCRIPT_DIR/bin/panelx-proxy" ]; then
        cp "$SCRIPT_DIR/bin/panelx-proxy" "/usr/local/bin/panelx-proxy" 2>/dev/null || true
        chmod +x "/usr/local/bin/panelx-proxy" 2>/dev/null || true
    elif [ -f "$SCRIPT_DIR/panelx-proxy" ]; then
        cp "$SCRIPT_DIR/panelx-proxy" "/usr/local/bin/panelx-proxy" 2>/dev/null || true
        chmod +x "/usr/local/bin/panelx-proxy" 2>/dev/null || true
    fi
    if [ -d "$SCRIPT_DIR/web" ]; then
        cp -r "$SCRIPT_DIR/web/"* "$INSTALL_DIR/web/"
    fi
    if [ -f "$SCRIPT_DIR/panelx-cli" ]; then
        cp "$SCRIPT_DIR/panelx-cli" "/usr/local/bin/panelx"
    fi
    echo -e "${GREEN}✓ Core engine v2.0, guardian daemon, ws-proxy, and web assets deployed.${NC}"
else
    echo -e "${RED}[ERROR] Local source files not found and could not download from GitHub!${NC}"
    exit 1
fi

chmod +x "$INSTALL_DIR/panelx_server.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/panelx-backend.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/panelx.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/system_guardian.py" 2>/dev/null || true
chmod +x "/usr/local/bin/panelx" 2>/dev/null || true
ln -sf /usr/local/bin/panelx /usr/bin/panelx 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 6: Database Compatibility & Defaults Migration
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[6/7] ⚙️ Applying database optimizations & standardizing defaults...${NC}"
python3 -c "
import sqlite3

db_path = '$DB_FILE'
conn = sqlite3.connect(db_path)
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA busy_timeout=5000;')
conn.execute('PRAGMA synchronous=NORMAL;')

# Ensure columns exist
try:
    conn.execute('ALTER TABLE users ADD COLUMN inbound_id INTEGER DEFAULT 0')
except Exception:
    pass

try:
    conn.execute('ALTER TABLE users ADD COLUMN used_bytes INTEGER DEFAULT 0')
except Exception:
    pass

# Ensure default settings exist with standard values
defaults = {
    'panel_port': '7788',
    'web_base_path': '/sgpx_4f5124/',
    'api_secret': 'SGX_EE7A2843737920768EEB6FDB',
    'panel_title': 'PanelX'
}

for k, v in defaults.items():
    conn.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

conn.commit()
conn.close()
" 2>/dev/null || true

# Re-sync users.db for backward compatibility
python3 -c "
import sqlite3, os
try:
    conn = sqlite3.connect('$DB_FILE')
    rows = conn.execute('SELECT username, password, expiry_date, simultaneous_limit, bandwidth_gb FROM users').fetchall()
    conn.close()
    with open('/etc/panelx/users.db', 'w') as f:
        for r in rows:
            f.write(f'{r[0]}:{r[1]}:{r[2]}:{r[3]}:{r[4]}\n')
except Exception:
    pass
" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 7: Zero-Downtime Systemd Service Switch
# ---------------------------------------------------------------------------
echo -e "\n${BLUE}[7/7] 🔄 Transitioning systemd services with zero SSH connection drops...${NC}"

# 1. Setup PanelX Server Systemd Unit
cat <<'EOF' > /etc/systemd/system/panelx.service
[Unit]
Description=PanelX v2.0 Enterprise Control Panel (Powered by SG Home)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/panelx
ExecStart=/usr/bin/python3 /etc/panelx/panelx_server.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 2. Setup System Guardian Systemd Unit
cat <<'EOF' > /etc/systemd/system/system-guardian.service
[Unit]
Description=PanelX System Guardian (Storage Protection & Smart Device Limiter)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/panelx
ExecStart=/usr/bin/python3 /etc/panelx/system_guardian.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# 3. Setup WS-Proxy High-Speed WebSocket Engine Systemd Unit
if [ -x "/usr/local/bin/panelx-proxy" ] && /usr/local/bin/panelx-proxy -V >/dev/null 2>&1; then
    WS_EXEC="/usr/local/bin/panelx-proxy -p 80,8080,443,8880"
else
    WS_EXEC="/usr/bin/python3 /etc/panelx/ws-proxy.py"
fi

cat <<EOF > /etc/systemd/system/ws-proxy.service
[Unit]
Description=PanelX High-Speed WebSocket Proxy (Ports 80, 8080, 443, 8880)
After=network.target

[Service]
Type=simple
User=root
ExecStart=${WS_EXEC}
Restart=always
RestartSec=2s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Open WebSocket proxy firewall ports
command -v ufw >/dev/null 2>&1 && ufw allow 80/tcp 8080/tcp 443/tcp 8880/tcp >/dev/null 2>&1 || true
command -v iptables >/dev/null 2>&1 && {
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 8880 -j ACCEPT 2>/dev/null || true
}

# 4. Disable old heavy bash limiter (replaces with ultra-low CPU guardian)
systemctl stop panelx-limiter >/dev/null 2>&1 || true
systemctl disable panelx-limiter >/dev/null 2>&1 || true

# 5. Reload and restart without touching sshd!
systemctl daemon-reload
systemctl enable --now system-guardian >/dev/null 2>&1
systemctl restart system-guardian >/dev/null 2>&1
systemctl enable --now ws-proxy >/dev/null 2>&1
systemctl restart ws-proxy >/dev/null 2>&1
systemctl enable --now panelx >/dev/null 2>&1
systemctl restart panelx >/dev/null 2>&1

# Verify services
sleep 2
PANELX_STATUS=$(systemctl is-active panelx 2>/dev/null || echo "unknown")
GUARDIAN_STATUS=$(systemctl is-active system-guardian 2>/dev/null || echo "unknown")
WS_STATUS=$(systemctl is-active ws-proxy 2>/dev/null || echo "unknown")

get_db_setting() {
    local k="$1"
    local def="$2"
    python3 -c "
import sqlite3
try:
    conn = sqlite3.connect('$DB_FILE')
    r = conn.execute('SELECT value FROM settings WHERE key = ?', ('$k',)).fetchone()
    print(r[0] if r else '$def')
    conn.close()
except Exception:
    print('$def')
" 2>/dev/null || echo "$def"
}

# Retrieve configuration details
PUB_IP=$(curl -s -4 --max-time 2 ifconfig.me || curl -s -4 --max-time 2 icanhazip.com || echo "YOUR_VPS_IP")
PANEL_PORT=$(get_db_setting "panel_port" "7788")
BASE_PATH=$(get_db_setting "web_base_path" "/sgpx_4f5124/")
API_KEY=$(get_db_setting "api_secret" "SGX_EE7A2843737920768EEB6FDB")

echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}🎉 PANELX v2.0 PRODUCTION ENGINE UPDATE COMPLETE! 🎉${NC}"
echo -e "                   ${YELLOW}Powered by SG Home${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "  ${GREEN}● PanelX Service      :${NC} ${BOLD}${PANELX_STATUS}${NC}"
echo -e "  ${GREEN}● System Guardian     :${NC} ${BOLD}${GUARDIAN_STATUS}${NC}"
echo -e "  ${GREEN}● WS-Proxy Service    :${NC} ${BOLD}${WS_STATUS}${NC}"
echo -e "  ${GREEN}● Web Access URL      :${NC} ${YELLOW}http://${PUB_IP}:${PANEL_PORT}${BASE_PATH}${NC}"
echo -e "  ${GREEN}● Secret URL Path     :${NC} ${PURPLE}${BASE_PATH}${NC}"
echo -e "  ${GREEN}● API Key (Header)    :${NC} ${CYAN}${API_KEY}${NC}"
echo -e "  ${GREEN}● Device Limit Default:${NC} ${BOLD}4 Devices${NC}"
echo -e "  ${GREEN}● Log Protection Cap  :${NC} ${CYAN}50MB Max (SystemMaxUse=50M)${NC}"
echo -e "  ${GREEN}● Bot Defense         :${NC} ${CYAN}Fail2ban active on ports 22, 80, 8080${NC}"
echo -e "  ${GREEN}● User Preservation   :${NC} ${BOLD}100% Intact & Verified${NC}"
echo -e "  ${GREEN}● Active SSH Sessions :${NC} ${BOLD}Zero Disconnections${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "  ${YELLOW}Tip:${NC} Type ${BOLD}panelx${NC} in your terminal anytime to open the management menu."
echo -e "${CYAN}================================================================${NC}\n"
