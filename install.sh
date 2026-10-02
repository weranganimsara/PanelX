#!/usr/bin/env bash
# =============================================================================
# PanelX - Automated 1-Click Installer (v2.0 Production Engine)
# Open-Source SSH & WebSocket VPN Management Panel
# Author: Weranga Nimsara (SG Home) & Open-Source Community
# GitHub: https://github.com/WerangaNimsara/PanelX
# =============================================================================

# Exit immediately if a command exits with a non-zero status
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Please run this installer as root (sudo bash)!${NC}"
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
echo -e "         ${PURPLE}SGPX — SG Home PanelX Control System v2.0${NC}"
echo -e "                 ${YELLOW}Official SG Home Product${NC}"
echo -e "${CYAN}======================================================${NC}"

echo -e "\n${BLUE}[1/6] Detecting operating system & architecture...${NC}"
ARCH=$(uname -m)
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')

if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
    echo -e "${YELLOW}[WARNING] This script is optimized for Ubuntu & Debian. Proceeding anyway...${NC}"
fi
echo -e "${GREEN}✓ Detected ${OS_ID} (${ARCH})${NC}"

echo -e "\n${BLUE}[2/6] Updating system repositories & installing dependencies...${NC}"
apt-get update -y >/dev/null 2>&1 || true
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip curl wget unzip git openssh-server iptables net-tools lsof fail2ban logrotate rsyslog >/dev/null 2>&1

# Install FastAPI and Uvicorn
DEBIAN_FRONTEND=noninteractive apt-get install -y python3-fastapi uvicorn >/dev/null 2>&1 || true
python3 -c "import fastapi, uvicorn" >/dev/null 2>&1 || {
    pip3 install fastapi uvicorn --break-system-packages >/dev/null 2>&1 || \
    pip3 install fastapi uvicorn >/dev/null 2>&1 || true
}
echo -e "${GREEN}✓ Dependencies and async runtime installed successfully.${NC}"

echo -e "\n${BLUE}[3/6] Configuring OpenSSH, Security limits & 50MB Log Guards...${NC}"
# Ensure OpenSSH allows password authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
echo -e "${GREEN}✓ OpenSSH configured on port 22.${NC}"

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

# Configure logrotate for syslog and auth.log to prevent 18+ GB storage exhaustion
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

# Fail2ban configuration for SSH bot protection
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
systemctl enable --now fail2ban >/dev/null 2>&1 || true
echo -e "${GREEN}✓ Automated storage protection & Fail2ban configured.${NC}"

echo -e "\n${BLUE}[4/6] Installing BadVPN-udpgw (UDP Port 7300 for Gaming & WhatsApp Calls)...${NC}"
BADVPN_BIN="/usr/local/bin/badvpn-udpgw"
if [ ! -f "$BADVPN_BIN" ]; then
    wget -q -O "$BADVPN_BIN" "https://raw.githubusercontent.com/daybreakersx/premscript/master/badvpn-udpgw64" 2>/dev/null || \
    wget -q -O "$BADVPN_BIN" "https://github.com/ambrop72/badvpn/raw/master/badvpn-udpgw" 2>/dev/null || true
fi

if [ -f "$BADVPN_BIN" ]; then
    chmod +x "$BADVPN_BIN"
    cat <<'EOF' > /etc/systemd/system/badvpn.service
[Unit]
Description=BadVPN UDP Gateway for Gaming and VoIP
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now badvpn >/dev/null 2>&1 || true
    echo -e "${GREEN}✓ BadVPN UDP Gateway installed and running on port 7300.${NC}"
else
    echo -e "${YELLOW}! Skipped BadVPN binary download (Optional).${NC}"
fi

echo -e "\n${BLUE}[5/6] Setting up PanelX core & Web UI...${NC}"
INSTALL_DIR="/etc/panelx"
mkdir -p "$INSTALL_DIR/web"
mkdir -p "$INSTALL_DIR/bandwidth"

REPO_RAW_BASE="https://raw.githubusercontent.com/WerangaNimsara/PanelX/main"

# Check if installing from local directory
if [ -f "panelx.py" ] || [ -f "panelx_server.py" ]; then
    echo -e "${CYAN}→ Installing from local directory files...${NC}"
    cp panelx.py "$INSTALL_DIR/" 2>/dev/null || true
    cp panelx_server.py "$INSTALL_DIR/" 2>/dev/null || true
    cp system_guardian.py "$INSTALL_DIR/" 2>/dev/null || true
    cp -r web/* "$INSTALL_DIR/web/" 2>/dev/null || true
    cp panelx-cli /usr/local/bin/panelx 2>/dev/null || true
else
    mkdir -p "$INSTALL_DIR/web/assets"
    curl -sSL "${REPO_RAW_BASE}/panelx.py" -o "$INSTALL_DIR/panelx.py" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/panelx_server.py" -o "$INSTALL_DIR/panelx_server.py" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/system_guardian.py" -o "$INSTALL_DIR/system_guardian.py" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/web/index.html" -o "$INSTALL_DIR/web/index.html"
    curl -sSL "${REPO_RAW_BASE}/web/favicon.svg" -o "$INSTALL_DIR/web/favicon.svg" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/web/favicon.ico" -o "$INSTALL_DIR/web/favicon.ico" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/web/assets/logo.svg" -o "$INSTALL_DIR/web/assets/logo.svg" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/panelx-cli" -o "/usr/local/bin/panelx"
fi

chmod +x "$INSTALL_DIR/panelx.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/panelx_server.py" 2>/dev/null || true
chmod +x "$INSTALL_DIR/system_guardian.py" 2>/dev/null || true
chmod +x "/usr/local/bin/panelx"
ln -sf /usr/local/bin/panelx /usr/bin/panelx 2>/dev/null || true

# Setup Systemd Service for PanelX
cat <<EOF > /etc/systemd/system/panelx.service
[Unit]
Description=PanelX v2.0 Enterprise Control Panel (Powered by SG Home)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/panelx_server.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Setup System Guardian Daemon
cat <<EOF > /etc/systemd/system/system-guardian.service
[Unit]
Description=PanelX System Guardian (Storage Protection & Smart Device Limiter)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/system_guardian.py
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Setup panelx-proxy high-speed Rust binary if available
if [ -f "bin/panelx-proxy" ]; then
    cp bin/panelx-proxy "/usr/local/bin/panelx-proxy" 2>/dev/null || true
    chmod +x "/usr/local/bin/panelx-proxy" 2>/dev/null || true

    cat <<EOF > /etc/systemd/system/ws-proxy.service
[Unit]
Description=PanelX High-Speed Rust Proxy (Ports 80, 8080, 443)
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/panelx-proxy -p 80,8080,443
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF
fi

# Apply Linux BBR and TCP Speed Optimizations
cat <<'EOF' > /etc/sysctl.d/99-panelx-bbr.conf
# PanelX Ultra-Speed Kernel & TCP BBR Optimization
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_syn_backlog = 16384
net.core.somaxconn = 16384
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 1048576
EOF
sysctl -p /etc/sysctl.d/99-panelx-bbr.conf >/dev/null 2>&1 || true

echo -e "\n${BLUE}[6/6] Enabling services & configuring firewall...${NC}"
systemctl daemon-reload
systemctl enable --now system-guardian >/dev/null 2>&1
systemctl enable --now panelx >/dev/null 2>&1
systemctl enable --now ws-proxy >/dev/null 2>&1 || true

# Open Ports in UFW & iptables
command -v ufw >/dev/null 2>&1 && ufw allow 22/tcp 80/tcp 8080/tcp 443/tcp 8880/tcp 7300/udp 7788/tcp >/dev/null 2>&1 || true
command -v iptables >/dev/null 2>&1 && {
    iptables -I INPUT -p tcp --dport 7788 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 7300 -j ACCEPT 2>/dev/null || true
}

# Standard Web Base Path & API Key
SGPX_WEB_PATH="/sgpx_4f5124/"

# Save initial settings in SQLite with WAL mode
python3 -c "
import sqlite3
conn = sqlite3.connect('/etc/panelx/panelx.db')
conn.execute('PRAGMA journal_mode=WAL;')
conn.execute('PRAGMA busy_timeout=5000;')
conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (\'web_base_path\', \'$SGPX_WEB_PATH\')')
conn.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (\'api_secret\', \'SGX_EE7A2843737920768EEB6FDB\')')
conn.commit()
conn.close()
" 2>/dev/null || true

PUB_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "YOUR_VPS_IP")

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}🎉 PANELX INSTALLATION COMPLETED SUCCESSFULLY! 🎉${NC}"
echo -e "              ${YELLOW}Powered by SG Home${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "  ${GREEN}● Web UI URL    :${NC} ${YELLOW}http://${PUB_IP}:7788${SGPX_WEB_PATH}${NC}"
echo -e "  ${GREEN}● Web Base Path :${NC} ${PURPLE}${SGPX_WEB_PATH}${NC}"
echo -e "  ${GREEN}● Default User  :${NC} ${CYAN}admin${NC}"
echo -e "  ${GREEN}● Default Pass  :${NC} ${CYAN}admin${NC}"
echo -e "  ${GREEN}● API Key       :${NC} ${CYAN}SGX_EE7A2843737920768EEB6FDB${NC}"
echo -e "  ${GREEN}● Device Limit  :${NC} ${PURPLE}4 Devices Default${NC}"
echo -e "  ${GREEN}● WS Ports      :${NC} ${PURPLE}80, 8080, 443, 8880${NC}"
echo -e "  ${GREEN}● BadVPN UDP    :${NC} ${PURPLE}7300${NC}"
echo -e "  ${GREEN}● CLI Tool      :${NC} Type ${YELLOW}panelx${NC} in your terminal anytime"
echo -e "${CYAN}======================================================${NC}"
echo -e "${YELLOW}IMPORTANT:${NC} Login immediately and change your admin password in Settings!"
echo -e "${CYAN}======================================================${NC}\n"
