#!/usr/bin/env bash
# =============================================================================
# PanelX - Automated 1-Click Installer
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
echo -e "         ${PURPLE}SGPX — SG Home PanelX Control System v2.4${NC}"
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
apt-get update -y >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    python3 python3-pip curl wget unzip git openssh-server iptables net-tools lsof >/dev/null 2>&1
echo -e "${GREEN}✓ Dependencies installed successfully.${NC}"

echo -e "\n${BLUE}[3/6] Configuring OpenSSH & Security limits...${NC}"
# Ensure OpenSSH allows password authentication
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config 2>/dev/null || true

systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
echo -e "${GREEN}✓ OpenSSH configured on port 22.${NC}"

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

REPO_RAW_BASE="https://raw.githubusercontent.com/WerangaNimsara/PanelX/main"

# Check if installing from local directory
if [ -f "panelx.py" ] || [ -f "bin/panelx-core" ]; then
    echo -e "${CYAN}→ Installing from local directory files...${NC}"
    cp panelx.py "$INSTALL_DIR/" 2>/dev/null || true
    cp -r web/* "$INSTALL_DIR/web/" 2>/dev/null || true
    cp panelx-cli /usr/local/bin/panelx 2>/dev/null || true
    if [ -f "bin/panelx-core" ]; then
        echo -e "${GREEN}✓ Installing compiled panelx-core binary...${NC}"
        cp bin/panelx-core /usr/local/bin/panelx-core
        chmod +x /usr/local/bin/panelx-core
    fi
else
    mkdir -p "$INSTALL_DIR/web/assets"
    curl -sSL "${REPO_RAW_BASE}/panelx.py" -o "$INSTALL_DIR/panelx.py" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/web/index.html" -o "$INSTALL_DIR/web/index.html"
    curl -sSL "${REPO_RAW_BASE}/web/favicon.svg" -o "$INSTALL_DIR/web/favicon.svg" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/web/favicon.ico" -o "$INSTALL_DIR/web/favicon.ico" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/web/assets/logo.svg" -o "$INSTALL_DIR/web/assets/logo.svg" 2>/dev/null || true
    curl -sSL "${REPO_RAW_BASE}/panelx-cli" -o "/usr/local/bin/panelx"
    # Download compiled binary if available
    echo -e "${CYAN}→ Downloading compiled panelx-core binary...${NC}"
    curl -sSL "${REPO_RAW_BASE}/bin/panelx-core" -o "/usr/local/bin/panelx-core" 2>/dev/null || true
    chmod +x "/usr/local/bin/panelx-core" 2>/dev/null || true
fi

chmod +x "$INSTALL_DIR/panelx.py" 2>/dev/null || true
chmod +x "/usr/local/bin/panelx"
ln -sf /usr/local/bin/panelx /usr/bin/panelx 2>/dev/null || true

# Determine ExecStart target (Binary preferred, Python fallback)
EXEC_TARGET="/usr/bin/python3 ${INSTALL_DIR}/panelx.py"
if [ -f "/usr/local/bin/panelx-core" ] && [ -x "/usr/local/bin/panelx-core" ]; then
    EXEC_TARGET="/usr/local/bin/panelx-core"
    echo -e "${GREEN}✓ Engine Execution Mode: Standalone Compiled Binary${NC}"
else
    echo -e "${YELLOW}! Engine Execution Mode: Python Runtime Fallback${NC}"
fi

# Setup Systemd Service for PanelX
cat <<EOF > /etc/systemd/system/panelx.service
[Unit]
Description=PanelX Modern SSH & WebSocket Management Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${EXEC_TARGET}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Setup panelx-proxy high-speed Rust binary
if [ -f "bin/panelx-proxy" ]; then
    cp bin/panelx-proxy "/usr/local/bin/panelx-proxy" 2>/dev/null || true
else
    curl -sSL "${REPO_RAW_BASE}/bin/panelx-proxy" -o "/usr/local/bin/panelx-proxy" 2>/dev/null || true
fi
chmod +x "/usr/local/bin/panelx-proxy" 2>/dev/null || true

# Setup Systemd Service for WS-Proxy (Using compiled Rust proxy binary)
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

# Setup panelx-limiter daemon
if [ -f "core/panelx-limiter.sh" ]; then
    cp core/panelx-limiter.sh "$INSTALL_DIR/"
else
    curl -sSL "${REPO_RAW_BASE}/core/panelx-limiter.sh" -o "$INSTALL_DIR/panelx-limiter.sh" 2>/dev/null || true
fi
chmod +x "$INSTALL_DIR/panelx-limiter.sh" 2>/dev/null || true

# Setup Systemd Service for Limiter
cat <<EOF > /etc/systemd/system/panelx-limiter.service
[Unit]
Description=PanelX Session & Bandwidth Limiter Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash ${INSTALL_DIR}/panelx-limiter.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

echo -e "\n${BLUE}[6/6] Enabling services & configuring firewall...${NC}"
systemctl daemon-reload
systemctl enable --now panelx >/dev/null 2>&1
systemctl enable --now ws-proxy >/dev/null 2>&1
systemctl enable --now panelx-limiter >/dev/null 2>&1 || true

# Open Ports in UFW & iptables
command -v ufw >/dev/null 2>&1 && ufw allow 22/tcp 80/tcp 8080/tcp 443/tcp 8880/tcp 7300/udp 7788/tcp >/dev/null 2>&1 || true
command -v iptables >/dev/null 2>&1 && {
    iptables -I INPUT -p tcp --dport 7788 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 7300 -j ACCEPT 2>/dev/null || true
}

PUB_IP=$(curl -s -4 ifconfig.me || curl -s -4 icanhazip.com || echo "YOUR_VPS_IP")

echo -e "\n${CYAN}======================================================${NC}"
echo -e "${GREEN}🎉 PANELX INSTALLATION COMPLETED SUCCESSFULLY! 🎉${NC}"
echo -e "              ${YELLOW}Powered by SG Home${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "  ${GREEN}● Web UI URL    :${NC} ${YELLOW}http://${PUB_IP}:7788${NC}"
echo -e "  ${GREEN}● Default User  :${NC} ${CYAN}admin${NC}"
echo -e "  ${GREEN}● Default Pass  :${NC} ${CYAN}admin${NC}"
echo -e "  ${GREEN}● WS Ports      :${NC} ${PURPLE}80, 8080, 443, 8880${NC}"
echo -e "  ${GREEN}● BadVPN UDP    :${NC} ${PURPLE}7300${NC}"
echo -e "  ${GREEN}● CLI Tool      :${NC} Type ${YELLOW}panelx${NC} in your terminal anytime"
echo -e "${CYAN}======================================================${NC}"
echo -e "${YELLOW}IMPORTANT:${NC} Login immediately and change your admin password in Settings!"
echo -e "${CYAN}======================================================${NC}\n"
