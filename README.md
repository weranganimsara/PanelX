<p align="center">
  <img src="assets/panelx-banner.svg" alt="PanelX - Powered by SG Home" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/weranganimsara/PanelX/stargazers"><img src="https://img.shields.io/github/stars/weranganimsara/PanelX?style=for-the-badge&color=00f2fe&logo=github" alt="Stars"/></a>
  <a href="https://github.com/weranganimsara/PanelX/network/members"><img src="https://img.shields.io/github/forks/weranganimsara/PanelX?style=for-the-badge&color=9d4edd&logo=github" alt="Forks"/></a>
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-blue?style=for-the-badge&logo=linux" alt="OS"/>
  <img src="https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Rust-High--Speed%20Proxy-orange?style=for-the-badge&logo=rust" alt="Rust"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <b>PanelX</b> is a modern, ultra-responsive Linux VPS, Firewall, and SSH/WebSocket VPN Management Control Panel.<br>
  Engineered with standard Python 3, high-speed compiled Rust networking, SQLite, and a dark Cyber NOC interface.<br>
  <b>Proudly Powered by SG Home.</b>
</p>

---

## ⚡ Quick 1-Command Installation

Log in as `root` to any fresh Linux VPS (Ubuntu 20/22/24 or Debian 10/11/12/13) and run:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/weranganimsara/PanelX/main/install.sh)
```

The installer will automatically detect your OS, install dependencies, configure OpenSSH, launch the compiled Rust proxy, initialize BadVPN, and start the PanelX web console on port `7788`.

### 🔑 Default Credentials:
* **Web UI Dashboard:** `http://YOUR_VPS_IP:7788`
* **Default Username:** `admin`
* **Default Password:** `admin`

---

## 💎 World-Class Feature Highlights

### 1. 🛡️ Firewall Center with 30-Second Lockout Safety
* **Real Linux Packet Filtering**: Seamlessly integrates with `iptables` and `ufw`.
* **Automated 30s Rollback Queue**: Applying risky rules triggers an automatic 30-second safety rollback timer. If not confirmed with **"Confirm & Keep"**, rules are reverted automatically to prevent remote admin lockout!
* **Quick Actions**: One-click Allow for SSH (22), HTTP (80), HTTPS (443), BadVPN UDP (7300), and immediate Malicious IP/CIDR blocking.

### 2. 📡 Carrier Inbounds & Payloads Manager (3X-UI Architecture)
* Dedicated Inbounds section for configuring carrier-specific bug hosts, SNI, and proxies:
  * 🔹 **Hutch Zero (NetMod HTTP Proxy)** with proxy host (`dpkids.lk:8080`)
  * 🔹 **Hutch Direct CDN (Proxy None)**
  * 🔹 **Mobitel All IP (Zoom Bug)**
  * 🔹 **Dialog Fastly 5G (Port 80 Bypass)**
* Add, edit, or remove custom carrier profiles anytime with zero service downtime.

### 3. 👥 SSH Client Accounts & Universal Exporter
* Single & Bulk account creation with customizable device limits (`maxlogins`) enforced via Linux `/etc/security/limits.conf`.
* **Client Configuration Modal**:
  * 📲 **SSH for NetMod URI:** Generates exact `ssh://user:pass@host:port/?payload#SG` URIs for 1-click import into NetMod Syna.
  * 📦 **HTTP Custom (`.hc`)**: `proxy:port@user:pass#payload` format.
  * 💬 **WhatsApp / Telegram**: Rich formatted messages with emojis.
  * 🌐 **Direct SSH URL & Live In-Browser QR Code!**

### 4. ⚡ High-Speed Compiled Rust Proxy (`panelx-proxy`)
* Replaces slow Python proxies with a native, compiled multi-port async Rust proxy on ports `80`, `8080`, and `443`.
* Handles WebSocket upgrade handshakes (`101 Switching Protocols` -> `200 Connection Established`) with ultra-low latency and minimal memory overhead (~500 KB RAM).

### 5. 🎮 BadVPN UDP Gateway (Port 7300)
* Built-in `badvpn-udpgw` service configured for low-latency mobile gaming (Free Fire, PUBG) and WhatsApp / VoIP calling.

### 6. ⚙️ Systemd & Process Management
* **System Services**: Filter all units by active/failed state, restart, stop, or view live `journalctl` logs.
* **Process Manager**: Sort top CPU and RAM processes, search by name/PID, and trigger graceful (`SIGTERM`) or force (`SIGKILL`) signals.

### 7. 🌐 Network Center & SSH Security Auditor
* **Port Monitor**: Real-time listening sockets (`ss -tulnp`).
* **SSH Hardening Audit**: Inspects `sshd_config` (`PermitRootLogin`, `PasswordAuthentication`, port) and computes security rating.
* **Active Sessions**: Inspects active SSH logins (`w -h`) with instant disconnect capability.

### 8. ⌨️ Universal Command Palette (`Ctrl + K`)
* Press `Ctrl + K` anywhere on the dashboard to open the spotlight command palette for fast page jumps and instant rule actions.

---

## 🖥️ Terminal Management (`panelx` CLI)

PanelX includes a dedicated interactive terminal utility:
```bash
panelx
```

### CLI Menu Options:
```text
  [1] Start / Restart All Services
  [2] Stop All Services
  [3] Check Service Status
  [4] Change Web UI Port
  [5] Reset Admin Password
  [6] View Live Proxy & System Logs
  [0] Exit
```

---

## 🔌 SG Home Paid Site REST API

PanelX provides a complete, authenticated REST API for integration with paid subscription websites:

```env
FALCON_API_URL=http://YOUR_VPS_IP:7788
FALCON_API_KEY=SG_HOME_FALCON_SECRET_2026
```

### Endpoints:

| Method | Endpoint | Description | Auth |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status & uptime | `x-api-key` |
| `GET` | `/api/system/status` | Live CPU, RAM, Disk & Health Score | Session / API Key |
| `GET` | `/api/firewall/status` | Current firewall backend & rules | Session / API Key |
| `POST` | `/api/firewall/rule/add` | Add rule with 30s safety rollback | Session / API Key |
| `POST` | `/api/firewall/rollback/confirm` | Confirm & retain applied rule | Session / API Key |
| `GET` | `/api/users/list` | List all SSH client accounts | Session / API Key |
| `POST` | `/api/user/create` | Provision new SSH account | `x-api-key` / Session |
| `POST` | `/api/user/renew` | Extend account validity | `x-api-key` / Session |
| `POST` | `/api/user/delete` | Delete account & revoke access | `x-api-key` / Session |
| `GET` | `/api/inbounds/list` | Retrieve carrier payload profiles | Session / API Key |
| `GET` | `/api/processes/list` | Top Linux processes (PID, CPU, Mem) | Session / API Key |
| `GET` | `/api/network/ports` | Listening local sockets (`ss -tulnp`) | Session / API Key |

---

## 📁 Repository Structure

```text
PanelX/
├── assets/
│   ├── panelx-banner.svg       # Official vector banner for GitHub
│   └── logo.svg                # High-res vector square logo
├── bin/
│   └── panelx-proxy            # Compiled high-speed async Rust proxy binary
├── core/
│   └── panelx-limiter.sh       # Multi-device session & bandwidth limiter
├── web/
│   ├── assets/
│   │   └── logo.svg            # App icon asset
│   └── index.html              # Cyber NOC Dark UI single-page application
├── install.sh                  # 1-click universal automated Linux installer
├── panelx.py                   # Pure Python 3 daemon & REST API engine
├── panelx-cli                  # Interactive terminal management CLI
└── README.md                   # Project documentation
```

---

## 📜 License & Credits

Distributed under the **MIT License**.

* **Author:** Weranga Nimsara
* **Organization:** [SG Home](https://sghome.space)
* **GitHub:** [weranganimsara/PanelX](https://github.com/weranganimsara/PanelX)

---

<p align="center">
  <b>⚡ PanelX — Complete Linux Server &amp; VPN Control</b><br>
  <i>Crafted with passion by Weranga Nimsara | Powered by SG Home</i>
</p>
