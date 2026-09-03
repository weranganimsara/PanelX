# 🚀 PanelX Manager

<p align="center">
  <img src="https://raw.githubusercontent.com/WerangaNimsara/PanelX/main/web/assets/logo.png" alt="PanelX Logo" width="100" onerror="this.style.display='none'"/>
</p>

<p align="center">
  <b>Modern, Ultra-Lightweight SSH & WebSocket VPN Management Panel</b><br>
  <i>Built with Python 3, SQLite, and a Stunning Glassmorphism Dark Web UI.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-blue?style=for-the-badge&logo=linux" alt="OS"/>
  <img src="https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Architecture-x86__64%20%7C%20aarch64-brightgreen?style=for-the-badge" alt="Arch"/>
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge" alt="License"/>
</p>

---

## ⚡ Quick 1-Command Installation

Log in as `root` to your fresh VPS (Ubuntu 20/22/24 or Debian 10/11/12) and run:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/WerangaNimsara/PanelX/main/install.sh)
```

After installation finishes, you will immediately see your access credentials in your terminal:
* **Web UI Dashboard:** `http://YOUR_VPS_IP:7788`
* **Default Username:** `admin`
* **Default Password:** `admin`

---

## ✨ Features

- 💎 **Stunning Glassmorphic Web UI**: Beautiful responsive dark mode interface designed for mobile and desktop.
- ⚡ **Zero External Dependencies**: Pure standard Python 3 + SQLite architecture. No heavy Node.js or Docker needed!
- 🚪 **Multi-Port WebSocket Proxy**: Built-in high-performance HTTP/WebSocket forwarder on ports `80`, `8080`, `443`, and `8880`.
- 🎮 **BadVPN UDP Gateway**: Auto-configures `badvpn-udpgw` on port `7300` for low-latency gaming (Free Fire, PUBG) and WhatsApp/VoIP calling.
- 👥 **Advanced Client Management**:
  - Add single client accounts with custom passwords or auto-generator.
  - One-click bulk client generator (generate 5 to 50 accounts in seconds).
  - Enforce simultaneous device limits (1 to 10 devices per account) using Linux `/etc/security/limits.conf`.
  - Expiry date tracking with automatic status updates (`Active`, `Expired`, `Warning`).
  - Extend / Renew accounts with a single click.
- 📲 **Universal Config & QR Code Exporter**:
  - One-click HTTP Custom (`.hc`) string generator.
  - Direct `ssh://` URI.
  - Formatted WhatsApp & Telegram stylized client messages.
  - Instant in-browser QR Code rendering.
  - Downloadable config `.txt` file.
- 📊 **Real-Time System Monitoring**: Live gauges for CPU %, RAM %, Disk Space, Uptime, Open Sockets, and Live Network Upload/Download speeds (KB/s).
- 🖥️ **Interactive Terminal CLI Tool**: Type `panelx` anytime in your SSH terminal to check status, restart services, change ports, or reset admin credentials!

---

## 🖥️ Terminal Management (`panelx` CLI)

You can manage PanelX directly from your SSH terminal at any time by simply typing:

```bash
panelx
```

This brings up the interactive control menu:

```text
  =========================================
      🦅 PanelX Management Tool    
  =========================================
  [1] Start PanelX
  [2] Stop PanelX
  [3] Restart PanelX
  [4] Check Full Service Status
  [5] Reset Admin Username & Password
  [6] Change Panel Port (Default: 7788)
  [7] Restart WebSocket Proxy & BadVPN
  [8] View Live Logs
  [0] Exit
  =========================================
```

---

## 🛠️ System Requirements

| Specification | Minimum | Recommended |
| :--- | :--- | :--- |
| **Operating System** | Ubuntu 20.04+, Debian 10+ | Ubuntu 22.04 / 24.04 LTS |
| **CPU** | 1 vCPU | 2 vCPU |
| **RAM** | 512 MB | 1 GB+ |
| **Disk** | 5 GB | 15 GB |
| **Access** | Root permissions (`sudo su`) | Root |

---

## 🔒 Security Best Practices

1. **Change Default Password**: Immediately after installation, visit `Settings` in the Web UI and update the default password (`admin`).
2. **Change Panel Port**: You can change the default port `7788` to any custom high port (e.g. `2082`, `54321`) in Settings or via the `panelx` CLI.
3. **Firewall**: Ensure ports `80`, `443`, `8080`, `7300`, and your panel port are allowed on your cloud provider firewall (e.g., AWS Security Groups, DigitalOcean, Oracle Cloud, Linode).

---

## 📄 License & Credits

* **Author:** [Weranga Nimsara](https://github.com/WerangaNimsara) & SG Home Network
* **License:** [MIT License](LICENSE)
* **Contributions:** Pull requests and community contributions are welcome!
