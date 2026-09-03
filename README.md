# 🔥 FALCON FIREWALL X

<p align="center">
  <b>"Complete Linux Server Control. One Powerful Interface."</b><br>
  <i>World-Class Linux VPS, Firewall, Network & SSH Management Control Panel.</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Debian-blue?style=for-the-badge&logo=linux" alt="OS"/>
  <img src="https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python" alt="Python"/>
  <img src="https://img.shields.io/badge/Architecture-x86__64%20%7C%20aarch64-brightgreen?style=for-the-badge" alt="Arch"/>
  <img src="https://img.shields.io/badge/License-MIT-red?style=for-the-badge" alt="License"/>
</p>

---

## ⚡ Quick 1-Command Installation

Log in as `root` to your fresh VPS (Ubuntu 20/22/24 or Debian 11/12/13) and run:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/weranganimsara/PanelX/main/install.sh)
```

After installation finishes, access the console immediately:
* **Web UI Console:** `http://YOUR_VPS_IP:7788`
* **Default Username:** `admin`
* **Default Password:** `admin`

---

## 💎 World-Class Feature Highlights

### 1. 🛡️ Falcon Firewall Center & Lockout Prevention
- **Automated Backend Detection**: Seamlessly integrates with `iptables` or `ufw`.
- **30-Second Safety Rollback Queue**: Before applying risky rules touching SSH or critical ports, a 30-second rollback transaction is started. If unconfirmed, rules are automatically reverted to prevent accidental admin lockout!
- **Quick Actions**: One-click Allow for SSH (22), HTTP (80), HTTPS (443), BadVPN (7300), and immediate Malicious IP/CIDR blocking.

### 2. 📡 Inbounds & Carrier Payload Profiles (3X-UI Inspired)
- Configure carrier-specific bug hosts, encrypted payloads, and HTTP proxy profiles.
- Pre-loaded with working presets:
  - *Hutch Zero (NetMod HTTP Proxy with custom proxy host:port)*
  - *Hutch Direct (CDN None)*
  - *Mobitel All IP (Zoom Bug)*
  - *Dialog Fastly 5G (Port 80 Bypass)*

### 3. 👥 SSH Client Provisioning & NetMod Exporter
- Single & Bulk account creation with customizable device limits (`maxlogins`) and validity days.
- **Client Configuration Modal**:
  - **SSH for NetMod**: Generates exact `ssh://user:pass@host:port?payload#remark` URIs for 1-click import into NetMod Syna.
  - **HTTP Custom (`.hc`)**: `proxy:port@user:pass#payload` format.
  - **WhatsApp / Telegram**: Rich formatted messages with emojis.
  - **In-Browser QR Code**: Instant scan on mobile devices.

### 4. ⚙️ Systemd & Process Management
- Inspect all systemd services, filter by active/failed state, restart/stop/reload with a single click.
- Real-time **Process Manager**: Sort top processes by CPU and RAM usage, send graceful `SIGTERM` or force `SIGKILL`.
- **Live System Logs**: Controlled `journalctl -u <service>` streaming with download support.

### 5. 🌐 Network & SSH Security Center
- **Port Monitor**: Real-time listening local sockets (`ss -tulnp`).
- **Network Diagnostics**: Integrated Ping and DNS lookup tools.
- **sshd Audit**: Scores SSH configuration (`PermitRootLogin`, `PasswordAuthentication`, `Port`) and inspects active SSH sessions (`w -h`) with disconnect triggers.

### 6. 🔌 REST API for Paid Sites & Automation
- Full compatibility with external websites (e.g. SG Home Paid Site):
  - `GET /api/health`
  - `POST /api/user/create`
  - `POST /api/user/renew`
  - `POST /api/user/delete`
  - Header: `x-api-key: YOUR_SECRET_KEY`

---

## 🖥️ Terminal Management (`panelx` CLI)

You can also manage the platform directly from your terminal:
```bash
panelx
```

---

## 📜 License
Released under the MIT License. Created by Weranga Nimsara (SG Home) & Open-Source Contributors.
