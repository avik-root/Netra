<div align="center">

<!-- Animated Banner -->
<img src="static/img/banner.png" alt="NETRA Banner" width="100%">

<br><br>

<!-- Animated Typing Header -->
<a href="https://github.com/avik-root/Netra">
  <img src="https://readme-typing-svg.demolab.com?font=Orbitron&weight=800&size=40&duration=3000&pause=1000&color=00F0FF&center=true&vCenter=true&multiline=true&repeat=true&width=700&height=55&lines=N+E+T+R+A" alt="NETRA Typing Animation" />
</a>

<br>

<a href="https://github.com/avik-root/Netra">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=500&size=16&duration=4000&pause=2000&color=00FF88&center=true&vCenter=true&repeat=true&width=600&height=25&lines=Network+Event+%26+Threat+Response+Analyst;Real-Time+Cybersecurity+Monitoring+%7C+Developed+by+MintFire;Secure+%E2%80%A2+Real-Time+%E2%80%A2+Industrial+Grade" alt="Subtitle Animation" />
</a>

<br><br>

<!-- Animated Badges -->
<img src="https://img.shields.io/badge/Version-1.0.0-00f0ff?style=for-the-badge&logo=hackthebox&logoColor=00f0ff&labelColor=0a0e17" alt="Version">
<img src="https://img.shields.io/badge/Python-3.9+-00ff88?style=for-the-badge&logo=python&logoColor=00ff88&labelColor=0a0e17" alt="Python">
<img src="https://img.shields.io/badge/Flask-3.1-ff6600?style=for-the-badge&logo=flask&logoColor=ff6600&labelColor=0a0e17" alt="Flask">
<img src="https://img.shields.io/badge/License-MIT-a855f7?style=for-the-badge&logo=opensourceinitiative&logoColor=a855f7&labelColor=0a0e17" alt="License">
<img src="https://img.shields.io/badge/Security-Hardened-ff3366?style=for-the-badge&logo=letsencrypt&logoColor=ff3366&labelColor=0a0e17" alt="Security">

<br>

<img src="https://img.shields.io/badge/WebSocket-Real--Time-00f0ff?style=flat-square&logo=socketdotio&logoColor=00f0ff&labelColor=0a0e17" alt="WebSocket">
<img src="https://img.shields.io/badge/Encryption-AES--128--CBC-00ff88?style=flat-square&logo=letsencrypt&logoColor=00ff88&labelColor=0a0e17" alt="Encryption">
<img src="https://img.shields.io/badge/CSRF-Protected-ffaa00?style=flat-square&logo=owasp&logoColor=ffaa00&labelColor=0a0e17" alt="CSRF">
<img src="https://img.shields.io/badge/Rate_Limiting-Active-ff3366?style=flat-square&logo=cloudflare&logoColor=ff3366&labelColor=0a0e17" alt="Rate Limiting">

<br><br>

<!-- Animated Wave Divider -->
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">

</div>

<br>

## 🔭 About

**NETRA** _(Network Event & Threat Response Analyst)_ is an industrial-grade, real-time cybersecurity monitoring tool built for system administrators and security professionals. It provides comprehensive visibility into system health, network activity, firewall rules, active connections, and security events — all through a stunning, futuristic web dashboard.

Built with **Flask**, **Socket.IO**, and **Chart.js**, NETRA delivers live metrics with sub-2-second refresh rates, encrypted credential storage, and enterprise-level security hardening out of the box.

<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║          NETRA – Network Event & Threat Response Analyst     ║
║          Version: 1.0.0                                      ║
║          Developed by: MintFire                              ║
║          Security: Rate Limiting | CSRF | Secure Headers     ║
╚══════════════════════════════════════════════════════════════╝
```

</div>

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## ⚡ Key Features

<table>
<tr>
<td width="50%">

### 🖥️ System Monitoring
- Real-time CPU, Memory, Disk & Swap tracking
- Per-core CPU usage visualization
- Disk partition analysis
- Battery status (laptops)
- System uptime & boot time

</td>
<td width="50%">

### 🌐 Network Intelligence
- Live bandwidth monitoring (upload/download)
- Interface discovery (WiFi, Ethernet, Bluetooth, VPN, Docker)
- Packet flow analysis per interface
- IPv4/IPv6/MAC address enumeration
- Real-time throughput charts

</td>
</tr>
<tr>
<td width="50%">

### 🛡️ Firewall & Security
- Firewall rule viewer (pf / iptables)
- Packet statistics (sent/received/errors/drops)
- Traffic distribution analysis
- Security event logging
- Real-time threat indicators

</td>
<td width="50%">

### 🔗 Connection Tracking
- Active TCP/UDP connection monitoring
- Process-to-connection mapping
- ESTABLISHED / LISTEN / TIME_WAIT tracking
- Local & remote address resolution
- Protocol distribution charts

</td>
</tr>
<tr>
<td width="50%">

### 📜 Log Analysis
- Real-time system log streaming
- Color-coded severity levels (info/warning/error)
- Full-text search & filtering
- Auto-scroll with manual override
- NETRA event integration

</td>
<td width="50%">

### 🔒 Enterprise Security
- **Fernet AES-128-CBC** encrypted credentials
- **CSRF protection** on all endpoints
- **Rate limiting** (5 attempts / 15 min)
- **Security headers** (X-Frame, XSS, etc.)
- **Strong password enforcement**

</td>
</tr>
</table>

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🏗️ Architecture

```mermaid
graph TB
    subgraph Client["🖥️ Browser Client"]
        UI["Dashboard UI<br><small>HTML5 + CSS3 + JS</small>"]
        Charts["Chart.js<br><small>Real-time Visualizations</small>"]
        WS_Client["Socket.IO Client<br><small>WebSocket Connection</small>"]
    end

    subgraph Server["⚙️ Flask Server"]
        direction TB
        App["app.py<br><small>Flask + SocketIO</small>"]
        Auth["Authentication<br><small>Session-based + CSRF</small>"]
        RateLimit["Rate Limiter<br><small>5 req / 15 min</small>"]
        Crypto["Fernet Encryption<br><small>AES-128-CBC</small>"]
        API["REST API<br><small>/api/* endpoints</small>"]
        BGThread["Background Thread<br><small>2s metric push</small>"]
    end

    subgraph DataLayer["💾 Data Layer"]
        AdminJSON["admin_data.json<br><small>Encrypted credentials</small>"]
        KeyFile[".netra_key<br><small>Fernet key (0600)</small>"]
        SecretFile[".netra_secret<br><small>Flask secret key</small>"]
    end

    subgraph SystemLayer["🖥️ System Layer"]
        PSUtil["psutil<br><small>System metrics</small>"]
        Firewall["pf / iptables<br><small>Firewall rules</small>"]
        SysLog["System Logs<br><small>journalctl / log</small>"]
        Git["Git<br><small>Auto-update</small>"]
    end

    UI --> WS_Client
    UI --> Charts
    WS_Client <-->|WebSocket| BGThread
    UI -->|HTTP| API
    API --> Auth
    Auth --> RateLimit
    Auth --> Crypto
    Crypto --> AdminJSON
    Crypto --> KeyFile
    App --> SecretFile
    API --> PSUtil
    API --> Firewall
    API --> SysLog
    API --> Git
    BGThread --> PSUtil

    style Client fill:#0a0e17,stroke:#00f0ff,color:#e0e6f0
    style Server fill:#0a0e17,stroke:#00ff88,color:#e0e6f0
    style DataLayer fill:#0a0e17,stroke:#ffaa00,color:#e0e6f0
    style SystemLayer fill:#0a0e17,stroke:#a855f7,color:#e0e6f0
```

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 📁 Project Structure

```
NETRA/
│
├── app.py                    # Flask server — routes, API, auth, security, WebSocket
├── requirements.txt          # Python dependencies
├── admin_data.json           # Encrypted admin credentials (auto-generated)
├── .netra_key                # Fernet encryption key (auto-generated, 0600)
├── .netra_secret             # Flask session secret key (auto-generated, 0600)
│
├── templates/
│   ├── dashboard.html        # Main dashboard — 8 monitoring panels
│   ├── login.html            # Authentication page with CSRF
│   └── setup.html            # First-time credential setup
│
└── static/
    ├── css/
    │   └── style.css         # Complete dark cyberpunk theme
    ├── js/
    │   └── main.js           # Chart.js, Socket.IO, CRUD logic
    └── img/
        ├── logo.png          # NETRA logo
        ├── favicon.png       # Browser tab icon
        └── banner.png        # README banner
```

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🚀 Quick Start

### Prerequisites

| Requirement | Version |
|:---|:---|
| **Python** | 3.9+ |
| **pip** | Latest |
| **Git** | Latest |
| **OS** | macOS / Linux |

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/avik-root/Netra.git
cd Netra

# 2. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch NETRA
python3 app.py
```

### 🌐 Access the Dashboard

```
http://localhost:5001
```

**Default Credentials** _(first launch only)_:
| Field | Value |
|:---|:---|
| Username | `netra` |
| Password | `pass0000` |

> ⚠️ **You will be prompted to set new credentials on first login.** The default password will no longer work after setup is complete.

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🔐 Security Architecture

NETRA implements **defense-in-depth** with multiple layers of security:

```mermaid
graph LR
    A["🌐 Request"] --> B["Rate Limiter<br><small>5 req / 15 min</small>"]
    B --> C["CSRF Validator<br><small>Per-session token</small>"]
    C --> D["Session Auth<br><small>HttpOnly + SameSite</small>"]
    D --> E["Security Headers<br><small>X-Frame, XSS, etc.</small>"]
    E --> F["✅ Protected Route"]

    style A fill:#ff3366,stroke:#ff3366,color:#fff
    style B fill:#ffaa00,stroke:#ffaa00,color:#0a0e17
    style C fill:#ffaa00,stroke:#ffaa00,color:#0a0e17
    style D fill:#00f0ff,stroke:#00f0ff,color:#0a0e17
    style E fill:#00f0ff,stroke:#00f0ff,color:#0a0e17
    style F fill:#00ff88,stroke:#00ff88,color:#0a0e17
```

### Security Features

| Layer | Feature | Details |
|:---|:---|:---|
| **Encryption** | Fernet (AES-128-CBC) | Admin credentials encrypted at rest |
| **Key Storage** | File-based (0600) | `.netra_key` with restricted permissions |
| **Authentication** | Session-based | 8-hour persistent sessions |
| **CSRF** | Per-session tokens | Validated on all POST endpoints |
| **Rate Limiting** | IP-based | 5 login attempts per 15-minute window |
| **Session Cookies** | Secure flags | `HttpOnly`, `SameSite=Lax` |
| **Headers** | 5+ security headers | X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy |
| **Password Policy** | Strong enforcement | Min 8 chars, uppercase, lowercase, digit, special character |
| **API Security** | No-cache headers | `Cache-Control: no-store` on all API responses |
| **Logging** | Failed login tracking | IP address + remaining attempts logged |
| **Secret Key** | Persistent | Survives server restarts (`.netra_secret`) |

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 📡 API Reference

All API endpoints require authentication. CSRF token must be included via `X-CSRF-Token` header for POST requests.

| Method | Endpoint | Description |
|:---:|:---|:---|
| `GET` | `/api/system` | CPU, memory, disk, swap, uptime, partitions |
| `GET` | `/api/network` | Interfaces, IO counters, active connections |
| `GET` | `/api/firewall` | Firewall status, rules, packet statistics |
| `GET` | `/api/services` | Running processes sorted by CPU usage |
| `GET` | `/api/connections` | TCP/UDP connections with process mapping |
| `GET` | `/api/logs` | System/security logs (last 5 minutes) |
| `GET` | `/api/info` | NETRA tool information |
| `POST` | `/api/change-password` | Change admin password (requires current) |
| `POST` | `/api/update` | Pull latest from Git repo |

### WebSocket Events

| Event | Direction | Payload |
|:---|:---:|:---|
| `system_metrics` | Server → Client | CPU, Memory, Disk, Network rates (every 2s) |
| `connect` | Client → Server | Connection established |
| `disconnect` | Client → Server | Connection terminated |

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🔄 Auto-Update

NETRA supports automatic updates from the Git repository while preserving your admin credentials:

```bash
# Via dashboard: Settings → Check & Update
# Or via API:
curl -X POST http://localhost:5001/api/update \
  -H "X-CSRF-Token: <your-token>" \
  -b "session=<your-session>"
```

**What's preserved during updates:**
- ✅ `admin_data.json` — Encrypted credentials
- ✅ `.netra_key` — Encryption key
- ✅ `.netra_secret` — Flask session key

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🧩 Tech Stack

<div align="center">

| Category | Technology | Purpose |
|:---|:---|:---|
| **Backend** | ![Flask](https://img.shields.io/badge/Flask-3.1-000?style=flat-square&logo=flask&logoColor=white) | Web framework & routing |
| **Real-time** | ![Socket.IO](https://img.shields.io/badge/Socket.IO-5.5-010101?style=flat-square&logo=socketdotio&logoColor=white) | WebSocket live data push |
| **System** | ![psutil](https://img.shields.io/badge/psutil-6.1-3776AB?style=flat-square&logo=python&logoColor=white) | Cross-platform system metrics |
| **Encryption** | ![Cryptography](https://img.shields.io/badge/Cryptography-44.0-D4AA00?style=flat-square&logo=letsencrypt&logoColor=white) | Fernet AES-128-CBC |
| **WSGI** | ![Eventlet](https://img.shields.io/badge/Eventlet-0.37-4B8BBE?style=flat-square&logo=python&logoColor=white) | Async WebSocket support |
| **Charts** | ![Chart.js](https://img.shields.io/badge/Chart.js-4.4-FF6384?style=flat-square&logo=chartdotjs&logoColor=white) | Real-time data visualization |
| **Icons** | ![Font Awesome](https://img.shields.io/badge/Font_Awesome-6.5-528DD7?style=flat-square&logo=fontawesome&logoColor=white) | Professional iconography |

</div>

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🎨 Dashboard Panels

<div align="center">

| Panel | Icon | Description |
|:---|:---:|:---|
| **Overview** | 📊 | System health at a glance — CPU, RAM, Disk, Network charts |
| **Network Monitor** | 🌐 | Interface details, bandwidth, packet analysis |
| **Firewall & Packets** | 🛡️ | Firewall rules, traffic distribution, error tracking |
| **Services** | ⚙️ | Process list with CPU/Memory, top consumers |
| **System Resources** | 🖥️ | Per-core CPU, memory breakdown, swap, partitions |
| **Connections** | 🔗 | Active TCP/UDP connections, process mapping |
| **Logs** | 📜 | Live log stream with color-coded severity |
| **Settings** | ⚡ | Admin password change, auto-update, security info |

</div>

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 🤝 Contributing

Contributions are welcome! To contribute:

1. **Fork** the repository
2. **Create** your feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

Please ensure your code follows the existing style and includes appropriate security measures.

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

<br>

<div align="center">
<img src="https://raw.githubusercontent.com/andreasbm/readme/master/assets/lines/aqua.png" alt="divider" width="100%">
</div>

<br>

<div align="center">

### Developed with 🔥 by **MintFire**

<br>

<a href="https://github.com/avik-root/Netra">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=400&size=14&duration=4000&pause=3000&color=6b7a99&center=true&vCenter=true&repeat=true&width=450&height=20&lines=Protecting+systems%2C+one+metric+at+a+time." alt="Footer" />
</a>

<br><br>

<img src="https://img.shields.io/badge/Made_with-Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Made_with-Flask-000?style=flat-square&logo=flask&logoColor=white" alt="Flask">
<img src="https://img.shields.io/badge/Made_with-❤️-ff3366?style=flat-square" alt="Love">

<br><br>

⭐ **Star this repo if you find NETRA useful!** ⭐

</div>
