# 🕵️ Intrusion Monitor
### A public live traffic observatory for security experimentation

Intrusion Monitor is an experimental cybersecurity project that visualizes real-world traffic interacting with an exposed web service.

Instead of hiding attacker activity, this project makes it visible — providing a real-time, interactive dashboard where anyone can observe scanners, bots and automated probing behavior as it happens.

---

## 🧪 Project Philosophy

This is **not** a production security tool.

Intrusion Monitor was created as an open experiment focused on exploration, learning and curiosity about how the internet behaves when a service is exposed.

The project is intentionally open and flexible:

- Run it anywhere
- Modify it freely
- Break it, learn from it, improve it
- Use it for research, education or experimentation

The dashboard is public by design — transparency and observation are part of the concept.

---

## 🚀 Features

- 🔴 Live traffic monitoring dashboard
- 🌍 IP enrichment (GeoIP, ASN, RDNS)
- 🤖 Automated scanner behavior visualization
- 🧠 Threat scoring heuristics
- 🧨 Malicious path detection
- ⚡ Real-time attack feed (Server-Sent Events)
- 📊 Interactive visualization of incoming activity

---

## ⚙️ Tech Stack

- Python 3
- Flask
- Jinja2
- JavaScript
- External threat intelligence APIs

---

## ▶️ Running locally

Clone the repository and run the application using a Python virtual environment.

### 1) Clone the repository

```bash
git clone https://github.com/SEUUSER/intrusion-monitor.git
cd intrusion-monitor
```

### 2) Create & activate a virtual environment

**Windows (PowerShell)**

```powershell
py -m venv .venv
.\.venv\Scripts\activate
py -m pip install -U pip
py -m pip install -r requirements.txt
```

**Linux / macOS / Kali**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
```

If you are using Kali Linux and `venv` is missing:

```bash
sudo apt update
sudo apt install -y python3-venv
```

### 3) Run the application

**Windows**

```powershell
py intrusion_detector.py
```

**Linux / macOS**

```bash
python intrusion_detector.py
```

### 4) Open in your browser

```
http://127.0.0.1:5000
```

The dashboard can also be accessed from other devices on your local network:

```
http://<your-local-ip>:5000
```

---

## 📁 Project Structure

```
intrusion-monitor/
│
├── intrusion_detector.py
├── templates/
├── static/
├── requirements.txt
└── README.md
```

---

## ⚠️ Security & Deployment Notes

This project is a **research and visualization experiment** and is not hardened for production environments.

If you choose to expose it to the public internet, consider:

- Running behind a reverse proxy or CDN
- Applying rate limiting
- Avoiding debug mode
- Running inside an isolated environment (VM/container)
- Avoiding elevated privileges

Anyone deploying this project publicly is responsible for their own configuration and exposure risks.

---

## 👨‍💻 Author

João Ramos Maciel  
Cybersecurity Engineer — Offensive Security & IT Audit

Building security experiments, automation tools and attack surface intelligence projects.