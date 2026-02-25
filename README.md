# 🕵️ Intrusion Monitoring Honeypot

A lightweight cybersecurity honeypot designed to monitor, analyze and profile real-world attackers.

This project captures incoming traffic, enriches attacker intelligence and visualizes threat activity in real time.

---

## 🚀 Features

- Live attack monitoring dashboard
- IP intelligence enrichment (ASN, RDNS, Geo)
- Threat scoring system
- Human vs Bot behavior detection
- Malicious path detection
- Real-time attack feed (SSE)

---

## 🧠 Purpose

This project was created as a research and learning platform for:

- Threat Intelligence
- Honeypot engineering
- Offensive security analysis
- Behavioral attacker profiling

---

## ⚙️ Tech Stack

- Python
- Flask
- JavaScript
- Threat intelligence APIs

---

## ▶️ Running locally

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

**Windows (PowerShell)**

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

The dashboard will also be accessible from other devices on your local network:

```
http://<your-local-ip>:5000
```