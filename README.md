# ⛏️ Redstone SOC

<p align="center">
  <img src="assets/banner.png" alt="Redstone SOC Banner" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit&logoColor=white">
  <img src="https://img.shields.io/badge/License-MIT-green">
  <img src="https://img.shields.io/badge/Status-Active-brightgreen">
</p>

<p align="center">
  🇧🇷 <a href="README.pt-BR.md">Leia em Português</a>
</p>

A lightweight, Minecraft-inspired **Security Operations Center (SOC)** and **File Integrity/Threat Detection Engine** built in Python.

Redstone SOC simulates real-world Blue Team and SecOps concepts — real-time file monitoring, hash analysis, Threat Intelligence lookup, MITRE ATT&CK mapping, external enrichment, and a full analyst dashboard — all wrapped in a Minecraft-themed architecture.

---

## 🎯 Project Goal

The primary goal of **Redstone SOC** is to practice and demonstrate hands-on concepts in:

* **Detection Engineering** — catching malicious samples and IOCs (Indicators of Compromise) automatically, layered by confidence (hash → filename → extension).
* **Security Operations & Automation** — monitoring file system events, scoring risk, and structuring JSON alerts.
* **Threat Intelligence & Enrichment** — mapping detections to MITRE ATT&CK and optionally cross-checking hashes against VirusTotal.
* **Software Architecture** — building modular, decoupled, and maintainable Python code for security tooling.

---

## ✨ Features

### 🔎 Detection Engine
- **Redstone Observer** — real-time file system monitoring via `watchdog`.
- **Automated SHA-256 Hashing** with retry handling for locked files.
- **Layered IOC Detection** — hash match → known filename → dangerous extension → safe extension → unknown.
- **Threat Score ("Redstone Power Level")** — a 0–100 risk score combining severity with detection-method confidence.
- **MITRE ATT&CK Mapping & Recommendations** for every detection.
- **Structured JSON Alerts** with full metadata, timestamps, severity, and reasoning.

### 📊 Analyst Dashboard (Streamlit)
- Real-time metrics (alert counts by severity, average Threat Score).
- Filters by severity, status, and date range.
- Search by filename.
- Interactive **Alert Timeline** (Plotly scatter: time × severity, sized by Threat Score).
- **Statistics panel** — severity distribution, alerts by hour, top detected extensions.
- **Threat Details** view per alert, including a Threat Score gauge.
- **IOC Database panel** — browse all known threat intelligence indicators, independent of triggered alerts.
- **CSV / PDF report export**, respecting active filters.
- Custom "Redstone" dark theme with a pixel-art accent header.

### 🌐 Optional Integrations (free, disabled by default)
- **Creeper Alert (Discord Webhook)** — real-time notification for HIGH/CRITICAL detections.
- **VirusTotal Lookup** — cross-checks HIGH/CRITICAL file hashes against 70+ AV engines via the free public API.

Both integrations run as safe no-ops when not configured — the core system never depends on them.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.x |
| File System Monitoring | `watchdog` |
| Dashboard | `streamlit` |
| Charts | `plotly` |
| Data Handling | `pandas`, JSON |
| PDF Reports | `fpdf2` |
| External Intel | VirusTotal Public API v3 |
| Notifications | Discord Webhooks |

---

## 🚀 Getting Started

### Prerequisites
Python 3.10+ installed on your system.

### Installation

```bash
git clone https://github.com/DanielJJunior/Redstone-SOC.git
cd Redstone-SOC

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### Running the Observer (real-time monitoring)

```bash
python main.py
```
This watches the `samples/` folder for new files and generates alerts in `alerts/`.

### Running the Dashboard

```bash
streamlit run dashboard/app.py
```
Run this from the project root, not from inside `dashboard/`.

---

## ⚙️ Optional Configuration (Discord & VirusTotal)

Both integrations are **free** and **fully optional**. The system works normally without them.

1. Copy the example settings file:
```bash
   cp config/settings.example.json config/settings.json
```
2. Fill in the values you want to use:
```json
   {
       "discord_webhook_url": "https://discord.com/api/webhooks/...",
       "virustotal_api_key": "your_virustotal_api_key"
   }
```
3. `config/settings.json` is git-ignored — never commit real credentials.

- **Discord webhook**: Channel Settings → Integrations → Webhooks → New Webhook.
- **VirusTotal API key**: create a free account at [virustotal.com](https://www.virustotal.com), then Profile → API Key. Public API is limited to 4 requests/minute — Redstone SOC only queries HIGH/CRITICAL detections to respect this quota.

---

## 🗃️ About the IOC Database

`config/iocs.json` is a **demonstration threat intelligence base**, built to showcase realistic detection categories: credential dumping, lateral movement, C2 frameworks, reconnaissance tools, remote access abuse, and ransomware indicators — each mapped to a MITRE ATT&CK technique.

It also includes the **official EICAR test file hash** (the antivirus industry's standard, safe test signature), allowing anyone to validate the hash-detection engine without using real malware. The remaining demo hashes are clearly placeholder values, not live threat feed data.

---

## 📁 Project Structure
Redstone-SOC/
├── main.py # Entry point — starts the Observer
├── config/
│ ├── iocs.json # Threat intelligence database
│ └── settings.example.json # Template for optional integrations
├── src/
│ ├── observer.py # Watchdog event handler
│ ├── file_analyzer.py # File metadata extraction
│ ├── hash_engine.py # SHA-256 hashing
│ ├── threat_intelligence.py# IOC lookups
│ ├── detection_engine.py # Detection logic + Threat Score
│ ├── alert_engine.py # Alert generation & persistence
│ ├── notifier.py # Discord webhook (Creeper Alert)
│ ├── virustotal.py # VirusTotal integration
│ ├── reporter.py # CSV/PDF report generation
│ └── utils.py
├── dashboard/
│ ├── app.py # Streamlit dashboard
│ └── dashboard_utils.py # Alert loading & statistics
├── .streamlit/config.toml # Redstone visual theme
├── samples/ # Watched folder (test files go here)
└── alerts/ # Generated alert JSONs
---

## 📜 License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 👤 Author

**Daniel Junior**
Built as a hands-on portfolio project to demonstrate practical Information Security concepts.