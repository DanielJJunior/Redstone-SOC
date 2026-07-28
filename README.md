# ⛏️ Redstone SOC

A lightweight, Minecraft-inspired **Security Operations Center (SOC)** and **File Integrity/Threat Detection Engine** built in Python.

This project simulates real-world Blue Team and SecOps concepts—such as real-time file monitoring, hash analysis, Threat Intelligence lookup, and alert generation—all wrapped in a fun Minecraft-themed architecture.

---

## 🎯 Project Goal

The primary goal of **Redstone SOC** is to practice and demonstrate hands-on concepts in:
* **Detection Engineering:** Catching malicious samples and IOCs (Indicators of Compromise) automatically.
* **Security Operations & Automation:** Monitoring file system events and structuring JSON alerts.
* **Software Architecture:** Building modular, decoupled, and maintainable Python code for security tooling.

---

## ✨ Current Features

- [x] **Redstone Observer (Real-time File System Monitoring):** Continuously watches target directories for newly created or modified files.
- [x] **Automated SHA-256 Hashing:** Automatically extracts unique file hashes upon detection.
- [x] **IOC Detection Engine:** Matches file signatures/hashes against a Threat Intelligence database.
- [x] **Decoupled Threat Intel Store:** Keeps intelligence signatures completely separated from core execution logic.
- [x] **Structured JSON Alerts:** Generates detailed alert logs containing metadata, timestamps, severity levels, and detection reasons.
- [x] **Event History & Logging:** Tracks system events and operational status in the terminal.

---

## 🛠️ Tech Stack & Dependencies

* **Language:** Python 3.x
* **File System Events:** `watchdog`
* **Data Interchange:** JSON
* **OS / Environment:** Cross-platform (Linux / Windows)

---

## 🚀 Getting Started

### Prerequisites
Make sure you have Python installed on your system.

### Installation & Execution

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/DanielJJunior/Redstone-SOC.git](https://github.com/DanielJJunior/Redstone-SOC.git)
   cd Redstone-SOC
