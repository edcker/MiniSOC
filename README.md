# 🛡️ MiniSOC — Custom Security Operations Center

A lightweight, automated Security Operations Center (SOC) built from first principles.  
This project ingests **Windows Security Event Logs**, applies **custom detection logic**, stores **structured findings**, and visualizes threats on a **real-time dashboard** — without relying on a commercial SIEM.

---

## 📌 Why This Project Exists

Most SOC labs focus on *using* SIEM tools, not understanding **how detections actually work**.

This project was built to:
- Learn **detection engineering**, not tool clicking
- Understand **Windows event logs at depth**
- Replicate **SOC workflows** using simple, transparent components
- Prove that detection logic is transferable across SIEM platforms

---

## 🧠 What This Demonstrates

### SOC Fundamentals
- Log ingestion and parsing
- Detection logic and thresholding
- Alert generation and severity classification
- Analyst-style investigation workflow

### Detection Engineering
- Event ID–based detections (not signatures)
- Time-window and threshold logic
- Append-only alert storage
- Safe handling of real security data

### Automation
- Scheduled execution using Windows Task Scheduler
- Continuous monitoring without manual intervention
- Repeatable, deterministic detections

### Visualization
- Real-time dashboard using HTML + JavaScript
- Severity filtering and aggregation
- Timeline-based event analysis

---

## 🏗️ Architecture Overview

