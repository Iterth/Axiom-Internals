# 🛡️ Axiom Internals - Advanced Forensic & Analysis Suite

Axiom Internals is a high-performance endpoint detection and response (EDR) and digital forensics tool designed for deep system analysis and proactive threat hunting. By leveraging a low-level C++ engine and a modern Python interface, it provides deep visibility into Windows system internals.

![Version](https://img.shields.io/badge/Version-v2.2.1-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---
> **⚠️ Project Status: Concluded & Archived**
> Active development on Axiom Internals has been officially concluded. This project successfully achieved its core goal: building a high-performance bridge between low-level C++ system internals and Python-based forensic architecture.
> 
> My engineering focus has now completely shifted to a new architectural challenge: **[Markdown Text Editor (MTE)](https://github.com/Iterth/Markdown-Text-Editor)**, a high-performance, lightweight documentation and text management engine built with PySide6. 
>
> *Axiom Internals will remain open-source and public for educational purposes and portfolio demonstration.*

---

## 🎯 What's New in v2.2.1?

- **Centralized Log System:** Network Monitor alerts, YARA scan matches, and Threat Hunter detections are now logged to daily log files under the `logs/` directory.
- **IP Whitelist:** Known safe IP addresses can be added to `config.json` under `whitelist_ips` to suppress false positives in Network Monitor.
- **Bug Fix:** Network Monitor now correctly detects all local network interface IPs using psutil, preventing false positives on multi-adapter systems.
- **Bug Fix:** Window and taskbar icon now display correctly in both script and compiled executable modes.

## 🎯 What's New in v2.2.0?

- **Real-Time Network Monitoring:** The Network Manager tab now features a live port scan detector powered by Scapy. Running in a dedicated background thread, it monitors all incoming TCP traffic and alerts when a suspicious number of unique ports are accessed from a single source IP within a configurable time window.
- **Configurable Port Scan Threshold:** The port scan detection sensitivity is now controlled via `config.json` (`port_count` field), allowing fine-tuning without touching source code.

## 🎯 What's New in v2.1.0?

- **YARA Rule Engine:** Suspicious processes are now scanned against YARA rulesets in real-time. Drop any `.yar` file into the `rules/` folder to extend detection coverage — no code changes required.
- **Auto-Generated Ruleset:** A default `mimikatz.yar` signature file is created automatically on first launch.
- **Config System:** `config.json` is auto-generated on first launch, storing the VirusTotal API key, suspicious keyword list, and port scan threshold.
- **Bug Fix:** Saving a VirusTotal API key no longer erases the `suspicious_keywords` list from `config.json`.
- **Bug Fix:** Suspicious process branch now correctly applies row colors for all process types.

## 🎯 What's New in v2.0.1?

- **Deep Memory Threat Hunter:** Real-time scans of RWX memory regions to detect hidden PE files (MZ Headers), identifying Process Hollowing and DLL Injection.
- **PEB Command-Line Extractor:** Bypasses standard API limitations via `NtQueryInformationProcess`, parsing the Process Environment Block (PEB) to retrieve hidden command-line parameters and flag LotL activity.
- **Fail-Safe Kernel Protection:** Prevents accidental termination of critical system processes (PID 0 & 4).
- **Forensic UI Refactoring:** Interactive column scaling, forensic tooltips, and rapid IoC extraction.

---

## ⚙️ Technical Stack

- **Backend:** C++ (WinAPI, NtDll, Toolhelp32, WinSock2)
- **Frontend:** Python (PySide6 / Qt)
- **Pattern Matching:** YARA (via yara-python)
- **Network Analysis:** Scapy + Npcap
- **Interoperability:** ctypes & JSON-based memory-safe bridge

---

## 🚀 Getting Started

### Requirements

- Windows 10/11 (64-bit)
- Python 3.10+
- Visual C++ Redistributable 2022
- [Npcap](https://npcap.com/#download) (required for network monitoring)

### Installation

```bash
pip install PySide6 requests yara-python scapy
```

Run the compiled `AxiomInternals.dll` alongside `main_window.py`, or use the provided release executable.

### First Launch

On first launch, Axiom will automatically create:
- `config.json` — stores your VirusTotal API key, suspicious keyword list, and port scan threshold
- `rules/mimikatz.yar` — a default YARA ruleset for Mimikatz detection

To add custom YARA rules, drop `.yar` files into the `rules/` folder. They will be loaded automatically on the next scan.

---

## 🔍 Features

| Module | Description |
|---|---|
| Process Explorer | Lists all active processes with PID, PPID, path, command line, and thread count |
| Threat Hunter | Scans RWX memory regions for injected PE files and anomalies |
| YARA Scanner | Matches suspicious process executables against custom YARA rulesets |
| Network Monitor | Real-time TCP traffic analysis with port scan detection and alerting |
| Auto-Runs (Registry) | Lists and manages autorun registry entries |
| Windows Services | Lists and controls running services |
| VirusTotal Integration | Submits SHA256 hashes for cloud-based threat analysis |
| Forensic Report | Generates HTML incident response reports per process |

---

## 🧠 Transparent Engineering & AI Collaboration

As a **Transparent Engineer**, I believe in leveraging cutting-edge technology to solve complex problems. This project is the result of human-AI collaboration where:

- **The Logic & Architecture:** All security logic, low-level Windows API implementations, YARA integration design, network monitoring architecture, and all technical decisions were designed and driven by me.
- **The AI's Role:** I utilized AI as a **Senior Pair Programmer** — for code optimization, cross-language documentation, and accelerating boilerplate development. Every line of code was written and understood by me before being committed.
- **The Result:** A tool that demonstrates how a modern engineer can orchestrate AI to master low-level system internals and cybersecurity forensics.

---

## ⚠️ Disclaimer

Developed for educational and authorized Blue Team / Incident Response purposes only. Do not use against systems you do not own or have explicit permission to analyze.
