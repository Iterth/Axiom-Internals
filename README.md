# 🛡️ Axiom Internals - Advanced Forensic & Analysis Suite

Axiom Internals is a high-performance endpoint detection and response (EDR) and digital forensics tool designed for deep system analysis and proactive threat hunting. By leveraging a low-level C++ engine and a modern Python interface, it provides deep visibility into Windows system internals.

![Version](https://img.shields.io/badge/Version-v2.1-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 🎯 What's New in v2.1.1?

- **YARA Rule Integration:** With this update YARA scan can be triggered manually on the action menu
- **Bug fix** Empty path is not crashes YARA scan anymore. 

---


---

## 🎯 What's New in v2.1?

- **YARA Rule Integration:** Suspicious processes are now scanned against YARA rules in real-time. A default `mimikatz.yar` ruleset is auto-generated on first launch. Drop any `.yar` file into the `rules/` folder to extend detection coverage.
- **Dynamic Rules Loading:** The engine automatically loads all `.yar` files from the `rules/` directory — no code changes required to add new signatures.
- **Config System:** `config.json` is auto-created on first launch, storing the VirusTotal API key and customizable `suspicious_keywords` list. Edit it directly to tune detection sensitivity.
- **Bug Fix:** Saving a VirusTotal API key no longer erases the `suspicious_keywords` list from config.

---

## 🎯 What's in v2.0?

- **Deep Memory Threat Hunter:** Real-time scans of RWX memory regions to detect hidden PE files (MZ Headers), identifying Process Hollowing and DLL Injection.
- **PEB Command-Line Extractor:** Bypasses standard API limitations via `NtQueryInformationProcess`, parsing the Process Environment Block (PEB) to retrieve hidden command-line parameters and flag LotL activity.
- **Fail-Safe Kernel Protection:** Prevents accidental termination of critical system processes (PID 0 & 4).
- **Forensic UI Refactoring:** Interactive column scaling, forensic tooltips, and rapid IoC extraction.

---

## ⚙️ Technical Stack

- **Backend:** C++ (WinAPI, NtDll, Toolhelp32, WinSock2)
- **Frontend:** Python (PySide6 / Qt)
- **Pattern Matching:** YARA (via yara-python)
- **Interoperability:** ctypes & JSON-based memory-safe bridge

---

## 🚀 Getting Started

### Requirements

- Windows 10/11 (64-bit)
- Python 3.10+
- Visual C++ Redistributable 2022

### Installation

```bash
pip install PySide6 requests yara-python
```

Run the compiled `AxiomInternals.dll` alongside `main_window.py`, or use the provided release executable.

### First Launch

On first launch, Axiom will automatically create:
- `config.json` — stores your VirusTotal API key and suspicious keyword list
- `rules/mimikatz.yar` — a default YARA ruleset for Mimikatz detection

To add custom YARA rules, drop `.yar` files into the `rules/` folder. They will be loaded automatically on the next scan.

---

## 🔍 Features

| Module | Description |
|---|---|
| Process Explorer | Lists all active processes with PID, PPID, path, command line, and thread count |
| Threat Hunter | Scans RWX memory regions for injected PE files and anomalies |
| YARA Scanner | Matches suspicious process executables against custom YARA rulesets |
| Auto-Runs (Registry) | Lists and manages autorun registry entries |
| Network Manager | Displays active TCP/UDP connections with process mapping |
| Windows Services | Lists and controls running services |
| VirusTotal Integration | Submits SHA256 hashes for cloud-based threat analysis |
| Forensic Report | Generates HTML incident response reports per process |

---

## 🧠 Transparent Engineering & AI Collaboration

As a **Transparent Engineer**, I believe in leveraging cutting-edge technology to solve complex problems. This project is the result of human-AI collaboration where:

- **The Logic & Architecture:** All security logic, low-level Windows API implementations, YARA integration design, and architectural decisions were designed and driven by me.
- **The AI's Role:** I utilized AI as a **Senior Pair Programmer** — for code optimization, cross-language documentation, and accelerating boilerplate development. Every line of code was written and understood by me before being committed.
- **The Result:** A tool that demonstrates how a modern engineer can orchestrate AI to master low-level system internals and cybersecurity forensics.

---

## ⚠️ Disclaimer

Developed for educational and authorized Blue Team / Incident Response purposes only. Do not use against systems you do not own or have explicit permission to analyze.
