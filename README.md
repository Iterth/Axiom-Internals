# 🛡️ Axiom Internals - Advanced Forensic & Analysis Suite

Axiom Internals is a high-performance endpoint detection and response (EDR) and digital forensics tool designed for deep system analysis and proactive threat hunting. By leveraging a low-level C++ engine and a modern Python interface, it provides deep visibility into Windows system internals.

![Version](https://img.shields.io/badge/Version-v2.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

## 🎯 What's New in V2.0?

* **Deep Memory Threat Hunter:** Discards static whitelisting. The engine now performs real-time scans of RWX memory regions to detect hidden PE files (**MZ Headers**), effectively identifying Process Hollowing and DLL Injection.
* **PEB Command-Line Extractor:** Bypasses standard API limitations via `NtQueryInformationProcess`. It parses the **Process Environment Block (PEB)** to retrieve hidden command-line parameters, flagging suspicious LotL activities (e.g., `-EncodedCommand`).
* **Fail-Safe Kernel Protection:** Hardened backend safeguards that prevent the accidental termination of critical system processes (PID 0 & 4), ensuring system stability during forensic analysis.
* **Forensic UI Refactoring:** Interactive column scaling, forensic tooltips, and rapid IoC extraction capabilities.

## 🧠 Transparent Engineering & AI Collaboration

As a **Transparent Engineer**, I believe in leveraging cutting-edge technology to solve complex problems. This project is a result of human-AI collaboration where:
* **The Logic & Architecture:** All security logic, low-level Windows API implementations, and architectural decisions were designed and driven by me.
* **The AI's Role:** I utilized Artificial Intelligence as a **Senior Pair Programmer** for code optimization, cross-language documentation (Doxygen style), and accelerating the development of boilerplate bridge components.
* **The Result:** A tool that demonstrates how a modern engineer can orchestrate AI to master low-level system internals and cybersecurity forensics.

## ⚙️ Technical Stack
* **Backend:** C++ (WinAPI, NtDll, Toolhelp32, WinSock2)
* **Frontend:** Python (PySide6 / Qt)
* **Interoperability:** ctypes & JSON-based memory-safe bridge.

## ⚠️ Disclaimer
Developed for educational and authorized Blue Team/Incident Response purposes only.
