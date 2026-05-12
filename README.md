# 🛡️ Axiom Internals - Advanced Forensic & Analysis Suite

Axiom Internals is a high-performance endpoint detection and response (EDR) and digital forensics tool designed for security analysts and threat hunters. By leveraging a low-level C++ engine and a modern Python interface, it provides deep visibility into Windows system internals, bypassing standard API limitations.

![Axiom Internals UI](https://img.shields.io/badge/Status-Active-success)
![Version](https://img.shields.io/badge/Version-v2.0-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

## 🎯 Key Features (V2.0 Major Update)

* **Deep Memory Threat Hunter:** Discards the traditional whitelist approach. Scans process virtual memory (RWX regions) and extracts the first bytes to detect hidden PE files (**MZ Headers**), identifying Process Hollowing and DLL Injection attacks.
* **PEB Command-Line Extractor:** Bypasses standard Windows API restrictions using undocumented `NtQueryInformationProcess`. Parses the **Process Environment Block (PEB)** to extract hidden command-line parameters, instantly flagging suspicious Living-off-the-Land (LotL) activities (e.g., `-EncodedCommand`, `-Hidden`).
* **Fail-Safe Kernel Protection:** Implemented strict process termination safeguards. Critical system processes like `PID 0` (Idle) and `PID 4` (System) are locked at the backend level, preventing accidental Blue Screen of Death (BSOD) scenarios.
* **Advanced Process Explorer:** Real-time enumeration of running processes, parent-child relationships, and active threads.
* **Live Network Monitor:** Maps active TCP/UDP connections directly to their owning Process IDs.
* **Persistence (Auto-Run) Scanner:** Deep registry scans to detect hidden startup mechanisms.
* **Heuristic Interface:** Dynamic column scaling, forensic tooltips, and interactive right-click menus for rapid IoC (Indicator of Compromise) extraction to VirusTotal.

## ⚙️ Architecture
* **Backend:** C++ (WinAPI, NtDll, Toolhelp32, WinSock2)
* **Frontend:** Python (PySide6 / Qt)
* **Bridge:** ctypes and JSON serialization for seamless memory-safe communication.

## ⚠️ Disclaimer
*Axiom Internals is developed strictly for educational, Blue Team, and Incident Response purposes. Ensure you have authorization before analyzing system memory in production environments.*
