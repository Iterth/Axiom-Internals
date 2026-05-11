# Axiom Internals - Advanced Forensic & Analysis Suite

Axiom Internals is a high-performance endpoint detection and response (EDR) and digital forensics tool designed for security analysts and threat hunters. By leveraging a low-level C++ engine and a modern Python interface, it provides deep visibility into Windows system internals.

## 🛡️ Key Features

* **⚙️ Advanced Process Explorer:** Real-time process enumeration with PID, PPID, thread counts, and full image paths. Includes safe process termination.
* **🔧 Windows Services & Drivers:** Direct interaction with the Service Control Manager (SCM). Monitor, Start, or Stop Win32 services and Kernel-mode drivers (crucial for rootkit hunting).
* **🌐 Network Intelligence:** Maps active TCP/UDP connections to specific processes. Includes integrated **IP-API Geolocation** to trace remote endpoints.
* **🚀 Auto-Runs (Persistence) Scanner:** Scans critical Windows Registry hives (`Run`, `RunOnce`) to detect malware persistence and allows safe deactivation.
* **🔐 Cryptographic Hashing:** Generates SHA256 fingerprints of any running executable using the native Windows Cryptography API.
* **📊 Forensic Reporting:** Generates professional, standalone HTML reports containing process snapshots, file hashes, and live network activity for incident documentation.
* **🔍 VirusTotal Integration:** Automated threat intelligence querying via VirusTotal V3 API based on file hashes.

## 🛠️ Technology Stack & Dependencies

### Backend (Core Engine)
- **C++20:** High-performance systems programming.
- **Windows API:** Direct interaction with system handles, SCM, and Registry.
- **[nlohmann/json](https://github.com/nlohmann/json):** A modern JSON library for C++ used for high-speed data serialization between the engine and UI.
- **WinSock2 & IPHlpApi:** For advanced network mapping.

### Frontend (User Interface)
- **Python 3.14:** Application logic and API orchestration.
- **PySide6 (Qt for Python):** For the industrial-grade SOC interface.
- **Requests:** For asynchronous communication with VirusTotal and Geolocation APIs.
- **Ctypes:** Bridge for high-speed communication with the C++ DLL.

## 🚀 Installation & Build

1.  **Build the Engine:** Open the C++ solution in Visual Studio. Set the configuration to `Release | x64` and build. This generates `AxiomInternals.dll`.
2.  **Environment Setup:** Ensure `AxiomInternals.dll` is in the same directory as the Python scripts.
3.  **Install Requirements:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Run the Suite:**
    ```bash
    python main_window.py
    ```

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer
Axiom Internals is intended for educational and professional security analysis purposes only. Use it responsibly on systems you own or have explicit permission to audit.
