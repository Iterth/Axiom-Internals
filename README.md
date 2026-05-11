# Axiom Internals - Advanced Forensic & Analysis Suite 🛡️

Axiom Internals is a high-performance endpoint detection and response (EDR) and digital forensics tool designed for security analysts and threat hunters. By leveraging a low-level C++ engine and a modern Python interface, it provides deep visibility into Windows system internals.

---

## 🚀 Key Features

* **⚙️ Advanced Process Explorer:** Real-time process enumeration with PID, PPID, thread counts, and full image paths. Includes safe process termination.
* **🔧 Windows Services & Drivers:** Direct interaction with the Service Control Manager (SCM). Monitor, Start, or Stop Win32 services and Kernel-mode drivers (crucial for rootkit hunting).
* **🌐 Network Intelligence:** Maps active TCP/UDP connections to specific processes. Includes integrated **IP-API Geolocation** to trace remote endpoints.
* **🚀 Auto-Runs (Persistence) Scanner:** Scans critical Windows Registry hives (`Run`, `RunOnce`) to detect malware persistence and allows safe deactivation.
* **🔐 Cryptographic Hashing:** Generates SHA256 fingerprints of any running executable using the native Windows Cryptography API.
* **📊 Forensic Reporting:** Generates professional, standalone HTML reports containing process snapshots, file hashes, and live network activity for incident documentation.
* **🔍 VirusTotal Integration:** Automated threat intelligence querying via VirusTotal V3 API based on file hashes.

---

## 🛠️ Technology Stack & Dependencies

### Backend (Core Engine)
- **C++20:** High-performance systems programming and memory management.
- **Windows API:** Direct interaction with system handles, SCM, and Registry.
- **nlohmann/json:** A modern JSON library for C++ used for high-speed data serialization.
- **WinSock2 & IPHlpApi:** For advanced network mapping and socket analysis.

### Frontend (User Interface)
- **Python 3.14:** Application logic and API orchestration.
- **PySide6 (Qt for Python):** For the industrial-grade SOC (Security Operations Center) interface.
- **Requests:** For asynchronous communication with VirusTotal and Geolocation APIs.
- **Ctypes:** Bridge for high-speed communication with the C++ DLL.

---

## 🤖 Modern Development Philosophy

In line with the evolution of software engineering, **Axiom Internals** was developed using **AI-assisted engineering methodologies**. 

The core architecture, security logic, and low-level Windows API integrations were architected and managed by the developer. AI tools were strategically utilized as a **Senior Pair Programmer** to:
* **Accelerate Prototyping:** Rapidly iterate on complex C++ logic and system-level structures.
* **Optimize Implementation:** Streamline the data bridge between the C++ engine and Python UI.
* **Quality Assurance:** Enhance code documentation and debugging efficiency.

This methodology demonstrates a commitment to modern engineering practices, focusing on architectural integrity and rapid problem-solving rather than manual boilerplate coding.

---

## 🚀 Installation & Build

1. **Build the Engine:** Open the C++ solution in Visual Studio. Set the configuration to `Release | x64` and build. This generates `AxiomInternals.dll`.
2. **Environment Setup:** Ensure `AxiomInternals.dll` is in the same directory as the Python scripts.
3. **Install Requirements:**
    ```bash
    pip install -r requirements.txt
    ```
4. **Run the Suite:**
    ```bash
    python main_window.py
    ```

---

## 📜 License
This project is licensed under the **MIT License**.

## ⚠️ Disclaimer
Axiom Internals is intended for **educational and professional security analysis purposes only**. Use it responsibly and ethically on systems you have explicit permission to audit.
