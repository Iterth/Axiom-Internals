\#Axiom Internals - Advanced Forensic and Analysis Suite

Axiom Internals is a cybersecurity tool made for deep system analysis and threat hunting. Thanks to its fast C++ core engine and modern Python PySide6 UI, nothing happening on your system goes unnoticed.



\##Features

* \*\*⚙️ Process Explorer:\*\* Lists all active processes with their PID, thread count, and full file path in real-time. You can kill suspicious processes with a single click.
* \*\*🚀 Auto-Runs (Registry Scanner):\*\* Detects malware hiding in Windows startup (persistence) and safely deletes them from the registry.
* \*\*🌐 Network Monitor:\*\* Maps all TCP network connections of your PC. It tracks connection states and shows exactly which application (Process Name) is connecting to where.
* \*\*🔐 Cryptographic File Hasher:\*\* Quickly calculates the SHA256 digital fingerprint of a suspicious file using the built-in Windows Cryptography API.
* \*\*🛡️ Threat Intelligence (VirusTotal Integration):\*\* Automatically sends the SHA256 hash of suspicious files to the VirusTotal API. It reports in seconds whether the file is clean or flagged as malware.



\##Technologies Used

* \*\*Backend Engine:\*\* C++, Windows API, WinSock2, Wincrypt
* \*\*Frontend UI:\*\* Python 3, PySide6
* \*\*Network Integration:\*\* Requests (REST API communication)



\##Installation and Usage

1. Clone or download this project to your computer.
2. Open the C++ project in the Source Files with Visual Studio and build it in x64 Release or Debug mode. (This will generate the AxiomInternals.dll file).
3. Install the required Python libraries (pyside6 and requests).
4. Run the main\_window.py file.
5. When you try to analyze a file via VirusTotal, the app will ask for your free API key. This key is saved locally in a config.json file and is never shared.



\##Developer Note

This project was created to speed up cybersecurity research, system analysis, and malware detection.

