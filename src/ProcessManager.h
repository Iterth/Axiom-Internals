#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

/**
 * @struct ProcessInfo
 * @brief Represents deep-dive telemetry for a specific system process.
 * Contains identifiers, execution paths, and memory-resident metadata.
 */
struct ProcessInfo {
    DWORD pid;                 // Unique Process Identifier
    DWORD ppid;                // Parent Process Identifier
    std::wstring name;         // Image name (e.g., explorer.exe)
    std::wstring fullPath;     // Full absolute disk path of the executable
    DWORD threadCount;         // Number of active execution threads
    std::wstring commandLine;  // The actual command used to launch the process (Extracted from PEB)
};

/**
 * @class ProcessManager
 * @brief Orchestrates system-level process management and forensic data retrieval.
 * Provides methods for enumeration, termination safety, and memory-resident metadata extraction.
 */
class ProcessManager {
public:
    static std::vector<ProcessInfo> GetProcessList();
    static bool TerminateProcessByPID(DWORD pid);
    static bool EnableDebugPrivilege();
    static std::wstring GetProcessNameFromPID(DWORD pid);
    static std::wstring GetProcessCommandLine(DWORD processID); // Forensic PEB analyzer
};