#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

/**
 * @struct ProcessInfo
 * @brief Holds detailed information about an active system process.
 */
struct ProcessInfo {
    DWORD pid;
    DWORD ppid;
    std::wstring name;
    std::wstring fullPath;
    DWORD threadCount;
};

/**
 * @class ProcessManager
 * @brief Handles process enumeration, termination, and privilege escalation.
 */
class ProcessManager {
public:
    static std::vector<ProcessInfo> GetProcessList();
    static bool TerminateProcessByPID(DWORD pid);
    static bool EnableDebugPrivilege();
    static std::wstring GetProcessNameFromPID(DWORD pid);
};