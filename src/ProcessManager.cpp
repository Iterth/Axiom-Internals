#include "ProcessManager.h"
#include <tlhelp32.h>

std::vector<ProcessInfo> ProcessManager::GetProcessList() {
    std::vector<ProcessInfo> processList;

    // 1. Take a snapshot of all running processes in the system
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // If the snapshot fails, return the empty list
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processList;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // 2. Iterate through the processes in the snapshot
    if (Process32First(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.ppid = pe32.th32ParentProcessID;
            info.name = pe32.szExeFile;
            info.threadCount = pe32.cntThreads;

            // --- Windows API Security: Attempt to resolve full executable path ---
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);

            if (hProcess != NULL) {
                WCHAR pathBuffer[MAX_PATH];
                DWORD bufferSize = MAX_PATH;
                if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, &bufferSize)) {
                    info.fullPath = pathBuffer;
                }
                else {
                    info.fullPath = L"<Path Not Available>";
                }
                CloseHandle(hProcess);
            }
            else {
                info.fullPath = L"<Access Denied>";
            }

            processList.push_back(info);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processList;
}

bool ProcessManager::TerminateProcessByPID(DWORD pid) {
    // 1. Open the process with termination rights
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    // 2. Execute the termination command
    BOOL result = TerminateProcess(hProcess, 0);

    CloseHandle(hProcess);
    return result == TRUE;
}

bool ProcessManager::EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    // 1. Open the current process token with adjustment privileges
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    // 2. Lookup the LUID for "SeDebugPrivilege"
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    // 3. Prepare the token privilege structure
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // 4. Inject the modified token back into our process
    AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    bool result = (GetLastError() == ERROR_SUCCESS);

    CloseHandle(hToken);
    return result;
}

std::wstring ProcessManager::GetProcessNameFromPID(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return L"Unknown";

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                CloseHandle(hSnapshot);
                return std::wstring(pe32.szExeFile);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return L"Unknown";
}