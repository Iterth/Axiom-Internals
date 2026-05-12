#include "ProcessManager.h"
#include <tlhelp32.h>
#include <winternl.h>

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

            info.commandLine = GetProcessCommandLine(info.pid);

            processList.push_back(info);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processList;
}

/**
 * Safely terminates a process while protecting critical kernel PIDs (0 & 4).
 */
bool ProcessManager::TerminateProcessByPID(DWORD pid) {
    // SECURITY GUARD: Never allow termination of Idle (0) or System (4) processes
    if (pid <= 4) {
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) return false;

    BOOL result = TerminateProcess(hProcess, 0);
    CloseHandle(hProcess); // Always close handles to prevent resource leaks
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

#include "ProcessManager.h"
#include <tlhelp32.h>
#include <winternl.h> // Required for NtQueryInformationProcess and PEB structures

// --- INTERNAL HELPERS ---
// Define the prototype for the undocumented ntdll function
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

/**
 * Retrieves the full command line of a process by manually parsing its
 * Process Environment Block (PEB) within the target process memory space.
 */
std::wstring ProcessManager::GetProcessCommandLine(DWORD processID) {
    std::wstring commandLine = L"<No Command Line / Access Denied>";

    // 1. Open the process with Query and VM_Read rights
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (!hProcess) return commandLine;

    // 2. Resolve the undocumented NtQueryInformationProcess from ntdll.dll
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) { CloseHandle(hProcess); return commandLine; }

    _NtQueryInformationProcess NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProcess) { CloseHandle(hProcess); return commandLine; }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;

    // 3. Query ProcessBasicInformation to find the address of the PEB
    if (NtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) >= 0 && pbi.PebBaseAddress) {
        PEB peb;
        // 4. Read the PEB structure from target process memory
        if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
            RTL_USER_PROCESS_PARAMETERS rtlParams;
            // 5. Locate the ProcessParameters block which contains the CommandLine
            if (ReadProcessMemory(hProcess, peb.ProcessParameters, &rtlParams, sizeof(rtlParams), NULL)) {

                // 6. Allocate buffer and read the actual Unicode CommandLine string
                PWSTR buffer = new WCHAR[rtlParams.CommandLine.Length / 2 + 1];
                if (ReadProcessMemory(hProcess, rtlParams.CommandLine.Buffer, buffer, rtlParams.CommandLine.Length, NULL)) {
                    buffer[rtlParams.CommandLine.Length / 2] = L'\0';
                    commandLine = buffer;
                }
                delete[] buffer;
            }
        }
    }
    CloseHandle(hProcess);
    return commandLine;
}
