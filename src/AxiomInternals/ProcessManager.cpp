#include "ProcessManager.h"
#include <tlhelp32.h>

std::vector<ProcessInfo> ProcessManager::GetProcessList() {
	std::vector<ProcessInfo> processList;

	// 1. Taking Snapshot of system.
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// If we couldn't take snapshot for a reason just show empty list.
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return processList;
	}

	// Thanks to PROCESSENTRY32 we can take list.
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	// 2. Try to read Process32First
	if (Process32First(hSnapshot, &pe32)) {
		do {
			// Populate the ProcessInfo struct with snapshot data.
			ProcessInfo info;
			info.pid = pe32.th32ProcessID;
			info.ppid = pe32.th32ParentProcessID;
			info.name = pe32.szExeFile;
			info.threadCount = pe32.cntThreads;

			// --- Windows API Security (Taking full path information.) ---
			// 1. Taking Permission.
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);

			if (hProcess != NULL) {
				WCHAR pathBuffer[MAX_PATH];
				DWORD bufferSize = MAX_PATH;

				// 2. Using Windows API
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
			// --------------------------------------------------------------

			processList.push_back(info);
		} while (Process32Next(hSnapshot, &pe32));
		// 3. Iterate through the remaining processes.
	}	
	// 4. Close the snapshot handle to avoid memory leaks.
	CloseHandle(hSnapshot);

	return processList;
}

bool ProcessManager::TerminateProcessByPID(DWORD pid) {
	// 1. Request termination permission from the kernel.
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);

	// If access is denied or process doesn't exist
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

	// 1. Taking token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return false;
	}

	// 2. Taking "SeDebugPrivilege" permission's LUID from windows.
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		CloseHandle(hToken);
		return false;
	}
	// 3. Setting up the packet.
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// 4. Injecting the packet, which we made it, into our process.
	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	bool result = (GetLastError() == ERROR_SUCCESS);

	CloseHandle(hToken);
	return result;
}

std::wstring ProcessManager::GetProcessNameFromPID(DWORD pid) {
	std::wstring name = L"<Unknown>";
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnapshot, &pe32)) {
			do {
				if (pe32.th32ProcessID == pid) {
					name = pe32.szExeFile;
					break;
				}
			} while (Process32NextW(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	return name;
}






