#include "InjectionDetector.h"
#include <psapi.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

namespace {
	// Helper Function to extract the name of a process given its handle
	std::string GetProcessNameFromHandle(HANDLE hProcess) {
		char processName[MAX_PATH] = "<unknown>";
		HMODULE hMod;
		DWORD cbNeeded;
		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
			GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName) / sizeof(char));
		}
		return std::string(processName);
	}
}

/**
 * Scans a process's virtual memory for RWX (Read/Write/Execute) pages that are
 * not backed by a disk file (Private), indicating possible code injection.
 */
void InjectionDetector::AnalyzeProcessMemory(DWORD processID, const std::string& processName, std::vector<InjectionInfo>& detectedInjections) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	if (hProcess == NULL) return;

	MEMORY_BASIC_INFORMATION mbi;
	LPCVOID address = 0;

	while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
		// Condition: Memory must be committed, private (not a mapped file), and RWX.
		bool isCommitted = (mbi.State == MEM_COMMIT);
		bool isPrivate = (mbi.Type == MEM_PRIVATE);
		bool isRWX = (mbi.Protect == PAGE_EXECUTE_READWRITE);

		if (isCommitted && isPrivate && isRWX) {
			char magicBytes[2] = { 0 };
			SIZE_T bytesRead = 0;

			// FORENSIC CHECK: Peek at the first two bytes to check for a PE signature (MZ)
			if (ReadProcessMemory(hProcess, mbi.BaseAddress, magicBytes, 2, &bytesRead) && bytesRead == 2) {
				InjectionInfo info;
				info.processID = processID;
				info.processName = processName;
				info.baseAddress = mbi.BaseAddress;
				info.regionSize = mbi.RegionSize;
				info.protection = "PAGE_EXECUTE_READWRITE";

				// DETECTION: If 'MZ' header is found in a private RWX region, it's likely a hidden PE/Module.
				if (magicBytes[0] == 'M' && magicBytes[1] == 'Z') {
					info.riskLevel = "CRITICAL (HIDDEN PE)";
				}
				else {
					// Likely a JIT engine or custom shellcode
					info.riskLevel = "WARNING (SHELLCODE/JIT)";
				}
				detectedInjections.push_back(info);
			}
		}
		address = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
	}
	CloseHandle(hProcess);
}
	

std::vector<InjectionInfo> InjectionDetector::ScanSystemForInjections() {
	std::vector<InjectionInfo> allInjections;
	DWORD aProcesses[1024], cbNeeded, cProcesses;

	// Enumerate all active Process IDs in the system
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		return allInjections;
	}

	cProcesses = cbNeeded / sizeof(DWORD);

	//Loop through every single process running on the OS
	for (unsigned i = 0; i < cProcesses; i++) {
		DWORD pid = aProcesses[i];
		if (pid != 0) {
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
			std::string procName = "<unknown>";

			if (hProcess != NULL) {
				procName = GetProcessNameFromHandle(hProcess);
				CloseHandle(hProcess);
			}

			// Send the process to our deep memory analyzer
			AnalyzeProcessMemory(pid, procName, allInjections);
		}
	}

	return allInjections;
}