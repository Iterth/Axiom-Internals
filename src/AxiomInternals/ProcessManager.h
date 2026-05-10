#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

struct ProcessInfo {
	DWORD pid;
	DWORD ppid;
	std::wstring name;
	std::wstring fullPath;
	DWORD threadCount;
};

class ProcessManager {
public:
	static std::vector<ProcessInfo> GetProcessList();
	static bool TerminateProcessByPID(DWORD pid);
	static bool EnableDebugPrivilege();
};
