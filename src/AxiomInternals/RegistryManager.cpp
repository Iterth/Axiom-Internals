#include "RegistryManager.h"
#include <iostream>
#include <filesystem>
#include <algorithm>

namespace fs = std::filesystem;

// Wrapper Function: Translates paths like %windir% or %appdata%.
std::wstring ExpandPath(std::wstring path) {
	wchar_t expanded[MAX_PATH];
	ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH);
	return std::wstring(expanded);
}

// Wrapper Function: Cleans path that comes from registry
std::wstring CleanPath(std::wstring path) {
	if (path.empty()) return path;
	if (path[0] == L'\"') {
		size_t secondQuote = path.find(L'\"', 1);
		if (secondQuote != std::wstring::npos)
			return path.substr(1, secondQuote - 1);
	}
	size_t spacePos = path.find(L' ');
	if (spacePos != std::wstring::npos && path.find(L'\\') != std::wstring::npos)
		return path.substr(0, spacePos);

	return path;
}

// -------------------------------------------------------------------------

// Wrapper Function: Reads the registry key
void ScanRegistryKey(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& locationLabel, std::vector<AutoRunInfo>& results) {
	HKEY hKey;
	if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD index = 0;
		WCHAR valueName[1024];
		DWORD valueNameSize = 1024;
		DWORD type;
		BYTE data[2048];
		DWORD dataSize = 2048;

		while (RegEnumValueW(hKey, index, valueName, &valueNameSize, NULL, &type, data, &dataSize) == ERROR_SUCCESS) {
			if (type == REG_SZ || type == REG_EXPAND_SZ) {
				AutoRunInfo info;
				info.name = valueName;
				info.command = reinterpret_cast<wchar_t*>(data);
				info.location = locationLabel;

				std::wstring expanded = ExpandPath(info.command);
				std::wstring cleanPath = CleanPath(expanded);
				try {
					info.exists = fs::exists(cleanPath);
				}
				catch (...) {
					info.exists = false;
				}

				results.push_back(info);
			}
			index++;
			valueNameSize = 1024;
			dataSize = 2048;
		}
		RegCloseKey(hKey);
	}
}
// -------------------------------------------------------------------------

std::vector<AutoRunInfo> RegistryManager::GetAutoRuns() {
	std::vector<AutoRunInfo> autoRuns;
	struct RegPath {
		HKEY root;
		std::wstring path;
		std::wstring label;
	};

	std::vector<RegPath> targets = {
		{HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKCU\\Run"},
		{HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKCU\\RunOnce"},
		{HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM\\Run"},
		{HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", L"HKLM\\RunOnce"},
		// 32-bit softwares (WoW6432Node).
		{HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", L"HKLM6432\\Run"}
	};

	for (const auto& target : targets) {
		ScanRegistryKey(target.root, target.path, target.label, autoRuns);
	}

	return autoRuns;
}

bool RegistryManager::DeleteAutoRun(const std::wstring& valueName, const std::wstring& locationLabel) {
	HKEY hKeyRoot;
	std::wstring subKey;

	if (locationLabel == L"HKCU\\Run") {
		hKeyRoot = HKEY_CURRENT_USER;
		subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	}
	else if (locationLabel == L"HKCU\\RunOnce") {
		hKeyRoot = HKEY_CURRENT_USER;
		subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
	}
	else if (locationLabel == L"HKLM\\Run") {
		hKeyRoot = HKEY_LOCAL_MACHINE;
		subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	}
	else if (locationLabel == L"HKLM\\RunOnce") {
		hKeyRoot = HKEY_LOCAL_MACHINE;
		subKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
	}
	else if (locationLabel == L"HKLM6432\\Run") {
		hKeyRoot = HKEY_LOCAL_MACHINE;
		subKey = L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
	}
	else {
		return false;
	}

	HKEY hKey;
	if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {

		// 1. First backup old data.
		wchar_t buffer[2048];
		DWORD bufferSize = sizeof(buffer);
		if (RegQueryValueExW(hKey, valueName.c_str(), NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {

			// 2. Rewrite again with prefix "AX_DISABLED_...".
			std::wstring disabledName = L"AX_DISABLED_" + valueName;
			RegSetValueExW(hKey, disabledName.c_str(), 0, REG_SZ, (LPBYTE)buffer, bufferSize);

			// 3. The old file could be deleted.(It has backup file)
			LSTATUS status = RegDeleteValueW(hKey, valueName.c_str());
			RegCloseKey(hKey);
			return (status == ERROR_SUCCESS);
		}
		RegCloseKey(hKey);
	}
	return false;
}