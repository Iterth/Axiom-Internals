#pragma once
#include <string>
#include <vector>
#include <windows.h>

/**
 * @struct AutoRunInfo
 * @brief Represents a persistent startup entry found in the Windows Registry.
 */
struct AutoRunInfo {
    std::wstring name;       // Name of the registry value
    std::wstring command;    // The executable path or command
    std::wstring location;   // The registry hive and subkey location
    bool exists;             // True if the target file actually exists on disk
};

/**
 * @class RegistryManager
 * @brief Scans and manages Windows Registry keys related to system startup (AutoRuns).
 */
class RegistryManager {
public:
    static std::vector<AutoRunInfo> GetAutoRuns();
    static bool DeleteAutoRun(const std::wstring& valueName, const std::wstring& location);
};