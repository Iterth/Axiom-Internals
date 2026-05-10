#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct AutoRunInfo {
    std::wstring name;       // Program name
    std::wstring command;    // Running path
    std::wstring location;   // Registry
    bool exists;
};

class RegistryManager {
public:
    static std::vector<AutoRunInfo> GetAutoRuns();
    static bool DeleteAutoRun(const std::wstring& valueName, const std::wstring& location);
};