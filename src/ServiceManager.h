#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct ServiceInfo {
    std::wstring name;
    std::wstring displayName;
    std::string state;
    std::string type;
    DWORD pid;
};

class ServiceManager {
public:
    static std::vector<ServiceInfo> GetWindowsServices();
    static bool ControlWindowsService(const std::wstring& serviceName, DWORD controlCode);
};