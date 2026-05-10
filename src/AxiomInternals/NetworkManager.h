#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <iphlpapi.h>

struct NetworkConnInfo {
    std::wstring localAddr;
    std::wstring remoteAddr;
    int localPort;
    int remotePort;
    std::wstring state;
    DWORD owningPid;
    std::wstring processName;
};

class NetworkManager {
public:
    static std::vector<NetworkConnInfo> GetActiveConnections();
};