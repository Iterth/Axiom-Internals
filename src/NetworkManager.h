#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <iphlpapi.h>

/**
 * @struct NetworkConnInfo
 * @brief Holds information about a single active network connection.
 */
struct NetworkConnInfo {
    std::wstring localAddr;
    std::wstring remoteAddr;
    int localPort;
    int remotePort;
    std::wstring state;
    DWORD owningPid;
    std::wstring processName;
};

/**
 * @class NetworkManager
 * @brief Handles enumeration and mapping of active TCP/UDP connections.
 */
class NetworkManager {
public:
    static std::vector<NetworkConnInfo> GetActiveConnections();
};