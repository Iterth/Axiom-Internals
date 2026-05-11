#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ProcessManager.h"
#include "NetworkManager.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

std::vector<NetworkConnInfo> NetworkManager::GetActiveConnections() {
    std::vector<NetworkConnInfo> connections;
    ULONG size = 0;

    // 1. Determine the required buffer size for the TCP table
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    // 2. Allocate memory for the table
    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!pTcpTable) return connections;

    // 3. Retrieve the actual TCP table data
    if (GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            NetworkConnInfo info;

            wchar_t localIP[INET_ADDRSTRLEN] = { 0 };
            wchar_t remoteIP[INET_ADDRSTRLEN] = { 0 };

            // Convert raw IP addresses to readable string format
            if (InetNtopW(AF_INET, &pTcpTable->table[i].dwLocalAddr, localIP, INET_ADDRSTRLEN))
                info.localAddr = localIP;
            else
                info.localAddr = L"0.0.0.0";

            if (InetNtopW(AF_INET, &pTcpTable->table[i].dwRemoteAddr, remoteIP, INET_ADDRSTRLEN))
                info.remoteAddr = remoteIP;
            else
                info.remoteAddr = L"0.0.0.0";

            info.localPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
            info.remotePort = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
            info.owningPid = pTcpTable->table[i].dwOwningPid;

            // Resolve process name from PID
            if (info.owningPid == 0) {
                info.processName = L"System Idle";
            }
            else if (info.owningPid == 4) {
                info.processName = L"System";
            }
            else {
                info.processName = ProcessManager::GetProcessNameFromPID(info.owningPid);
            }

            // Map TCP state codes to readable strings
            switch (pTcpTable->table[i].dwState) {
            case MIB_TCP_STATE_ESTAB: info.state = L"ESTABLISHED"; break;
            case MIB_TCP_STATE_LISTEN: info.state = L"LISTENING"; break;
            case MIB_TCP_STATE_TIME_WAIT: info.state = L"TIME_WAIT"; break;
            case MIB_TCP_STATE_CLOSE_WAIT: info.state = L"CLOSE_WAIT"; break;
            case MIB_TCP_STATE_SYN_SENT: info.state = L"SYN_SENT"; break;
            case MIB_TCP_STATE_SYN_RCVD: info.state = L"SYN_RCVD"; break;
            default: info.state = L"UNKNOWN"; break;
            }

            connections.push_back(info);
        }
    }

    // 4. CRITICAL FIX: Free allocated memory to prevent memory leaks!
    free(pTcpTable);

    return connections;
}