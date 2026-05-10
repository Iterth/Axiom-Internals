#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ProcessManager.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include "NetworkManager.h"


#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

std::vector<NetworkConnInfo> NetworkManager::GetActiveConnections() {
    std::vector<NetworkConnInfo> connections;
    ULONG size = 0;

    // Boyutu al
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    PMIB_TCPTABLE_OWNER_PID pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (pTcpTable && GetExtendedTcpTable(pTcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {

        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            NetworkConnInfo info;

            wchar_t localIP[INET_ADDRSTRLEN] = { 0 };
            wchar_t remoteIP[INET_ADDRSTRLEN] = { 0 };

            struct in_addr localAddr, remoteAddr;
            localAddr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
            remoteAddr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;

            if (InetNtopW(AF_INET, &localAddr, localIP, INET_ADDRSTRLEN))
                info.localAddr = localIP;
            else
                info.localAddr = L"0.0.0.0";

            if (InetNtopW(AF_INET, &remoteAddr, remoteIP, INET_ADDRSTRLEN))
                info.remoteAddr = remoteIP;
            else
                info.remoteAddr = L"0.0.0.0";

            info.localPort = ntohs((u_short)pTcpTable->table[i].dwLocalPort);
            info.remotePort = ntohs((u_short)pTcpTable->table[i].dwRemotePort);
            info.owningPid = pTcpTable->table[i].dwOwningPid;

            if (info.owningPid == 0) {
                info.processName = L"System Idle";
            }
            else if (info.owningPid == 4) {
                info.processName = L"System";
            }
            else {
                info.processName = ProcessManager::GetProcessNameFromPID(info.owningPid);
            }

            switch (pTcpTable->table[i].dwState) {
            case MIB_TCP_STATE_ESTAB: info.state = L"ESTABLISHED"; break;
            case MIB_TCP_STATE_LISTEN: info.state = L"LISTENING"; break;
            case MIB_TCP_STATE_TIME_WAIT: info.state = L"TIME_WAIT"; break;
            case MIB_TCP_STATE_CLOSE_WAIT: info.state = L"CLOSE_WAIT"; break;
            default: info.state = L"UNKNOWN"; break;
            }
            connections.push_back(info);
        }
    }

    if (pTcpTable) free(pTcpTable);
    return connections;
}