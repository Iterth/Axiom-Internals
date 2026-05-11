#include "ServiceManager.h"

std::vector<ServiceInfo> ServiceManager::GetWindowsServices() {
    std::vector<ServiceInfo> serviceList;

    // 1. Connect to the Service Control Manager (SCM)
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return serviceList;

    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;

    // 2. Query required buffer size for both Win32 services and Kernel Drivers
    EnumServicesStatusEx(
        hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL
    );

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(hSCM);
        return serviceList;
    }

    // 3. Allocate memory and fetch the data
    std::vector<BYTE> buffer(bytesNeeded);
    ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)buffer.data();

    if (EnumServicesStatusEx(
        hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
        (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL
    )) {
        // 4. Parse the results into the structural list
        for (DWORD i = 0; i < servicesReturned; i++) {
            ServiceInfo info;
            info.name = services[i].lpServiceName;
            info.displayName = services[i].lpDisplayName;
            info.pid = services[i].ServiceStatusProcess.dwProcessId;

            switch (services[i].ServiceStatusProcess.dwCurrentState) {
            case SERVICE_STOPPED: info.state = "STOPPED"; break;
            case SERVICE_START_PENDING: info.state = "START PENDING"; break;
            case SERVICE_STOP_PENDING: info.state = "STOP PENDING"; break;
            case SERVICE_RUNNING: info.state = "RUNNING"; break;
            case SERVICE_CONTINUE_PENDING: info.state = "CONTINUE PENDING"; break;
            case SERVICE_PAUSE_PENDING: info.state = "PAUSE PENDING"; break;
            case SERVICE_PAUSED: info.state = "PAUSED"; break;
            default: info.state = "UNKNOWN"; break;
            }

            if (services[i].ServiceStatusProcess.dwServiceType & SERVICE_DRIVER) {
                info.type = "KERNEL DRIVER";
            }
            else {
                info.type = "WIN32 SERVICE";
            }

            serviceList.push_back(info);
        }
    }

    CloseServiceHandle(hSCM);
    return serviceList;
}

bool ServiceManager::ControlWindowsService(const std::wstring& serviceName, DWORD controlCode) {
    // Connect to SCM with basic interaction rights
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;

    // Determine the required access level
    DWORD access = (controlCode == SERVICE_CONTROL_STOP) ? SERVICE_STOP : SERVICE_START;
    SC_HANDLE hService = OpenService(hSCM, serviceName.c_str(), access);

    bool success = false;
    if (hService) {
        if (controlCode == SERVICE_CONTROL_STOP) {
            SERVICE_STATUS status;
            success = ControlService(hService, SERVICE_CONTROL_STOP, &status);
        }
        else {
            success = StartService(hService, 0, NULL);
        }
        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);
    return success;
}