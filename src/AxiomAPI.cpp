#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ProcessManager.h"
#include "RegistryManager.h"
#include "NetworkManager.h"
#include "HashManager.h"
#include "ServiceManager.h"
#include "json.hpp"
#include <string>
#include <windows.h>

using json = nlohmann::json;

// --- WRAPPER FUNCTION: WString (UTF-16) to String (UTF-8) Converter ---
// JSON uses UTF-8 but our processmanager is using WString which is also main language of windows.
// So thanks to this we can translate them.
std::string WStringToString(const std::wstring& wstr) {
	if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}
// --------------------------------------------------------------------------

// --- WRAPPER FUNCTION: String (UTF-8) to WString (UTF-16) Converter ---
std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}
// --------------------------------------------------------------------------

// Keeps the data until Python read that.
static std::string processJsonBuffer;
static std::string registryJsonBuffer;
static std::string networkJsonBuffer;
static std::string serviceJsonBuffer;

// --- STARTUP BRIDGE ---
extern "C" {
    // ---------------------------------------------------------
    // 1. PROCESS MODULE BRIDGES
    // ---------------------------------------------------------

    __declspec(dllexport) const char* GetProcessListJSON() {
        ProcessManager::EnableDebugPrivilege();

        std::vector<ProcessInfo> processList = ProcessManager::GetProcessList();

        json jArray = json::array();

        for (const auto& proc : processList) {
            json jProc;
            jProc["pid"] = proc.pid;
            jProc["ppid"] = proc.ppid;
            jProc["name"] = WStringToString(proc.name);
            jProc["path"] = WStringToString(proc.fullPath);
            jProc["threads"] = proc.threadCount;

            jArray.push_back(jProc);
        }

        processJsonBuffer = jArray.dump();
        return processJsonBuffer.c_str();
    }

    __declspec(dllexport) bool KillProcessByPID(DWORD pid) {
        ProcessManager::EnableDebugPrivilege();
        return ProcessManager::TerminateProcessByPID(pid);
    }

    // ---------------------------------------------------------
    // 2. REGISTRY (AUTO-RUN) MODULE BRIDGES
    // ---------------------------------------------------------

    __declspec(dllexport) const char* GetAutoRunsJSON() {
        std::vector<AutoRunInfo> autorunList = RegistryManager::GetAutoRuns();

        json jArray = json::array();
        for (const auto& item : autorunList) {
            json jItem;
            jItem["name"] = WStringToString(item.name);
            jItem["command"] = WStringToString(item.command);
            jItem["location"] = WStringToString(item.location);
            jItem["exists"] = item.exists;
            jArray.push_back(jItem);
        }

        registryJsonBuffer = jArray.dump();
        return registryJsonBuffer.c_str();
    }

    __declspec(dllexport) bool DeleteAutoRunKey(const char* valueName, const char* locationLabel) {
        std::wstring wValueName = StringToWString(valueName);
        std::wstring wLocation = StringToWString(locationLabel);

        return RegistryManager::DeleteAutoRun(wValueName, wLocation);
    }

    // ---------------------------------------------------------
    // 3. NETWORK MODULE BRIDGES
    // ---------------------------------------------------------

    __declspec(dllexport) const char* GetNetworkConnectionsJSON() {
        std::vector<NetworkConnInfo> netList = NetworkManager::GetActiveConnections();

        json jArray = json::array();
        for (const auto& conn : netList) {
            json jConn;
            jConn["local"] = WStringToString(conn.localAddr) + ":" + std::to_string(conn.localPort);
            jConn["remote"] = WStringToString(conn.remoteAddr) + ":" + std::to_string(conn.remotePort);
            jConn["state"] = WStringToString(conn.state);
            jConn["pid"] = conn.owningPid;
            jConn["name"] = WStringToString(conn.processName);
            jArray.push_back(jConn);
        }

        networkJsonBuffer = jArray.dump();
        return networkJsonBuffer.c_str();
    }

    // ---------------------------------------------------------
    // 4. FILE HASHER MODULE BRIDGES
    // ---------------------------------------------------------

    __declspec(dllexport) const char* GetFileSHA256(const char* filePath) {
        static std::string lastHash;

        std::wstring wPath = StringToWString(filePath);
        lastHash = HashManager::CalculateSHA256(wPath);

        return lastHash.c_str();
    }

    // ---------------------------------------------------------
    // 5. SERVICES MANAGER MODULE BRIDGES
    // ---------------------------------------------------------

    __declspec(dllexport) const char* GetWindowsServicesJSON() {
        std::vector<ServiceInfo> services = ServiceManager::GetWindowsServices();

        json jArray = json::array();
        for (const auto& svc : services) {
            json jServ;
            jServ["name"] = WStringToString(svc.name);
            jServ["display_name"] = WStringToString(svc.displayName);
            jServ["state"] = svc.state;
            jServ["type"] = svc.type;
            jServ["pid"] = svc.pid;
            jArray.push_back(jServ);
        }

        serviceJsonBuffer = jArray.dump();
        return serviceJsonBuffer.c_str();
    }
    __declspec(dllexport) bool ControlServiceByName(const char* serviceName, bool stop) {

        std::wstring wName = StringToWString(serviceName);
        DWORD code = stop ? SERVICE_CONTROL_STOP : 0;
        return ServiceManager::ControlWindowsService(wName, code);
    }
}