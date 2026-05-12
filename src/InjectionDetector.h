#pragma once
#pragma once
#include <windows.h>
#include <string>
#include <vector>

/**
 * @struct InjectionInfo
 * @brief Holds data about potentially malicious memory regions injected into a process.
 */
struct InjectionInfo {
    DWORD processID;
    std::string processName;
    LPCVOID baseAddress;      
    SIZE_T regionSize;          
    std::string protection;     
    std::string riskLevel;      
};

/**
 * @class InjectionDetector
 * @brief Scans running processes to detect memory anomalies indicating code injection.
 */
class InjectionDetector {
public:
    static std::vector<InjectionInfo> ScanSystemForInjections();

private:
    static void AnalyzeProcessMemory(DWORD processID, const std::string& processName, std::vector<InjectionInfo>& detectedInjections);
};