#pragma once
#include <string>
#include <vector>
#include <windows.h>

/**
 * @struct MemoryStringInfo
 * @brief Holds information about a string extracted from process memory.
 */
struct MemoryStringInfo {
    std::string extractedText;
    LPCVOID memoryAddress;     
};

/**
 * @class MemoryScanner
 * @brief Handles deep memory scanning and string extraction for running processes.
 */
class MemoryScanner {
public:
    static std::vector<MemoryStringInfo> ScanProcessMemory(DWORD processID);
};