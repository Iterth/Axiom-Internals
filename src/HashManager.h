#pragma once
#include <string>
#include <windows.h>

/**
 * @class HashManager
 * @brief Handles cryptographic operations, specifically SHA256 file hashing.
 */
class HashManager {
public:
    static std::string CalculateSHA256(const std::wstring& filePath);
};