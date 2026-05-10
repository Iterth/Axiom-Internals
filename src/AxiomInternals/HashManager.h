#pragma once
#include <string>
#include <windows.h>

class HashManager {
public:
	static std::string CalculateSHA256(const std::wstring& filePath);
};
