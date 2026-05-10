#include "HashManager.h"
#include <wincrypt.h>
#include <fstream>
#include <iomanip>
#include <sstream>

// REQUIRED
#pragma comment(lib, "advapi32.lib")

std::string HashManager::CalculateSHA256(const std::wstring& filePath) {
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	std::string hashStr = "";

	// 1. Starting
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return "ERROR_CRYPT_CONTEXT";
	}

	// 2. SHA256 Creating Hash Object.
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		return "ERROR_CREATE_HASH";
	}

	// 3. Open file in Safe Read Mode (Even another program uses it.).
	HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return "FILE_NOT_FOUND_OR_ACCESS_DENIED";
	}

	// 4. Chunk 1mb for RAM
	const DWORD BUFSIZE = 1024 * 1024;
	BYTE* rgbFile = new BYTE[BUFSIZE];
	DWORD cbRead = 0;
	bool success = true;

	while (ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)) {
		if (cbRead == 0) break;
		if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
			success = false;
			break;
		}
	}

	delete[] rgbFile;
	CloseHandle(hFile);

	if (success) {
		DWORD cbHash = 32; // Byte Length of SHA256
		BYTE rgbHash[32];
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
			std::ostringstream oss;
			for (DWORD i = 0; i < cbHash; i++) {
				oss << std::hex << std::setw(2) << std::setfill('0') << (int)rgbHash[i];
			}
			hashStr = oss.str();
		}
	}
	else {
		hashStr = "ERROR_READING_DATA";
	}

	// Cleaning RAM
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return hashStr;
}