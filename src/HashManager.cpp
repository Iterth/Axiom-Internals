#include "HashManager.h"
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

std::string HashManager::CalculateSHA256(const std::wstring& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    // 1. Initialize the Cryptographic Service Provider (CSP)
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "ERROR_CRYPT_CONTEXT";
    }

    // 2. Create the SHA-256 hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "ERROR_CREATE_HASH";
    }

    // 3. Open the target file in safe read-only mode
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "FILE_NOT_FOUND_OR_ACCESS_DENIED";
    }

    // 4. Read file in chunks (1MB) to optimize RAM usage for large files
    const DWORD BUFSIZE = 1024 * 1024;
    BYTE* rgbFile = new BYTE[BUFSIZE];
    DWORD cbRead = 0;
    bool success = true;

    while (ReadFile(hFile, rgbFile, BUFSIZE, &cbRead, NULL)) {
        if (cbRead == 0) break; // End of file

        // Hash the current chunk
        if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
            success = false;
            break;
        }
    }

    delete[] rgbFile;
    CloseHandle(hFile);

    // 5. Finalize and extract the hash string
    std::string hashStr = "";
    if (success) {
        DWORD cbHash = 0;
        DWORD dwCount = sizeof(DWORD);

        if (CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHash, &dwCount, 0)) {
            BYTE* rgbHash = new BYTE[cbHash];
            if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
                char hexFormat[3];
                for (DWORD i = 0; i < cbHash; i++) {
                    sprintf_s(hexFormat, "%02x", rgbHash[i]);
                    hashStr += hexFormat;
                }
            }
            delete[] rgbHash;
        }
    }

    // 6. Cleanup Cryptographic handles
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return success ? hashStr : "ERROR_HASH_CALCULATION";
}