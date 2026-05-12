#include "MemoryScanner.h"
#include <iostream>

std::vector<MemoryStringInfo> MemoryScanner::ScanProcessMemory(DWORD processID) {
    std::vector<MemoryStringInfo> foundStrings;

    // Step 1: Open the process with required privileges to read its virtual memory
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        // Access denied (e.g., system process) or process does not exist
        return foundStrings;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID address = 0; // Start scanning from the base address (0x0)
    const size_t MIN_STRING_LENGTH = 5; // Filter out garbage data, keep strings >= 5 chars

    // Step 2: Iterate through the virtual memory pages of the target process
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {

        // We only care about pages that are physically committed to RAM
        bool isCommitted = (mbi.State == MEM_COMMIT);

        // Ensure we only read pages with read permissions to prevent access violations/crashes
        bool isReadable = (mbi.Protect == PAGE_READONLY ||
            mbi.Protect == PAGE_READWRITE ||
            mbi.Protect == PAGE_EXECUTE_READ ||
            mbi.Protect == PAGE_EXECUTE_READWRITE);

        if (isCommitted && isReadable) {
            // Create a local buffer to hold the memory block we are about to read
            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T bytesRead;

            // Step 3: Read the memory block into our local buffer
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {

                std::string currentString = "";
                LPCVOID stringStartAddress = nullptr;

                // Parse the buffer byte by byte to extract printable ASCII characters
                for (SIZE_T i = 0; i < bytesRead; ++i) {
                    char c = buffer[i];

                    // Check if the character is printable ASCII (between 32 and 126)
                    if (c >= 32 && c <= 126) {
                        if (currentString.empty()) {
                            // Record the actual memory address where the string begins
                            stringStartAddress = (LPCVOID)((uintptr_t)mbi.BaseAddress + i);
                        }
                        currentString += c;
                    }
                    else {
                        // Non-printable character encountered. Check if the accumulated string is valid.
                        if (currentString.length() >= MIN_STRING_LENGTH) {
                            MemoryStringInfo info;
                            info.extractedText = currentString;
                            info.memoryAddress = stringStartAddress;
                            foundStrings.push_back(info);
                        }
                        currentString = ""; // Reset for the next string extraction
                    }
                }

                // Catch any remaining valid string at the end of the memory block
                if (currentString.length() >= MIN_STRING_LENGTH) {
                    MemoryStringInfo info;
                    info.extractedText = currentString;
                    info.memoryAddress = stringStartAddress;
                    foundStrings.push_back(info);
                }
            }
        }

        // Move to the next memory region
        address = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    // Always close the handle to prevent memory leaks
    CloseHandle(hProcess);

    return foundStrings;
}