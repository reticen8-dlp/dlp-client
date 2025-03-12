#include <windows.h>
#include <iostream>
#include <aclapi.h>
#include <psapi.h>
#include <vector>
#include <string>


bool IsNormalFileExplorer() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return false;

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;

    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH)) {
        CloseHandle(hProcess);
        return std::wstring(buffer).find(L"explorer.exe") != std::wstring::npos;
    }

    CloseHandle(hProcess);
    return false;
}


void LockFile(const std::wstring& filePath) {
    PACL pDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Get current security info
    if (GetNamedSecurityInfoW(filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pDacl, NULL, &pSD) != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] Failed to get security info for: " << filePath << std::endl;
        return;
    }

    // Create an empty DACL (removes all permissions)
    PACL pEmptyDacl = (PACL)LocalAlloc(LPTR, sizeof(ACL));
    if (!InitializeAcl(pEmptyDacl, sizeof(ACL), ACL_REVISION)) {
        std::wcerr << L"[ERROR] Failed to initialize empty DACL." << std::endl;
        return;
    }

    // Apply the empty DACL to lock down the file
    if (SetNamedSecurityInfoW((LPWSTR)filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pEmptyDacl, NULL) != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] Failed to apply empty DACL." << std::endl;
        return;
    }

    std::wcout << L"[LOCKED] File fully locked: " << filePath << std::endl;
}

void UnlockFile(const std::wstring& filePath) {
    if (SetNamedSecurityInfoW((LPWSTR)filePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
        std::wcerr << L"[ERROR] Failed to unlock file: " << filePath << std::endl;
        return;
    }

    std::wcout << L"[UNLOCKED] File unlocked: " << filePath << std::endl;
}

int main() {
    
    std::vector<std::wstring> files;
    std::wstring input;
    std::wstring line;

    std::wcout << L"[INFO] Enter file paths (end with an empty line):" << std::endl;
    while (std::getline(std::wcin, line) && !line.empty()) {
        files.emplace_back(line);
    }

    if (files.empty()) {
        std::wcerr << L"[ERROR] No file paths provided." << std::endl;
        return 1;
    }
    bool lastState = IsNormalFileExplorer();

    while (true) {
        bool currentState = IsNormalFileExplorer();

        if (currentState != lastState) {
            if (currentState) {
                for (const auto& file : files) {
                    UnlockFile(file);
                    continue;
                }
            } else {
                for (const auto& file : files) {
                    LockFile(file);
                }
            }
            lastState = currentState;
        }

        Sleep(100);
    }
    return 0;
}

// g++ upload.cpp -o File_Upload.exe -lpsapi -static

//give file paths as input without double brackets.
// for multiple file paths press enter after each file path and press enter again to end the input.
// for example:
// C:\Users\user\Desktop\file1.txt
// C:\Users\user\Desktop\file2.txt
// C:\Users\user\Desktop\file3.txt
// press enter again to end the input.
// the files will be locked and unlocked based on the file explorer state.
// if the file explorer is in normal state the files will be unlocked and if the file explorer is not in normal state the files will be locked.
