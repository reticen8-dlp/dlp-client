#include <windows.h>
#include <aclapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <thread>
#include <sddl.h>
#include <cstdlib>
#include <shellapi.h>
#include <shobjidl.h> // For SetCurrentProcessExplicitAppUserModelID
#include <fstream>
#include <set>
#include <map>
#include <sstream>
#include <algorithm>
#include <dbt.h>
#include <conio.h>
#include <regex>
#include <atomic>
// #include <libsqlite3/sqlite3.h>
// #include <cryptlib.h>
// #include <aes.h>
// #include <filters.h>
// #include <modes.h>
// #include <base64.h>
// using namespace CryptoPP;
#include "nlohmann/json.hpp" // JSON library folder (included as a separate folder)

// const string DB_PATH = "Proprium_dlp.db";
// const byte AES_KEY[32] = "Y0jXXrE803umfYOW4mqOpWRUeaHPRMeIeNDTnMFcZ8I=";

// string base64_decode(const string& encoded) {
//     string decoded;
//     StringSource(encoded, true, new Base64Decoder(new StringSink(decoded)));
//     return decoded;
// }
// // AES-256-CBC decryption function
// string decrypt_aes(const string& encrypted) {
//     string decoded = base64_decode(encrypted);

//     byte iv[AES::BLOCKSIZE];
//     memcpy(iv, decoded.data(), AES::BLOCKSIZE);  // Extract IV
//     string cipher_text = decoded.substr(AES::BLOCKSIZE);

//     string decrypted;
//     CBC_Mode<AES>::Decryption decryptor;
//     decryptor.SetKeyWithIV(AES_KEY, sizeof(AES_KEY), iv);

//     StringSource(cipher_text, true,
//         new StreamTransformationFilter(decryptor,
//             new StringSink(decrypted),
//             BlockPaddingSchemeDef::PKCS_PADDING)
//     );

//     return decrypted;
// }

// // Fetch encrypted data from SQLite and decrypt it
// void fetch_and_decrypt_policy() {
//     sqlite3* db;
//     sqlite3_stmt* stmt;
//     string sql = "SELECT policy FROM policy ORDER BY timestamp DESC LIMIT 1;";

//     if (sqlite3_open(DB_PATH.c_str(), &db) == SQLITE_OK) {
//         if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
//             if (sqlite3_step(stmt) == SQLITE_ROW) {
//                 string encrypted_data = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
//                 string decrypted_data = decrypt_aes(encrypted_data);
//                 cout << "Decrypted Policy: " << decrypted_data << endl;
//             }
//         }
//         sqlite3_finalize(stmt);
//         sqlite3_close(db);
//     }
// }
// Create an alias for the JSON library
using json = nlohmann::json;
json lastValidPolicy;
// Function to load only the "Drive Lock Policy" section from policy.json
json LoadDriveLockPolicy() { 
    std::ifstream file("Policy.json"); 
    json policies; 
     
    if (!file.is_open()) { 
        std::cerr << "Failed to open Policy.json" << std::endl; 
        return {}; 
    } 
 
    try { 
        file >> policies; 
        file.close(); 
    } catch (const std::exception& e) { 
        std::cerr << "Error parsing JSON: " << e.what() << std::endl; 
        return {}; 
    } 
 
    // If the JSON isn't an array, wrap it into an array.
    if (!policies.is_array()) { 
        policies = json::array({ policies }); 
    } 
 
    return policies;  
} 
// Function to validate the policy format
// Modified isValidDriveLockPolicy function
bool isValidDriveLockPolicy(const json& policyData) {
    return  
           policyData.contains("action") && 
           policyData["action"].contains("channel_action") &&  // Fix: Add "channel_action" level
           policyData["action"]["channel_action"].contains("endpoint_channels") &&
           policyData["action"]["channel_action"]["endpoint_channels"].contains("LocalDrives") &&
           policyData["action"]["channel_action"]["endpoint_channels"].contains("RemovableDrives");
}


#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

// Force Unicode
#ifdef UNICODE
#define _UNICODE
#endif

// Application identifier for Windows
#define APP_ID L"Reticen8-DLP"
#define WINDOW_CLASS_NAME L"NotificationWindow"

// Custom window message
#define WM_TRAYICON (WM_USER + 1)

// Global variables
NOTIFYICONDATAW nid = {};
HWND hwnd;

using namespace std;
// Helper function to check and display errors
void DisplayError(const wchar_t* action, DWORD error) {
    wchar_t* errorMsg = nullptr;
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr,
        error,
        0,
        (LPWSTR)&errorMsg,
        0,
        nullptr
    );
    std::wcerr << L"Error " << action << L": " << (errorMsg ? errorMsg : L"Unknown error") << std::endl;
    LocalFree(errorMsg);
}


// Window procedure
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &nid);
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void ShowNotification(const wchar_t* title, const wchar_t* message) {
    // Initialize COM
    HRESULT hr = CoInitialize(NULL);
    if (SUCCEEDED(hr)) {
        // Set the app ID for Windows
        hr = SetCurrentProcessExplicitAppUserModelID(APP_ID);
        if (FAILED(hr)) {
            std::cerr << "Failed to set App ID" << std::endl;
        }
    }

    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = WINDOW_CLASS_NAME;
    RegisterClassExW(&wc);

    // Create hidden window
    hwnd = CreateWindowExW(
        0,
        WINDOW_CLASS_NAME,
        APP_ID,
        WS_OVERLAPPED,
        CW_USEDEFAULT, CW_USEDEFAULT,
        CW_USEDEFAULT, CW_USEDEFAULT,
        NULL,
        NULL,
        GetModuleHandleW(NULL),
        NULL
    );

    if (!hwnd) {
        std::cerr << "Failed to create window" << std::endl;
        CoUninitialize();
        return;
    }

    // Initialize NOTIFYICONDATA
    nid.cbSize = sizeof(NOTIFYICONDATAW);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_INFO;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = (HICON)LoadImageW(
        NULL,
        (LPCWSTR)IDI_WARNING,
        IMAGE_ICON,
        0,
        0,
        LR_SHARED
    );
    
    wcscpy_s(nid.szTip, sizeof(nid.szTip)/sizeof(wchar_t), APP_ID);
    wcscpy_s(nid.szInfo, sizeof(nid.szInfo)/sizeof(wchar_t), message);
    wcscpy_s(nid.szInfoTitle, sizeof(nid.szInfoTitle)/sizeof(wchar_t), title);
    nid.dwInfoFlags = NIIF_INFO;
    nid.uTimeout = 2000; // 2 seconds

    // Show notification
    Shell_NotifyIconW(NIM_ADD, &nid);
    // Shell_NotifyIconW(NIM_MODIFY, &nid);

    // Message loop - wait for 2 seconds
    MSG msg;
    ULONGLONG startTime = GetTickCount64();
    while (GetTickCount64() - startTime < 2000) {
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(100);
    }

    // Clean up
    Shell_NotifyIconW(NIM_DELETE, &nid);
    DestroyWindow(hwnd);
    UnregisterClassW(WINDOW_CLASS_NAME, GetModuleHandleW(NULL));
    CoUninitialize();
}

vector<wstring> ListAvailableDrives() {
    vector<wstring> drives;
    DWORD driveMask = GetLogicalDrives();
    
    for (int i = 0; i < 26; i++) {
        if (driveMask & (1 << i)) {
            wchar_t driveLetter = L'A' + i;
            wstring drivePath = wstring(1, driveLetter) + L":\\";
            
            if (GetDriveTypeW(drivePath.c_str()) == DRIVE_FIXED) {
                drives.push_back(drivePath);
            }
        }
    }
    return drives;
}



bool ModifyDriveAccess(const wstring& drive, bool restrict)  {
   
    PSID pAdminSID = NULL;
    PSID pSystemSID = NULL;
    PSID pEveryoneSID = NULL;
    PACL pNewDACL = NULL;
    bool success = false;

    try {
        // Create SIDs for required groups
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY worldAuthority = SECURITY_WORLD_SID_AUTHORITY;

        // Create Admin SID
        if (!AllocateAndInitializeSid(&ntAuthority, 2, 
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSID)) {
            throw GetLastError();
        }

        // Create System SID
        if (!AllocateAndInitializeSid(&ntAuthority, 1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &pSystemSID)) {
            throw GetLastError();
        }

        // Create Everyone SID
        if (!AllocateAndInitializeSid(&worldAuthority, 1,
            SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
            throw GetLastError();
        }

        // Prepare EXPLICIT_ACCESS structures
        EXPLICIT_ACCESS ea[3] = {};
        ZeroMemory(&ea, 3 * sizeof(EXPLICIT_ACCESS));

        // Admin full control (always)
        ea[0].grfAccessPermissions = GENERIC_ALL;
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[0].Trustee.ptstrName = (LPTSTR)pAdminSID;

        // System full control (always)
        ea[1].grfAccessPermissions = GENERIC_ALL;
        ea[1].grfAccessMode = SET_ACCESS;
        ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[1].Trustee.ptstrName = (LPTSTR)pSystemSID;

        // Everyone - restricted or full access
        ea[2].grfAccessPermissions = restrict ? 0 : GENERIC_ALL;
        ea[2].grfAccessMode = restrict ? DENY_ACCESS : SET_ACCESS;
        ea[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[2].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

        // Create new ACL
        DWORD dwRes = SetEntriesInAcl(3, ea, NULL, &pNewDACL);
        if (dwRes != ERROR_SUCCESS) {
            throw dwRes;
        }

        // Apply the new ACL
        dwRes = SetNamedSecurityInfoW(
            (LPWSTR)drive.c_str(), 
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            pNewDACL,
            NULL
        );

        if (dwRes != ERROR_SUCCESS) {
            throw dwRes;
        }

        success = true;
        wcout << (restrict ? L"Locked " : L"Unlocked ") << drive << endl;
    }
    catch (DWORD error) {
        wstring action = restrict ? L"restricting E: drive" : L"unrestricting " + drive + L" : drive";
        DisplayError(action.c_str(), error);
    }

    // Cleanup
    if (pAdminSID) FreeSid(pAdminSID);
    if (pSystemSID) FreeSid(pSystemSID);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pNewDACL) LocalFree(pNewDACL);

    if(success){
        wstring status = restrict ? L"locked" : L"unlocked";
        wstring message = L"Drive " + wstring(1, drive[0]) + L": Access Modified: " + status;
        ShowNotification(L"Security Alert", message.c_str());
    }
    return success;
}


bool ReadOnlyAccess(const wstring& drive, bool restrict) {
    PSID pAdminSID = NULL;
    PSID pSystemSID = NULL;
    PSID pEveryoneSID = NULL;
    PACL pNewDACL = NULL;
    bool success = false;

    try {
        // Create SIDs for required groups
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY worldAuthority = SECURITY_WORLD_SID_AUTHORITY;

        // Create Admin SID
        if (!AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSID)) {
            throw GetLastError();
        }

        // Create System SID
        if (!AllocateAndInitializeSid(&ntAuthority, 1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &pSystemSID)) {
            throw GetLastError();
        }

        // Create Everyone SID
        if (!AllocateAndInitializeSid(&worldAuthority, 1,
            SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
            throw GetLastError();
        }

        // Prepare EXPLICIT_ACCESS structures - we'll need 5 entries for complete control
        EXPLICIT_ACCESS ea[5] = {};
        ZeroMemory(&ea, 5 * sizeof(EXPLICIT_ACCESS));

        if (restrict) {
            // Admin - Only allow read and security permissions
            ea[0].grfAccessPermissions = READ_CONTROL | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
            ea[0].grfAccessMode = SET_ACCESS;
            ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea[0].Trustee.ptstrName = (LPTSTR)pAdminSID;

            // Admin - Deny write permissions
            ea[1].grfAccessPermissions = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                                       FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE;
            ea[1].grfAccessMode = DENY_ACCESS;
            ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

            // System - Same as admin
            ea[2].grfAccessPermissions = READ_CONTROL | WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY;
            ea[2].grfAccessMode = SET_ACCESS;
            ea[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[2].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea[2].Trustee.ptstrName = (LPTSTR)pSystemSID;

            // Everyone - Read only permissions
            ea[3].grfAccessPermissions = FILE_GENERIC_READ | FILE_LIST_DIRECTORY | 
                                       FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
            ea[3].grfAccessMode = SET_ACCESS;
            ea[3].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[3].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[3].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[3].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

            // Everyone - Explicitly deny write permissions
            ea[4].grfAccessPermissions = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
                                       FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE;
            ea[4].grfAccessMode = DENY_ACCESS;
            ea[4].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[4].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[4].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[4].Trustee.ptstrName = (LPTSTR)pEveryoneSID;
        } else {
            // Restore full access
            // Admin full control
            ea[0].grfAccessPermissions = GENERIC_ALL;
            ea[0].grfAccessMode = SET_ACCESS;
            ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea[0].Trustee.ptstrName = (LPTSTR)pAdminSID;

            // System full control
            ea[1].grfAccessPermissions = GENERIC_ALL;
            ea[1].grfAccessMode = SET_ACCESS;
            ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            ea[1].Trustee.ptstrName = (LPTSTR)pSystemSID;

            // Everyone full access
            ea[2].grfAccessPermissions = GENERIC_ALL;
            ea[2].grfAccessMode = SET_ACCESS;
            ea[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[2].Trustee.ptstrName = (LPTSTR)pEveryoneSID;
        }

        // Create new ACL
        DWORD dwRes = SetEntriesInAcl(restrict ? 5 : 3, ea, NULL, &pNewDACL);
        if (dwRes != ERROR_SUCCESS) {
            throw dwRes;
        }

        // Apply the new ACL
        dwRes = SetNamedSecurityInfoW(
            (LPWSTR)drive.c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            pNewDACL,
            NULL
        );

        if (dwRes != ERROR_SUCCESS) {
            throw dwRes;
        }

        success = true;
        wcout << (restrict ? L"Set strict read-only access for " : L"Restored full access for ") << drive << endl;
    }
    catch (DWORD error) {
        wstring action = restrict ? L"setting read-only access for " : L"restoring full access for ";
        action += drive;
        wcout << L"Error: " << action << L" drive" << endl;
    }

    // Cleanup
    if (pAdminSID) FreeSid(pAdminSID);
    if (pSystemSID) FreeSid(pSystemSID);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pNewDACL) LocalFree(pNewDACL);

    if(success){
        wstring status = restrict ? L"Read-Only" : L"unlocked";
        wstring message = L"Drive " + wstring(1, drive[0]) + L": Access Modified: " + status;
        ShowNotification(L"Security Alert", message.c_str());
    }

    return success;
}

// ****************** CODE FOR REMOVABLE DISK INHERITED ********************************
// Structure to hold drive information
struct DriveInfo {
    wstring letter;
    wstring label;
    wstring type;
    bool isLocked;
    ULONG serialNumber;
    ULARGE_INTEGER totalSpace;
    ULARGE_INTEGER freeSpace;
};
// Global variables
map<wstring, DriveInfo> removableDrives;
bool isRunning = true;
bool menuActive = false;

// Helper function to get drive label
wstring GetDriveLabel(const wstring& drive) {
    wchar_t label[MAX_PATH + 1] = { 0 };
    GetVolumeInformationW(drive.c_str(), label, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0);
    return wstring(label);
}
// void PrintDriveInfo(const map<wstring, DriveInfo>& drives) {
//     system("cls");
//     wcout << L"\nCurrent Removable Drives:\n" << endl;
//     int index = 1;
//     for (const auto& drive : drives) {
//         wcout << index << L" -> Drive " << drive.second.letter << L":\\" << endl;
//         wcout << L"     Label: " << (drive.second.label.empty() ? L"No Label" : drive.second.label) << endl;
//         wcout << L"     Status: " << (drive.second.isLocked ? L"Locked" : L"Unlocked") << endl;
//         wcout << L"     Size: " << (drive.second.totalSpace.QuadPart / (1024 * 1024 * 1024)) << L" GB" << endl;
//         wcout << L"------------------------" << endl;
//         index++;
//     }
// }

// namespace fs = std::filesystem;

// void ApplyPermissionsRecursively(const std::wstring& path, PACL pOldDACL) {
//     PACL pNewDACL = NULL;
//     EXPLICIT_ACCESSW explicitAccess = {};

//     explicitAccess.grfAccessPermissions = GENERIC_READ | FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
//     explicitAccess.grfAccessMode = SET_ACCESS;
//     explicitAccess.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
//     explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
//     explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_USER;
//     explicitAccess.Trustee.ptstrName = (LPWSTR)L"EVERYONE";

//     DWORD result = SetEntriesInAclW(1, &explicitAccess, pOldDACL, &pNewDACL);
//     if (result != ERROR_SUCCESS) {
//         std::wcerr << L"Failed to set entries in ACL for " << path << L". Error: " << result << std::endl;
//         return;
//     }

//     result = SetNamedSecurityInfoW(
//         (LPWSTR)path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
//         NULL, NULL, pNewDACL, NULL
//     );

//     if (result != ERROR_SUCCESS) {
//         std::wcerr << L"Failed to set security info for " << path << L". Error: " << result << std::endl;
//     }

//     if (pNewDACL) LocalFree(pNewDACL);
// }

// void SetReadOnlyPermissions(const std::wstring& drivePath) {
//     PACL pOldDACL = NULL;
//     PSECURITY_DESCRIPTOR pSD = NULL;

//     DWORD result = GetNamedSecurityInfoW(
//         drivePath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
//         NULL, NULL, &pOldDACL, NULL, &pSD
//     );

//     if (result != ERROR_SUCCESS) {
//         std::wcerr << L"Failed to get security info. Error: " << result << std::endl;
//         return;
//     }

//     ApplyPermissionsRecursively(drivePath, pOldDACL);

//     for (const auto& entry : fs::recursive_directory_iterator(drivePath, fs::directory_options::skip_permission_denied)) {
//         ApplyPermissionsRecursively(entry.path().wstring(), pOldDACL);
//     }

//     if (pSD) LocalFree(pSD);

//     std::wcout << L"Strict read-only permissions set successfully for " << drivePath << std::endl;
// }

// Helper function to parse drive numbers
// vector<int> ParseDriveNumbers(const string& input) {
//     vector<int> numbers;
//     stringstream ss(input);
//     string item;
//     while (getline(ss, item, ',')) {
//         try {
//             int num = stoi(item);
//             if (num > 0 && num <= removableDrives.size()) {
//                 numbers.push_back(num);
//             }
//         } catch (...) {
//             // Ignore invalid numbers
//         }
//     }
//     return numbers;
// }
// Modified MonitorDriveChanges function
void MonitorDriveChanges() {
    while (isRunning) {
        if (!menuActive) {  // Only check for new drives when menu is not active
            DWORD driveMask = GetLogicalDrives();
            
            // Check for new drives
            for (char letter = 'A'; letter <= 'Z'; ++letter) {
                if (driveMask & (1 << (letter - 'A'))) {
                    wstring driveLetter(1, letter);
                    wstring drivePath = driveLetter + L":\\";
                    
                    if (GetDriveTypeW(drivePath.c_str()) == DRIVE_REMOVABLE) {
                        if (removableDrives.find(driveLetter) == removableDrives.end()) {
                            DriveInfo info;
                            info.letter = driveLetter;
                            info.label = GetDriveLabel(drivePath);
                            info.isLocked = false;
                            
                            ULARGE_INTEGER totalBytes;
                            if (GetDiskFreeSpaceExW(drivePath.c_str(), nullptr, &totalBytes, nullptr)) {
                                info.totalSpace = totalBytes;
                            }
                            
                            removableDrives[driveLetter] = info;
                            
                        }
                    }
                }
            }
            
            // Remove disconnected drives
            auto it = removableDrives.begin();
            while (it != removableDrives.end()) {
                wstring drivePath = it->first + L":\\";
                if (!(driveMask & (1 << (it->first[0] - 'A'))) || 
                    GetDriveTypeW(drivePath.c_str()) != DRIVE_REMOVABLE) {
                    it = removableDrives.erase(it);
                } else {
                    ++it;
                }
            }
        }
        Sleep(1000);
    }
}

// *******************CODE FOR REMOVABLE DRIVE ENDS HERE ********************************

// Modified enforceDriveLockPolicy function
void enforceDriveLockPolicy(const json& policyData, const vector<wstring>& availableDrives, const vector<wstring>& availableRemovableDrives) {
    auto& localDrives = policyData["action"]["channel_action"]["endpoint_channels"]["LocalDrives"];
    string Localaction = localDrives["action"];
    vector<string> Localincluded = localDrives["included"];
    vector<string> Localexcluded = localDrives["excluded"];

    // Handle Block action
    if (Localaction == "Block") {
        if (Localincluded.empty()) {
            // If included is empty, do nothing
            return;
        }

        bool applyToAll = (find(Localincluded.begin(), Localincluded.end(), "*") != Localincluded.end());

        for (const auto& drive : availableDrives) {
            string driveLetter = string(1, drive[0]) + ":\\";

            // If applying to all drives, exclude ones in the excluded list
            if (applyToAll) {
                if (find(Localexcluded.begin(), Localexcluded.end(), driveLetter) == Localexcluded.end()) {
                    ModifyDriveAccess(drive, true); // Lock the drive if not found in excluded list
                }
            } 
            // Otherwise, apply only to included drives, except those in excluded list
            else if (find(Localincluded.begin(), Localincluded.end(), driveLetter) != Localincluded.end()) {
                if (find(Localexcluded.begin(), Localexcluded.end(), driveLetter) == Localexcluded.end()) {
                    ModifyDriveAccess(drive, true); // Lock the drive if it is in included list but not in excluded list
                }
            }
        }
    }
        
    // Handle Pass action
    else if (Localaction == "Allow") {
        bool applyToAll = (find(Localincluded.begin(), Localincluded.end(), "*") != Localincluded.end());
        bool lockAllExceptIncluded = (find(Localexcluded.begin(), Localexcluded.end(), "*") != Localexcluded.end());

        for (const auto& drive : availableDrives) {
            string driveLetter = string(1, drive[0]) + ":\\";

            if (applyToAll) {
                // Unlock all drives except those in excluded list
                if (find(Localexcluded.begin(), Localexcluded.end(), driveLetter) == Localexcluded.end()) {
                    ModifyDriveAccess(drive, false); // Unlock the drive
                }
                //lock all drives in the excluded list
                else{
                    ModifyDriveAccess(drive, true); // Lock the drive
                }
            } else if (lockAllExceptIncluded) {
                // Lock all drives except those in included list
                if (find(Localincluded.begin(), Localincluded.end(), driveLetter) == Localincluded.end()) {
                    ModifyDriveAccess(drive, true); // Lock the drive
                }
            } else {
                // Unlock only included drives
                if (find(Localincluded.begin(), Localincluded.end(), driveLetter) != Localincluded.end()) {
                    ModifyDriveAccess(drive, false); // Unlock the drive
                }
                // Lock only excluded drives
                if (find(Localexcluded.begin(), Localexcluded.end(), driveLetter) != Localexcluded.end()) {
                    ModifyDriveAccess(drive, true); // Lock the drive
                }
            }
        }
    }
    else if (Localaction == "Read-only") {
        if (Localincluded.empty()) {
            return;
        }
    
        bool applyToAll = (find(Localincluded.begin(), Localincluded.end(), "*") != Localincluded.end());
    
        for (const auto& drive : availableDrives) {
            string driveLetter = string(1, drive[0]) + ":\\";
    
            if (applyToAll) {
                if (find(Localexcluded.begin(), Localexcluded.end(), driveLetter) == Localexcluded.end()) {
                    ReadOnlyAccess(wstring(drive.begin(), drive.end()), true);
                }
            } 
            else if (find(Localincluded.begin(), Localincluded.end(), driveLetter) != Localincluded.end()) {
                if (find(Localexcluded.begin(), Localexcluded.end(), driveLetter) == Localexcluded.end()) {
                    ReadOnlyAccess(wstring(drive.begin(), drive.end()), true);
                }
            }
        }
    }

    // Handle RemovableMedia similarly
    auto& removableMedia = policyData["action"]["channel_action"]["endpoint_channels"]["RemovableDrives"];
    string Removableaction = removableMedia["action"];
    vector<string> Removableincluded = removableMedia["included"];
    vector<string> Removableexcluded = removableMedia["excluded"];

    if (Removableaction == "Block") {
        if (Removableincluded.empty()) {
            return;
        }
        
        bool applyToAll = (find(Removableincluded.begin(), Removableincluded.end(), "*") != Removableincluded.end());
        
        for (const auto& drive : availableRemovableDrives) {
            wstring driveLabelW = GetDriveLabel(drive);
            string driveLabel(driveLabelW.begin(), driveLabelW.end());
             // Convert "*" to ".*" for regex
            auto toValidRegex = [](const string& pattern) {
                return (pattern == "*") ? ".*" : pattern;
            };

            bool isExcluded = any_of(Removableexcluded.begin(), Removableexcluded.end(), [&](const string& pattern) {
                return regex_match(driveLabel, regex(toValidRegex(pattern)));
            });

            string driveLetter = string(1, drive[0]) + ":\\";
            
            if (applyToAll) {
                if (!isExcluded) {
                    ModifyDriveAccess(drive, true);
                }
            } else {
                bool isIncluded = any_of(Removableincluded.begin(), Removableincluded.end(), [&](const string& pattern) {
                    return regex_match(driveLabel, regex(toValidRegex(pattern)));
                });
                if (isIncluded && !isExcluded) {
                    ModifyDriveAccess(drive, true);
                }
            }
        }
    } 
    else if (Removableaction == "Allow") {
        bool applyToAll = (find(Removableincluded.begin(), Removableincluded.end(), "*") != Removableincluded.end());
        bool lockAllExceptIncluded = (find(Removableexcluded.begin(), Removableexcluded.end(), "*") != Removableexcluded.end());

        for (const auto& drive : availableRemovableDrives) {

            wstring driveLabelW = GetDriveLabel(drive);
            string driveLabel(driveLabelW.begin(), driveLabelW.end());
            auto toValidRegex = [](const string& pattern) {
                return (pattern == "*") ? ".*" : pattern;
            };

            bool isExcluded = any_of(Removableexcluded.begin(), Removableexcluded.end(), [&](const string& pattern) {
                return regex_match(driveLabel,regex(toValidRegex(pattern)));
            });
            
            bool isIncluded = any_of(Removableincluded.begin(), Removableincluded.end(), [&](const string& pattern) {
                return regex_match(driveLabel, regex(toValidRegex(pattern)));
            });

            string driveLetter = string(1, drive[0]) + ":\\";
            
            if (applyToAll && !isExcluded) {
                    ModifyDriveAccess(drive, false);
            } else if (isIncluded) {
                    ModifyDriveAccess(drive, false);
            } 
            if (lockAllExceptIncluded && !isIncluded) {
                ModifyDriveAccess(drive, true);
            }
        }
    }
    else if (Removableaction == "Read-only") {
        if (Removableincluded.empty()) {
            return;
        }
    
        bool applyToAll = (find(Removableincluded.begin(), Removableincluded.end(), "*") != Removableincluded.end());
    
        for (const auto& drive : availableRemovableDrives) {
            string driveLetter = string(1, drive[0]) + ":\\";
    
            if (applyToAll) {
                if (find(Removableexcluded.begin(), Removableexcluded.end(), driveLetter) == Removableexcluded.end()) {
                    ReadOnlyAccess(wstring(drive.begin(), drive.end()), true);
                }
            } 
            else if (find(Removableincluded.begin(), Removableincluded.end(), driveLetter) != Removableincluded.end()) {
                if (find(Removableexcluded.begin(), Removableexcluded.end(), driveLetter) == Removableexcluded.end()) {
                    ReadOnlyAccess(wstring(drive.begin(), drive.end()), true);
                }
            }
        }
    }

}

// Modified runPolicyEnforcementLoop function

// Modified runPolicyEnforcementLoop function
void runPolicyEnforcementLoop(int intervalSeconds, const vector<wstring>& availableDrives, atomic<bool>& stopFlag,const string& policyId,const json& policyData) {
    while (!stopFlag.load()) {// Keep running until stopFlag becomes true
        // string decrypted_data = fetch_decrypted_policy();
        // json policies = json::parse(decrypted_data);
        json policies = policyData;
       
        
        vector<wstring> AvailableRemovableDrives;
        
        // Get current removable drives
        for (const auto& drive : removableDrives) {
            wcout<< "Removable Drive: "<<drive.second.letter<<endl;
            AvailableRemovableDrives.push_back(drive.second.letter + L":\\");
        }

        // If policy is invalid, continue using the last valid policy
        if (policies.empty() || !policies.is_array()) { 
            std::cerr << "Invalid or missing policy data, continuing with last valid policies." << std::endl; 
            policies = lastValidPolicy; 
        } 
        if (policies != lastValidPolicy) { 
            for (const auto& policy : policies) { 
                if(policy["policy_id"] == policyId){
                if (!isValidDriveLockPolicy(policy)) { 
                    std::cerr << "Invalid policy detected, skipping." << std::endl; 
                    continue; 
                } 
                // Enforce the current policy 
                enforceDriveLockPolicy(policy, availableDrives, AvailableRemovableDrives); 
            }
            } 
            lastValidPolicy = policies; 
        } else { 
            std::cout << "No policy change detected." << std::endl; 
        } 
 
        // Sleep for the specified interval before running again 
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds)); 
    } 
    cout << "Policy enforcement loop stopping." << endl; 
}





// int main(){

//     // Start drive monitoring in a separate thread
//     thread monitorThread(MonitorDriveChanges);
//     monitorThread.detach();
    
//     vector<wstring> availableDrives = ListAvailableDrives();
//     if (availableDrives.empty()) {
//         wcerr << L"No fixed drives available." << endl;
//         return 1;
//     }
    
//     wcout << L"Available Drives:" << endl;
//     for (size_t i = 0; i < availableDrives.size(); ++i) {
//         wcout << i + 1 << L": " << availableDrives[i] << endl;
//     }
    
//     int timeInterval = 30; // Run every 30 seconds
//     runPolicyEnforcementLoop(timeInterval, availableDrives);


//     return 0;
// }



//USED THIS TO CREATE EXE: g++ -static -o DiskControl.exe DriveControl.cpp -I./nlohmann -L. -static-libgcc -static-libstdc++ -lole32 -std=c++17
// Action : Block , Allow , Read-only
// * means all
//Be Careful to exclude "C:\\" while action= Block and include = *, also when action = Allow and include = *, exclude must not contain "C:\\"
//For Removable Drives, include and exclude should be the label of the drive