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



// Function to enable required privileges
bool EnablePrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return false;
    }

    LUID luidRestore, luidSecurity;
    if (!LookupPrivilegeValue(NULL, SE_SECURITY_NAME, &luidSecurity) ||
        !LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &luidRestore)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 2;
    tp.Privileges[0].Luid = luidSecurity;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[1].Luid = luidRestore;
    tp.Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);
    return result;
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

bool IsRestrictedTime() {
    time_t now = time(0);
    struct tm t;
    localtime_s(&t, &now);
    
    // Restricted time: Monday-Friday (1-5), 9 AM to 6 PM
    bool isWorkday = (t.tm_wday >= 1 && t.tm_wday <= 5);
    bool isWorktime = (t.tm_hour >= 9 && t.tm_hour < 18);
    
    cout << "Current time: " << t.tm_hour << ":" << t.tm_min 
         << " (Day: " << t.tm_wday << ")" << endl;
    
    return isWorkday && isWorktime;
}

int main() {
    vector<wstring> availableDrives = ListAvailableDrives();
    if (availableDrives.empty()) {
        wcerr << L"No fixed drives available." << endl;
        return 1;
    }

    wcout << L"Available Drives:" << endl;
    for (size_t i = 0; i < availableDrives.size(); ++i) {
        wcout << i + 1 << L": " << availableDrives[i] << endl;
    }

    wcout << L"Enter the number(s) of the drive(s) you want to control (comma-separated): ";
    string input;
    getline(cin, input);

    vector<int> selectedDrives;
    size_t pos = 0;
    while ((pos = input.find(',')) != string::npos) {
        selectedDrives.push_back(stoi(input.substr(0, pos)) - 1);
        input.erase(0, pos + 1);
    }
    selectedDrives.push_back(stoi(input) - 1);

    wcout << L"Press 'L' to lock the selected drives, 'U' to unlock them, or 'Q' to quit." << endl;
    while (true) {
        if (GetAsyncKeyState('L') & 0x8000) {
            for (int index : selectedDrives) {
                if (index >= 0 && index < availableDrives.size())
                    ModifyDriveAccess(availableDrives[index], true);
            }
            Sleep(500);
        }
        if (GetAsyncKeyState('U') & 0x8000) {
            for (int index : selectedDrives) {
                if (index >= 0 && index < availableDrives.size())
                    ModifyDriveAccess(availableDrives[index], false);
            }
            Sleep(500);
        }
        if (GetAsyncKeyState('Q') & 0x8000) {
            wcout << L"Exiting..." << endl;
            break;
        }
        Sleep(100);
    }
    return 0;
}



//USED THIS TO CREATE EXE:  g++ DiskLock.cpp -o DiskLock -static -static-libgcc -static-libstdc++ -lole32
