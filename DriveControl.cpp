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
#include "nlohmann/json.hpp" // JSON library folder (included as a separate folder)

// Create an alias for the JSON library
using json = nlohmann::json;
json lastValidPolicy;
// Function to load only the "Drive Lock Policy" section from policy.json
json LoadDriveLockPolicy() {
    std::ifstream file("policy.json");
    json fullPolicy;
    
    if (!file.is_open()) {
        std::cerr << "Failed to open policy.json" << std::endl;
        return {};
    }

    try {
        file >> fullPolicy;
        file.close();

        // Check if "policies" exist
        if (!fullPolicy.contains("policies")) {
            std::cerr << "Invalid policy format: 'policies' key missing." << std::endl;
            return {};
        }

        // Find "Drive Lock Policy"
        for (const auto& policy : fullPolicy["policies"]) {
            if (policy.contains("policy_id") && policy["policy_id"] == "POL-002") {
                return policy; // Return only this section
            }
        }

        std::cerr << "Drive Lock Policy (POL-002) not found." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    }

    return {}; // Return empty if not found
}
// Function to validate the policy format
bool isValidDriveLockPolicy(const json& policyData) {
    if (!policyData.contains("conditions")) return false;
    if (!policyData["conditions"].contains("time_policy")) return false;
    if (!policyData["conditions"].contains("drive_lock")) return false;
    if (!policyData["conditions"]["time_policy"].contains("start_time")) return false;
    if (!policyData["conditions"]["time_policy"].contains("end_time")) return false;
    if (!policyData["conditions"]["time_policy"].contains("days")) return false;
    if (!policyData["conditions"]["drive_lock"].contains("local_drives")) return false;

    return true;
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
void PrintDriveInfo(const map<wstring, DriveInfo>& drives) {
    system("cls");
    wcout << L"\nCurrent Removable Drives:\n" << endl;
    int index = 1;
    for (const auto& drive : drives) {
        wcout << index << L" -> Drive " << drive.second.letter << L":\\" << endl;
        wcout << L"     Label: " << (drive.second.label.empty() ? L"No Label" : drive.second.label) << endl;
        wcout << L"     Status: " << (drive.second.isLocked ? L"Locked" : L"Unlocked") << endl;
        wcout << L"     Size: " << (drive.second.totalSpace.QuadPart / (1024 * 1024 * 1024)) << L" GB" << endl;
        wcout << L"------------------------" << endl;
        index++;
    }
}
// Helper function to parse drive numbers
vector<int> ParseDriveNumbers(const string& input) {
    vector<int> numbers;
    stringstream ss(input);
    string item;
    while (getline(ss, item, ',')) {
        try {
            int num = stoi(item);
            if (num > 0 && num <= removableDrives.size()) {
                numbers.push_back(num);
            }
        } catch (...) {
            // Ignore invalid numbers
        }
    }
    return numbers;
}
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

// Function to check if current time is within policy
// Function to check if the current time is within the policy schedule
bool isWithinPolicyTime(const json& policyData) {
    // Ensure "conditions" and "time_policy" exist
    if (!policyData.contains("conditions") || !policyData["conditions"].contains("time_policy")) {
        std::cerr << "Time policy section missing!" << std::endl;
        return false;
    }

    json timePolicy = policyData["conditions"]["time_policy"];

    // Ensure time policy is enabled
    if (!timePolicy.contains("enabled") || !timePolicy["enabled"].get<bool>()) {
        std::cerr << "Time policy is disabled!" << std::endl;
        return false;
    }

    // Get current time
    time_t now = time(nullptr);
    tm* localTime = localtime(&now);

    int currentHour = localTime->tm_hour;
    int currentMinute = localTime->tm_min;
    int currentDay = localTime->tm_wday; // Sunday = 0, Monday = 1, etc.

    // Ensure required fields exist
    if (!timePolicy.contains("start_time") || !timePolicy.contains("end_time") || !timePolicy.contains("days")) {
        std::cerr << "Invalid time policy format!" << std::endl;
        return false;
    }

    string startTimeStr = timePolicy["start_time"];
    string endTimeStr = timePolicy["end_time"];

    int startHour = stoi(startTimeStr.substr(0, 2));
    int startMinute = stoi(startTimeStr.substr(3, 2));
    int endHour = stoi(endTimeStr.substr(0, 2));
    int endMinute = stoi(endTimeStr.substr(3, 2));

    // Check if today is an allowed day
    vector<int> allowedDays = timePolicy["days"];
    if (find(allowedDays.begin(), allowedDays.end(), currentDay) == allowedDays.end()) {
        std::cerr << "Today is not in the allowed days." << std::endl;
        return false;
    }

    // Compare current time with the allowed time range
    if ((currentHour > startHour || (currentHour == startHour && currentMinute >= startMinute)) &&
        (currentHour < endHour || (currentHour == endHour && currentMinute < endMinute))) {
        return true;
    } else {
        std::cerr << "Current time is outside the allowed range." << std::endl;
    }

    return false;
}

void enforceDriveLockPolicy(const json& policyData, const vector<wstring>& availableDrives,const vector<wstring>& availableRemovableDrives , bool withinTime) {
    // Ensure "conditions" and "drive_lock" exist
    if (!policyData.contains("conditions") || !policyData["conditions"].contains("drive_lock")) {
        std::cerr << "Drive lock policy section missing!" << std::endl;
        return;
    }

    json driveLock = policyData["conditions"]["drive_lock"];

    // Iterate through the list of drives in the policy
    for (const auto& drive : driveLock["local_drives"]) {
        if (!drive.contains("drive") || !drive.contains("lock")) {
            std::cerr << "Invalid drive lock format!" << std::endl;
            continue;
        }

        std::string driveLetter = drive["drive"];
        bool lockStatus = false;  // Default: unlock

        if (withinTime) {
            lockStatus = drive["lock"];  // Apply policy lock state
        }

        // Apply policy to the available drives
        for (const auto& availableDrive : availableDrives) {
            if (availableDrive[0] == driveLetter[0]) {
                ModifyDriveAccess(availableDrive, lockStatus);
            }
        }
    }

    // Process Removable Drives
    if (driveLock.contains("removable_drives")) {
        for (const auto& drive : driveLock["removable_drives"]) {
            if (!drive.contains("drive") || !drive.contains("lock")) {
                std::cerr << "Invalid removable drive lock format!" << std::endl;
                continue;
            }

            std::string driveLetter = drive["drive"];
            bool lockStatus = false;  // Default: unlock

            if (withinTime) {
                lockStatus = drive["lock"];  // Apply policy lock state
            }

            // Apply policy to the available removable drives
            for (const auto& availableDrive : availableRemovableDrives) {
                if (availableDrive[0] == driveLetter[0]) {
                    ModifyDriveAccess(availableDrive, lockStatus);
                }
            }
        }
    }
}

void runPolicyEnforcementLoop(int intervalSeconds, const vector<wstring>& availableDrives) {
    while (true) {
        json policyData = LoadDriveLockPolicy();
        //load the removable drives here available after each minute
        vector<wstring> AvailableRemovableDrives;
        cout<< "Avaialble Removable Drives: "<<endl;
        for (const auto& drive : removableDrives) {
            wcout << L"Drive: " << drive.second.letter <<endl ;
            AvailableRemovableDrives.push_back(drive.second.letter + L":\\");
        }


        // If policy is invalid, continue using the last valid policy
        if (policyData.empty() || !isValidDriveLockPolicy(policyData)) {
            std::cerr << "Invalid or missing policy data, continuing with last valid policy." << std::endl;
            policyData = lastValidPolicy; // Use last known good policy
        } else {
            if (policyData != lastValidPolicy) {
                bool withinTime = isWithinPolicyTime(policyData);
                enforceDriveLockPolicy(policyData, availableDrives, AvailableRemovableDrives ,withinTime);
                lastValidPolicy = policyData; // Update stored policy
            }else {
                std::cout << "No policy change detected." << std::endl;
            }

        }

        // Sleep for the specified interval before running again
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
    }
}





int main() {

    // Start drive monitoring in a separate thread
    thread monitorThread(MonitorDriveChanges);
    monitorThread.detach();
    
    vector<wstring> availableDrives = ListAvailableDrives();
    if (availableDrives.empty()) {
        wcerr << L"No fixed drives available." << endl;
        return 1;
    }
    
    wcout << L"Available Drives:" << endl;
    for (size_t i = 0; i < availableDrives.size(); ++i) {
        wcout << i + 1 << L": " << availableDrives[i] << endl;
    }
    
    int timeInterval = 60; // Run every 60 seconds
    runPolicyEnforcementLoop(timeInterval, availableDrives);


    return 0;
}

//USED THIS TO CREATE EXE:  g++ DiskLock.cpp -o DiskLock -static -static-libgcc -static-libstdc++ -lole32