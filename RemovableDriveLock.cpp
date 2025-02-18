#include <windows.h>
#include <aclapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <sstream>
#include <algorithm>
#include <thread>
#include <dbt.h>
#include <sddl.h>
#include <conio.h>
#include <iostream>

using namespace std;

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


// Helper function to get drive type string
wstring GetDriveTypeString(const wstring& drive) {
    switch (GetDriveTypeW(drive.c_str())) {
        case DRIVE_REMOVABLE: return L"Removable";
        case DRIVE_FIXED: return L"Fixed";
        case DRIVE_REMOTE: return L"Network";
        case DRIVE_CDROM: return L"CD-ROM";
        case DRIVE_RAMDISK: return L"RAM Disk";
        default: return L"Unknown";
    }
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

// Helper function to get drive information
DriveInfo GetDriveInfo(const wstring& driveLetter) {
    DriveInfo info;
    wstring drive = driveLetter + L":\\";
    
    info.letter = driveLetter;
    info.label = GetDriveLabel(drive);
    info.type = GetDriveTypeString(drive);
    info.isLocked = false;

    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (GetDiskFreeSpaceExW(drive.c_str(), &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        info.totalSpace = totalBytes;
        info.freeSpace = freeBytesAvailable;
    }

    return info;
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

// Function to print drive information
void PrintDriveInfo(const DriveInfo& info, int index) {
    wcout << index << L" -> Drive " << info.letter << L":\\" << endl;
    wcout << L"     Label: " << (info.label.empty() ? L"No Label" : info.label) << endl;
    wcout << L"     Type: " << info.type << endl;
    wcout << L"     Status: " << (info.isLocked ? L"Locked" : L"Unlocked") << endl;
    wcout << L"     Total Space: " << (info.totalSpace.QuadPart / (1024 * 1024 * 1024)) << L" GB" << endl;
    wcout << L"     Free Space: " << (info.freeSpace.QuadPart / (1024 * 1024 * 1024)) << L" GB" << endl;
    wcout << L"------------------------" << endl;
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
                            
                            system("cls");
                            wcout << L"\nNew removable drive detected!" << endl;
                            PrintDriveInfo(removableDrives);
                            wcout << L"\nMenu Options:" << endl;
                            wcout << L"L - Lock drives" << endl;
                            wcout << L"U - Unlock drives" << endl;
                            wcout << L"Q - Quit" << endl;
                            wcout << L"Enter choice: ";
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
                    system("cls");
                    wcout << L"\nDrive list updated:" << endl;
                    PrintDriveInfo(removableDrives);
                    wcout << L"\nMenu Options:" << endl;
                    wcout << L"L - Lock drives" << endl;
                    wcout << L"U - Unlock drives" << endl;
                    wcout << L"Q - Quit" << endl;
                    wcout << L"Enter choice: ";
                } else {
                    ++it;
                }
            }
        }
        Sleep(1000);
    }
}



bool ModifyDriveAccess(const wstring& drive, bool restrict) {
    PSID pAdminSID = NULL;
    PSID pSystemSID = NULL;
    PSID pEveryoneSID = NULL;
    PACL pNewDACL = NULL;
    bool success = false;

    try {
        // Create SIDs
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY worldAuthority = SECURITY_WORLD_SID_AUTHORITY;

        if (!AllocateAndInitializeSid(&ntAuthority, 2, 
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &pAdminSID)) {
            throw GetLastError();
        }

        if (!AllocateAndInitializeSid(&ntAuthority, 1,
            SECURITY_LOCAL_SYSTEM_RID,
            0, 0, 0, 0, 0, 0, 0, &pSystemSID)) {
            throw GetLastError();
        }

        if (!AllocateAndInitializeSid(&worldAuthority, 1,
            SECURITY_WORLD_RID,
            0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
            throw GetLastError();
        }

        EXPLICIT_ACCESS ea[3];
        ZeroMemory(&ea, 3 * sizeof(EXPLICIT_ACCESS));

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

        // Everyone - restricted or full access
        ea[2].grfAccessPermissions = restrict ? 0 : GENERIC_ALL;
        ea[2].grfAccessMode = restrict ? DENY_ACCESS : SET_ACCESS;
        ea[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[2].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

        DWORD dwRes = SetEntriesInAcl(3, ea, NULL, &pNewDACL);
        if (dwRes != ERROR_SUCCESS) {
            throw dwRes;
        }

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
        std::wcout << (restrict ? L"Restricted access to " : L"Unrestricted access to ") << drive << endl;
    }
    catch (DWORD error) {
        DisplayError(restrict ? L"restricting drive" : L"unrestricting drive", error);
    }

    if (pAdminSID) FreeSid(pAdminSID);
    if (pSystemSID) FreeSid(pSystemSID);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pNewDACL) LocalFree(pNewDACL);
    return success;
}


int main() {
    // [Previous initialization code remains the same until the menu loop]

    // Start drive monitoring in a separate thread
    thread monitorThread(MonitorDriveChanges);
    monitorThread.detach();

    wcout << L"Removable Drive Monitor Started\n";
    wcout << L"\nMenu Options:" << endl;
    wcout << L"L - Lock drives" << endl;
    wcout << L"U - Unlock drives" << endl;
    wcout << L"Q - Quit" << endl;
    wcout << L"Enter choice: ";

    string input;
    while (isRunning) {
        if (_kbhit()) {  // Check if a key was pressed
            char choice = _getch();
            choice = toupper(choice);
            
            menuActive = true;
            
            switch (choice) {
                case 'L': {
                    if (removableDrives.empty()) {
                        wcout << L"\nNo removable drives connected." << endl;
                    } else {
                        PrintDriveInfo(removableDrives);
                        wcout << L"\nEnter drive numbers to lock (comma-separated, e.g., 1,2,3): ";
                        getline(cin, input);
                        vector<int> driveNums = ParseDriveNumbers(input);
                        
                        int index = 1;
                        for (auto& drive : removableDrives) {
                            if (find(driveNums.begin(), driveNums.end(), index) != driveNums.end()) {
                                if (ModifyDriveAccess(drive.first + L":\\", true)) {
                                    drive.second.isLocked = true;
                                }
                            }
                            index++;
                        }
                    }
                    break;
                }
                case 'U': {
                    if (removableDrives.empty()) {
                        wcout << L"\nNo removable drives connected." << endl;
                    } else {
                        PrintDriveInfo(removableDrives);
                        wcout << L"\nEnter drive numbers to unlock (comma-separated, e.g., 1,2,3): ";
                        getline(cin, input);
                        vector<int> driveNums = ParseDriveNumbers(input);
                        
                        int index = 1;
                        for (auto& drive : removableDrives) {
                            if (find(driveNums.begin(), driveNums.end(), index) != driveNums.end()) {
                                if (ModifyDriveAccess(drive.first + L":\\", false)) {
                                    drive.second.isLocked = false;
                                }
                            }
                            index++;
                        }
                    }
                    break;
                }
                case 'Q': {
                    wcout << L"\nDo you want to restore all drive permissions before exiting? (Y/N): ";
                    char response;
                    cin >> response;
                    response = toupper(response);
                    
                    if (response == 'Y') {
                        for (auto& drive : removableDrives) {
                            if (drive.second.isLocked) {
                                ModifyDriveAccess(drive.first + L":\\", false);
                            }
                        }
                    }
                    
                    isRunning = false;
                    return 0;
                }
            }
            
            menuActive = false;
            system("cls");
            PrintDriveInfo(removableDrives);
            wcout << L"\nMenu Options:" << endl;
            wcout << L"L - Lock drives" << endl;
            wcout << L"U - Unlock drives" << endl;
            wcout << L"Q - Quit" << endl;
            wcout << L"Enter choice: ";
        }
        Sleep(100);
    }

    return 0;
}