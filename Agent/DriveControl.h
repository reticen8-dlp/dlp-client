#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <atomic>
#include "nlohmann/json.hpp"

// JSON alias
using json = nlohmann::json;

// Structures
struct DriveInfo {
    std::wstring letter;
    std::wstring label;
    std::wstring type;
    bool isLocked;
    ULONG serialNumber;
    ULARGE_INTEGER totalSpace;
    ULARGE_INTEGER freeSpace;
};

// Global variables (declared in test2.cpp, used elsewhere)
extern json lastValidPolicy;
extern std::map<std::wstring, DriveInfo> removableDrives;
extern bool isRunning;
extern bool menuActive;

// Function declarations
json LoadDriveLockPolicy();
bool isValidDriveLockPolicy(const json& policyData);
void DisplayError(const wchar_t* action, DWORD error);
std::vector<std::wstring> ListAvailableDrives();
bool ModifyDriveAccess(const std::wstring& drive, bool restrict);
bool ReadOnlyAccess(const std::wstring& drive, bool restrict);
std::wstring GetDriveLabel(const std::wstring& drive);
void MonitorDriveChanges();
void enforceDriveLockPolicy(const json& policyData, const std::vector<std::wstring>& availableDrives, const std::vector<std::wstring>& availableRemovableDrives);
void runPolicyEnforcementLoop(int intervalSeconds, const std::vector<std::wstring>& availableDrives, std::atomic<bool>& stopFlag, const std::string& policyId,const nlohmann::json& policyData);
void ShowNotification(const wchar_t* title, const wchar_t* message);
