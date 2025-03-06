// this file is used to implement the scheduler for the enforcement loop 
// this file uses schedules.json file and based on the priority cron>>daily>>weekly, it loads the schedules and start and stops according to it
// this file uses the functions from DriveControl.cpp to enforce the policy , functions are loaded from DriveControl.h file 

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <string>
#include <regex>
#include <vector>
#include "nlohmann/json.hpp"
#include "DriveControl.h" // Assuming DriveControl.h has related declarations of function from DriveControl.cpp
#include <atomic>


using namespace std;
using json = nlohmann::json;

// Global variables
json lastValidSchedule;
bool serviceRunning = false;
// Global flag to control the running state of the enforcement loop
atomic<bool> stopEnforcement{false};

// Function to load scheduler data
json loadSchedulerData(const string& filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Failed to open schedules.json" << endl;
        return json{};
    }
    json data;
    try {
        file >> data;
    } catch (const exception& e) {
        cerr << "Error parsing JSON: " << e.what() << endl;
        return json{};
    }
    return data;
}

// Get current day of the week
string getCurrentDayOfWeek() {
    auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    tm localTime;
    localtime_s(&localTime, &now);
    char dayBuffer[10];
    strftime(dayBuffer, sizeof(dayBuffer), "%A", &localTime);
    return string(dayBuffer);
}
// Determine start and end time based on priority
pair<string, string> determineSchedule(const json& scheduleData, string& recurrenceType) {
    string startTime, endTime;

        if (!scheduleData["cron_expression"].is_null()) {
            return {"", ""}; // Cron job not supported yet 
        } 
        if (scheduleData["recurrence"] == "Daily") {
            startTime = (scheduleData["start_time"].get<string>()).substr(11, 5);
            endTime = (scheduleData["end_time"].get<string>()).substr(11, 5);
            recurrenceType = "Daily";
            return {startTime, endTime};  // Prioritize and return immediately
        } 
        if (scheduleData["recurrence"] == "Weekly") {
            string currentDay = getCurrentDayOfWeek();
            if (scheduleData["days_of_week"].is_array() && find(scheduleData["days_of_week"].begin(), scheduleData["days_of_week"].end(), currentDay) != scheduleData["days_of_week"].end()) {
                startTime = (scheduleData["start_time"].get<string>()).substr(11, 5);
                endTime = (scheduleData["end_time"].get<string>()).substr(11, 5);
                recurrenceType = "Weekly";
            }
        }
    
    cout<< "Start Time: "<<startTime<<endl;
    cout<< "End Time: "<<endTime<<endl;
    return {startTime, endTime};
}

// Function to compare current time with start and end time
bool isTimeInRange(const string& startTime, const string& endTime) {
    auto now = chrono::system_clock::to_time_t(chrono::system_clock::now());
    tm localTime;
    localtime_s(&localTime, &now);
    char currentTime[6];
    strftime(currentTime, sizeof(currentTime), "%H:%M", &localTime);

    return string(currentTime) >= startTime && string(currentTime) < endTime;
}

unordered_map<string, atomic<bool>> serviceRunningMap;
unordered_map<string, atomic<bool>> stopEnforcementMap;
void setServiceRunningForPolicy(const string& policyId, bool status) {
    serviceRunningMap[policyId] = status;
}
bool serviceRunningForPolicy(const string& policyId) {
    if (serviceRunningMap.find(policyId) != serviceRunningMap.end())
        return serviceRunningMap[policyId].load();
    return false;
}
atomic<bool>& getStopFlagForPolicy(const string& policyId) {
    // Create a stop flag if it doesn't exist.
    if (stopEnforcementMap.find(policyId) == stopEnforcementMap.end()) {
        stopEnforcementMap[policyId] = false;
    }
    return stopEnforcementMap[policyId];
}

wstring normalizeDrive(const wstring& s) {
    wstring result = s;
    // Convert to uppercase.
    transform(result.begin(), result.end(), result.begin(), ::towupper);
    // Trim spaces (optional, if needed)
    result.erase(remove(result.begin(), result.end(), L' '), result.end());
    // If the drive doesn't end with a backslash, append one.
    if (!result.empty() && result.back() != L'\\') {
        result.push_back(L'\\');
    }
    return result;
}

// Updated matchesPattern function.
bool matchesPattern(const wstring& drive, const vector<string>& patterns) {
    // Normalize the drive for consistent comparison.
    wstring normalizedDrive = normalizeDrive(drive);

    for (const auto& pat : patterns) {
        // Convert the pattern to a wide string.
        wstring wPat(pat.begin(), pat.end());

        // If the pattern is a single letter and doesn't contain a colon,
        // assume it's a drive letter and append ":\\".
        if (wPat.size() == 1 && iswalpha(wPat[0])) {
            wPat += L":\\";
        }

        // If the pattern is a wildcard "*", it matches every drive.
        if (wPat == L"*") {
            return true;
        }

        // Normalize the pattern similarly.
        wstring normalizedPattern = normalizeDrive(wPat);

        // Direct comparison: if the normalized drive equals the normalized pattern.
        if (normalizedDrive == normalizedPattern) {
            return true;
        }

        // As an extra measure, support wildcard matching via regex.
        try {
            // Convert wildcard "*" into ".*" for regex.
            wstring regexPattern = regex_replace(wPat, wregex(L"\\*"), L".*");
            wregex re(regexPattern, regex::icase);
            if (regex_match(normalizedDrive, re)) {
                return true;
            }
        } catch (...) {
            // On regex error, skip this pattern.
        }
    }
    return false;
}

vector<wstring> getDrivesToReset(
    const vector<wstring>& systemDrives, 
    const string& policyAction, 
    const vector<string>& included, 
    const vector<string>& excluded
) {
    vector<wstring> drivesToReset;
    for (const auto& drive : systemDrives) {
        // Implement a matching function that checks if the drive matches any pattern.
        // For example, if the pattern is "*" then it matches all drives,
        // or if the pattern is "D" or "D:\\" then it only matches drive D.
        wcout<<"Drive: "<<drive<<endl;
        bool isIncluded = matchesPattern(drive, included);
        bool isExcluded = matchesPattern(drive, excluded);
        wcout<<"Included: "<<isIncluded<<endl;
        if ((policyAction == "Block" || policyAction == "Read-Only") && isIncluded && !isExcluded) {
            drivesToReset.push_back(drive);
        }
        else if (policyAction == "Allow" && isExcluded) {
            drivesToReset.push_back(drive);
        }
    }
    return drivesToReset;
}

// void schedulerLoop(const string& scheduleFile, int checkInterval) {
//     while (true) {
//         //print the current time here
//         time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
//         tm localTime;
//         localtime_s(&localTime, &now);
//         char currentTime[6];
//         strftime(currentTime, sizeof(currentTime), "%H:%M", &localTime);
//         cout << "Current Time: " << currentTime << endl;

//         json scheduleData = loadSchedulerData(scheduleFile);
//         // cout << "Checking schedule..." << scheduleData <<endl;
//         if (!scheduleData.empty() && scheduleData != lastValidSchedule) {
//             lastValidSchedule = scheduleData;
//         }
//         string recurrenceType;
//         auto [startTime, endTime] = determineSchedule(lastValidSchedule, recurrenceType);
//         cout<< "Start Time: "<<startTime<<endl;
//         cout<< "End Time: "<<endTime<<endl;

//         if (startTime.empty() || endTime.empty()) {
//             this_thread::sleep_for(chrono::seconds(checkInterval));
//             cout << "Invalid schedule data. Skipping..." << endl;
//             continue;
//         }
//         vector<wstring> availableDrives = ListAvailableDrives();
//         for(const auto& drive : availableDrives){
//             wcout<< "Available Drive: "<<drive<<endl;
//         }

//         if (isTimeInRange(startTime, endTime) && !serviceRunning) {
//             cout << "Starting service: " << recurrenceType << " schedule" << endl;
//             stopEnforcement = false; // Reset the flag when starting
//             thread(runPolicyEnforcementLoop, 5, availableDrives, ref(stopEnforcement)).detach();
//             serviceRunning = true;
//         } else if (!isTimeInRange(startTime, endTime) && serviceRunning) {
//             vector<wstring> AllDrives;
//             for (const auto& drive : removableDrives) {
//                 // wcout<< "Removable Drive: "<<drive.second.letter<<endl;
//                 AllDrives.push_back(drive.second.letter + L":\\");
//             }
//             for(const auto& drive :availableDrives){
//                 AllDrives.push_back(drive);
//             }
//             for (const auto& drive : AllDrives) {
//                 ModifyDriveAccess(drive, false);
//             }
//             stopEnforcement = true; // Signal the thread to stop
//             cout << "Stopping service..." << endl;
//             serviceRunning = false;
//         }

//         this_thread::sleep_for(chrono::seconds(checkInterval));
//     }
// }
void schedulerLoop(const string& scheduleFile, int checkInterval) {
    while (true) {
        // Print the current time.
        time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        tm localTime;
        localtime_s(&localTime, &now);
        char currentTime[6];
        strftime(currentTime, sizeof(currentTime), "%H:%M", &localTime);
        cout << "Current Time: " << currentTime << endl;

        json scheduleData = loadSchedulerData(scheduleFile);
        if (scheduleData.empty() || !scheduleData.is_array()) {
            cout << "No schedule data available." << endl;
            this_thread::sleep_for(chrono::seconds(checkInterval));
            continue;
        }
        // Loop over each policy in the scheduler data.
        for (auto& policy : scheduleData) {
            string policyId = policy.value("policy_id", "");
            if (policyId.empty()) {
                cout << "Policy without policy_id encountered. Skipping..." << endl;
                continue;
            }
            // Check if scheduler information exists in this policy.
            if (!policy.contains("action") || !policy["action"].contains("schedule")) {
                cout << "No scheduler found for policy " << policyId << ". Skipping..." << endl;
                continue;
            }
            json schedulers = policy["action"]["schedule"];
            string recurrenceType;
            cout<<"scheduler"<<schedulers<<endl;
            auto [startTime, endTime] = determineSchedule(schedulers, recurrenceType);
            cout<< "Start Time: "<<startTime<<endl;
            cout<< "End Time: "<<endTime<<endl;

            if (startTime.empty() || endTime.empty()) {
                cout << "Invalid schedule data for policy " << policyId << ". Skipping..." << endl;
                continue;
            }
            vector<wstring> availableDrives = ListAvailableDrives();
            for (const auto& drive : availableDrives) {
                    wcout << L"Available Drive: " << drive << endl;
                }
            if (isTimeInRange(startTime, endTime) && !serviceRunningForPolicy(policyId)) {
                    cout << "Starting service for policy " << policyId << " (" << recurrenceType << " schedule)" << endl;
                    // Reset the stop flag for this policy.
                    getStopFlagForPolicy(policyId) = false;
                    thread(runPolicyEnforcementLoop, 5, availableDrives, ref(getStopFlagForPolicy(policyId)), policyId).detach();
                    setServiceRunningForPolicy(policyId, true);
                }
                // Otherwise, if not in time range and service is running, stop enforcement.
                if (!isTimeInRange(startTime, endTime) && serviceRunningForPolicy(policyId)) {
                    cout << "time up" << endl;
                    json channels = policy["action"]["channel_action"][ "endpoint_channels"];
                    // --- Process Removable Drives ---
                    cout << "Processing local Drives..." << endl;

                     // --- Process Local Drives ---
                     if (channels.contains("LocalDrives")) {
                        cout<<"Local Drives found"<<endl;
                        json localPolicy = channels["LocalDrives"];
                        string localAction = localPolicy.value("action", "");
                        vector<string> localIncluded = localPolicy["included"].get<vector<string>>();
                        vector<string> localExcluded = localPolicy["excluded"].get<vector<string>>();
                        
                        vector<wstring> availableDrives = ListAvailableDrives();
                        cout << "Local drives available: " << availableDrives.size() << endl;
                        vector<wstring> drivesToReset = getDrivesToReset(availableDrives, localAction, localIncluded, localExcluded);
                        cout << "Local Drives to reset: " << drivesToReset.size() << endl;
                        for (const auto& drive : drivesToReset) {
                            cout << "Resetting local drive: ";
                            wcout << drive << endl;
                            ModifyDriveAccess(drive, false);
                        }
                    }

                    vector<wstring> remDrives;
                    // Build list from global removableDrives.
                    for (const auto& drive : removableDrives) {
                        remDrives.push_back(drive.second.letter + L":\\");
                    }
                    cout<<"Removable Drives: "<<remDrives.size()<<endl;
                    if (channels.contains("RemovableDrives")) {
                        json remPolicy = channels["RemovableDrives"];
                        string remAction = remPolicy.value("action", "");
                        vector<string> remIncluded = remPolicy["included"].get<vector<string>>();
                        vector<string> remExcluded = remPolicy["excluded"].get<vector<string>>();
                        
                        vector<wstring> drivesToReset = getDrivesToReset(remDrives, remAction, remIncluded, remExcluded);
                        cout << "Removable Drives to reset: " << drivesToReset.size() << endl;
                        for (const auto& drive : drivesToReset) {
                            cout << "Resetting removable drive: ";
                            wcout << drive << endl;
                            ModifyDriveAccess(drive, false);
                        }
                    }
                   
                    getStopFlagForPolicy(policyId) = true;
                    cout << "Stopping service for policy " << policyId << "..." << endl;
                    setServiceRunningForPolicy(policyId, false);
                }
            }
            this_thread::sleep_for(chrono::seconds(checkInterval));
        }
    }




int main() {
    const string scheduleFile = "Policy.json";
    schedulerLoop(scheduleFile, 60);
    return 0;
}
