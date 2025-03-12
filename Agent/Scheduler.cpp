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
// #include <libsqlite3/sqlite3.h>
// #include <cryptlib.h>
// #include <aes.h>
// #include <filters.h>
// #include <modes.h>
// #include <base64.h>
// using namespace CryptoPP;
using namespace std;
using json = nlohmann::json;

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

void schedulerLoop(json &scheduleData,int checkInterval) {
    while (true) {
        // Print the current time.
        time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        tm localTime;
        localtime_s(&localTime, &now);
        char currentTime[6];
        strftime(currentTime, sizeof(currentTime), "%H:%M", &localTime);
        cout << "Current Time: " << currentTime << endl;

        // json scheduleData = loadSchedulerData(scheduleFile);
        // string decrypted_data = fetch_decrypted_policy();
        // json scheduleData = json::parse(decrypted_data);
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
                    thread(runPolicyEnforcementLoop, 5, availableDrives, std::ref(getStopFlagForPolicy(policyId)), policyId,scheduleData).detach();
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
        string input;
        string line;
    
        while (getline(cin, line)) {
            input += line + "\n"; 
        }
    
        try {
            json jsonData = json::parse(input);
            schedulerLoop(jsonData, 60);
        } catch (json::parse_error& e) {
            cerr << "Failed to parse JSON: " << e.what() << endl;
            return 1;
        }
    
        return 0;
    }
