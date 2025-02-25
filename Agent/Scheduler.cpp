// this file is used to implement the scheduler for the enforcement loop 
// this file uses schedules.json file and based on the priority cron>>daily>>weekly, it loads the schedules and start and stops according to it
// this file uses the functions from DriveControl.cpp to enforce the policy , functions are loaded from DriveControl.h file 

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <string>
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
        cerr << "Failed to open scheduler.json" << endl;
        return json{};
    }
    json data;
    file >> data;
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

    for (const auto& schedule : scheduleData) {
        if (!schedule["cron_expression"].is_null()) {
            continue; // Cron job not supported yet 
        } 
        if (schedule["recurrence"] == "Daily") {
            startTime = (schedule["start_time"].get<string>()).substr(11, 5);
            endTime = (schedule["end_time"].get<string>()).substr(11, 5);
            recurrenceType = "Daily";
            return {startTime, endTime};  // Prioritize and return immediately
        } 
        if (schedule["recurrence"] == "Weekly") {
            string currentDay = getCurrentDayOfWeek();
            if (schedule["days_of_week"].is_array() && find(schedule["days_of_week"].begin(), schedule["days_of_week"].end(), currentDay) != schedule["days_of_week"].end()) {
                startTime = (schedule["start_time"].get<string>()).substr(11, 5);
                endTime = (schedule["end_time"].get<string>()).substr(11, 5);
                recurrenceType = "Weekly";
            }
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

// Function to start and stop the service based on time
void schedulerLoop(const string& scheduleFile, int checkInterval) {
    while (true) {
        //print the current time here
        time_t now = chrono::system_clock::to_time_t(chrono::system_clock::now());
        tm localTime;
        localtime_s(&localTime, &now);
        char currentTime[6];
        strftime(currentTime, sizeof(currentTime), "%H:%M", &localTime);
        cout << "Current Time: " << currentTime << endl;

        json scheduleData = loadSchedulerData(scheduleFile);
        // cout << "Checking schedule..." << scheduleData <<endl;
        if (!scheduleData.empty() && scheduleData != lastValidSchedule) {
            lastValidSchedule = scheduleData;
        }
        string recurrenceType;
        auto [startTime, endTime] = determineSchedule(lastValidSchedule, recurrenceType);
        cout<< "Start Time: "<<startTime<<endl;
        cout<< "End Time: "<<endTime<<endl;

        if (startTime.empty() || endTime.empty()) {
            this_thread::sleep_for(chrono::seconds(checkInterval));
            cout << "Invalid schedule data. Skipping..." << endl;
            continue;
        }
        vector<wstring> availableDrives = ListAvailableDrives();
        for(const auto& drive : availableDrives){
            wcout<< "Available Drive: "<<drive<<endl;
        }

        if (isTimeInRange(startTime, endTime) && !serviceRunning) {
            cout << "Starting service: " << recurrenceType << " schedule" << endl;
            stopEnforcement = false; // Reset the flag when starting
            thread(runPolicyEnforcementLoop, 5, availableDrives, ref(stopEnforcement)).detach();
            serviceRunning = true;
        } else if (!isTimeInRange(startTime, endTime) && serviceRunning) {
            vector<wstring> AllDrives;
            for (const auto& drive : removableDrives) {
                // wcout<< "Removable Drive: "<<drive.second.letter<<endl;
                AllDrives.push_back(drive.second.letter + L":\\");
            }
            for(const auto& drive :availableDrives){
                AllDrives.push_back(drive);
            }
            for (const auto& drive : AllDrives) {
                ModifyDriveAccess(drive, false);
            }
            stopEnforcement = true; // Signal the thread to stop
            cout << "Stopping service..." << endl;
            serviceRunning = false;
        }

        this_thread::sleep_for(chrono::seconds(checkInterval));
    }
}

int main() {
    const string scheduleFile = "Schedules.json";
    schedulerLoop(scheduleFile, 60);
    return 0;
}
