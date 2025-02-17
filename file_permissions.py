import sqlite3
import json
import subprocess
import os
from file_monitoring import get_monitored_files
import tempfile
from settings import POWERSHELL_SCRIPT_PATH

def enforce_file_protection(file_paths):
    # Create a temporary file to store the file paths
    with tempfile.NamedTemporaryFile(delete=False, mode='w', newline='') as temp_file:
        for path in file_paths:
            temp_file.write(path + '\n')
        temp_file_path = temp_file.name

    # Call the PowerShell script with the temporary file as an argument
    subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", POWERSHELL_SCRIPT_PATH, temp_file_path])
def main():
    monitored_files = get_monitored_files()
    if monitored_files:
        enforce_file_protection(monitored_files)
    else:
        print("No monitored files found.")

if __name__ == "__main__":
    main()