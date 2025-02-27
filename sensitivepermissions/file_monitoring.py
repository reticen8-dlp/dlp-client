# any file create delete modify or edit will be monitored in given dir.(for detecting sensitive data files) for alerts.
# enforce # Grant read and execute permissions - Deny delete, rename, and move  the file's permissions

import json
import os
import sqlite3
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32api
import win32con
import win32gui
import os
# from settings import INDEXING_DATABASE
# from settings import FILE_CHANGES_DATABASE


POWERSHELL_SCRIPT_PATH = r"sensitivepermissions\file_protect.ps1"
REVOKE_POWERSHELL_SCRIPT_PATH = r"sensitivepermissions\file_revoke.ps1"
LOCK_POWERSHELL_SCRIPT_PATH = r"sensitivepermissions\file_lock.ps1"

import subprocess
import tempfile
import argparse
DB_PATH = "Proprium_dlp.db"
# Fetch monitored file paths from the database

def show_notification(title, message):
    """Display a Windows notification in the system tray"""
    # Define balloon tip icons
    NIIF_INFO = 0x00000001
    NIIF_WARNING = 0x00000002
    
    # Try to find an existing notification window to reuse
    hwnd = win32gui.FindWindow(None, "ClipboardSecurityNotification")
    if not hwnd:
        # Create a window for notifications
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = "ClipboardSecurityNotificationClass"
        wc.lpfnWndProc = lambda *args: None
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.hIcon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
        wc.hCursor = win32gui.LoadCursor(0, win32con.IDC_ARROW)
        wc.hbrBackground = win32con.COLOR_WINDOW
        
        try:
            class_atom = win32gui.RegisterClass(wc)
            hwnd = win32gui.CreateWindow(
                class_atom, "ClipboardSecurityNotification", 0, 0, 0, 
                win32con.CW_USEDEFAULT, win32con.CW_USEDEFAULT, 
                0, 0, wc.hInstance, None
            )
        except Exception as e:
            print(f"Error creating notification window: {e}")
            return
    
    # Set up notification data
    flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP | win32gui.NIF_INFO
    nid = (
        hwnd, 0, flags, win32con.WM_USER + 20, 
        win32gui.LoadIcon(0, win32con.IDI_APPLICATION),
        "Clipboard Security", message, 10, title, NIIF_WARNING
    )
    
    try:
        # Add or modify notification
        win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, nid)
    except:
        try:
            # If modification fails, add new notification
            win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, nid)
        except Exception as e:
            print(f"Error showing notification: {e}")


def get_monitored_files():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT path FROM files WHERE has_sensitive_data = 1")
    file_paths = [row[0] for row in cursor.fetchall()]

    # with open("monitored_files.json", "w") as json_file:
    #     json.dump(file_paths, json_file, indent=4)

    conn.close()
    return file_paths


def get_sensitive_files():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT file_path FROM sensitive_data")
    file_paths = [row[0] for row in cursor.fetchall()]

    # with open("monitored_files.json", "w") as json_file:
    #     json.dump(file_paths, json_file, indent=4)

    conn.close()
    return file_paths


# Get monitored files and their parent directories
MONITORED_FILES = set(get_monitored_files())
MONITORED_DIRS = {os.path.dirname(path) for path in MONITORED_FILES}

# Dictionary to store last modification time of files (to prevent duplicate logs)
last_modified_times = {}

# Time threshold to prevent logging duplicate events (debounce mechanism)
DEBOUNCE_TIME = 2  # seconds

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            file_path TEXT,
            file_type TEXT,
            file_size INTEGER,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

class FilePermissions():
 
    def __init__(self):
        pass
       
    

    def enforce_file_protection(self,file_paths):
        
        # filtered_paths = [path for path in file_paths if any(path.endswith(ext) for ext in types)]
        # Create a temporary file to store the file paths
        with tempfile.NamedTemporaryFile(delete=False, mode='w', newline='') as temp_file:
            for path in file_paths:
                temp_file.write(path + '\n')
            temp_file_path = temp_file.name

        # Call the PowerShell script with the temporary file as an argument
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", POWERSHELL_SCRIPT_PATH, temp_file_path])
   
    def revoke_file_protection(self,file_paths):
        with tempfile.NamedTemporaryFile(delete=False, mode='w', newline='') as temp_file:
            for path in file_paths:
                temp_file.write(path + '\n')
            temp_file_path = temp_file.name
        
        # Call the PowerShell revoke script with the temporary file as an argument
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", REVOKE_POWERSHELL_SCRIPT_PATH, temp_file_path])

    def lock_files(self,file_paths):
        with tempfile.NamedTemporaryFile(delete=False, mode='w', newline='') as temp_file:
            for path in file_paths:
                temp_file.write(path + '\n')
            temp_file_path = temp_file.name
        
        # Call the PowerShell revoke script with the temporary file as an argument
        subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", LOCK_POWERSHELL_SCRIPT_PATH, temp_file_path])    
         
    
class FileMonitorHandler(FileSystemEventHandler):

    last_event = {}  # Dictionary to store last event type for each file

    def process_event(self, event_type, file_path):
        # Ignore files that are not in MONITORED_FILES
        if file_path not in MONITORED_FILES:
            return
        
        file_type = os.path.splitext(file_path)[1] or "Folder"
        file_size = os.path.getsize(file_path) if os.path.isfile(file_path) else 0
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        # Prevent duplicate modifications
        if event_type == "Modified" and self.last_event.get(file_path) == "Created":
            time.sleep(1)  # Small delay to allow file content to stabilize
            self.last_event[file_path] = "Modified"  # Update last event
            return  # Skip this "Modified" event
        # Store event in database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO file_changes (event_type, file_path, file_type, file_size, timestamp) VALUES (?, ?, ?, ?, ?)",
                       (event_type, file_path, file_type, file_size, timestamp))
        conn.commit()
        conn.close()

        self.last_event[file_path] = event_type  # Track last event type

        # Show Windows Notification
        notification_title = f"File {event_type}"
        notification_message = f"{file_path} ({file_type}, {file_size} bytes)"
        show_notification(notification_title, notification_message)  # 

        print(f"{event_type}: {file_path} ({file_type}, {file_size} bytes)")

    def on_created(self, event):
        self.process_event("Created", event.src_path)

    def on_modified(self, event):
        self.process_event("Modified", event.src_path)

    def on_deleted(self, event):
        self.process_event("Deleted", event.src_path)

    def on_moved(self, event):
        self.process_event("Moved", f"{event.src_path} → {event.dest_path}")




def start_monitoring():
    init_db()
    observer = Observer()

    for directory in MONITORED_DIRS:
        if os.path.exists(directory):  # Ensure directory exists
            event_handler = FileMonitorHandler()
            observer.schedule(event_handler, directory, recursive=False)
            print(f"Monitoring: {directory}")

    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Monitoring stopped.")
    observer.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor sensitive files for changes")
    parser.add_argument("--monitor", action="store_true", help="Start file monitoring")
    parser.add_argument("--enforce", action="store_true", help="Enforce file protection")
    parser.add_argument("--revoke", action="store_true", help="Enforce file protection")
    parser.add_argument("--lock", action="store_true", help="Enforce file protection")
    parser.add_argument('files', nargs='*', help='List of files for enforcement or revocation')

    args = parser.parse_args()

    if args.monitor:
        start_monitoring()
    elif args.enforce:
        enforce_files = args.files  # directly use the list of file paths
        if enforce_files:
            permissions = FilePermissions()
            permissions.enforce_file_protection(enforce_files)
    elif args.revoke:
        revoke_files = args.files  # directly use the list of file paths
        print(revoke_files)
        if revoke_files:
            permissions = FilePermissions()
            permissions.revoke_file_protection(revoke_files)
    elif args.lock:
        enforce_files = args.files  # directly use the list of file paths
        if enforce_files:
            permissions = FilePermissions()
            permissions.lock_files(enforce_files)

    else:
        parser.print_help()