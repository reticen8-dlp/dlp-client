import json
import os
import sqlite3
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from settings import INDEXING_DATABASE
from settings import FILE_CHANGES_DATABASE
from notification import show_notification  # Import your notification script

# Fetch monitored file paths from the database
def get_monitored_files():
    conn = sqlite3.connect(INDEXING_DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT path FROM files WHERE has_sensitive_data = 1")
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

# Database setup
DB_FILE = os.path.abspath(FILE_CHANGES_DATABASE)

def init_db():
    conn = sqlite3.connect(DB_FILE)
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
        conn = sqlite3.connect(DB_FILE)
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
    start_monitoring()
