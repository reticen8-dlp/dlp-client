import os
import time
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from indexing import FileSystemIndexer # Importing your existing indexer
import settings
# Define directories to monitor

# Initialize the indexer
indexer = FileSystemIndexer(settings.INDEXING_DATABASE)

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"New file detected: {file_path}")
            has_sensitive_data = indexer.process_single_file(file_path)
            print(f"File {file_path} indexed with sensitive data status: {has_sensitive_data}")
    
    def on_deleted(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"File deleted: {file_path}")
            self.remove_file_from_db(file_path)
    
    def on_moved(self, event):
        if not event.is_directory:
            old_path = event.src_path
            new_path = event.dest_path
            print(f"File moved/renamed from {old_path} to {new_path}")
            self.update_file_in_db(old_path, new_path)
    
    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            print(f"File modified: {file_path}")
            has_sensitive_data = indexer.process_single_file(file_path)
            print(f"File {file_path} re-indexed with sensitive data status: {has_sensitive_data}")
    
    def remove_file_from_db(self, file_path):
        with indexer.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM files WHERE path = ?", (file_path,))
            print(f"Removed {file_path} from database.")

    def update_file_in_db(self, old_path, new_path):
        with indexer.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE files SET path = ? WHERE path = ?", (new_path, old_path))
            print(f"Updated database: {old_path} -> {new_path}")


if __name__ == "__main__":
    event_handler = NewFileHandler()
    observer = Observer()
    MONITORED_DIRECTORIES = settings.MONITORED_DIRECTORIES
    for directory in MONITORED_DIRECTORIES:
        if os.path.exists(directory):
            observer.schedule(event_handler, directory, recursive=True)
    
    observer.start()
    print("Monitoring started for directories:", MONITORED_DIRECTORIES)
    
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
