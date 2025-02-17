import sqlite3
import shutil
import os

def fetch_sensitive_files(db_path: str) -> list:
    """Fetch paths of files with sensitive data from the database."""
    sensitive_files = []
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT path FROM files WHERE has_sensitive_data = 1")
            sensitive_files = [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    
    return sensitive_files

def copy_files_to_directory(file_paths: list, target_directory: str) -> None:
    """Copy files to the target directory."""
    if not os.path.exists(target_directory):
        os.makedirs(target_directory)
    
    for file_path in file_paths:
        try:
            if os.path.exists(file_path):
                shutil.copy(file_path, target_directory)
                print(f"Copied: {file_path}")
            else:
                print(f"File not found: {file_path}")
        except Exception as e:
            print(f"Error copying {file_path}: {e}")

def main():
    db_path = "file_index.db"
    target_directory = r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\sensitivefiles"
    
    # Fetch sensitive files
    sensitive_files = fetch_sensitive_files(db_path)
    
    if sensitive_files:
        print(f"Found {len(sensitive_files)} sensitive files. Copying to {target_directory}...")
        copy_files_to_directory(sensitive_files, target_directory)
    else:
        print("No sensitive files found.")

if __name__ == "__main__":
    main()
