# make dir. for sensitive files and copy them to that dir based on patterns

import sqlite3
import shutil
import os
import json
from settings import patterns_to_search, PATTERNS_JSON_PATH  



def fetch_sensitive_files(db_path: str, patterns: list) -> list:
    """Fetch paths of files with sensitive data that match specified patterns."""
    sensitive_files = []
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Construct SQL query with multiple patterns
            placeholders = ', '.join(['?'] * len(patterns))
            query = f"""
                SELECT path FROM files 
                WHERE has_sensitive_data = 1 
                AND patterns IN ({placeholders})
            """
            
            cursor.execute(query, patterns)
            sensitive_files = [row[0] for row in cursor.fetchall()]
    
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    
    return sensitive_files

# Load patterns from JSON file using the full path from settings
try:
    with open(PATTERNS_JSON_PATH, "r") as f:
        patterns_dict = json.load(f)
except FileNotFoundError:
    print(f"Error: The file {PATTERNS_JSON_PATH} was not found.")
    exit(1)

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

# def main():
#     db_path = "file_index.db"
#     target_directory = r"C:\Users\Ravi Sangwan\Dropbox\My PC (DESKTOP-BNB4CVI)\Desktop\ENFORCEMENT\filnal\sensitivefiles"
    
#     # Fetch sensitive files
#     sensitive_files = fetch_sensitive_files(db_path,patterns_to_search)
    
#     if sensitive_files:
#         print(f"Found {len(sensitive_files)} sensitive files. Copying to {target_directory}...")
#         copy_files_to_directory(sensitive_files, target_directory)
#     else:
#         print("No sensitive files found.")

# if __name__ == "__main__":
#     main()
