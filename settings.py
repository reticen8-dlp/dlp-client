import os

BASE_DIR = r"C:\Users\Ravi Sangwan\Dropbox\My PC (DESKTOP-BNB4CVI)\Desktop\ENFORCEMENT\filnal"
PATTERNS_JSON_PATH = os.path.join(BASE_DIR, "patterns.json")

patterns_to_search = ["email", "password"]  # Your required patterns
SENSITIVE_FILES_DIR = os.path.join(BASE_DIR, "sensitivefiles")

INDEXING_DATABASE = r"C:\Users\Ravi Sangwan\Dropbox\My PC (DESKTOP-BNB4CVI)\Desktop\ENFORCEMENT\filnal\file_index.db"
FILE_CHANGES_DATABASE = "file_changes.db"
INDEXING_DIRECTORIES = r"C:\Users\Ravi Sangwan\Dropbox\My PC (DESKTOP-BNB4CVI)\Desktop\OFFICE\New folder"
patterns_to_search = ["email", "password"]
MONITORED_DIRECTORIES = ["D:\\", "E:\\", r"C:\Users\Ravi Sangwan\Dropbox\My PC (DESKTOP-BNB4CVI)\Desktop\OFFICE\New folder"]
POWERSHELL_SCRIPT_PATH = os.path.join(BASE_DIR, "file_protect.ps1")
patterns_file_path =r"C:\Users\Ravi Sangwan\Dropbox\My PC (DESKTOP-BNB4CVI)\Desktop\ENFORCEMENT\filnal\patterns.json"