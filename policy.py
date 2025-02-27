import json
import argparse
import subprocess
import os,sys
import sqlite3
from contextlib import contextmanager

DB_PATH= "Proprium_dlp.db"
# for monitor or indexing----
DIRECTORIES = [r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\sensitivefiles"]
# where to store sensitive files
SENSITIVE_FOLDER = r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\sensitivefiles"

FILE_TYPES = [".txt"]

POLICY = {"policy_id": "2ec6695b-d83d-43e9-8a6b-8c081751f1f1",
"name": "TEST POL",
"description": "test policy deemasc",
"status": "Active",
"severity": "High",
"pattern": [
        {"id": "1", "name": "keyword", "type": "key-email", "input": "gmail,yahoo,hotmail"},
        {"id": "2", "name": "keyword", "type": "key-credit-card", "input": "visa,mastercard,amex,password"},
        {"id": "3", "name": "regex", "type": "email", "input": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"},
        {"id": "4", "name": "regex", "type": "credit-card", "input": r"\b\d{4}-\d{4}-\d{4}-\d{4}\b"}
    ],
"file": [{"id": "None", "name": None, "type": None, "size": None, "age": None
    }],
"action": {"channel_action": {"network_channels": {"Email": {"action": "", "included": [], "excluded": []
                }, "FTP": {"action": "", "included": [], "excluded": []
                }, "HTTP/S": {"action": "", "included": [], "excluded": []
                }, "Chat": {"action": "Always Permitted", "included": [], "excluded": []
                }, "Plaintext": {"action": "Always Permitted", "included": [], "excluded": []
                }
            }, "endpoint_channels": {"Apps": {"action": "", "included": [], "excluded": []
                }, " a": {"action": "", "included": [], "excluded": []
                }, "Directories": {"action": "", "included": [], "excluded": []
                }, "LAN": {"action": "", "included": [], "excluded": []
                }, "Printing": {"action": "", "included": [], "excluded": []
                }
            }
        }
    }
}
def create_sensitive_table():
    """Initialize SQLite database with optimized schema"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS sensitive_folder(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE
            );
        ''')
        conn.commit()


@contextmanager
def get_db_connection(self, db_path: str = "Proprium_dlp.db"): 
        """Database connection context manager with proper initialization""" 
        conn = sqlite3.connect(db_path) 
        conn.execute('PRAGMA journal_mode=WAL') 
        conn.execute('PRAGMA synchronous=NORMAL') 
    
        try: 
            yield conn 
        except Exception as e: 
            conn.rollback() 
            raise 
        else: 
            conn.commit() 
        finally: 
            conn.close()

def store_senstive_files(policy=POLICY):
    create_sensitive_table()
    patterns = policy["pattern"] 
    files = policy['file']
    sensitive_filepaths=[]
    pattern_type = [pattern["type"] for pattern in patterns]
    file_name = [file["name"] for file in files]
    file_type = [file["type"] for file in files]

    with get_db_connection(DB_PATH) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT path, patterns FROM files""")
                files_data= cursor.fetchall() 
                for path,file_pattern in files_data:
                    patterns_list = [pattern.strip() for pattern in file_pattern.split(',')] if file_pattern else []
                    name, ext = os.path.splitext(os.path.basename(path))

                    for pattern in patterns_list:
                        if pattern in pattern_type or name in file_name or ext in file_type:
                            sensitive_filepaths.append(path)
                        
                # return list(set(sensitive_filepaths))

                cursor.execute("""
                    SELECT path FROM sensitive_folder""")
                old_sensitive_filepaths = cursor.fetchall()

                cursor.execute("""
                DELETE FROM sensitive_folder""") 
                cursor.executemany("INSERT OR REPLACE INTO sensitive_folder (path) VALUES (?)", 
                               [(path,) for path in list(set(sensitive_filepaths))])


                return list(set(sensitive_filepaths)), [path[0] for path in old_sensitive_filepaths]
            
            except sqlite3.Error as e:
                print(f"Database error while fetching data: {e}")

def revoke_file_paths():
    sensitive_folder, old_sensitive_folder = store_senstive_files()
    revoke_file_paths = [item for item in old_sensitive_folder if item not in sensitive_folder]
    return revoke_file_paths

def store_patterns(policy=POLICY): 
    patterns = policy["pattern"] 
    keyword_dict = {} 
    regex_dict = {} 

    for pattern in patterns: 
        if pattern["name"] == "keyword": 
            keyword_dict[pattern["type"]] = pattern["input"].split(",")  # Remove extra list nesting
        if pattern["name"] == "regex": 
            regex_dict[pattern["type"]] = pattern["input"] 
     
    result = { 
        "keywords": keyword_dict, 
        "regex": regex_dict 
    } 
    return result 
    



PATTERNS = store_patterns()

# store files in sensitive folder
result = subprocess.run("python store_sensitivefiles.py", capture_output=True, text=True)




if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Optimized DLP Fingerprinting System")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Build subcommand
    parser_Disk_control = subparsers.add_parser("disk-control", help="manage disks")
    parser_filesystem = subparsers.add_parser("filesystem", help="manage filesystem")
    index_subparser = parser_filesystem.add_subparsers(dest="index_command", required=True)
    parser_indexing = index_subparser.add_parser("indexing", help="complete indexing")
    # parser_indexing.add_argument("-d", "--directories", required=True, help="directories to scan (LIST)")
    parser_maintain = index_subparser.add_parser("maintain", help="maintain indexing")
    # parser_maintain.add_argument("-d", "--directories", required=True, help="directories to scan (LIST)")

    parser_clipboard = subparsers.add_parser("clipboard", help="Build fingerprint index")

    # Sensitive Files subparser
    parser_sensitive_files = subparsers.add_parser("sensitive_files", help="manage sensitive files")
    sensitive_subparsers = parser_sensitive_files.add_subparsers(dest="sensitive_command", required=True)

    # Subcommands for sensitive files
    parser_monitor_files = sensitive_subparsers.add_parser("monitor-files", help="create delete modify or edit will be monitored in given dir. (for detecting sensitive data files) for alerts.")
    parser_enforce_permissions = sensitive_subparsers.add_parser("enforce-permissions", help="enforce # Grant read and execute permissions - Deny delete, rename, and move the file's permissions")
    parser_scan_sensitive_files = sensitive_subparsers.add_parser("scan-files", help="Build fingerprint index")
    parser_scan_sensitive_files = sensitive_subparsers.add_parser("revoke-permissions", help="revoke-permissions non sensitive files")
    parser_lock_permissions = sensitive_subparsers.add_parser("lock-permissions", help="lock # Deny all the file's permissions")
    # parser_scan_sensitive_files.add_argument("-d", "--directory", required=True, help="directory to scan")

    args = parser.parse_args()
    
    if args.command == "filesystem":
        if args.index_command == "indexing":
            command = [
                sys.executable, r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\dlp-client-main\indexing\indexing.py", "indexing",  # Run the indexing subcommand
                "--db_path", DB_PATH,  # Specify your db path
                "--directories", json.dumps(DIRECTORIES),
                "--patterns", json.dumps(PATTERNS)
            ]
            try:
                subprocess.run(command, check=True)
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")
        elif args.index_command == "maintain":
            command = [
                sys.executable, r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\dlp-client-main\indexing\indexing.py", "maintain",  # Run the indexing subcommand
                "--db_path", DB_PATH,  # Specify your db path
                "--directories", json.dumps(DIRECTORIES),
                "--patterns", json.dumps(PATTERNS)
            ]
            try:
                subprocess.run(command, check=True)
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")


    elif args.command == "clipboard":
        result = subprocess.run([sys.executable,"monitoring/clipboard_monitoring.py","--patterns",PATTERNS,"--db_path",DB_PATH], capture_output=True, text=True,encoding="utf-8")
        print(f"result output : {result.stdout}, error : {result.stderr}")


    elif args.command == "sensitive_files":
        if args.sensitive_command == "scan-files":
            result = subprocess.run([sys.executable , "sensitivepermissions/file_fingerprinting.py","build","--folder",SENSITIVE_FOLDER,"--db",DB_PATH], capture_output=True, text=True, encoding="utf-8")
            print(f"result output : {result.stdout}, error : {result.stderr}")
        elif args.sensitive_command == "monitor-files":
            result = subprocess.run("python file_monitoring.py --monitor", capture_output=True, text=True)
        elif args.sensitive_command == "enforce-permissions":
            sensitive_folder, old_sensitive_folder = store_senstive_files()
            result = subprocess.run([sys.executable, "sensitivepermissions/file_monitoring.py", "--enforce"] + sensitive_folder, capture_output=True, text=True)
            print(f" result: {result.stdout} error: {result.stderr}")
        elif args.sensitive_command == "lock-permissions":
            sensitive_folder, old_sensitive_folder = store_senstive_files()
            result = subprocess.run([sys.executable, "sensitivepermissions/file_monitoring.py", "--lock"] + sensitive_folder, capture_output=True, text=True)
            print(f" result: {result.stdout} error: {result.stderr}")    
        elif args.sensitive_command == "revoke-permissions":
            revoke_files = revoke_file_paths()
            print(revoke_files)
            result = subprocess.run([sys.executable, "sensitivepermissions/file_monitoring.py", "--revoke"] + revoke_files, capture_output=True, text=True)
            print(f" result: {result.stdout} error: {result.stderr}")

    elif args.command == "disl-control":
        result = subprocess.run(r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\dlp-client-main\diskcontrol\DiskControl.exe")


