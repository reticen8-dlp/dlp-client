import queue
import sys
sys.modules["Queue"] = queue

import json
import argparse
import subprocess
import os,sys
import sqlite3
from contextlib import contextmanager
from gRPC.client import register_client, read_policy
from cryptography.fernet import Fernet
import grpc
import runpy

# print(Fernet.generate_key())
KEY = b'Y0jXXrE803umfYOW4mqOpWRUeaHPRMeIeNDTnMFcZ8I=' 
cipher_suite = Fernet(KEY)


def run_script(script_path, new_args):
    # import multiprocessing
    # multiprocessing.freeze_support()
    original_argv = sys.argv[:]
    sys.argv = new_args
    try:
        runpy.run_path(script_path, run_name="__main__")
    except Exception as e:
        print(f"Error running script {script_path}: {e}")
    finally:
        sys.argv = original_argv

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller temporary folder
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

DB_PATH= resource_path("Proprium_dlp.db")


def get_policy():
    policy ={}
    """Fetch policy from the server."""
    client_id,_ = register_client()
    if client_id:
        policy = read_policy(client_id)
    else:
        print("Failed to register client or fetch policy.")
    return policy    

def create_store_policy():
    policy = get_policy()
    
    policy_str = json.dumps(policy)
    
    encrypted_policy = cipher_suite.encrypt(policy_str.encode('utf-8'))
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS policy(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        if policy:
            cursor = conn.cursor()
            try:
                # Store the encrypted policy (as a string) in the database.
                cursor.execute("INSERT INTO policy (policy) VALUES (?)", (encrypted_policy.decode('utf-8'),))
                conn.commit()
            except sqlite3.Error as e:
                print(f"Database error while storing data: {e}")

def fetch_decrypted_policy():
    create_store_policy()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT policy FROM policy ORDER BY timestamp DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            encrypted_policy = row[0]
            try:
                # Decrypt the stored policy.
                decrypted_policy_bytes = cipher_suite.decrypt(encrypted_policy.encode('utf-8'))
                decrypted_policy_str = decrypted_policy_bytes.decode('utf-8')
                # Convert the JSON string back to a Python object.
                policy_data = json.loads(decrypted_policy_str)
                return policy_data
            except Exception as e:
                print(f"Error during decryption: {e}")
                return None
        else:
            print("No policy found.")
            return None

print("start")              
POLICY = fetch_decrypted_policy()
# print(f"Policy: {POLICY}")
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

def store_patterns(policies=POLICY):
    keyword_dict = {}
    regex_dict = {}
    
    # Iterate over the policies
    for policy in policies:
        patterns = policy["patterns"]
        
        for pattern in patterns:
            pattern_name = pattern["name"]  # Use the pattern name as the key
            
            if "keywords" in pattern["type"]:
                keyword_dict[pattern_name] = pattern["type"]["keywords"]
            
            if "regex" in pattern["type"]:
                regex_dict[pattern_name] = pattern["type"]["regex"]
    
    result = {
        "keywords": keyword_dict,
        "regex": regex_dict
    }
    
    return result



PATTERNS = store_patterns()
with open('policies.json', 'w') as f:
    json.dump(POLICY, f)
# print(f" in policy : {POLICY} paterns are {PATTERNS}")


if __name__ == "__main__":
    import sys
    # Remove extra arguments injected by PyInstaller
    # sys.argv = [arg for arg in sys.argv if not (arg.startswith("parent_pid=") or arg.startswith("pipe_handle="))]

    # import multiprocessing
    # multiprocessing.freeze_support()
    # if sys.platform == "win32":
    #     # multiprocessing.freeze_support()
    #     multiprocessing.set_start_method('spawn', force=True)
        
    parser = argparse.ArgumentParser(description="Optimized DLP Fingerprinting System")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Top-level subcommands
    parser_disk_control = subparsers.add_parser("disk-control", help="manage disks")
    parser_filesystem = subparsers.add_parser("filesystem", help="manage filesystem")
    parser_clipboard = subparsers.add_parser("clipboard", help="Build fingerprint index")
    parser_sensitive_files = subparsers.add_parser("sensitive_files", help="manage sensitive files")

    # Filesystem subcommands
    fs_subparsers = parser_filesystem.add_subparsers(dest="index_command", required=True)
    parser_indexing = fs_subparsers.add_parser("indexing", help="complete indexing")
    parser_indexing.add_argument("-d", "--directories", required=True, nargs='+', help="directories to scan (LIST)")
    parser_maintain = fs_subparsers.add_parser("maintain", help="maintain indexing")
    parser_maintain.add_argument("-d", "--directories", required=True, nargs='+', help="directories to scan (LIST)")

    # sf_subparsers = parser_sensitive_files.add_subparsers(dest="sensitive_command", required=True)
    # parser_monitor_files = sf_subparsers.add_parser("monitor-files", help="monitor sensitive file changes")
    # parser_enforce_permissions = sf_subparsers.add_parser("enforce-permissions", help="enforce permissions")
    # parser_scan_sensitive_files = sf_subparsers.add_parser("scan-files", help="build fingerprint index for sensitive files")
    # parser_scan_sensitive_files.add_argument("-d", "--directory", required=True, help="directory to scan")
    # parser_revoke_permissions = sf_subparsers.add_parser("revoke-permissions", help="revoke permissions on non-sensitive files")
    # parser_lock_permissions = sf_subparsers.add_parser("lock-permissions", help="lock all file permissions")

    args, unknown = parser.parse_known_args()

    if args.command == "filesystem":
        if args.index_command == "indexing":
            print(f"hello {args.directories}")
            indexing_script = resource_path(os.path.join("indexing", "indexing.py"))
            new_args = [
                indexing_script, "indexing",
                "--db_path", DB_PATH,
                "--directories", json.dumps(args.directories),
                "--patterns", json.dumps(PATTERNS)
            ]
            run_script(indexing_script, new_args)
        elif args.index_command == "maintain":
            indexing_script = resource_path(os.path.join("indexing", "indexing.py"))
            new_args = [
                indexing_script, "maintain",
                "--db_path", DB_PATH,
                "--directories", json.dumps(args.directories),
                "--patterns", json.dumps(PATTERNS)
            ]
            run_script(indexing_script, new_args)

    elif args.command == "clipboard":
        print("Starting clipboard monitoring...")
        clipboard_script = resource_path(os.path.join("monitoring", "clipboard_monitoring.py"))
        new_args = [
            clipboard_script,
            "--patterns", json.dumps(PATTERNS),
            "--db_path", DB_PATH
        ]
        run_script(clipboard_script, new_args)

    # elif args.command == "sensitive_files":
    #     if args.sensitive_command == "scan-files":
    #         # import multiprocessing
    #         # if sys.platform == "win32":
    #         #     multiprocessing.freeze_support() 
    #         # # Set sharing strategy for multiprocessing
    #         # multiprocessing.set_start_method('spawn', force=True)
    #         from sensitivepermissions.file_fingerprinting import EnhancedFingerprinter
    #         fingerprinter = EnhancedFingerprinter(DB_PATH)  
    #         print("............")  
    #         # directory = json.loads(args.folder)
    #         fingerprinter.build_index(args.directory, DB_PATH) 
    #         # print(f"Scanning sensitive files in {args.directory}")
    #         # fingerprint_script = resource_path(os.path.join("sensitivepermissions", "file_fingerprinting.py"))
    #         # new_args = [
    #         #     fingerprint_script, "build",
    #         #     "--folder", json.dumps(args.directory),
    #         #     "--db", DB_PATH
    #         # ]
    #         # run_script(fingerprint_script, new_args)
    #     elif args.sensitive_command == "monitor-files":
    #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
    #         new_args = [monitor_script, "--monitor"]
    #         run_script(monitor_script, new_args)
    #     elif args.sensitive_command == "enforce-permissions":
    #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
    #         sensitive_folder, _ = store_senstive_files()
    #         new_args = [monitor_script, "--enforce"] + sensitive_folder
    #         run_script(monitor_script, new_args)
    #     elif args.sensitive_command == "lock-permissions":
    #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
    #         sensitive_folder, _ = store_senstive_files()
    #         new_args = [monitor_script, "--lock"] + sensitive_folder
    #         run_script(monitor_script, new_args)
    #     elif args.sensitive_command == "revoke-permissions":
    #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
    #         revoke_files = revoke_file_paths()
    #         print(revoke_files)
    #         new_args = [monitor_script, "--revoke"] + revoke_files
    #         run_script(monitor_script, new_args)

    # elif args.command == "disk-control":
    #     # For non-Python executables, use subprocess
    #     disk_Control_script = resource_path(os.path.join("diskcontrol", "DiskControl.exe"))
    #     try:
    #         import subprocess
    #         result = subprocess.run(disk_Control_script, capture_output=True, text=True)
    #         print(result.stdout)
    #     except Exception as e:
    #         print(f"Error running disk-control: {e}")


# pyinstaller --clean --onefile --debug=all --add-data "diskcontrol;diskcontrol" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="DLP_Client_ind" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" policy.py

# pyinstaller --clean --onefile --add-data "diskcontrol;diskcontrol" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="DLP_Client_clip" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --hidden-import="pyperclip" --hidden-import="win32clipboard" --hidden-import="uuid" --hidden-import="winreg" --hidden-import="ctypes" --hidden-import="ctypes.wintypes" --hidden-import="difflib" --hidden-import="win10toast" --hidden-import="win32con" --hidden-import="win32api" --hidden-import="win32gui" --hidden-import="threading" --hidden-import="datetime" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" --collect-all "pyperclip" --collect-all "win10toast" policy.py

# pyinstaller --clean --onefile --add-data "diskcontrol;diskcontrol" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="DLP_Client_permissions1" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --hidden-import="pyperclip" --hidden-import="win32clipboard" --hidden-import="uuid" --hidden-import="winreg" --hidden-import="ctypes" --hidden-import="ctypes.wintypes" --hidden-import="difflib" --hidden-import="win10toast" --hidden-import="win32con" --hidden-import="win32api" --hidden-import="win32gui" --hidden-import="threading" --hidden-import="datetime" --hidden-import="time" --hidden-import="mss" --hidden-import="mss.tools" --hidden-import="pygetwindow" --hidden-import="pathlib" --hidden-import="multiprocessing" --hidden-import="itertools" --hidden-import="contextlib" --hidden-import="numpy.linalg" --hidden-import="re" --hidden-import="subprocess" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" --collect-all "pyperclip" --collect-all "multiprocessing" --collect-all "win10toast" --collect-all "numpy" policy.py