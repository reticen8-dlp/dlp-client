import queue
import sys
sys.modules["Queue"] = queue

import json
import argparse
import subprocess
import os
import sqlite3
from contextlib import contextmanager
from gRPC.client import register_client, read_policy
from gRPC.logger import send_log
from cryptography.fernet import Fernet
import grpc
import runpy
import threading
import psutil
import time
from monitoring.clipboard_monitoring import Clipboard, clipboardHistory
# print(Fernet.generate_key())
CLIENT_ID_FILE = "client_id.txt"
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

DB_PATH= "Proprium_dlp.db"

def logmessage(level,message):
    client_id = None
    agent_id = None
    if os.path.exists(CLIENT_ID_FILE):
       with open(CLIENT_ID_FILE, "r") as file:
        lines = file.readlines()  # Read all lines
        client_id = None
        agent_id = None
        for line in lines:
            line = line.strip()
            if line.startswith("client_id="):
                client_id = line.split("=")[1]
            elif line.startswith("agent_id="):
                agent_id = line.split("=")[1]
    if client_id is None or agent_id is None:
        print("Warning: client_id or agent_id missing or incomplete in file. Registering new client.")
        client_id, agent_id = register_client()

    if client_id and agent_id:
        send_log(client_id,agent_id,level, message)  

def get_policy():
    policy ={}
    client_id = None
    agent_id = None
    """Fetch policy from the server."""
    if os.path.exists(CLIENT_ID_FILE):
       with open(CLIENT_ID_FILE, "r") as file:
        lines = file.readlines()  # Read all lines
        client_id = None
        agent_id = None
        for line in lines:
            line = line.strip()
            if line.startswith("client_id="):
                client_id = line.split("=")[1]
            elif line.startswith("agent_id="):
                agent_id = line.split("=")[1]
    if client_id is None or agent_id is None:
            print("Warning: client_id or agent_id missing or incomplete in file. Registering new client.")
       
            client_id, agent_id = register_client()    

    if client_id and agent_id:
        policy = read_policy(client_id,agent_id)
    else:
        print("Failed to register client or fetch policy.")
    return policy    


def update_policy():   
    global clipboard_thread
    prev_policy = None
    while(True): 
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS policy(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            ''')
            policy = get_policy()
            # print(f"Policy: {policy}")
            if policy:
                policy_str = json.dumps(policy)
                if policy_str != prev_policy:
                    print("Policy changed, updating...")
                    with open('Policy.json', 'w') as f:
                        json.dump(policy, f)
                        print("Policy updated")
        
                    encrypted_policy = cipher_suite.encrypt(policy_str.encode('utf-8'))
                    cursor = conn.cursor()
                    try:
                        # Store the encrypted policy (as a string) in the database.
                        cursor.execute("INSERT INTO policy (policy) VALUES (?)", (encrypted_policy.decode('utf-8'),))
                        conn.commit()
                    except sqlite3.Error as e:
                        print(f"Database error while storing data: {e}")
                    prev_policy = policy_str

                    if clipboard_thread and clipboard_thread.is_alive():
                            print("Stopping clipboard monitoring thread...")
                            clipboard_thread_running = False  # Signal the thread to stop
                            clipboard_thread.join()  # Ensure it stops

                    print("Restarting clipboard monitoring thread...")
                    clipboard_thread = threading.Thread(target=run_instance.clipboard_monitoring, daemon=True)
                    clipboard_thread.start()   

        time.sleep(3)            

def create_store_policy():    
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS policy(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        policy = get_policy()
        # print(f"Policy: {policy}")
        if policy:
            with open('Policy.json', 'w') as f:
                json.dump(policy, f)
            policy_str = json.dumps(policy)
    
            encrypted_policy = cipher_suite.encrypt(policy_str.encode('utf-8'))
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
# with open('Policy.json', 'w') as f:
#     json.dump(POLICY, f)
print(f" in policy : {POLICY}  paterns are {PATTERNS}")


def list_main_storage_locations():
    main_locations = []
    
    # Get all disk partitions (ignoring virtual and irrelevant ones)
    partitions = psutil.disk_partitions(all=False)
    for partition in partitions:
        # Each partition.mountpoint is a main storage directory
        main_locations.append(partition.mountpoint)
    
    # For Unix-like systems, ensure the root '/' is present.
    if os.name != 'nt' and "/" not in main_locations:
        main_locations.insert(0, "/")
    
    return main_locations

DIRECTORIES = list_main_storage_locations()
print(f"Directories: {DIRECTORIES}")  

class Run():
    def __init__(self, policy=fetch_decrypted_policy(),directories=DIRECTORIES):
        self.policy = policy
        self.patterns = store_patterns(policy)
        self.directories = directories
        # Process handles for indexing tasks
        self.indexing_process = None
        self.maintain_process = None

    # def clipboard_monitoring(self):
    #     logmessage("INFO", "Starting clipboard monitoring...")
    #     print("Starting clipboard monitoring...")
    #     clipboard_script = resource_path(os.path.join("monitoring", "clipboard_monitoring.py"))
    #     if not os.path.exists(clipboard_script):
    #         print(f"Error: Script {clipboard_script} not found!")
    #         logmessage("ERROR", f"Script {clipboard_script} not found!")
    #         return
    #     new_args = [
    #         sys.executable,
    #         clipboard_script,
    #         "--patterns", json.dumps(PATTERNS),
    #         "--db_path", DB_PATH
    #     ]
    #     try:
    #         process = subprocess.Popen(new_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #         stdout, stderr = process.communicate()
    #         print(f"Clipboard Monitoring Output:\n{stdout}")
            
    #         if stderr:
    #                 print(f"Error Output error: {stderr}")
            
    #     except subprocess.CalledProcessError as e:
    #         print(f"Error running disk-control: {e}")
    #         print(f"Return Code: {e.returncode}")
    #         print(f"Output: {e.output}")
    #     logmessage("INFO", "Clipboard monitoring finished or stopped.")
    def clipboard_monitoring(self):
        logmessage("INFO", "Starting clipboard monitoring...")
        print("Starting clipboard monitoring...")

        try:
            pol = fetch_decrypted_policy()
            pattern = store_patterns(pol)
            print(f"patterns {pattern}")
            clipboard = Clipboard(pattern)
            clipboard_history = clipboardHistory(pattern)

            clipboard_thread = threading.Thread(target=clipboard.monitor_clipboard_content, daemon=True)
            history_thread = threading.Thread(target=clipboard_history.monitor_clipboard_for_sensitive_data, daemon=True)

            clipboard_thread.start()
            history_thread.start()

        except Exception as e:
            logmessage("ERROR", f"Clipboard monitoring failed: {e}")
            print(f"Error: {e}")


    def Indexing(self):
        logmessage("INFO", f"Starting indexing on directories: {self.directories}")
        print(f"Starting indexing on directories: {self.directories}")
        indexing_script = resource_path(os.path.join("indexing", "indexing.py"))
        new_args = [
            sys.executable,
            indexing_script, "indexing",
            "--db_path", DB_PATH,
            "--directories", json.dumps(self.directories),
            "--patterns", json.dumps(self.patterns)
        ]
        # Launch indexing as a subprocess so that it can be terminated later
        self.indexing_process = subprocess.Popen(new_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = self.indexing_process.communicate()
        if stderr:
            logmessage("ERROR", f"Indexing Error: {stderr}")
            print(f"Indexing Error: {stderr}")

    def maintain_indexing(self):
        logmessage("INFO", "Starting maintain indexing...")
        print("Starting maintain indexing...")
        indexing_script = resource_path(os.path.join("indexing", "indexing.py"))
        new_args = [
            sys.executable,
            indexing_script, "maintain",
            "--db_path", DB_PATH,
            "--directories", json.dumps(self.directories),
            "--patterns", json.dumps(self.patterns)
        ]
        self.maintain_process = subprocess.Popen(new_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = self.maintain_process.communicate()
        if stderr:
            logmessage("ERROR", f"Maintain Indexing Error: {stderr}")
            print(f"Maintain Indexing Error: {stderr}")


    def Disk_Control(self):
        print("Starting disk protection...")
        logmessage("INFO", "Starting Disk Protection.")
        disk_Control_script = resource_path(os.path.join("Agent", "DiskControl.exe"))
        if not os.path.isfile(disk_Control_script):
            print(f"Error: {disk_Control_script} not found.")
        else:
            try:
                process = subprocess.Popen(disk_Control_script, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                if stderr:
                    print(f"Error Output: {stderr}")
            
            except subprocess.CalledProcessError as e:
                print(f"Error running disk-control: {e}")
                print(f"Return Code: {e.returncode}")
                print(f"Output: {e.output}")    

    def stop_indexing(self):
        """Terminate the indexing and maintain_indexing subprocesses if they are running."""
        if self.indexing_process and self.indexing_process.poll() is None:
            self.indexing_process.terminate()
            self.indexing_process.wait()
            print("Indexing process terminated.")
        if self.maintain_process and self.maintain_process.poll() is None:
            self.maintain_process.terminate()
            self.maintain_process.wait()
            print("Maintain indexing process terminated.")

    def restart_indexing(self):
        """Stop running indexing tasks, update directories, and re-run indexing."""
        self.stop_indexing()
        # Update directories
        self.directories = list_main_storage_locations()
        print(f"Restarting indexing with new directories: {self.directories}")
        # Run indexing and maintain_indexing in new threads
        threading.Thread(target=self.Indexing).start()
        threading.Thread(target=self.maintain_indexing).start()


def monitor_directories(run_instance, poll_interval=10):
    """
    Monitor the system storage locations and compare with the previous list.
    If a change is detected, restart the indexing functions.
    """
    previous_dirs = run_instance.directories
    while True:
        time.sleep(poll_interval)
        current_dirs = list_main_storage_locations()
        if current_dirs != previous_dirs:
            message = f"Directory change detected. Old: {previous_dirs} New: {current_dirs}"
            logmessage("INFO", message)
            print(f"Directory change detected.\nOld: {previous_dirs}\nNew: {current_dirs}")
            run_instance.restart_indexing()
            previous_dirs = current_dirs


if __name__ == "__main__":
    clipboard_thread = None
    print("Starting DLP Agent...")
    run_instance = Run()

    # Create threads for each task
    policy_thread = threading.Thread(target=update_policy, daemon=True)
    disk_thread = threading.Thread(target=run_instance.Disk_Control, daemon=True)
    clipboard_thread_running = True
    clipboard_thread = threading.Thread(target=run_instance.clipboard_monitoring, daemon=True)
    # indexing_thread = threading.Thread(target=run_instance.Indexing, daemon=True)
    # maintain_thread = threading.Thread(target=run_instance.maintain_indexing, daemon=True)
    # monitor_thread = threading.Thread(target=monitor_directories, args=(run_instance,), daemon=True)

    # Start all threads
    disk_thread.start()
    clipboard_thread.start()
    policy_thread.start()
    # indexing_thread.start()
    # maintain_thread.start()
    # monitor_thread.start()

    # Keep the main thread alive or wait for the threads (if necessary)
    try:
        disk_thread.join()
        clipboard_thread.join()
        # indexing_thread.join()
        # maintain_thread.join()
    except KeyboardInterrupt:
        print("Exiting program...")




# if __name__ == "__main__":
#     import sys
#     # Remove extra arguments injected by PyInstaller
#     # sys.argv = [arg for arg in sys.argv if not (arg.startswith("parent_pid=") or arg.startswith("pipe_handle="))]

#     # import multiprocessing
#     # multiprocessing.freeze_support()
#     # if sys.platform == "win32":
#     #     # multiprocessing.freeze_support()
#     #     multiprocessing.set_start_method('spawn', force=True)
        
#     parser = argparse.ArgumentParser(description="Optimized DLP Fingerprinting System")
#     subparsers = parser.add_subparsers(dest="command", required=True)

#     # Top-level subcommands
#     parser_disk_control = subparsers.add_parser("disk-control", help="manage disks")
#     parser_filesystem = subparsers.add_parser("filesystem", help="manage filesystem")
#     parser_clipboard = subparsers.add_parser("clipboard", help="Build fingerprint index")
#     parser_sensitive_files = subparsers.add_parser("sensitive_files", help="manage sensitive files")

#     # Filesystem subcommands
#     fs_subparsers = parser_filesystem.add_subparsers(dest="index_command", required=True)
#     parser_indexing = fs_subparsers.add_parser("indexing", help="complete indexing")
#     parser_indexing.add_argument("-d", "--directories", required=True, nargs='+', help="directories to scan (LIST)")
#     parser_maintain = fs_subparsers.add_parser("maintain", help="maintain indexing")
#     parser_maintain.add_argument("-d", "--directories", required=True, nargs='+', help="directories to scan (LIST)")

#     # sf_subparsers = parser_sensitive_files.add_subparsers(dest="sensitive_command", required=True)
#     # parser_monitor_files = sf_subparsers.add_parser("monitor-files", help="monitor sensitive file changes")
#     # parser_enforce_permissions = sf_subparsers.add_parser("enforce-permissions", help="enforce permissions")
#     # parser_scan_sensitive_files = sf_subparsers.add_parser("scan-files", help="build fingerprint index for sensitive files")
#     # parser_scan_sensitive_files.add_argument("-d", "--directory", required=True, help="directory to scan")
#     # parser_revoke_permissions = sf_subparsers.add_parser("revoke-permissions", help="revoke permissions on non-sensitive files")
#     # parser_lock_permissions = sf_subparsers.add_parser("lock-permissions", help="lock all file permissions")

#     args, unknown = parser.parse_known_args()

#     if args.command == "filesystem":
#         if args.index_command == "indexing":
#             print(f"hello {args.directories}")
#             indexing_script = resource_path(os.path.join("indexing", "indexing.py"))
#             new_args = [
#                 indexing_script, "indexing",
#                 "--db_path", DB_PATH,
#                 "--directories", json.dumps(args.directories),
#                 "--patterns", json.dumps(PATTERNS)
#             ]
#             run_script(indexing_script, new_args)
#         elif args.index_command == "maintain":
#             indexing_script = resource_path(os.path.join("indexing", "indexing.py"))
#             new_args = [
#                 indexing_script, "maintain",
#                 "--db_path", DB_PATH,
#                 "--directories", json.dumps(args.directories),
#                 "--patterns", json.dumps(PATTERNS)
#             ]
#             run_script(indexing_script, new_args)

#     elif args.command == "clipboard":
#         print("Starting clipboard monitoring...")
#         clipboard_script = resource_path(os.path.join("monitoring", "clipboard_monitoring.py"))
#         new_args = [
#             clipboard_script,
#             "--patterns", json.dumps(PATTERNS),
#             "--db_path", DB_PATH
#         ]
#         run_script(clipboard_script, new_args)

#     # elif args.command == "sensitive_files":
#     #     if args.sensitive_command == "scan-files":
#     #         # import multiprocessing
#     #         # if sys.platform == "win32":
#     #         #     multiprocessing.freeze_support() 
#     #         # # Set sharing strategy for multiprocessing
#     #         # multiprocessing.set_start_method('spawn', force=True)
#     #         from sensitivepermissions.file_fingerprinting import EnhancedFingerprinter
#     #         fingerprinter = EnhancedFingerprinter(DB_PATH)  
#     #         print("............")  
#     #         # directory = json.loads(args.folder)
#     #         fingerprinter.build_index(args.directory, DB_PATH) 
#     #         # print(f"Scanning sensitive files in {args.directory}")
#     #         # fingerprint_script = resource_path(os.path.join("sensitivepermissions", "file_fingerprinting.py"))
#     #         # new_args = [
#     #         #     fingerprint_script, "build",
#     #         #     "--folder", json.dumps(args.directory),
#     #         #     "--db", DB_PATH
#     #         # ]
#     #         # run_script(fingerprint_script, new_args)
#     #     elif args.sensitive_command == "monitor-files":
#     #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
#     #         new_args = [monitor_script, "--monitor"]
#     #         run_script(monitor_script, new_args)
#     #     elif args.sensitive_command == "enforce-permissions":
#     #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
#     #         sensitive_folder, _ = store_senstive_files()
#     #         new_args = [monitor_script, "--enforce"] + sensitive_folder
#     #         run_script(monitor_script, new_args)
#     #     elif args.sensitive_command == "lock-permissions":
#     #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
#     #         sensitive_folder, _ = store_senstive_files()
#     #         new_args = [monitor_script, "--lock"] + sensitive_folder
#     #         run_script(monitor_script, new_args)
#     #     elif args.sensitive_command == "revoke-permissions":
#     #         monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
#     #         revoke_files = revoke_file_paths()
#     #         print(revoke_files)
#     #         new_args = [monitor_script, "--revoke"] + revoke_files
#     #         run_script(monitor_script, new_args)

#     elif args.command == "disk-control":
#         # For non-Python executables, use subprocess
#         disk_Control_script = resource_path(os.path.join("Agent", "DiskControl.exe"))
#         if not os.path.isfile(disk_Control_script):
#             print(f"Error: {disk_Control_script} not found.")
#         else:
#             try:
#                 process = subprocess.Popen(disk_Control_script, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#                 stdout, stderr = process.communicate()
#                 if stderr:
#                     print(f"Error Output: {stderr}")
            
#             except subprocess.CalledProcessError as e:
#                 print(f"Error running disk-control: {e}")
#                 print(f"Return Code: {e.returncode}")
#                 print(f"Output: {e.output}")


# pyinstaller --clean --onefile --debug=all --add-data "Agent;Agent" --add-data "Policy.json;Policy.json" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="DLP_Client_ind" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="win32gui_struct" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" policy.py

# pyinstaller --clean --onefile --add-data "Agent;Agent" --add-data "gRPC/keys/server.crt;gRPC/keys" --add-data "Policy.json;Policy.json" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="Proprium-DlP" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="win32gui_struct" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --hidden-import="pyperclip" --hidden-import="win32clipboard" --hidden-import="uuid" --hidden-import="winreg" --hidden-import="ctypes" --hidden-import="ctypes.wintypes" --hidden-import="difflib" --hidden-import="win10toast" --hidden-import="win32con" --hidden-import="win32api" --hidden-import="win32gui" --hidden-import="threading" --hidden-import="datetime" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" --collect-all "pyperclip" --collect-all "win10toast" policy.py

# pyinstaller --clean --onefile --add-data "Agent;Agent" --add-data "gRPC/keys/server.crt;gRPC/keys" --add-data "Policy.json;Policy.json" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="Reticen8-DLP" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="win32gui_struct" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --hidden-import="pyperclip" --hidden-import="win32clipboard" --hidden-import="uuid" --hidden-import="winreg" --hidden-import="ctypes" --hidden-import="ctypes.wintypes" --hidden-import="difflib" --hidden-import="win10toast" --hidden-import="win32con" --hidden-import="win32api" --hidden-import="win32gui" --hidden-import="threading" --hidden-import="datetime" --hidden-import="time" --hidden-import="mss" --hidden-import="mss.tools" --hidden-import="pygetwindow" --hidden-import="pathlib" --hidden-import="multiprocessing" --hidden-import="itertools" --hidden-import="contextlib" --hidden-import="numpy.linalg" --hidden-import="win32com.client" --hidden-import="re" --hidden-import="subprocess" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" --collect-all "pyperclip" --collect-all "multiprocessing" --collect-all "win10toast" --collect-all "numpy" policy.py

# 1)policy update automatic 2) hide processes 3) hide exe and files 4) no * and C:\\ to block

#  pyinstaller --clean --onefile --add-data "Agent;Agent" --add-data "gRPC/keys/server.crt;gRPC/keys" --add-data "Policy.json;Policy.json" --add-data "gRPC;gRPC" --add-data "indexing;indexing" --add-data "monitoring;monitoring" --add-data "screencapturing;screencapturing" --add-data "sensitivepermissions;sensitivepermissions" --add-data "system;system" --add-data "uploads;uploads" --name="Reticen8-DLP" --hidden-import="grpcio" --hidden-import="grpcio-tools" --hidden-import="protobuf" --hidden-import="magic" --hidden-import="pptx" --hidden-import="pdfminer" --hidden-import="pdfminer.high_level" --hidden-import="pdf2image" --hidden-import="docx" --hidden-import="watchdog" --hidden-import="watchdog.observers" --hidden-import="watchdog.events" --hidden-import="PIL" --hidden-import="PIL.Image" --hidden-import="cv2" --hidden-import="numpy" --hidden-import="pandas" --hidden-import="sqlite3" --hidden-import="win32gui_struct" --hidden-import="queue" --hidden-import="logging" --hidden-import="tempfile" --hidden-import="json" --hidden-import="csv" --hidden-import="pyperclip" --hidden-import="win32clipboard" --hidden-import="uuid" --hidden-import="winreg" --hidden-import="ctypes" --hidden-import="ctypes.wintypes" --hidden-import="difflib" --hidden-import="win10toast" --hidden-import="win32con" --hidden-import="win32api" --hidden-import="win32gui" --hidden-import="threading" --hidden-import="datetime" --collect-all "easyocr" --collect-all "concurrent.futures" --collect-all "win32com" --collect-all "pyperclip" --collect-all "psutil" --collect-all "psutil" --collect-all "win10toast" --version-file=version_info.txt policy.py