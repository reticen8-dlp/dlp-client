import json
import argparse
import os
import sys
import sqlite3
import runpy
from contextlib import contextmanager
import concurrent.futures
import concurrent.futures._base
import concurrent.futures.thread
import concurrent.futures.process
import preload  
import altgraph
from queue import Queue


# Helper function to run a Python script in-process
def run_script(script_path, new_args):
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

DB_PATH = resource_path("Proprium_dlp.db")
# for monitor or indexing----
DIRECTORIES = [r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\sensitivefiles"]
# where to store sensitive files
SENSITIVE_FOLDER = r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\sensitivefiles"

FILE_TYPES = [".txt"]

POLICY = {
    "policy_id": "2ec6695b-d83d-43e9-8a6b-8c081751f1f1",
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
    "file": [{"id": "None", "name": None, "type": None, "size": None, "age": None}],
    "action": {
        "channel_action": {
            "network_channels": {
                "Email": {"action": "", "included": [], "excluded": []},
                "FTP": {"action": "", "included": [], "excluded": []},
                "HTTP/S": {"action": "", "included": [], "excluded": []},
                "Chat": {"action": "Always Permitted", "included": [], "excluded": []},
                "Plaintext": {"action": "Always Permitted", "included": [], "excluded": []}
            },
            "endpoint_channels": {
                "Apps": {"action": "", "included": [], "excluded": []},
                " a": {"action": "", "included": [], "excluded": []},
                "Directories": {"action": "", "included": [], "excluded": []},
                "LAN": {"action": "", "included": [], "excluded": []},
                "Printing": {"action": "", "included": [], "excluded": []}
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
def get_db_connection(dummy, db_path: str = "Proprium_dlp.db"):
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
    files = policy["file"]
    sensitive_filepaths = []
    pattern_type = [pattern["type"] for pattern in patterns]
    file_name = [file["name"] for file in files]
    file_type = [file["type"] for file in files]

    with get_db_connection(None, DB_PATH) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""SELECT path, patterns FROM files""")
            files_data = cursor.fetchall()
            for path, file_pattern in files_data:
                patterns_list = [pattern.strip() for pattern in file_pattern.split(',')] if file_pattern else []
                name, ext = os.path.splitext(os.path.basename(path))
                for pattern in patterns_list:
                    if pattern in pattern_type or name in file_name or ext in file_type:
                        sensitive_filepaths.append(path)

            cursor.execute("""SELECT path FROM sensitive_folder""")
            old_sensitive_filepaths = cursor.fetchall()

            cursor.execute("""DELETE FROM sensitive_folder""")
            cursor.executemany("INSERT OR REPLACE INTO sensitive_folder (path) VALUES (?)",
                               [(path,) for path in list(set(sensitive_filepaths))])
            return list(set(sensitive_filepaths)), [path[0] for path in old_sensitive_filepaths]
        except sqlite3.Error as e:
            print(f"Database error while fetching data: {e}")

def revoke_file_paths():
    sensitive_folder, old_sensitive_folder = store_senstive_files()
    revoke_filepaths = [item for item in old_sensitive_folder if item not in sensitive_folder]
    return revoke_filepaths

def store_patterns(policy=POLICY):
    patterns = policy["pattern"]
    keyword_dict = {}
    regex_dict = {}
    for pattern in patterns:
        if pattern["name"] == "keyword":
            keyword_dict[pattern["type"]] = pattern["input"].split(",")
        if pattern["name"] == "regex":
            regex_dict[pattern["type"]] = pattern["input"]
    return {"keywords": keyword_dict, "regex": regex_dict}

PATTERNS = store_patterns()

# Main entrypoint with argument parsing
if __name__ == "__main__":
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

    # Sensitive files subcommands
    sf_subparsers = parser_sensitive_files.add_subparsers(dest="sensitive_command", required=True)
    parser_monitor_files = sf_subparsers.add_parser("monitor-files", help="monitor sensitive file changes")
    parser_enforce_permissions = sf_subparsers.add_parser("enforce-permissions", help="enforce permissions")
    parser_scan_sensitive_files = sf_subparsers.add_parser("scan-files", help="build fingerprint index for sensitive files")
    parser_scan_sensitive_files.add_argument("-d", "--directory", required=True, help="directory to scan")
    parser_revoke_permissions = sf_subparsers.add_parser("revoke-permissions", help="revoke permissions on non-sensitive files")
    parser_lock_permissions = sf_subparsers.add_parser("lock-permissions", help="lock all file permissions")

    args = parser.parse_args()

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

    elif args.command == "sensitive_files":
        if args.sensitive_command == "scan-files":
            fingerprint_script = resource_path(os.path.join("sensitivepermissions", "file_fingerprinting.py"))
            new_args = [
                fingerprint_script, "build",
                "--folder", json.dumps(args.directory),
                "--db", DB_PATH
            ]
            run_script(fingerprint_script, new_args)
        elif args.sensitive_command == "monitor-files":
            monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
            new_args = [monitor_script, "--monitor"]
            run_script(monitor_script, new_args)
        elif args.sensitive_command == "enforce-permissions":
            monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
            sensitive_folder, _ = store_senstive_files()
            new_args = [monitor_script, "--enforce"] + sensitive_folder
            run_script(monitor_script, new_args)
        elif args.sensitive_command == "lock-permissions":
            monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
            sensitive_folder, _ = store_senstive_files()
            new_args = [monitor_script, "--lock"] + sensitive_folder
            run_script(monitor_script, new_args)
        elif args.sensitive_command == "revoke-permissions":
            monitor_script = resource_path(os.path.join("sensitivepermissions", "file_monitoring.py"))
            revoke_files = revoke_file_paths()
            print(revoke_files)
            new_args = [monitor_script, "--revoke"] + revoke_files
            run_script(monitor_script, new_args)

    elif args.command == "disk-control":
        # For non-Python executables, use subprocess
        disk_Control_script = resource_path(os.path.join("diskcontrol", "DiskControl.exe"))
        try:
            import subprocess
            result = subprocess.run(disk_Control_script, capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error running disk-control: {e}")
