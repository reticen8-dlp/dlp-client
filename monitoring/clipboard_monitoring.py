import re
import time
import pyperclip
import win32clipboard 
import json
import uuid
import winreg
import ctypes
import subprocess
import threading
import json, sys
import sqlite3
from typing import List, Dict
import difflib
from difflib import SequenceMatcher
from win10toast import ToastNotifier
import time
from contextlib import contextmanager
import argparse
import ctypes
import ctypes.wintypes
from ctypes import windll, byref, Structure, POINTER, WINFUNCTYPE
from ctypes.wintypes import DWORD, HWND, UINT, WPARAM, LPARAM, BOOL
import win32api
import win32con
import win32gui
import win32gui_struct
# import pywintypes
from datetime import datetime
import sys,os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from screencapturing.capturingfast import EnhancedDLPMonitor

from gRPC.client import register_client
from gRPC.logger import send_log

CLSCTX_ALL = 0x00000001 + 0x00000002 + 0x00000004

def log_message(level,message):
    if os.path.exists("client_id.txt"):
        with open("client_id.txt", "r") as file:
            client_id = file.read().strip()
    else:
        client_id,_ = register_client()    
    os.system(f'echo "Here at client {client_id}" >> logfile.txt')            
    if client_id:
        send_log(client_id, "agent-008",level, message)  
                        
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS  # PyInstaller temporary folder
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

DELETE_CLIPBOARD_ITEM =resource_path(os.path.join("monitoring", "delete_clipboard_item.ps1")) 

GET_CLIPBOARD_ITEM = resource_path(os.path.join("monitoring", "get_clipboard_history.ps1"))

def show_notification(title, message):

    try:
        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=1, threaded=True)
        return
    except Exception as e:
        print(f"win10toast notification failed: {e}")


    """Display a Windows notification in the system tray"""
    # Define balloon tip icons
    NIIF_INFO = 0x00000001
    NIIF_WARNING = 0x00000002
    
    # Try to find an existing notification window to reuse
    hwnd = win32gui.FindWindow(None, "Reticen8-DLP")
    if not hwnd:
        # Create a window for notifications
        wc = win32gui.WNDCLASS()
        wc.lpszClassName = "NotificationWindow"
        wc.lpfnWndProc = lambda *args: None
        wc.hInstance = win32api.GetModuleHandle(None)
        wc.hIcon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
        wc.hCursor = win32gui.LoadCursor(0, win32con.IDC_ARROW)
        wc.hbrBackground = win32con.COLOR_WINDOW
        
        try:
            class_atom = win32gui.RegisterClass(wc)
            hwnd = win32gui.CreateWindow(
                class_atom, "Reticen8-DLP", 0, 0, 0, 
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



def detect_sensitive_data(text, PATTERNS):
    detected = {}
    
    try:
        print("PATTERNS keywords:", PATTERNS["keywords"],PATTERNS["regex"])
        print("Text being analyzed:", text)
        
        # Search using regex patterns
        if isinstance(PATTERNS, dict) and "regex" in PATTERNS and "keywords" in PATTERNS:
            # Search using regex patterns
            if isinstance(PATTERNS["regex"], dict):
                for category, pattern_list in PATTERNS["regex"].items():
                    if isinstance(pattern_list, list):
                        for pattern in pattern_list:
                            if isinstance(pattern, str):  # Ensure the pattern is a string
                                matches = re.findall(pattern, text)
                                if matches:
                                    detected[category] = matches
                    elif isinstance(pattern_list, str):  # Handle case where pattern is a single string
                        matches = re.findall(pattern_list, text)
                        if matches:
                            detected[category] = matches
            
            # Search for keyword matches
            if isinstance(PATTERNS["keywords"], dict):
                for category, keywords in PATTERNS["keywords"].items():
                    if isinstance(keywords, list):  # Ensure keywords is a list
                        keyword_matches = [kw for kw in keywords if kw in text]
                        if keyword_matches:
                            detected[category] = detected.get(category, []) + keyword_matches
        print(f"detected: {detected}")
        os.system(f'echo "Here at detected: {detected}" >> logfile.txt')
        # result = subprocess.run([sys.executable , "sensitivepermissions/file_fingerprinting.py","scan","--text",text,"--db","Proprium_dlp.db"], capture_output=True, text=True, encoding="utf-8")
        # output = result.stdout
    #     print("scaning files")
    #     result = scan_data.scan_file(text,DATA)
    #     output = result
    #     print(f"output: {output}")
    #         # Parse the output and check conditi
    #     for match in output:
    #         if match['direct-match'] or match['direct_match_percentage'] > 50 or match['partial_similarity'] > 50:
    #             detected['direct_match'] = True
    #             break
            
    #     print(f"detected: {detected}")
            
            
    except Exception as e:
        print(f"Error in detecting: {e}")
    
    return detected


class scan_sesnitive_data:
    def __init__(self,db_path):
        self.db_path = db_path

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
        
    def normalize_text(self, text: str) -> str:
        return re.sub(r'[\s\W_]+', '', text.lower())
    
    def direct_match_percentage(self,str1: str, str2: str) -> float:
     
        i, j = 0,0 # Pointers for str1 and str2
        while i < len(str1) and j < len(str2):
            if str1[i] == str2[j]:  # If chars match, move str2 pointer
                j += 1
               
            i += 1  # Always move str1 pointer
        
        match_percentage = (j / len(str1)) * 100 
        return match_percentage

    def compute_difflib_ratio(self, text1: str, text2: str):
        matcher = difflib.SequenceMatcher(None, text1, text2)
        diff_sim = difflib.SequenceMatcher(None, text1, text2).ratio()

        matching_blocks = matcher.get_matching_blocks()
    
        # Sum up the lengths of the matching blocks
        match_length = sum(block.size for block in matching_blocks)
        
        # Calculate the percentage of str1 that is found in str2
        match_percentage = (match_length / len(text1)) * 100 if len(text2) > 0 else 0
        return match_percentage ,diff_sim

    def load_index(self,db_path: str) -> None:
        index_data = {}
        with self.get_db_connection(db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT path, normalized_text FROM file_Fingerprint")
                for path, normalized in cursor.fetchall():
                    index_data[path] = normalized
            except sqlite3.Error as e:
                print(f"Database error while fetching data: {e}")
        return index_data

    def scan_file(self, text, index_data) -> List[Dict]:
        if not index_data:
            print("No index data loaded. Call load_index() first.")
            return []
        print("in function")

        normalized_input = self.normalize_text(text)

        matches = []
        print("ready for loops")
        for file_path, file_data in index_data.items():
            print("lets start")
            file_norm = file_data
            # Direct substring check
            direct_match = normalized_input in file_norm
            if direct_match:
                print("______++++++TRUE++++_______")
            direct_match_percentage = self.direct_match_percentage(normalized_input, file_norm)
            match_percent,diff_sim = self.compute_difflib_ratio(normalized_input, file_norm)
            matches.append({

                'file_path': file_path,
                'direct-match' : direct_match,
                'direct_match_percentage': direct_match_percentage,
                'partial_similarity': match_percent,
               
            })
        
        return sorted(matches, key=lambda x: x['partial_similarity'], reverse=True)

class Clipboard():
    def __init__(self, PATTERNS):
        self.Patterns = PATTERNS

    def overwrite_and_clear_clipboard(self):
        try:
            # Use pyperclip instead of direct win32clipboard to avoid WNDPROC errors
            pyperclip.copy("CLEARED")  # Overwrite with non-sensitive data
            pyperclip.copy("")  # Clear clipboard
            show_notification("Clipboard Cleared", "Sensitive data removed permanently!")
            
        except Exception as e:
            print("Error clearing clipboard:", e)

    def monitor_clipboard_content(self):
        last_clipboard_data = ""
        while True:
            try:
                # Check current clipboard content
                try:
                    clipboard_content = pyperclip.paste()
                except:
                    clipboard_content = ""
                    print("Error accessing clipboard")
                with open("logfile.txt", 'a') as f:
                    f.write(f"Here at content :{clipboard_content}\n")
                if clipboard_content:
                    log_message( level="INFO",message= f"copied content: {clipboard_content}")
                    # print(f"Clipboard content: {clipboard_content}")
                    last_clipboard_data = clipboard_content
                    
                    # Check for sensitive data in current clipboard
                    current_time =time.time()
                    print(f"content: {clipboard_content}")
                    # print(f"detecting sensitive data: {detect_sensitive_data(clipboard_content))}")
                    detected = detect_sensitive_data(clipboard_content,self.Patterns)
                    with open("logfile.txt", 'a') as f:
                        f.write(f"Here at detection :{detected}\n")
                    if detected:
                        with open("logfile.txt", 'a') as f:
                            f.write(f"Here at :cleared\n")
                        self.overwrite_and_clear_clipboard()
                        log_message(level="WARNING",message=f"sensitive data is present in: {clipboard_content} detected data: {str(detected)}")
                        # screen_monitor = EnhancedDLPMonitor()    
                        # print(f"-------Time Sensitive data detected: {time.time()-current_time} {detected}")
                        # image_path = screen_monitor.save_evidence("clipboard")
                        # print(f"Image path: {image_path}")
                        
                time.sleep(1)
            
            except Exception as e:
                print(f"Error in main loop: {e}")
                time.sleep(2)


class clipboardHistory:
    def __init__(self, PATTERNS):
        # Start a persistent PowerShell process that stays open.
        # Using "-Command -" tells PowerShell to run interactively.
        self.process = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "-"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1  # line-buffered
        )
        # Lock to avoid concurrent access to the process's pipes.
        self.lock = threading.Lock()
        self.Patterns = PATTERNS

    def _send_command(self, command):
        with self.lock:
            # Write the command with a unique end marker.
            end_marker = "<<<END_OF_COMMAND>>>"
            self.process.stdin.write(command + f"\nWrite-Output '{end_marker}'\n")
            self.process.stdin.flush()

            # Read lines until we see the marker.
            output_lines = []
            while True:
                line = self.process.stdout.readline()
                if not line:
                    break  # Process closed unexpectedly.
                if end_marker in line:
                    break
                output_lines.append(line)
            return "".join(output_lines)
        
    def get_clipboard_history(self):
        # Build the command to run your GetClipboardItem PowerShell script.
        command = f"& '{GET_CLIPBOARD_ITEM}'"
        output = self._send_command(command)
        try:
            return json.loads(output)
        except json.JSONDecodeError as e:
            raise Exception(f"JSON decode error: {e}\nOutput was: {output}")


    def delete_clipboard_item(self, item_id):
        # Build the command to run your DeleteClipboardItem script with parameter.
        command = f"& '{DELETE_CLIPBOARD_ITEM}' -ItemId '{item_id}'"
        output = self._send_command(command)
        return output

    def close(self):
        with self.lock:
            self.process.stdin.write("exit\n")
            self.process.stdin.flush()
            self.process.wait()


    def monitor_clipboard_for_sensitive_data(self, interval=2):
        print(f"Starting clipboard history monitoring (checking every {interval} seconds)")
        
        while True:
            try:
                history_items = self.get_clipboard_history()
                if len(history_items) <= 1:
                    print("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
                    dummy_text = " "
                    win32clipboard.OpenClipboard()
                    win32clipboard.EmptyClipboard()  # Clears the clipboard before setting new text
                    win32clipboard.SetClipboardText(dummy_text)
                    win32clipboard.CloseClipboard()
                    history_items = self.get_clipboard_history()  # Refresh history  
 
                removed_count = 0
                
                for item in history_items:
                    if 'Text' in item and item['Text']:
                        detected = detect_sensitive_data(item['Text'],self.Patterns)
                        if detected:
                            # screen_monitor = EnhancedDLPMonitor()
                            # Found sensitive data, remove the item
                            # print(f"Found sensitive data: {', '.join(detected.keys())}")
                            # image_path = screen_monitor.save_evidence("clipboard")
                            # print(f"Image path: {image_path}")
                            if self.delete_clipboard_item(item['Id']):
                                removed_count += 1
                                show_notification("Sensitive Data Removed from history", 
                                              f"Removed clipboard item with {', '.join(detected.keys())}")
                            else:
                                print(f"Failed to remove item with ID {item['Id']}")
                
                if removed_count > 0:
                    print(f"Removed {removed_count} clipboard history items with sensitive data")
                    show_notification("Clipboard Cleanup history", f"Removed {removed_count} items with sensitive data")
                
                # Sleep before checking again
                time.sleep(interval)
                
            except Exception as e:
                print(f"Error monitoring clipboard: {e}")
                time.sleep(interval)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Monitor clipboard for sensitive data')
    parser.add_argument('-p', '--patterns',required=True , help='patterns to detect')
    parser.add_argument("-db","--db_path",default="Proprium_dlp.db",help='db where scanned data is stored')
    # PATTERNS = { 
    # "keywords": { 
    #     "email": ["gmail", "yahoo", "hotmail"], 
    #     "credit-card": ["visa", "mastercard", "amex"] 
    # }, 
    # "regex": { 
    #     "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 
    #     "credit-card": r"\b\d{4}-\d{4}-\d{4}-\d{4}\b" 
    # } 
    # }
    # db_path = "Proprium_dlp.db"
    args = parser.parse_args()
    PATTERNS = json.loads(args.patterns)
    db_path = args.db_path
    log_message( level="INFO",message=f"data patterns: {PATTERNS}")
    os.system(f'echo "Here at {PATTERNS}  {db_path}" >> logfile.txt')
    print(f"Patterns: {PATTERNS}")
    # scan_data = scan_sesnitive_data(db_path)
    # DATA = scan_data.load_index(db_path)
    # print(data)
    clipboard = Clipboard()
    clipboard_history = clipboardHistory()
    clipboard_thread = threading.Thread(target=clipboard.monitor_clipboard_content)
    history_thread = threading.Thread(target=clipboard_history.monitor_clipboard_for_sensitive_data)

    clipboard_thread.start()
    history_thread.start()

    clipboard_thread.join()
    history_thread.join()




