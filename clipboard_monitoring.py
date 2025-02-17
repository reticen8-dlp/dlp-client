import re
import time
import pyperclip
import win32clipboard
import json
import uuid
import winreg
import ctypes
from settings import PATTERNS_JSON_PATH

from notification import show_notification
# ✅ Sensitive Data Patterns
# Load sensitive data patterns from JSON file
with open(PATTERNS_JSON_PATH, 'r') as file:
    SENSITIVE_PATTERNS = json.load(file)

# ✅ Function to check for sensitive data
def detect_sensitive_data(text):
    detected = {}
    for category, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            detected[category] = matches
    return detected

# ✅ Function to overwrite clipboard before clearing
def overwrite_and_clear_clipboard():
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText("CLEARED")  # Overwrite with non-sensitive data
        win32clipboard.EmptyClipboard()
        win32clipboard.CloseClipboard()
        show_notification("Clipboard Cleared", "Sensitive data removed permanently!")
    except Exception as e:
        print("Error clearing clipboard:", e)

# ✅ Function to completely disable clipboard history & prevent re-enabling
def disable_clipboard_history_permanently():
    try:
        # Disable Clipboard History
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "EnableClipboardHistory", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        # Prevent Users from Turning it Back On (Lock UI)
        policy_key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\System")
        winreg.SetValueEx(policy_key, "AllowClipboardHistory", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(policy_key)

        # Force Windows to Apply Policy
        ctypes.windll.user32.SystemParametersInfoW(0, 0, None, 0x01)
        
        show_notification("Security Update", "Clipboard history permanently disabled!")
    except Exception as e:
        print("Failed to disable clipboard history:", e)



def enable_clipboard_history():
    try:
        # Enable Clipboard History in User Settings
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Clipboard")
        winreg.SetValueEx(key, "EnableClipboardHistory", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        # Remove Restriction from Group Policy
        policy_key_path = r"SOFTWARE\Policies\Microsoft\Windows\System"
        try:
            policy_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, policy_key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(policy_key, "AllowClipboardHistory")  # Remove the restriction
            winreg.CloseKey(policy_key)
        except FileNotFoundError:
            print("[INFO] Policy key not found, may already be removed.")

        # Force Windows to Apply Policy
        ctypes.windll.user32.SystemParametersInfoW(0, 0, None, 0x01)

        print("[INFO] Clipboard history has been enabled. Restart may be required.")
    except Exception as e:
        print("[ERROR] Failed to enable clipboard history:", e)

# ✅ Function to monitor clipboard
def monitor_clipboard():
    last_clipboard_data = ""

    while True:
        try:
            clipboard_content = pyperclip.paste()
            if clipboard_content != last_clipboard_data:
                last_clipboard_data = clipboard_content

                # ✅ Detect sensitive data
                detected = detect_sensitive_data(clipboard_content)
                if detected:
                    alert_message = f"Sensitive data detected: {json.dumps(detected, indent=2)}"
                    show_notification("Security Alert", alert_message)
                    
                    # ✅ Overwrite clipboard to prevent leaks
                    overwrite_and_clear_clipboard()

            time.sleep(1)
        except Exception as e:
            print("Error:", e)
            time.sleep(2)

# ✅ Apply security measures
# run the script with administrator privilages to disable clipboard history (win+V)

# ✅ Re-enable clipboard history
# enable_clipboard_history()

#it clipboard is still not visible  try : 
    #Restart Explorer (Optional)
        # Press Ctrl + Shift + Esc to open Task Manager.
        # Find Windows Explorer, right-click, and select Restart.
# ✅ Start monitoring clipboard
if __name__ == "__main__":
    monitor_clipboard()
    disable_clipboard_history_permanently()

    # enable_clipboard_history()