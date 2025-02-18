import re
import time
import pyperclip
import win32clipboard
import json
import uuid
import winreg
import ctypes
import subprocess



from win10toast import ToastNotifier
import time

def show_notification(title, message):
    # Create a toast notifier instance
    toaster = ToastNotifier()

    # Show the notification
    toaster.show_toast(title, message, duration=2)

    # Delay to ensure the notification is shown before script exits
    time.sleep(2)


import tempfile,os

def detect_sensitive_data(text):
    detected = {}
    for category, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            detected[category] = matches
    try:
        exe_path = r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\dist\filefingerprinting.exe"
        index_path = r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\fingerprinting\dist\fingerprint_index.json"
        
        args = [
            exe_path,
            "scan",
            "--text", text,
            "--db", index_path
        ]
        
        result = subprocess.run(args, capture_output=True, text=True)
        
        output = result.stdout
        
        print("output",output)
        print("result",result)

            # Parse the output and check conditions
        lines = output.splitlines()
        for line in lines:
            if 'direct-match similarity: True' in line or 'Direct match found!' in line:
                detected['direct_match'] = detected.get('direct_match', []) + [line]
            elif 'partial similarity:' in line:
                # Extract the partial similarity percentage
                match = re.search(r"partial similarity:\s*([0-9.]+)%", line)
                if match:
                    similarity_percentage = float(match.group(1))
                    if similarity_percentage > 50:
                        detected['high_similarity'] = detected.get('high_similarity', []) + [line]
            
        print(f"detected: {detected}")
            
            
    except Exception as e:
        print(f"Error: {e}")
    
    return detected


def overwrite_and_clear_clipboard():
    try:
        # Use pyperclip instead of direct win32clipboard to avoid WNDPROC errors
        pyperclip.copy("CLEARED")  # Overwrite with non-sensitive data
        pyperclip.copy("")  # Clear clipboard
        show_notification("Clipboard Cleared", "Sensitive data removed permanently!")
    except Exception as e:
        print("Error clearing clipboard:", e)

def get_clipboard_history_items():
    """Get all items from the clipboard history using PowerShell"""
    try:
        # Modified PowerShell command to avoid WNDPROC errors
        ps_command = """
        # Alternative approach without using Windows.Forms
        $null = [Windows.Clipboard,Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089]

        # Get clipboard history items using ClipboardStatic class
        $historyItems = @()
        try {
            # Using ClipboardStatic
            $clipboardStatic = [Windows.Forms.ClipboardStatic]::GetHistoryItems()
            
            foreach ($item in $clipboardStatic) {
                $itemData = @{
                    'Id' = $item.Id
                    'Text' = ''
                }
                
                try {
                    # Get text if available
                    if ($item.Contains("Text")) {
                        $itemData.Text = $item.GetText()
                    }
                } catch {
                    $itemData.Text = "Unable to extract text"
                }
                
                $historyItems += $itemData
            }
        } catch {
            Write-Error "Error accessing clipboard history: $_"
        }

        # Convert to JSON
        $historyItems | ConvertTo-Json
        """
        
        # Run PowerShell with increased timeout
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30  # Increased timeout
        )
        
        # Parse JSON output
        if result.returncode == 0 and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                print(f"Error parsing JSON: {result.stdout}")
                return []
        return []
    
    except subprocess.TimeoutExpired:
        print("PowerShell command timed out")
        return []
    except Exception as e:
        print(f"Error getting clipboard history: {e}")
        return []

def remove_clipboard_history_item(item_id):
    """Remove a specific item from clipboard history by ID"""
    try:
        # Modified PowerShell command to avoid WNDPROC errors
        ps_command = f"""
        # Initialize clipboard API
        $null = [Windows.Clipboard,Windows.Forms,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b77a5c561934e089]
        
        # Remove specific history item
        try {{
            [Windows.Forms.ClipboardStatic]::RemoveHistoryItem('{item_id}')
            $true  # Return success
        }} catch {{
            Write-Error "Failed to remove clipboard history item: $_"
            $false  # Return failure
        }}
        """
        
        result = subprocess.run(
            ["powershell", "-Command", ps_command], 
            capture_output=True,
            text=True
        )
        
        return "True" in result.stdout
    
    except Exception as e:
        print(f"Error removing clipboard history item: {e}")
        return False

def check_and_clean_clipboard_history():
    """Check all clipboard history items and remove ones with sensitive data"""
    history_items = get_clipboard_history_items()
    removed_count = 0
    
    if not history_items:
        print("No clipboard history items found or unable to access clipboard history")
        return 0
    
    for item in history_items:
        if 'Text' in item and item['Text'] and item['Text'] != "Unable to extract text":
            detected = detect_sensitive_data(item['Text'])
            if detected:
                if remove_clipboard_history_item(item['Id']):
                    removed_count += 1
                    categories = list(detected.keys())
                    show_notification(
                        "Sensitive Data Removed",
                        f"Removed clipboard history item containing {', '.join(categories)}"
                    )
    
    if removed_count > 0:
        show_notification(
            "Clipboard Cleanup Complete",
            f"Removed {removed_count} history items with sensitive data"
        )
    
    return removed_count

def monitor_clipboard_with_history():
    
    while True:
        try:
            # Check current clipboard content
            try:
                clipboard_content = pyperclip.paste()
            except:
                clipboard_content = ""
                print("Error accessing clipboard")
            
            if clipboard_content :
                last_clipboard_data = clipboard_content
                
                # Check for sensitive data in current clipboard
                current_time =time.time()
                detected = detect_sensitive_data(clipboard_content)
                if detected:
                    print(f"Time Sensitive data detected: {time.time()-current_time}")
                    categories = list(detected.keys())
                    alert_message = f"Sensitive data detected: {', '.join(categories)}"
                    show_notification("Security Alert", alert_message)
                    
                    # Clear current clipboard
                    overwrite_and_clear_clipboard()
            
            # Check clipboard history periodically (every 30 seconds)
            
            check_and_clean_clipboard_history()
             
            
            time.sleep(1)
        
        except Exception as e:
            print(f"Error in main loop: {e}")
            time.sleep(2)

if __name__ == "__main__":
    # Run the monitor function
    # Load sensitive data patterns
    with open(r"C:\Users\Shreshth Graak\reticen\VIVEK\dlp\indexing\final\patterns.json", 'r') as file:
        SENSITIVE_PATTERNS = json.load(file)
    monitor_clipboard_with_history()




