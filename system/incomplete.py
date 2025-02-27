import json
import wmi
import winreg
import traceback
import time
import os
import datetime
import hashlib
from win32com.client import Dispatch
import win32gui
import win32process
import win32api
import win32con

# --- Global Constants ---
DATA_DIR = "monitoring_data"
SNAPSHOT_FILE = os.path.join(DATA_DIR, "system_snapshot.json")
CHANGES_LOG = os.path.join(DATA_DIR, "system_changes.log")
POLLING_INTERVAL = 300  # Time in seconds between checks (5 minutes)

# --- Utility Functions ---
def save_json(data, filepath):
    """Save data to a JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, indent=4, f)

def load_json(filepath):
    """Load data from a JSON file."""
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'r') as f:
        return json.load(f)

def log_change(change_type, details):
    """Log a system change to the change log file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {change_type}: {json.dumps(details)}\n"
    
    with open(CHANGES_LOG, 'a') as f:
        f.write(log_entry)

def calculate_hash(filepath):
    """Calculate SHA-256 hash of a file."""
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()
    except Exception:
        return None

# --- Hardware Information Functions ---

def get_computer_system_info():
    """Get basic computer system information."""
    c = wmi.WMI()
    info = {}
    try:
        for cs in c.Win32_ComputerSystem():
            info = {
                'Manufacturer': cs.Manufacturer,
                'Model': cs.Model,
                'Name': cs.Name,
                'TotalPhysicalMemory': cs.TotalPhysicalMemory
            }
    except Exception as e:
        info['error'] = str(e)
    return info

def get_processor_info():
    """Get processor details."""
    c = wmi.WMI()
    processors = []
    try:
        for proc in c.Win32_Processor():
            processors.append({
                'Name': proc.Name,
                'NumberOfCores': proc.NumberOfCores,
                'NumberOfLogicalProcessors': proc.NumberOfLogicalProcessors,
                'MaxClockSpeed': proc.MaxClockSpeed
            })
    except Exception as e:
        processors.append({'error': str(e)})
    return processors

def get_bios_info():
    """Get BIOS information."""
    c = wmi.WMI()
    info = {}
    try:
        for bios in c.Win32_BIOS():
            info = {
                'Manufacturer': bios.Manufacturer,
                'SerialNumber': bios.SerialNumber,
                'Version': bios.SMBIOSBIOSVersion,
                'ReleaseDate': bios.ReleaseDate
            }
    except Exception as e:
        info['error'] = str(e)
    return info

def get_os_info():
    """Get Operating System details."""
    c = wmi.WMI()
    info = {}
    try:
        for os in c.Win32_OperatingSystem():
            info = {
                'Caption': os.Caption,
                'Version': os.Version,
                'InstallDate': os.InstallDate,
                'BuildNumber': os.BuildNumber,
                'OSArchitecture': os.OSArchitecture
            }
    except Exception as e:
        info['error'] = str(e)
    return info

def get_physical_memory_info():
    """Get information about physical memory modules."""
    c = wmi.WMI()
    modules = []
    try:
        for mem in c.Win32_PhysicalMemory():
            modules.append({
                'Manufacturer': mem.Manufacturer,
                'Capacity': mem.Capacity,
                'Speed': mem.Speed,
                'PartNumber': mem.PartNumber
            })
    except Exception as e:
        modules.append({'error': str(e)})
    return modules

def get_disk_drive_info():
    """Get disk drive information."""
    c = wmi.WMI()
    disks = []
    try:
        for disk in c.Win32_DiskDrive():
            disks.append({
                'Model': disk.Model,
                'InterfaceType': disk.InterfaceType,
                'Size': disk.Size,
                'SerialNumber': getattr(disk, "SerialNumber", "N/A")
            })
    except Exception as e:
        disks.append({'error': str(e)})
    return disks

def get_usb_devices():
    """Get information about connected USB devices."""
    c = wmi.WMI()
    usb_devices = []
    try:
        for device in c.Win32_USBController():
            usb_devices.append({
                'Name': device.Name,
                'DeviceID': device.DeviceID,
                'Status': device.Status,
                'Type': 'Controller'
            })
        
        for device in c.Win32_USBHub():
            usb_devices.append({
                'Name': device.Name,
                'DeviceID': device.DeviceID,
                'Status': device.Status,
                'Type': 'Hub'
            })
            
        # Get more detailed USB device information
        for device in c.Win32_PnPEntity():
            if "USB" in device.Caption:
                usb_devices.append({
                    'Name': device.Caption,
                    'DeviceID': device.DeviceID,
                    'Status': device.Status,
                    'Type': 'Device'
                })
    except Exception as e:
        usb_devices.append({'error': str(e)})
    return usb_devices

def get_network_adapters():
    """Get information about network adapters."""
    c = wmi.WMI()
    adapters = []
    try:
        for nic in c.Win32_NetworkAdapter():
            if nic.PhysicalAdapter:
                adapters.append({
                    'Name': nic.Name,
                    'MACAddress': nic.MACAddress,
                    'AdapterType': getattr(nic, 'AdapterType', "Unknown"),
                    'Speed': getattr(nic, 'Speed', "Unknown"),
                    'ConnectionStatus': nic.NetConnectionStatus
                })
    except Exception as e:
        adapters.append({'error': str(e)})
    return adapters

def get_gpu_info():
    """Get information about graphics processors."""
    c = wmi.WMI()
    gpus = []
    try:
        for gpu in c.Win32_VideoController():
            gpus.append({
                'Name': gpu.Name,
                'DriverVersion': gpu.DriverVersion,
                'VideoProcessor': getattr(gpu, 'VideoProcessor', "Unknown"),
                'AdapterRAM': gpu.AdapterRAM if hasattr(gpu, 'AdapterRAM') else "Unknown",
                'CurrentResolution': f"{gpu.CurrentHorizontalResolution}x{gpu.CurrentVerticalResolution}" if hasattr(gpu, 'CurrentHorizontalResolution') else "Unknown"
            })
    except Exception as e:
        gpus.append({'error': str(e)})
    return gpus

# --- Software Information Functions ---

def get_installed_apps_from_reg(root, path):
    """
    Fetch installed applications from a specific registry key.
    Many applications list info in the Uninstall registry key.
    """
    apps = []
    try:
        reg_key = winreg.OpenKey(root, path)
    except FileNotFoundError:
        return apps

    num_subkeys = winreg.QueryInfoKey(reg_key)[0]
    for i in range(num_subkeys):
        try:
            subkey_name = winreg.EnumKey(reg_key, i)
            subkey_path = f"{path}\\{subkey_name}"
            subkey = winreg.OpenKey(root, subkey_path)
            app = {}
            try:
                app['DisplayName'] = winreg.QueryValueEx(subkey, 'DisplayName')[0]
            except FileNotFoundError:
                continue  # Skip entries without a DisplayName
            # Optional fields
            try:
                app['DisplayVersion'] = winreg.QueryValueEx(subkey, 'DisplayVersion')[0]
            except FileNotFoundError:
                app['DisplayVersion'] = None
            try:
                app['Publisher'] = winreg.QueryValueEx(subkey, 'Publisher')[0]
            except FileNotFoundError:
                app['Publisher'] = None
            try:
                app['InstallDate'] = winreg.QueryValueEx(subkey, 'InstallDate')[0]
            except FileNotFoundError:
                app['InstallDate'] = None
            try:
                app['InstallLocation'] = winreg.QueryValueEx(subkey, 'InstallLocation')[0]
            except FileNotFoundError:
                app['InstallLocation'] = None
            try:
                app['UninstallString'] = winreg.QueryValueEx(subkey, 'UninstallString')[0]
            except FileNotFoundError:
                app['UninstallString'] = None

            apps.append(app)
        except Exception as e:
            # Skip problematic entries
            continue
    return apps

def get_installed_applications():
    """
    Get a list of installed applications by querying both
    the 64-bit and 32-bit registry keys.
    """
    apps = []
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ]
    for root, path in registry_paths:
        apps.extend(get_installed_apps_from_reg(root, path))
    return apps

def get_running_processes():
    """Get information about currently running processes."""
    c = wmi.WMI()
    processes = []
    try:
        for process in c.Win32_Process():
            try:
                owner = process.GetOwner()
                if owner[0] is not None:
                    owner_info = f"{owner[1]}\\{owner[0]}"
                else:
                    owner_info = "SYSTEM"
            except:
                owner_info = "Unknown"
                
            processes.append({
                'Name': process.Name,
                'ProcessId': process.ProcessId,
                'ExecutablePath': process.ExecutablePath,
                'CommandLine': process.CommandLine,
                'ParentProcessId': process.ParentProcessId,
                'Owner': owner_info,
                'CreationDate': process.CreationDate
            })
    except Exception as e:
        processes.append({'error': str(e)})
    return processes

def get_active_windows():
    """Get information about currently active windows."""
    active_windows = []
    
    def enum_window_callback(hwnd, results):
        if win32gui.IsWindowVisible(hwnd):
            window_title = win32gui.GetWindowText(hwnd)
            if window_title:
                try:
                    _, process_id = win32process.GetWindowThreadProcessId(hwnd)
                    try:
                        process_handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, process_id)
                        exe_path = win32process.GetModuleFileNameEx(process_handle, 0)
                        win32api.CloseHandle(process_handle)
                    except:
                        exe_path = "Unknown"
                    
                    results.append({
                        'WindowTitle': window_title,
                        'WindowHandle': hwnd,
                        'ProcessId': process_id,
                        'ExecutablePath': exe_path
                    })
                except:
                    pass
        return True
    
    try:
        win32gui.EnumWindows(enum_window_callback, active_windows)
    except Exception as e:
        active_windows.append({'error': str(e)})
    
    return active_windows

def get_system_services():
    """Get information about system services."""
    c = wmi.WMI()
    services = []
    try:
        for service in c.Win32_Service():
            services.append({
                'Name': service.Name,
                'DisplayName': service.DisplayName,
                'StartMode': service.StartMode,
                'State': service.State,
                'PathName': service.PathName,
                'StartName': service.StartName  # The account under which the service runs
            })
    except Exception as e:
        services.append({'error': str(e)})
    return services

def get_scheduled_tasks():
    """Get information about scheduled tasks."""
    tasks = []
    try:
        scheduler = Dispatch('Schedule.Service')
        scheduler.Connect()
        
        folders = [scheduler.GetFolder('\\')]
        
        while folders:
            folder = folders.pop(0)
            for subfolder in folder.GetFolders(0):
                folders.append(subfolder)
            
            for task in folder.GetTasks(0):
                task_info = {
                    'Name': task.Name,
                    'Path': task.Path,
                    'Enabled': task.Enabled,
                    'LastRunTime': str(task.LastRunTime) if task.LastRunTime else None,
                    'NextRunTime': str(task.NextRunTime) if task.NextRunTime else None
                }
                tasks.append(task_info)
        
        return tasks
    except Exception as e:
        tasks.append({'error': str(e)})
    return tasks

def get_startup_items():
    """Get applications configured to run at startup."""
    startup_items = []
    
    # Check Run keys in registry
    registry_paths = [
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    ]
    
    for root, path in registry_paths:
        try:
            reg_key = winreg.OpenKey(root, path)
            for i in range(winreg.QueryInfoKey(reg_key)[1]):
                name, value, _ = winreg.EnumValue(reg_key, i)
                startup_items.append({
                    'Name': name,
                    'Command': value,
                    'Location': f"{path} (Registry)",
                    'Type': 'Registry'
                })
        except Exception:
            pass
    
    # Check Startup folders
    startup_folders = [
        os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ["PROGRAMDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup")
    ]
    
    for folder in startup_folders:
        if os.path.exists(folder):
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                startup_items.append({
                    'Name': item,
                    'Path': item_path,
                    'Location': folder,
                    'Type': 'Startup Folder'
                })
    
    return startup_items

def get_installed_drivers():
    """Get information about installed drivers."""
    c = wmi.WMI()
    drivers = []
    try:
        for driver in c.Win32_SystemDriver():
            drivers.append({
                'Name': driver.Name,
                'DisplayName': driver.DisplayName,
                'State': driver.State,
                'StartMode': driver.StartMode,
                'PathName': driver.PathName
            })
    except Exception as e:
        drivers.append({'error': str(e)})
    return drivers

# --- Change Detection Functions ---

def detect_hardware_changes(previous, current):
    """Detect changes in hardware configuration."""
    changes = {}
    
    # Check USB devices
    if 'USBDevices' in previous and 'USBDevices' in current:
        prev_usb_ids = {dev.get('DeviceID'): dev for dev in previous['USBDevices'] if dev.get('DeviceID')}
        curr_usb_ids = {dev.get('DeviceID'): dev for dev in current['USBDevices'] if dev.get('DeviceID')}
        
        new_usbs = [curr_usb_ids[id] for id in set(curr_usb_ids) - set(prev_usb_ids)]
        removed_usbs = [prev_usb_ids[id] for id in set(prev_usb_ids) - set(curr_usb_ids)]
        
        if new_usbs or removed_usbs:
            changes['USBDevices'] = {
                'added': new_usbs,
                'removed': removed_usbs
            }
    
    # Check network adapters
    if 'NetworkAdapters' in previous and 'NetworkAdapters' in current:
        prev_adapters = {adapter.get('MACAddress'): adapter for adapter in previous['NetworkAdapters'] if adapter.get('MACAddress')}
        curr_adapters = {adapter.get('MACAddress'): adapter for adapter in current['NetworkAdapters'] if adapter.get('MACAddress')}
        
        new_adapters = [curr_adapters[mac] for mac in set(curr_adapters) - set(prev_adapters)]
        removed_adapters = [prev_adapters[mac] for mac in set(prev_adapters) - set(curr_adapters)]
        
        if new_adapters or removed_adapters:
            changes['NetworkAdapters'] = {
                'added': new_adapters,
                'removed': removed_adapters
            }
    
    # Check disks
    if 'DiskDrives' in previous and 'DiskDrives' in current:
        prev_disks = {disk.get('SerialNumber'): disk for disk in previous['DiskDrives'] if disk.get('SerialNumber') != "N/A"}
        curr_disks = {disk.get('SerialNumber'): disk for disk in current['DiskDrives'] if disk.get('SerialNumber') != "N/A"}
        
        new_disks = [curr_disks[sn] for sn in set(curr_disks) - set(prev_disks)]
        removed_disks = [prev_disks[sn] for sn in set(prev_disks) - set(curr_disks)]
        
        if new_disks or removed_disks:
            changes['DiskDrives'] = {
                'added': new_disks,
                'removed': removed_disks
            }
    
    return changes

def detect_software_changes(previous, current):
    """Detect changes in installed applications."""
    changes = {}
    
    # Check installed applications
    if 'InstalledApplications' in previous and 'InstalledApplications' in current:
        prev_apps = {app.get('DisplayName'): app for app in previous['InstalledApplications'] if app.get('DisplayName')}
        curr_apps = {app.get('DisplayName'): app for app in current['InstalledApplications'] if app.get('DisplayName')}
        
        new_apps = [curr_apps[name] for name in set(curr_apps) - set(prev_apps)]
        removed_apps = [prev_apps[name] for name in set(prev_apps) - set(curr_apps)]
        
        # Check for version changes
        updated_apps = []
        for name in set(prev_apps).intersection(set(curr_apps)):
            if prev_apps[name].get('DisplayVersion') != curr_apps[name].get('DisplayVersion'):
                updated_apps.append({
                    'Name': name,
                    'OldVersion': prev_apps[name].get('DisplayVersion'),
                    'NewVersion': curr_apps[name].get('DisplayVersion')
                })
        
        if new_apps or removed_apps or updated_apps:
            changes['InstalledApplications'] = {
                'added': new_apps,
                'removed': removed_apps,
                'updated': updated_apps
            }
    
    # Check services
    if 'SystemServices' in previous and 'SystemServices' in current:
        prev_services = {svc.get('Name'): svc for svc in previous['SystemServices'] if svc.get('Name')}
        curr_services = {svc.get('Name'): svc for svc in current['SystemServices'] if svc.get('Name')}
        
        new_services = [curr_services[name] for name in set(curr_services) - set(prev_services)]
        removed_services = [prev_services[name] for name in set(prev_services) - set(curr_services)]
        
        # Check for state changes
        changed_services = []
        for name in set(prev_services).intersection(set(curr_services)):
            if prev_services[name].get('State') != curr_services[name].get('State'):
                changed_services.append({
                    'Name': name,
                    'OldState': prev_services[name].get('State'),
                    'NewState': curr_services[name].get('State')
                })
        
        if new_services or removed_services or changed_services:
            changes['SystemServices'] = {
                'added': new_services,
                'removed': removed_services,
                'stateChanged': changed_services
            }
    
    # Check scheduled tasks
    if 'ScheduledTasks' in previous and 'ScheduledTasks' in current:
        prev_tasks = {task.get('Path'): task for task in previous['ScheduledTasks'] if task.get('Path')}
        curr_tasks = {task.get('Path'): task for task in current['ScheduledTasks'] if task.get('Path')}
        
        new_tasks = [curr_tasks[path] for path in set(curr_tasks) - set(prev_tasks)]
        removed_tasks = [prev_tasks[path] for path in set(prev_tasks) - set(curr_tasks)]
        
        # Check for enabled/disabled changes
        changed_tasks = []
        for path in set(prev_tasks).intersection(set(curr_tasks)):
            if prev_tasks[path].get('Enabled') != curr_tasks[path].get('Enabled'):
                changed_tasks.append({
                    'Path': path,
                    'Name': curr_tasks[path].get('Name'),
                    'OldState': 'Enabled' if prev_tasks[path].get('Enabled') else 'Disabled',
                    'NewState': 'Enabled' if curr_tasks[path].get('Enabled') else 'Disabled'
                })
        
        if new_tasks or removed_tasks or changed_tasks:
            changes['ScheduledTasks'] = {
                'added': new_tasks,
                'removed': removed_tasks,
                'stateChanged': changed_tasks
            }
    
    # Check drivers
    if 'InstalledDrivers' in previous and 'InstalledDrivers' in current:
        prev_drivers = {driver.get('Name'): driver for driver in previous['InstalledDrivers'] if driver.get('Name')}
        curr_drivers = {driver.get('Name'): driver for driver in current['InstalledDrivers'] if driver.get('Name')}
        
        new_drivers = [curr_drivers[name] for name in set(curr_drivers) - set(prev_drivers)]
        removed_drivers = [prev_drivers[name] for name in set(prev_drivers) - set(curr_drivers)]
        
        if new_drivers or removed_drivers:
            changes['InstalledDrivers'] = {
                'added': new_drivers,
                'removed': removed_drivers
            }