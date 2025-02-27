import json
import wmi
import winreg
import traceback
import os
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

# --- Hardware Information Functions using WMI ---

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

# --- Installed Applications Functions using Registry ---
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
# detection
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

def get_running_processes():
    """Get information about currently running processes."""
    c = wmi.WMI()
    processes = []
    try:
        for process in c.Win32_Process():
            processes.append({
                'Name': process.Name,
                'ProcessId': process.ProcessId,
                'ExecutablePath': process.ExecutablePath,
                'CommandLine': process.CommandLine,
                'ParentProcessId': process.ParentProcessId,
                'CreationDate': process.CreationDate
            })
    except Exception as e:
        processes.append({'error': str(e)})
    return processes

def get_active_windows():
    """Get information about currently active windows."""
    try:
        import win32gui
        
        def callback(hwnd, windows_list):
            if win32gui.IsWindowVisible(hwnd):
                window_title = win32gui.GetWindowText(hwnd)
                if window_title:
                    windows_list.append({
                        'Handle': hwnd,
                        'Title': window_title
                    })
            return True
            
        windows = []
        win32gui.EnumWindows(callback, windows)
        return windows
    except Exception as e:
        return [{'error': str(e)}]
    
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

    return changes          

def get_scheduled_tasks():
    """Get information about scheduled tasks."""
    try:
        import win32com.client
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        
        tasks = []
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
                    'LastRunTime': task.LastRunTime,
                    'NextRunTime': task.NextRunTime
                }
                tasks.append(task_info)
        
        return tasks
    except Exception as e:
        return [{'error': str(e)}]
    
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
                'PathName': service.PathName
            })
    except Exception as e:
        services.append({'error': str(e)})
    return services


# --- Main Collection Function ---

def collect_complete_system_info():
    """
    Collect comprehensive system information including hardware,
    software, running processes, and active windows.
    """
    system_info = {
        'CollectionTime': datetime.datetime.now().isoformat(),
        'ComputerSystem': get_computer_system_info(),
        'Processor': get_processor_info(),
        'BIOS': get_bios_info(),
        'OperatingSystem': get_os_info(),
        'PhysicalMemory': get_physical_memory_info(),
        'DiskDrives': get_disk_drive_info(),
        'USBDevices': get_usb_devices(),
        'NetworkAdapters': get_network_adapters(),
        'GPUs': get_gpu_info(),
        'InstalledApplications': get_installed_applications(),
        'InstalledDrivers': get_installed_drivers(),
        'SystemServices': get_system_services(),
        'StartupItems': get_startup_items(),
        'ScheduledTasks': get_scheduled_tasks(),
        'RunningProcesses': get_running_processes(),
        'ActiveWindows': get_active_windows()
    }
    return system_info

def save_system_info(info, filename="system_info.json"):
    """Save system information to a JSON file."""
    with open(filename, "w") as f:
        json.dump(info, indent=4, default=str, fp=f)
    return filename

def generate_system_report(current_info, previous_info=None):
    """
    Generate a report of system information and changes if previous info is available.
    """
    report = {
        'GeneratedAt': datetime.datetime.now().isoformat(),
        'SystemInfo': current_info
    }
    
    # If previous info exists, detect and report changes
    if previous_info:
        hardware_changes = detect_hardware_changes(previous_info, current_info)
        software_changes = detect_software_changes(previous_info, current_info)
        
        if hardware_changes or software_changes:
            report['Changes'] = {
                'HardwareChanges': hardware_changes,
                'SoftwareChanges': software_changes
            }
    
    return report

def load_previous_system_info(filename="system_info.json"):
    """Load previously saved system information."""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def calculate_system_hash(info):
    """Calculate a hash of key system components to detect changes."""
    # Convert selected system components to string and hash
    components = {
        'BIOS': info.get('BIOS', {}),
        'ComputerSystem': info.get('ComputerSystem', {}),
        'Processor': info.get('Processor', []),
        'PhysicalMemory': info.get('PhysicalMemory', []),
        'DiskDrives': info.get('DiskDrives', []),
        'NetworkAdapters': info.get('NetworkAdapters', [])
    }
    
    # Convert to string and hash
    components_str = json.dumps(components, sort_keys=True)
    return hashlib.sha256(components_str.encode()).hexdigest()



def monitor_system_changes(interval=5, alert_method="console", log_file="system_changes_log.txt"):
    """
    Continuously monitor system for changes with short intervals.
    
    Args:
        interval: Seconds between checks (default 5 seconds)
        alert_method: How to alert on changes (console, file, or both)
        log_file: File to log changes when they occur
    """
    print(f"Starting continuous system monitoring (checking every {interval} seconds)...")
    print("Press Ctrl+C to stop monitoring.")
    
    # Get initial system state
    current_info = collect_complete_system_info()
    
    # Track specific components that should trigger alerts
    hardware_components = {
        'USBDevices': [dev.get('DeviceID') for dev in current_info.get('USBDevices', []) if dev.get('DeviceID')],
        'NetworkAdapters': [adapter.get('MACAddress') for adapter in current_info.get('NetworkAdapters', []) if adapter.get('MACAddress')],
        'DiskDrives': [disk.get('SerialNumber') for disk in current_info.get('DiskDrives', []) if disk.get('SerialNumber') != "N/A"],
    }
    
    software_components = {
        'InstalledApplications': {app.get('DisplayName'): app.get('DisplayVersion') 
                                 for app in current_info.get('InstalledApplications', []) if app.get('DisplayName')},
        'SystemServices': {svc.get('Name'): svc.get('State') 
                          for svc in current_info.get('SystemServices', []) if svc.get('Name')},
        'InstalledDrivers': {driver.get('Name'): driver.get('State') 
                            for driver in current_info.get('InstalledDrivers', []) if driver.get('Name')},
        'RunningProcesses': {proc.get('ProcessId'): proc.get('Name') 
                            for proc in current_info.get('RunningProcesses', []) if proc.get('ProcessId')}
    }
    
    # Initialize log file if needed
    if alert_method in ["file", "both"]:
        with open(log_file, "a") as f:
            f.write(f"\n\n--- System Monitoring Started at {datetime.datetime.now().isoformat()} ---\n")
    
    try:
        while True:
            time.sleep(interval)
            
            # Collect current system state
            new_info = collect_complete_system_info()
            
            # Check for hardware changes
            hardware_changes = {}
            
            # Check USB devices
            new_usb_ids = [dev.get('DeviceID') for dev in new_info.get('USBDevices', []) if dev.get('DeviceID')]
            added_usbs = [dev for dev in new_info.get('USBDevices', []) 
                         if dev.get('DeviceID') and dev.get('DeviceID') not in hardware_components['USBDevices']]
            removed_usbs = [dev_id for dev_id in hardware_components['USBDevices'] if dev_id not in new_usb_ids]
            
            if added_usbs or removed_usbs:
                hardware_changes['USBDevices'] = {
                    'added': added_usbs,
                    'removed': removed_usbs
                }
                # Update tracked USB devices
                hardware_components['USBDevices'] = new_usb_ids
            
            # Check network adapters
            new_mac_addrs = [adapter.get('MACAddress') for adapter in new_info.get('NetworkAdapters', []) if adapter.get('MACAddress')]
            added_adapters = [adapter for adapter in new_info.get('NetworkAdapters', []) 
                             if adapter.get('MACAddress') and adapter.get('MACAddress') not in hardware_components['NetworkAdapters']]
            removed_adapters = [mac for mac in hardware_components['NetworkAdapters'] if mac not in new_mac_addrs]
            
            if added_adapters or removed_adapters:
                hardware_changes['NetworkAdapters'] = {
                    'added': added_adapters,
                    'removed': removed_adapters
                }
                # Update tracked network adapters
                hardware_components['NetworkAdapters'] = new_mac_addrs
            
            # Check disk drives
            new_disk_sns = [disk.get('SerialNumber') for disk in new_info.get('DiskDrives', []) if disk.get('SerialNumber') != "N/A"]
            added_disks = [disk for disk in new_info.get('DiskDrives', []) 
                          if disk.get('SerialNumber') != "N/A" and disk.get('SerialNumber') not in hardware_components['DiskDrives']]
            removed_disks = [sn for sn in hardware_components['DiskDrives'] if sn not in new_disk_sns]
            
            if added_disks or removed_disks:
                hardware_changes['DiskDrives'] = {
                    'added': added_disks,
                    'removed': removed_disks
                }
                # Update tracked disk drives
                hardware_components['DiskDrives'] = new_disk_sns
            
            # Check for software changes
            software_changes = {}
            
            # Check installed applications
            new_apps = {app.get('DisplayName'): app.get('DisplayVersion') 
                       for app in new_info.get('InstalledApplications', []) if app.get('DisplayName')}
            
            added_apps = [app for app in new_info.get('InstalledApplications', []) 
                         if app.get('DisplayName') and app.get('DisplayName') not in software_components['InstalledApplications']]
            
            removed_apps = [{'DisplayName': name, 'DisplayVersion': version} 
                           for name, version in software_components['InstalledApplications'].items() if name not in new_apps]
            
            updated_apps = []
            for name, version in new_apps.items():
                if name in software_components['InstalledApplications'] and version != software_components['InstalledApplications'][name]:
                    updated_apps.append({
                        'DisplayName': name,
                        'OldVersion': software_components['InstalledApplications'][name],
                        'NewVersion': version
                    })
            
            if added_apps or removed_apps or updated_apps:
                software_changes['InstalledApplications'] = {
                    'added': added_apps,
                    'removed': removed_apps,
                    'updated': updated_apps
                }
                # Update tracked applications
                software_components['InstalledApplications'] = new_apps
            
            # Check running processes
            new_processes = {proc.get('ProcessId'): proc.get('Name') 
                            for proc in new_info.get('RunningProcesses', []) if proc.get('ProcessId')}
            
            added_procs = [proc for proc in new_info.get('RunningProcesses', []) 
                          if proc.get('ProcessId') and proc.get('ProcessId') not in software_components['RunningProcesses']]
            
            terminated_procs = [{'ProcessId': pid, 'Name': name} 
                               for pid, name in software_components['RunningProcesses'].items() if pid not in new_processes]
            
            if added_procs or terminated_procs:
                software_changes['RunningProcesses'] = {
                    'started': added_procs,
                    'terminated': terminated_procs
                }
                # Update tracked processes
                software_components['RunningProcesses'] = new_processes
            
            # Alert if any changes detected
            if hardware_changes or software_changes:
                timestamp = datetime.datetime.now().isoformat()
                changes = {
                    'Timestamp': timestamp,
                    'HardwareChanges': hardware_changes,
                    'SoftwareChanges': software_changes
                }
                
                # Format the changes for display/logging
                alert_message = f"\n--- System Changes Detected at {timestamp} ---\n"
                
                if hardware_changes:
                    alert_message += "\nHARDWARE CHANGES:\n"
                    for component, change in hardware_changes.items():
                        alert_message += f"\n{component}:\n"
                        
                        if change.get('added'):
                            alert_message += "  ADDED:\n"
                            for item in change['added']:
                                if component == 'USBDevices':
                                    alert_message += f"    - {item.get('Name', 'Unknown Device')}\n"
                                elif component == 'NetworkAdapters':
                                    alert_message += f"    - {item.get('Name', 'Unknown Adapter')} ({item.get('MACAddress', 'Unknown MAC')})\n"
                                elif component == 'DiskDrives':
                                    alert_message += f"    - {item.get('Model', 'Unknown Disk')} ({item.get('Size', 'Unknown Size')})\n"
                        
                        if change.get('removed'):
                            alert_message += "  REMOVED:\n"
                            for item in change['removed']:
                                if isinstance(item, str):
                                    alert_message += f"    - {item}\n"
                                else:
                                    name = item.get('Name', 'Unknown Device')
                                    alert_message += f"    - {name}\n"
                
                if software_changes:
                    alert_message += "\nSOFTWARE CHANGES:\n"
                    for component, change in software_changes.items():
                        alert_message += f"\n{component}:\n"
                        
                        if component == 'InstalledApplications':
                            if change.get('added'):
                                alert_message += "  INSTALLED:\n"
                                for app in change['added']:
                                    alert_message += f"    - {app.get('DisplayName', 'Unknown App')} {app.get('DisplayVersion', '')}\n"
                            
                            if change.get('removed'):
                                alert_message += "  UNINSTALLED:\n"
                                for app in change['removed']:
                                    alert_message += f"    - {app.get('DisplayName', 'Unknown App')} {app.get('DisplayVersion', '')}\n"
                            
                            if change.get('updated'):
                                alert_message += "  UPDATED:\n"
                                for app in change['updated']:
                                    alert_message += f"    - {app.get('DisplayName', 'Unknown App')}: {app.get('OldVersion', '')} -> {app.get('NewVersion', '')}\n"
                        
                        elif component == 'RunningProcesses':
                            if change.get('started'):
                                alert_message += "  STARTED:\n"
                                for proc in change['started']:
                                    alert_message += f"    - {proc.get('Name', 'Unknown')} (PID: {proc.get('ProcessId', 'Unknown')})\n"
                            
                            if change.get('terminated'):
                                alert_message += "  TERMINATED:\n"
                                for proc in change['terminated']:
                                    alert_message += f"    - {proc.get('Name', 'Unknown')} (PID: {proc.get('ProcessId', 'Unknown')})\n"
                
                # Output alerts according to specified method
                if alert_method in ["console", "both"]:
                    print(alert_message)
                
                if alert_method in ["file", "both"]:
                    with open(log_file, "a") as f:
                        f.write(alert_message)
                
                # Save detailed JSON report for significant changes
                if hardware_changes:
                    report_file = f"hardware_changes_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    save_system_info(changes, report_file)
                
                if 'InstalledApplications' in software_changes or 'InstalledDrivers' in software_changes:
                    report_file = f"software_changes_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    save_system_info(changes, report_file)
    
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
        if alert_method in ["file", "both"]:
            with open(log_file, "a") as f:
                f.write(f"\n--- System Monitoring Stopped at {datetime.datetime.now().isoformat()} ---\n")


def main():
    """
    Main function to collect system information, compare with previous data,
    and generate a report.
    """
    # Parse command line arguments if needed
    import argparse
    parser = argparse.ArgumentParser(description="Collect and analyze Windows system information")
    parser.add_argument("-o", "--output", help="Output file name", default="system_info.json")
    parser.add_argument("-c", "--compare", help="Compare with previous run", action="store_true")
    parser.add_argument("-m", "--monitor", help="Monitor system continuously", action="store_true")
    parser.add_argument("-i", "--interval", help="Monitoring interval in seconds", type=int, default=5)
    parser.add_argument("-a", "--alert", help="Alert method (console, file, both)", default="console")
    parser.add_argument("-l", "--log", help="Log file for changes", default="system_changes_log.txt")
    args = parser.parse_args()
    
    print("Collecting system information...")
    current_info = collect_complete_system_info()
    current_hash = calculate_system_hash(current_info)
    
    if args.compare:
        print("Loading previous system information...")
        previous_info = load_previous_system_info(args.output)
        
        if previous_info:
            previous_hash = calculate_system_hash(previous_info)
            
            if current_hash != previous_hash:
                print("System changes detected! Generating report...")
                report = generate_system_report(current_info, previous_info)
                report_file = f"system_changes_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                save_system_info(report, report_file)
                print(f"Change report saved to {report_file}")
            else:
                print("No significant system changes detected.")
        else:
            print("No previous system information found.")
    
    # Save current system information
    saved_file = save_system_info(current_info, args.output)
    print(f"System information saved to {saved_file}")
    
    # Continuous monitoring if requested
    if args.monitor:
        # Start continuous monitoring with immediate detection
        monitor_system_changes(interval=args.interval, alert_method=args.alert, log_file=args.log)
        return

if __name__ == "__main__":
    main()