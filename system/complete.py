import json
import wmi
import winreg
import traceback
import os
import time
import datetime
import hashlib
from win32com.client import Dispatch
import win32gui
import win32process
import win32api
import win32con
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Union, Set
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("system_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("SystemMonitor")

# ======================================================================
# Data Classes
# ======================================================================

@dataclass
class SystemInfo:
    """Container for all system information components"""
    collection_time: str
    computer_system: Dict[str, Any] = field(default_factory=dict)
    processor: List[Dict[str, Any]] = field(default_factory=list)
    bios: Dict[str, Any] = field(default_factory=dict)
    operating_system: Dict[str, Any] = field(default_factory=dict)
    physical_memory: List[Dict[str, Any]] = field(default_factory=list)
    disk_drives: List[Dict[str, Any]] = field(default_factory=list)
    usb_devices: List[Dict[str, Any]] = field(default_factory=list)
    network_adapters: List[Dict[str, Any]] = field(default_factory=list)
    gpus: List[Dict[str, Any]] = field(default_factory=list)
    installed_applications: List[Dict[str, Any]] = field(default_factory=list)
    installed_drivers: List[Dict[str, Any]] = field(default_factory=list)
    system_services: List[Dict[str, Any]] = field(default_factory=list)
    startup_items: List[Dict[str, Any]] = field(default_factory=list)
    scheduled_tasks: List[Dict[str, Any]] = field(default_factory=list)
    running_processes: List[Dict[str, Any]] = field(default_factory=list)
    active_windows: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class SystemChange:
    """Container for system changes"""
    timestamp: str
    hardware_changes: Dict[str, Any] = field(default_factory=dict)
    software_changes: Dict[str, Any] = field(default_factory=dict)

# ======================================================================
# Hardware Information Collection
# ======================================================================

class HardwareCollector:
    """Collects information about hardware components"""
    
    def __init__(self):
        self.wmi_client = wmi.WMI()
        
    def get_computer_system(self) -> Dict[str, Any]:
        """Get basic computer system information."""
        try:
            for cs in self.wmi_client.Win32_ComputerSystem():
                return {
                    'Manufacturer': cs.Manufacturer,
                    'Model': cs.Model,
                    'Name': cs.Name,
                    'TotalPhysicalMemory': cs.TotalPhysicalMemory
                }
        except Exception as e:
            logger.error(f"Error getting computer system info: {e}")
            return {'error': str(e)}
        return {}

    def get_processor(self) -> List[Dict[str, Any]]:
        """Get processor details."""
        processors = []
        try:
            for proc in self.wmi_client.Win32_Processor():
                processors.append({
                    'Name': proc.Name,
                    'NumberOfCores': proc.NumberOfCores,
                    'NumberOfLogicalProcessors': proc.NumberOfLogicalProcessors,
                    'MaxClockSpeed': proc.MaxClockSpeed
                })
        except Exception as e:
            logger.error(f"Error getting processor info: {e}")
            processors.append({'error': str(e)})
        return processors

    def get_bios(self) -> Dict[str, Any]:
        """Get BIOS information."""
        try:
            for bios in self.wmi_client.Win32_BIOS():
                return {
                    'Manufacturer': bios.Manufacturer,
                    'SerialNumber': bios.SerialNumber,
                    'Version': bios.SMBIOSBIOSVersion,
                    'ReleaseDate': bios.ReleaseDate
                }
        except Exception as e:
            logger.error(f"Error getting BIOS info: {e}")
            return {'error': str(e)}
        return {}

    def get_os(self) -> Dict[str, Any]:
        """Get Operating System details."""
        try:
            for os in self.wmi_client.Win32_OperatingSystem():
                return {
                    'Caption': os.Caption,
                    'Version': os.Version,
                    'InstallDate': os.InstallDate,
                    'BuildNumber': os.BuildNumber,
                    'OSArchitecture': os.OSArchitecture
                }
        except Exception as e:
            logger.error(f"Error getting OS info: {e}")
            return {'error': str(e)}
        return {}

    def get_physical_memory(self) -> List[Dict[str, Any]]:
        """Get information about physical memory modules."""
        modules = []
        try:
            for mem in self.wmi_client.Win32_PhysicalMemory():
                modules.append({
                    'Manufacturer': mem.Manufacturer,
                    'Capacity': mem.Capacity,
                    'Speed': mem.Speed,
                    'PartNumber': mem.PartNumber
                })
        except Exception as e:
            logger.error(f"Error getting physical memory info: {e}")
            modules.append({'error': str(e)})
        return modules

    def get_disk_drives(self) -> List[Dict[str, Any]]:
        """Get disk drive information."""
        disks = []
        try:
            for disk in self.wmi_client.Win32_DiskDrive():
                disks.append({
                    'Model': disk.Model,
                    'InterfaceType': disk.InterfaceType,
                    'Size': disk.Size,
                    'SerialNumber': getattr(disk, "SerialNumber", "N/A")
                })
        except Exception as e:
            logger.error(f"Error getting disk drive info: {e}")
            disks.append({'error': str(e)})
        return disks

    def get_usb_devices(self) -> List[Dict[str, Any]]:
        """Get information about connected USB devices."""
        usb_devices = []
        try:
            # Get USB controllers
            for device in self.wmi_client.Win32_USBController():
                usb_devices.append({
                    'Name': device.Name,
                    'DeviceID': device.DeviceID,
                    'Status': device.Status,
                    'Type': 'Controller'
                })
            
            # Get USB hubs
            for device in self.wmi_client.Win32_USBHub():
                usb_devices.append({
                    'Name': device.Name,
                    'DeviceID': device.DeviceID,
                    'Status': device.Status,
                    'Type': 'Hub'
                })
                
            # Get more detailed USB device information
            for device in self.wmi_client.Win32_PnPEntity():
                if "USB" in getattr(device, 'Caption', ''):
                    usb_devices.append({
                        'Name': device.Caption,
                        'DeviceID': device.DeviceID,
                        'Status': device.Status,
                        'Type': 'Device'
                    })
        except Exception as e:
            logger.error(f"Error getting USB device info: {e}")
            usb_devices.append({'error': str(e)})
        return usb_devices

    def get_network_adapters(self) -> List[Dict[str, Any]]:
        """Get information about network adapters."""
        adapters = []
        try:
            for nic in self.wmi_client.Win32_NetworkAdapter():
                if nic.PhysicalAdapter:
                    adapters.append({
                        'Name': nic.Name,
                        'MACAddress': nic.MACAddress,
                        'AdapterType': getattr(nic, 'AdapterType', "Unknown"),
                        'Speed': getattr(nic, 'Speed', "Unknown"),
                        'ConnectionStatus': nic.NetConnectionStatus
                    })
        except Exception as e:
            logger.error(f"Error getting network adapter info: {e}")
            adapters.append({'error': str(e)})
        return adapters

    def get_gpu(self) -> List[Dict[str, Any]]:
        """Get information about graphics processors."""
        gpus = []
        try:
            for gpu in self.wmi_client.Win32_VideoController():
                gpus.append({
                    'Name': gpu.Name,
                    'DriverVersion': gpu.DriverVersion,
                    'VideoProcessor': getattr(gpu, 'VideoProcessor', "Unknown"),
                    'AdapterRAM': gpu.AdapterRAM if hasattr(gpu, 'AdapterRAM') else "Unknown",
                    'CurrentResolution': f"{gpu.CurrentHorizontalResolution}x{gpu.CurrentVerticalResolution}" 
                                        if hasattr(gpu, 'CurrentHorizontalResolution') else "Unknown"
                })
        except Exception as e:
            logger.error(f"Error getting GPU info: {e}")
            gpus.append({'error': str(e)})
        return gpus

# ======================================================================
# Software Information Collection
# ======================================================================

class SoftwareCollector:
    """Collects information about installed software and system configuration"""
    
    def __init__(self):
        self.wmi_client = wmi.WMI()
    
    def get_installed_applications(self) -> List[Dict[str, Any]]:
        """Get a list of installed applications from registry."""
        apps = []
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        
        for root, path in registry_paths:
            try:
                apps.extend(self._get_apps_from_reg(root, path))
            except Exception as e:
                logger.error(f"Error reading registry path {path}: {e}")
        
        return apps
    
    def _get_apps_from_reg(self, root, path) -> List[Dict[str, Any]]:
        """Fetch installed applications from a specific registry key."""
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
                
                # Required field
                try:
                    app['DisplayName'] = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                except FileNotFoundError:
                    continue  # Skip entries without a DisplayName
                
                # Optional fields
                for field in ['DisplayVersion', 'Publisher', 'InstallDate', 'InstallLocation', 'UninstallString']:
                    try:
                        app[field] = winreg.QueryValueEx(subkey, field)[0]
                    except FileNotFoundError:
                        app[field] = None
                
                apps.append(app)
                
            except Exception as e:
                # Skip problematic entries
                continue
                
        return apps
        
    def get_installed_drivers(self) -> List[Dict[str, Any]]:
        """Get information about installed drivers."""
        drivers = []
        try:
            for driver in self.wmi_client.Win32_SystemDriver():
                drivers.append({
                    'Name': driver.Name,
                    'DisplayName': driver.DisplayName,
                    'State': driver.State,
                    'StartMode': driver.StartMode,
                    'PathName': driver.PathName
                })
        except Exception as e:
            logger.error(f"Error getting driver info: {e}")
            drivers.append({'error': str(e)})
        return drivers
    
    def get_startup_items(self) -> List[Dict[str, Any]]:
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
            except Exception as e:
                logger.error(f"Error reading startup registry: {e}")
        
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
    
    def get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get information about scheduled tasks."""
        try:
            scheduler = Dispatch('Schedule.Service')
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
            logger.error(f"Error getting scheduled tasks: {e}")
            return [{'error': str(e)}]
    
    def get_system_services(self) -> List[Dict[str, Any]]:
        """Get information about system services."""
        services = []
        try:
            for service in self.wmi_client.Win32_Service():
                services.append({
                    'Name': service.Name,
                    'DisplayName': service.DisplayName,
                    'StartMode': service.StartMode,
                    'State': service.State,
                    'PathName': service.PathName
                })
        except Exception as e:
            logger.error(f"Error getting system services: {e}")
            services.append({'error': str(e)})
        return services
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Get information about currently running processes."""
        processes = []
        try:
            for process in self.wmi_client.Win32_Process():
                processes.append({
                    'Name': process.Name,
                    'ProcessId': process.ProcessId,
                    'ExecutablePath': process.ExecutablePath,
                    'CommandLine': process.CommandLine,
                    'ParentProcessId': process.ParentProcessId,
                    'CreationDate': process.CreationDate
                })
        except Exception as e:
            logger.error(f"Error getting process info: {e}")
            processes.append({'error': str(e)})
        return processes
    
    def get_active_windows(self) -> List[Dict[str, Any]]:
        """Get information about currently active windows."""
        try:
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
            logger.error(f"Error getting active windows: {e}")
            return [{'error': str(e)}]

# ======================================================================
# System Information Manager
# ======================================================================

class SystemInfoManager:
    """Manages collection, storage, and comparison of system information"""
    
    def __init__(self):
        self.hardware_collector = HardwareCollector()
        self.software_collector = SoftwareCollector()
    
    def collect_system_info(self) -> SystemInfo:
        """Collect comprehensive system information"""
        logger.info("Collecting system information...")
        
        return SystemInfo(
            collection_time=datetime.datetime.now().isoformat(),
            computer_system=self.hardware_collector.get_computer_system(),
            processor=self.hardware_collector.get_processor(),
            bios=self.hardware_collector.get_bios(),
            operating_system=self.hardware_collector.get_os(),
            physical_memory=self.hardware_collector.get_physical_memory(),
            disk_drives=self.hardware_collector.get_disk_drives(),
            usb_devices=self.hardware_collector.get_usb_devices(),
            network_adapters=self.hardware_collector.get_network_adapters(),
            gpus=self.hardware_collector.get_gpu(),
            installed_applications=self.software_collector.get_installed_applications(),
            installed_drivers=self.software_collector.get_installed_drivers(),
            system_services=self.software_collector.get_system_services(),
            startup_items=self.software_collector.get_startup_items(),
            scheduled_tasks=self.software_collector.get_scheduled_tasks(),
            running_processes=self.software_collector.get_running_processes(),
            active_windows=self.software_collector.get_active_windows()
        )
    
    def save_system_info(self, info: SystemInfo, filename: str = "system_info.json") -> str:
        """Save system information to a JSON file."""
        with open(filename, "w") as f:
            json.dump(asdict(info), indent=4, default=str, fp=f)
        logger.info(f"System information saved to {filename}")
        return filename
    
    def load_system_info(self, filename: str = "system_info.json") -> Optional[Dict[str, Any]]:
        """Load previously saved system information."""
        try:
            with open(filename, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Error loading system info: {e}")
            return None
    
    def calculate_system_hash(self, info: Union[SystemInfo, Dict[str, Any]]) -> str:
        """Calculate a hash of key system components to detect changes."""
        # Convert to dict if it's a SystemInfo object
        if isinstance(info, SystemInfo):
            info_dict = asdict(info)
        else:
            info_dict = info
            
        # Select key components for hashing
        components = {
            'bios': info_dict.get('bios', {}),
            'computer_system': info_dict.get('computer_system', {}),
            'processor': info_dict.get('processor', []),
            'physical_memory': info_dict.get('physical_memory', []),
            'disk_drives': info_dict.get('disk_drives', []),
            'network_adapters': info_dict.get('network_adapters', [])
        }
        
        # Convert to string and hash
        components_str = json.dumps(components, sort_keys=True)
        return hashlib.sha256(components_str.encode()).hexdigest()

# ======================================================================
# Change Detection
# ======================================================================

class ChangeDetector:
    """Detects changes between system scans"""
    
    @staticmethod
    def detect_hardware_changes(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Detect changes in hardware configuration."""
        changes = {}
        
        # Check USB devices
        if 'usb_devices' in previous and 'usb_devices' in current:
            prev_usb_ids = {dev.get('DeviceID'): dev for dev in previous['usb_devices'] if dev.get('DeviceID')}
            curr_usb_ids = {dev.get('DeviceID'): dev for dev in current['usb_devices'] if dev.get('DeviceID')}
            
            new_usbs = [curr_usb_ids[id] for id in set(curr_usb_ids) - set(prev_usb_ids)]
            removed_usbs = [prev_usb_ids[id] for id in set(prev_usb_ids) - set(curr_usb_ids)]
            
            if new_usbs or removed_usbs:
                changes['USBDevices'] = {
                    'added': new_usbs,
                    'removed': removed_usbs
                }
        
        # Check network adapters
        if 'network_adapters' in previous and 'network_adapters' in current:
            prev_adapters = {adapter.get('MACAddress'): adapter for adapter in previous['network_adapters'] 
                            if adapter.get('MACAddress')}
            curr_adapters = {adapter.get('MACAddress'): adapter for adapter in current['network_adapters'] 
                            if adapter.get('MACAddress')}
            
            new_adapters = [curr_adapters[mac] for mac in set(curr_adapters) - set(prev_adapters)]
            removed_adapters = [prev_adapters[mac] for mac in set(prev_adapters) - set(curr_adapters)]
            
            if new_adapters or removed_adapters:
                changes['NetworkAdapters'] = {
                    'added': new_adapters,
                    'removed': removed_adapters
                }
        
        # Check disks
        if 'disk_drives' in previous and 'disk_drives' in current:
            prev_disks = {disk.get('SerialNumber'): disk for disk in previous['disk_drives'] 
                         if disk.get('SerialNumber') != "N/A"}
            curr_disks = {disk.get('SerialNumber'): disk for disk in current['disk_drives'] 
                         if disk.get('SerialNumber') != "N/A"}
            
            new_disks = [curr_disks[sn] for sn in set(curr_disks) - set(prev_disks)]
            removed_disks = [prev_disks[sn] for sn in set(prev_disks) - set(curr_disks)]
            
            if new_disks or removed_disks:
                changes['DiskDrives'] = {
                    'added': new_disks,
                    'removed': removed_disks
                }
        
        return changes
    
    @staticmethod
    def detect_software_changes(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Detect changes in installed applications."""
        changes = {}
        
        # Check installed applications
        if 'installed_applications' in previous and 'installed_applications' in current:
            prev_apps = {app.get('DisplayName'): app for app in previous['installed_applications'] 
                        if app.get('DisplayName')}
            curr_apps = {app.get('DisplayName'): app for app in current['installed_applications'] 
                        if app.get('DisplayName')}
            
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
        if 'system_services' in previous and 'system_services' in current:
            prev_services = {svc.get('Name'): svc for svc in previous['system_services'] if svc.get('Name')}
            curr_services = {svc.get('Name'): svc for svc in current['system_services'] if svc.get('Name')}
            
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
        if 'scheduled_tasks' in previous and 'scheduled_tasks' in current:
            prev_tasks = {task.get('Path'): task for task in previous['scheduled_tasks'] if task.get('Path')}
            curr_tasks = {task.get('Path'): task for task in current['scheduled_tasks'] if task.get('Path')}
            
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
        if 'installed_drivers' in previous and 'installed_drivers' in current:
            prev_drivers = {driver.get('Name'): driver for driver in previous['installed_drivers'] 
                           if driver.get('Name')}
            curr_drivers = {driver.get('Name'): driver for driver in current['installed_drivers'] 
                           if driver.get('Name')}
            
            new_drivers = [curr_drivers[name] for name in set(curr_drivers) - set(prev_drivers)]
            removed_drivers = [prev_drivers[name] for name in set(prev_drivers) - set(curr_drivers)]
            
            if new_drivers or removed_drivers:
                changes['InstalledDrivers'] = {
                    'added': new_drivers,
                    'removed': removed_drivers
                }

        return changes

# ======================================================================
# System Monitor
# ======================================================================

class SystemMonitor:
    """Continuously monitors the system for changes"""
    
    def __init__(self, 
                 interval: int = 5, 
                 alert_method: str = "console", 
                 log_file: str = "system_changes_log.txt"):
        self.interval = interval
        self.alert_method = alert_method
        self.log_file = log_file
        self.system_manager = SystemInfoManager()
        self.change_detector = ChangeDetector()
        
        # Initialize log file if needed
        if alert_method in ["file", "both"]:
            with open(log_file, "a") as f:
                f.write(f"\n\n--- System Monitoring Started at {datetime.datetime.now().isoformat()} ---\n")
    
    def start_monitoring(self):
        """Start continuous monitoring of system changes"""
        logger.info(f"Starting continuous system monitoring (checking every {self.interval} seconds)...")
        
        # Initial scan
        previous_scan = self.system_manager.collect_system_info()
        prev_scan_dict = asdict(previous_scan)
        
        try:
            while True:
                # Wait for the specified interval
                time.sleep(self.interval)
                
                # Collect current system state
                current_scan = self.system_manager.collect_system_info()
                curr_scan_dict = asdict(current_scan)
                
                # Detect changes
                hardware_changes = self.change_detector.detect_hardware_changes(prev_scan_dict, curr_scan_dict)
                software_changes = self.change_detector.detect_software_changes(prev_scan_dict, curr_scan_dict)
                
                # Check if any changes were detected
                if hardware_changes or software_changes:
                    # Create change record
                    change = SystemChange(
                        timestamp=datetime.datetime.now().isoformat(),
                        hardware_changes=hardware_changes,
                        software_changes=software_changes
                    )
                    
                    # Alert about changes
                    self._alert_changes(change)
                    
                    # Save current state for comparison in next iteration
                    previous_scan = current_scan
                    prev_scan_dict = curr_scan_dict
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user.")
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
            logger.error(traceback.format_exc())
    
    def _alert_changes(self, change: SystemChange):
        """Alert about detected changes using the configured method"""
        change_dict = asdict(change)
        change_str = json.dumps(change_dict, indent=2, default=str)
        
        # Format a more human-readable summary
        summary = self._format_change_summary(change)
        
        # Log to console
        if self.alert_method in ["console", "both"]:
            logger.info("SYSTEM CHANGES DETECTED:")
            logger.info(summary)
        
        # Log to file
        if self.alert_method in ["file", "both"]:
            with open(self.log_file, "a") as f:
                f.write(f"\n--- Changes detected at {change.timestamp} ---\n")
                f.write(summary)
                f.write("\n")
    
    def _format_change_summary(self, change: SystemChange) -> str:
        """Format change information as a human-readable summary"""
        lines = []
        lines.append(f"System changes detected at {change.timestamp}")
        
        # Hardware changes
        if change.hardware_changes:
            lines.append("\nHARDWARE CHANGES:")
            
            for category, details in change.hardware_changes.items():
                lines.append(f"\n  {category}:")
                
                if 'added' in details and details['added']:
                    lines.append("    Added:")
                    for item in details['added']:
                        name = item.get('Name', item.get('DeviceID', 'Unknown'))
                        lines.append(f"      - {name}")
                
                if 'removed' in details and details['removed']:
                    lines.append("    Removed:")
                    for item in details['removed']:
                        name = item.get('Name', item.get('DeviceID', 'Unknown'))
                        lines.append(f"      - {name}")
        
        # Software changes
        if change.software_changes:
            lines.append("\nSOFTWARE CHANGES:")
            
            for category, details in change.software_changes.items():
                lines.append(f"\n  {category}:")
                
                if 'added' in details and details['added']:
                    lines.append("    Added:")
                    for item in details['added']:
                        name = item.get('Name', item.get('DisplayName', 'Unknown'))
                        lines.append(f"      - {name}")
                
                if 'removed' in details and details['removed']:
                    lines.append("    Removed:")
                    for item in details['removed']:
                        name = item.get('Name', item.get('DisplayName', 'Unknown'))
                        lines.append(f"      - {name}")
                
                if 'updated' in details and details['updated']:
                    lines.append("    Updated:")
                    for item in details['updated']:
                        lines.append(f"      - {item.get('Name')}: {item.get('OldVersion')} → {item.get('NewVersion')}")
                
                if 'stateChanged' in details and details['stateChanged']:
                    lines.append("    State Changed:")
                    for item in details['stateChanged']:
                        lines.append(f"      - {item.get('Name')}: {item.get('OldState')} → {item.get('NewState')}")
        
        return "\n".join(lines)

# ======================================================================
# Main Function
# ======================================================================

def main():
    """Main function to run the system monitoring tool"""
    parser = argparse.ArgumentParser(description="Windows System Information Monitor")
    parser.add_argument("--scan", action="store_true", help="Perform a one-time system scan")
    parser.add_argument("--compare", type=str, nargs=2, metavar=('FILE1', 'FILE2'), 
                        help="Compare two system scan files")
    parser.add_argument("--monitor", action="store_true", help="Continuously monitor for system changes")
    parser.add_argument("--interval", type=int, default=60, 
                        help="Monitoring interval in seconds (default: 60)")
    parser.add_argument("--output", type=str, default="system_info.json", 
                        help="Output file for system scan (default: system_info.json)")
    parser.add_argument("--alert", type=str, choices=["console", "file", "both"], default="console",
                        help="Alert method for detected changes (default: console)")
    parser.add_argument("--log", type=str, default="system_changes_log.txt",
                        help="Log file for detected changes (default: system_changes_log.txt)")
    
    args = parser.parse_args()
    
    # Create system manager
    system_manager = SystemInfoManager()
    
    if args.scan:
        # Perform one-time scan
        system_info = system_manager.collect_system_info()
        system_manager.save_system_info(system_info, args.output)
        logger.info(f"System scan completed and saved to {args.output}")
        
    elif args.compare:
        # Compare two scan files
        file1, file2 = args.compare
        logger.info(f"Comparing {file1} and {file2}")
        
        prev_scan = system_manager.load_system_info(file1)
        curr_scan = system_manager.load_system_info(file2)
        
        if prev_scan and curr_scan:
            change_detector = ChangeDetector()
            hardware_changes = change_detector.detect_hardware_changes(prev_scan, curr_scan)
            software_changes = change_detector.detect_software_changes(prev_scan, curr_scan)
            
            change = SystemChange(
                timestamp=datetime.datetime.now().isoformat(),
                hardware_changes=hardware_changes,
                software_changes=software_changes
            )
            
            # Create a temporary monitor just to use its formatting method
            temp_monitor = SystemMonitor()
            summary = temp_monitor._format_change_summary(change)
            print(summary)
            
            # Save to file if requested
            if args.alert in ["file", "both"]:
                with open(args.log, "a") as f:
                    f.write(f"\n--- Comparison between {file1} and {file2} at {datetime.datetime.now().isoformat()} ---\n")
                    f.write(summary)
                    f.write("\n")
        else:
            logger.error("Error loading scan files for comparison")
            
    elif args.monitor:
        # Start continuous monitoring
        monitor = SystemMonitor(interval=args.interval, alert_method=args.alert, log_file=args.log)
        monitor.start_monitoring()
        
    else:
        # Default: show help
        parser.print_help()

if __name__ == "__main__":
    main()