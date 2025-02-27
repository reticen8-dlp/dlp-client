import json
import wmi
import winreg
import traceback

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

            apps.append(app)
        except Exception as e:
            # Uncomment the following line for debugging purposes:
            # print(f"Error reading subkey: {traceback.format_exc()}")
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
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    ]
    for root, path in registry_paths:
        apps.extend(get_installed_apps_from_reg(root, path))
    return apps

# --- Main Collection Function ---

def collect_system_info():
    """
    Collect all desired system information and return as a dictionary.
    """
    system_info = {
        'ComputerSystem': get_computer_system_info(),
        'Processor': get_processor_info(),
        'BIOS': get_bios_info(),
        'OperatingSystem': get_os_info(),
        'PhysicalMemory': get_physical_memory_info(),
        'DiskDrives': get_disk_drive_info(),
        'InstalledApplications': get_installed_applications()
    }
    return system_info

def main():
    # Collect all system info
    info = collect_system_info()
    
    # Output the data as formatted JSON
    output = json.dumps(info, indent=4)
    # print(output)
    
    # Optionally, write to a file:
    with open("system_info.json", "w") as f:
        f.write(output)

if __name__ == "__main__":
    main()
