"""
Advanced Screen Capture and Monitoring with MSS (Multi-Screen Shot)
Provides better performance than PIL/ImageGrab
"""
import numpy as np
import cv2
import time
import threading
import mss
import mss.tools
import pygetwindow as gw
import win32clipboard
import win32gui
import os
import logging
from datetime import datetime
import json
from pathlib import Path
import mss
import mss.tools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='dlp_monitor.log'
)
logger = logging.getLogger('DLP')

class FastScreenCapture:
    """High-performance screen capture using MSS"""
    
    def __init__(self):
        """Initialize the screen capture"""
        self.mss = mss.mss()
        # Get monitor information
        self.monitors = self.mss.monitors
        self.primary_monitor = self.monitors[1]  # Index 0 is all monitors combined
        
        logger.info(f"Primary monitor: {self.primary_monitor['width']}x{self.primary_monitor['height']}")
        logger.info(f"Total monitors detected: {len(self.monitors)-1}")
    
    def capture_screen(self, monitor_num=1, filename=None):
        try:
            # Capture the monitor
            screenshot = self.mss.grab(self.monitors[monitor_num])
            
            # Save if filename provided
            if filename:
                try:
                    # Try alternative method to save
                    from PIL import Image
                    img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
                    img.save(filename)
                    print(f"Screenshot saved to {filename} using PIL")
                except Exception as e:
                    print(f"Error saving screenshot with PIL: {e}")
                    try:
                        # Try direct save with mss
                        with open(filename, 'wb') as f:
                            f.write(mss.tools.to_png(screenshot.rgb, screenshot.size))
                        print(f"Screenshot saved to {filename} using mss.tools.to_png with write")
                    except Exception as e2:
                        print(f"Error saving screenshot with direct write: {e2}")
            
            return np.array(screenshot)
        except Exception as e:
            print(f"Error capturing screen: {e}")
            return None
        
    def capture_region(self, left, top, width, height, filename=None):
        """Capture specific region of the screen
        
        Args:
            left, top, width, height: Region coordinates
            filename: Optional filename to save screenshot
            
        Returns:
            numpy array of screenshot
        """
        try:
            # Define region
            region = {"left": left, "top": top, "width": width, "height": height}
            
            # Capture the region
            screenshot = self.mss.grab(region)
            
            # Save if filename provided
            if filename:
                with open(filename, "wb") as f:
                    f.write(mss.tools.to_png(screenshot.rgb, screenshot.size))
                logger.info(f"Screenshot saved to {filename}")
            # Convert to numpy array
            return np.array(screenshot)
        except Exception as e:
            logger.error(f"Error capturing region: {e}")
            return None
    
    def capture_window(self, window_title, filename=None):
        """Capture a specific window by title
        
        Args:
            window_title: Title of window to capture
            filename: Optional filename to save screenshot
            
        Returns:
            numpy array of screenshot or None if window not found
        """
        try:
            # Find window by title
            windows = gw.getWindowsWithTitle(window_title)
            
            if not windows:
                logger.warning(f"Window '{window_title}' not found")
                return None
            
            # Get the first matching window
            window = windows[0]
            
            # Ensure window is not minimized
            if window.isMinimized:
                logger.warning(f"Window '{window_title}' is minimized, cannot capture")
                return None
            
            # Get window position and size
            region = {
                "left": window.left,
                "top": window.top,
                "width": window.width,
                "height": window.height
            }
            
            # Capture the window
            screenshot = self.mss.grab(region)
            
            # Save if filename provided
            if filename:
                mss.tools.to_png(screenshot.rgb, screenshot.size, output=filename)
                logger.info(f"Window screenshot saved to {filename}")
            
            # Convert to numpy array
            return np.array(screenshot)
        except Exception as e:
            logger.error(f"Error capturing window: {e}")
            return None
    
    def close(self):
        """Close MSS resources"""
        self.mss.close()


class AdvancedScreenMonitor:
    """High-performance screen monitor with advanced features"""
    
    def __init__(self):
        """Initialize the monitor"""
        self.capture = FastScreenCapture()
        self.running = False
        self.thread = None
        self.previous_frame = None
        self.change_regions = []  # Track regions that changed
        
        # Configuration
        self.interval = 0.5  # seconds
        self.threshold = 0.01  # 1% change
        self.region_size = 50  # Divide screen into regions of this size
        self.min_region_threshold = 5  # Minimum number of changed pixels in a region
    
    def set_region_analysis(self, region_size=50, min_region_threshold=5):
        """Configure region-based analysis settings
        
        Args:
            region_size: Size of regions for detection (smaller = more precise but slower)
            min_region_threshold: Minimum pixel changes needed in a region
        """
        self.region_size = region_size
        self.min_region_threshold = min_region_threshold
    
    def _compare_frames_region(self, frame1, frame2):
        """Compare two frames using region-based analysis for better change detection
        
        Returns:
            (bool, list): Changed status and list of changed regions
        """
        if frame1 is None or frame2 is None or frame1.shape != frame2.shape:
            return True, []
        
        # Convert to grayscale for faster comparison
        gray1 = cv2.cvtColor(frame1, cv2.COLOR_BGR2GRAY)
        gray2 = cv2.cvtColor(frame2, cv2.COLOR_BGR2GRAY)
        
        # Calculate absolute difference
        diff = cv2.absdiff(gray1, gray2)
        
        # Apply threshold to get significant changes
        _, thresh = cv2.threshold(diff, 30, 255, cv2.THRESH_BINARY)
        
        # Analyze by regions
        height, width = thresh.shape
        changed_regions = []
        total_changed_regions = 0
        
        # Loop through regions
        for y in range(0, height, self.region_size):
            for x in range(0, width, self.region_size):
                # Extract region
                region = thresh[y:min(y + self.region_size, height), 
                                x:min(x + self.region_size, width)]
                
                # Count changed pixels in region
                changed_pixels = np.count_nonzero(region)
                
                if changed_pixels > self.min_region_threshold:
                    # Region has significant change
                    changed_regions.append((x, y, 
                                          min(x + self.region_size, width), 
                                          min(y + self.region_size, height)))
                    total_changed_regions += 1
        
        # Calculate percentage of changed regions
        total_regions = (height // self.region_size + 1) * (width // self.region_size + 1)
        change_percentage = total_changed_regions / total_regions
        
        # Store changed regions for potential use
        self.change_regions = changed_regions
        
        return change_percentage > self.threshold, changed_regions
    
    def start_monitoring(self, interval=0.5, threshold=0.01, on_change=None):
        """Start monitoring for screen changes
        
        Args:
            interval: Time between captures in seconds
            threshold: Percentage of regions that need to change
            on_change: Callback that receives the new frame and list of changed regions
        """
        if self.running:
            logger.warning("Monitor already running")
            return
        
        self.interval = interval
        self.threshold = threshold
        self.running = True
        
        # Create and start monitoring thread
        self.thread = threading.Thread(
            target=self._monitor_thread,
            args=(on_change,),
            daemon=True
        )
        self.thread.start()
        logger.info(f"Started advanced monitoring with interval={interval}s, threshold={threshold}")
    
    def _monitor_thread(self, on_change):
        """Background thread that monitors for screen changes"""
        self.previous_frame = self.capture.capture_screen()
        
        while self.running:
            time.sleep(self.interval)
            
            # Capture current frame
            current_frame = self.capture.capture_screen()
            
            # Check if frame changed beyond threshold
            changed, regions = self._compare_frames_region(self.previous_frame, current_frame)
            
            if changed:
                logger.info(f"Screen change detected in {len(regions)} regions")
                
                if on_change:
                    on_change(current_frame, regions)
            
            self.previous_frame = current_frame
    
    def stop_monitoring(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        self.capture.close()
        logger.info("Advanced monitoring stopped")


class EnhancedDLPMonitor:
    """Enhanced Data Loss Prevention monitor with multiple detection methods"""
    
    def __init__(self):
        """Initialize the DLP monitor"""
        self.capture = FastScreenCapture()
        self.running = False
        self.thread = None
        
        # DLP configuration
        self.config = {
            "monitor_clipboard": True,
            "monitor_window_titles": True,
            "monitor_screen_changes": True,
            "monitor_usb_devices": True,
            "sensitive_window_titles": [
                "password", "credential", "secret", "confidential", "ssn", 
                "credit card", "banking", "admin", "manager", "social security"
            ],
            "screenshot_dir": "dlp_evidence",
            "save_evidence": True
        }
        
        # Create output directory
        os.makedirs(self.config["screenshot_dir"], exist_ok=True)
        
        # State tracking
        self.last_clipboard_content = None
        self.last_active_window = None
        self.last_screenshot = None
        self.violation_count = 0
        
        # Load config if exists
        config_path = Path("dlp_config.json")
        if config_path.exists():
            try:
                with open(config_path, "r") as f:
                    user_config = json.load(f)
                    self.config.update(user_config)
                logger.info("Loaded DLP configuration from file")
            except Exception as e:
                logger.error(f"Error loading config: {e}")
    
    def save_evidence(self, reason):
        """Save evidence of DLP violation"""
        if not self.config["save_evidence"]:
            logger.info("Evidence saving disabled in config")
            return None
                
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.config['screenshot_dir']}/violation_{timestamp}_{reason.replace(' ', '_')[:50]}.png"
                
        # Capture and save screenshot
        screenshot = self.capture.capture_screen(filename=filename)
        
        # Verify screenshot was saved
        if not os.path.exists(filename):
            logger.error(f"Screenshot file not created at {filename}")
            return None
                
        # Save additional metadata
        meta_file = filename.replace(".png", ".json")
        metadata = {
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "active_window": self.last_active_window,
            "violation_id": self.violation_count
        }
                
        try:
            with open(meta_file, "w") as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Metadata saved to {meta_file}")
        except Exception as e:
            logger.error(f"Error saving metadata: {e}")
                    
        return filename
    
    def _check_clipboard(self):
        """Check if clipboard content has changed"""
        if not self.config["monitor_clipboard"]:
            return False
        
        try:
            win32clipboard.OpenClipboard()
            
            # Try different clipboard formats
            formats = [win32clipboard.CF_UNICODETEXT, win32clipboard.CF_TEXT]
            current_content = None
            
            for fmt in formats:
                try:
                    current_content = win32clipboard.GetClipboardData(fmt)
                    break
                except:
                    pass
            
            win32clipboard.CloseClipboard()
            
            # Check if content has changed
            if self.last_clipboard_content is not None and current_content != self.last_clipboard_content:
                self.last_clipboard_content = current_content
                return True
            
            self.last_clipboard_content = current_content
            return False
        except Exception as e:
            logger.error(f"Error checking clipboard: {e}")
            return False
    
    def _check_window_title(self):
        """Check if active window has sensitive title"""
        if not self.config["monitor_window_titles"]:
            return None
        
        try:
            # Get active window handle and title
            hwnd = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(hwnd).lower()
            
            # Store for metadata
            self.last_active_window = title
            
            # Only check if title is different from last time
            if title == self.last_active_window:
                return None
            
            # Check if title contains any sensitive terms
            for sensitive_term in self.config["sensitive_window_titles"]:
                if sensitive_term in title:
                    return sensitive_term
            
            return None
        except Exception as e:
            logger.error(f"Error checking window title: {e}")
            return None
    
    def start_monitoring(self, on_violation=None):
        """Start DLP monitoring
        
        Args:
            on_violation: Callback that receives violation reason and evidence path
        """
        if self.running:
            logger.warning("DLP monitor already running")
            return
        
        # Initialize state
        self.running = True
        self.violation_count = 0
        
        # Get initial clipboard content
        if self.config["monitor_clipboard"]:
            try:
                win32clipboard.OpenClipboard()
                try:
                    self.last_clipboard_content = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                except:
                    try:
                        self.last_clipboard_content = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                    except:
                        self.last_clipboard_content = None
                win32clipboard.CloseClipboard()
            except:
                self.last_clipboard_content = None
        
        # Get initial active window
        try:
            hwnd = win32gui.GetForegroundWindow()
            self.last_active_window = win32gui.GetWindowText(hwnd).lower()
        except:
            self.last_active_window = None
        
        # Create and start monitoring thread
        self.thread = threading.Thread(
            target=self._monitor_thread,
            args=(on_violation,),
            daemon=True
        )
        self.thread.start()
        logger.info("Started enhanced DLP monitoring")
    
    def _monitor_thread(self, on_violation):
        """Background thread that monitors for DLP violations"""
        while self.running:
            time.sleep(0.5)  # Check every 500ms
            
            # Check for clipboard changes
            if self._check_clipboard():
                reason = "Clipboard content changed"
                logger.warning(f"DLP VIOLATION: {reason}")
                
                self.violation_count += 1
                evidence_path = self.save_evidence("clipboard")
                
                if on_violation:
                    on_violation(reason, evidence_path)
            
            # Check for sensitive window titles
            sensitive_term = self._check_window_title()
            if sensitive_term:
                reason = f"Sensitive window detected: '{sensitive_term}'"
                logger.warning(f"DLP VIOLATION: {reason}")
                
                self.violation_count += 1
                evidence_path = self._save_evidence(sensitive_term)
                
                if on_violation:
                    on_violation(reason, evidence_path)
    
    def stop_monitoring(self):
        """Stop the DLP monitoring thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2.0)
        
        # Close capture resources
        self.capture.close()
        logger.info(f"Enhanced DLP monitoring stopped. Total violations: {self.violation_count}")
        
        return self.violation_count

def test_screenshot():
    capture = FastScreenCapture()
    test_file = os.path.abspath("test_screenshot.png")
    print(f"Saving to absolute path: {test_file}")
    screenshot = capture.capture_screen(filename=test_file)
    print(f"Screenshot captured: {screenshot is not None}")
    print(f"File exists: {os.path.exists(test_file)}")
    if os.path.exists(test_file):
        print(f"File size: {os.path.getsize(test_file)} bytes")
    return screenshot, test_file

# Example usage
if __name__ == "__main__":

# Call this function to test in isolation
    test_result, test_file = test_screenshot()
    # print("Advanced Python Screen Capture and DLP Monitor")
    # print("---------------------------------------------")
    
    # # Example 1: Fast screen capture
    # print("\n1. Testing fast screen capture...")
    # capture = FastScreenCapture()
    # screenshot = capture.capture_screen(filename="fast_screenshot.png")
    # if screenshot is not None:
    #     print(f"Screenshot saved with resolution: {screenshot.shape[1]}x{screenshot.shape[0]}")
    # capture.close()
    
    # # Example 2: Advanced screen monitoring
    # print("\n2. Starting advanced screen monitoring...")
    # monitor = AdvancedScreenMonitor()
    # change_count = 0
    
    # def on_screen_change(frame, regions):
    #     global change_count
    #     change_count += 1
    #     print(f"Screen change #{change_count} detected in {len(regions)} regions")
    
    # monitor.set_region_analysis(region_size=100, min_region_threshold=10)
    # monitor.start_monitoring(interval=0.5, threshold=0.01, on_change=on_screen_change)
    
    # Example 3: Enhanced DLP monitoring
    # print("\n3. Starting enhanced DLP monitoring...")
    # dlp = EnhancedDLPMonitor()
    
    # def on_dlp_violation(reason, evidence_path):
    #     print(f"DLP VIOLATION: {reason}")
    #     if evidence_path:
    #         print(f"Evidence saved to: {evidence_path}")
    
    # dlp.start_monitoring(on_violation=on_dlp_violation)
    
    # try:
    #     print("\nMonitoring started. Make some screen changes, copy text, etc.")
    #     print("Press Ctrl+C to stop...")
        
    #     # Keep main thread alive
    #     while True:
    #         time.sleep(1)
    # except KeyboardInterrupt:
    #     print("\nStopping all monitoring...")
    #     monitor.stop_monitoring()
    #     violation_count = dlp.stop_monitoring()
        
    #     print(f"\nResults:")
    #     print(f"- Detected {change_count} screen changes")
    #     print(f"- Recorded {violation_count} DLP violations")
        
    #     print("\nCheck the 'dlp_evidence' folder for violation screenshots.")