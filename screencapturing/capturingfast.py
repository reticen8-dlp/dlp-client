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
    
    def record_screen(self, output="output.mp4", crop_rect=None, buffer_seconds=5):
        """
        Records the previous 5 seconds of screen activity and saves to a video file
        without using OpenCV GUI functionality.
        
        Args:
            output (str): Output video filename
            crop_rect (tuple, optional): Region to capture (left, top, width, height)
            buffer_seconds (int): Number of seconds to keep in buffer (default 5)
        """
        sct = mss.mss()
        # Default to primary monitor if no crop_rect provided
        if crop_rect is None:
            monitor = sct.monitors[1]
        else:
            # crop_rect: (left, top, width, height)
            monitor = {"left": crop_rect[0], "top": crop_rect[1],
                    "width": crop_rect[2], "height": crop_rect[3]}
                
        # Set up parameters
        fps = 20
        buffer_size = fps * buffer_seconds  # Number of frames to keep in buffer
        frame_buffer = []
        
        # Set up VideoWriter
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        
        try:
            print(f"Starting buffer recording for {buffer_seconds} seconds...")
            
            # Continuously capture frames for buffer_seconds
            start_time = time.time()
            while time.time() - start_time < buffer_seconds:
                # Capture frame
                img = np.array(sct.grab(monitor))
                frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
                
                # Add to buffer
                frame_buffer.append(frame)
                
                # Control frame rate
                time.sleep(1/fps)
            
            # Save the buffer to video file
            out = cv2.VideoWriter(output, fourcc, fps, (monitor["width"], monitor["height"]))
            print(f"Saving {buffer_seconds} seconds of recording to {output}...")
            
            for frame in frame_buffer:
                out.write(frame)
                
            out.release()
            print(f"Video saved to {output}")
            
        except Exception as e:
            print(f"Error in recording: {e}")


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
        file_mp4 = f"{self.config['screenshot_dir']}/violation_{timestamp}_{reason.replace(' ', '_')[:50]}.mp4"        
        # Capture and save screenshot
        
        screenshot = self.capture.capture_screen(filename=filename)
        recording = self.capture.record_screen(output=file_mp4)
        
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
    
   

# Example usage
# if __name__ == "__main__":

# Call this function to test in isolation
    # test_result, test_file = test_screenshot()
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