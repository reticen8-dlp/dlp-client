#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <gdiplus.h>
#include <memory>
#pragma comment(lib, "gdiplus.lib")

class ScreenCapture {
private:
    int screenWidth;
    int screenHeight;
    
public:
    ScreenCapture() {
        // Get screen dimensions
        screenWidth = GetSystemMetrics(SM_CXSCREEN);
        screenHeight = GetSystemMetrics(SM_CYSCREEN);
    }
    
    // Capture screen and save to file
    bool captureScreen(const std::wstring& filename) {
        // Initialize GDI+
        Gdiplus::GdiplusStartupInput gdiplusStartupInput;
        ULONG_PTR gdiplusToken;
        Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
        
        // Create device contexts
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMemory = CreateCompatibleDC(hdcScreen);
        
        // Create compatible bitmap
        HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
        HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMemory, hbmScreen);
        
        // Copy screen to memory DC using BitBlt
        BitBlt(hdcMemory, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
        
        // Save bitmap to file
        CLSID encoderClsid;
        getEncoderClsid(L"image/png", &encoderClsid);
        
        Gdiplus::Bitmap bitmap(hbmScreen, NULL);
        bool result = (bitmap.Save(filename.c_str(), &encoderClsid, NULL) == Gdiplus::Ok);
        
        // Clean up
        SelectObject(hdcMemory, hbmOld);
        DeleteObject(hbmScreen);
        DeleteDC(hdcMemory);
        ReleaseDC(NULL, hdcScreen);
        
        Gdiplus::GdiplusShutdown(gdiplusToken);
        
        return result;
    }
    
    // Get raw screen data for processing
    std::vector<BYTE> captureScreenData() {
        // Create device contexts
        HDC hdcScreen = GetDC(NULL);
        HDC hdcMemory = CreateCompatibleDC(hdcScreen);
        
        // Create compatible bitmap
        HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
        HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMemory, hbmScreen);
        
        // Copy screen to memory DC
        BitBlt(hdcMemory, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);
        
        // Get bitmap data
        BITMAPINFOHEADER bi = {0};
        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = screenWidth;
        bi.biHeight = -screenHeight; // Top-down
        bi.biPlanes = 1;
        bi.biBitCount = 32;
        bi.biCompression = BI_RGB;
        
        // Calculate data size and allocate buffer
        int dataSize = screenWidth * screenHeight * 4; // 32bpp = 4 bytes per pixel
        std::vector<BYTE> buffer(dataSize);
        
        // Get the DIB bits
        GetDIBits(hdcMemory, hbmScreen, 0, screenHeight, buffer.data(), 
                  (BITMAPINFO*)&bi, DIB_RGB_COLORS);
        
        // Clean up
        SelectObject(hdcMemory, hbmOld);
        DeleteObject(hbmScreen);
        DeleteDC(hdcMemory);
        ReleaseDC(NULL, hdcScreen);
        
        return buffer;
    }
    
private:
    // Helper function to get encoder CLSID
    int getEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT num = 0;
        UINT size = 0;
        
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;
        
        std::vector<BYTE> buffer(size);
        Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)buffer.data();
        
        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        
        for (UINT i = 0; i < num; ++i) {
            if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[i].Clsid;
                return i;
            }
        }
        
        return -1;
    }
};

class ScreenMonitor {
private:
    ScreenCapture capture;
    bool running = false;
    DWORD interval = 1000; // Default interval in ms
    std::vector<BYTE> previousFrame;
    
public:
    // Start monitoring with callback on changes
    void startMonitoring(DWORD intervalMs, std::function<void(const std::vector<BYTE>&)> onChange) {
        interval = intervalMs;
        running = true;
        
        // Create monitoring thread
        std::thread monitorThread([this, onChange]() {
            previousFrame = capture.captureScreenData();
            
            while (running) {
                Sleep(interval);
                
                auto currentFrame = capture.captureScreenData();
                
                // Check if frame changed
                if (compareFrames(previousFrame, currentFrame)) {
                    onChange(currentFrame);
                }
                
                previousFrame = std::move(currentFrame);
            }
        });
        
        monitorThread.detach();
    }
    
    // Stop monitoring
    void stopMonitoring() {
        running = false;
    }
    
private:
    // Compare two frames to detect changes
    bool compareFrames(const std::vector<BYTE>& frame1, const std::vector<BYTE>& frame2) {
        if (frame1.size() != frame2.size()) return true;
        
        // Calculate difference and threshold
        int diffCount = 0;
        int threshold = static_cast<int>(frame1.size() * 0.01); // 1% change threshold
        
        for (size_t i = 0; i < frame1.size(); i += 4) { // Check every pixel (RGBA)
            if (frame1[i] != frame2[i] || frame1[i+1] != frame2[i+1] || frame1[i+2] != frame2[i+2]) {
                diffCount++;
                if (diffCount > threshold) return true;
            }
        }
        
        return false;
    }
};

// Example usage
int main() {
    // Initialize COM for the thread
    CoInitialize(NULL);
    
    // Example 1: Single screenshot
    ScreenCapture capture;
    capture.captureScreen(L"screenshot.png");
    std::cout << "Screenshot saved to screenshot.png" << std::endl;
    
    // Example 2: Screen monitoring
    ScreenMonitor monitor;
    int captureCount = 0;
    
    std::cout << "Starting screen monitoring. Press Enter to stop..." << std::endl;
    
    monitor.startMonitoring(500, [&captureCount](const std::vector<BYTE>& frameData) {
        // This callback runs when screen changes are detected
        captureCount++;
        std::cout << "Screen change detected! (#" << captureCount << ")" << std::endl;
        
        // Here you could:
        // 1. Save the image
        // 2. Process the data
        // 3. Send alert
        // 4. Log the event
    });
    
    // Wait for Enter key to stop monitoring
    std::cin.get();
    
    monitor.stopMonitoring();
    std::cout << "Monitoring stopped. Detected " << captureCount << " changes." << std::endl;
    
    // Clean up COM
    CoUninitialize();
    
    return 0;
}