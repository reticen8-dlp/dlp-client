#include <windows.h>
#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <memory>
#include <iostream>
#include <vector>
#include <thread>
#include <functional>
#include <wrl/client.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

using Microsoft::WRL::ComPtr;

class D3DScreenCapture {
private:
    ComPtr<ID3D11Device> d3dDevice;
    ComPtr<ID3D11DeviceContext> d3dContext;
    ComPtr<IDXGIOutputDuplication> deskDupl;
    DXGI_OUTPUT_DESC outputDesc;
    bool initialized = false;
    int width = 0;
    int height = 0;

public:
    D3DScreenCapture() {
        initialize();
    }

    ~D3DScreenCapture() {
        releaseResources();
    }

    bool initialize() {
        // Create D3D device
        D3D_FEATURE_LEVEL featureLevel;
        HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                                      0, nullptr, 0, D3D11_SDK_VERSION,
                                      d3dDevice.GetAddressOf(), &featureLevel, 
                                      d3dContext.GetAddressOf());
        if (FAILED(hr)) return false;

        // Get DXGI device
        ComPtr<IDXGIDevice> dxgiDevice;
        hr = d3dDevice.As(&dxgiDevice);
        if (FAILED(hr)) return false;

        // Get DXGI adapter
        ComPtr<IDXGIAdapter> dxgiAdapter;
        hr = dxgiDevice->GetAdapter(dxgiAdapter.GetAddressOf());
        if (FAILED(hr)) return false;

        // Get output (monitor)
        ComPtr<IDXGIOutput> dxgiOutput;
        hr = dxgiAdapter->EnumOutputs(0, dxgiOutput.GetAddressOf());
        if (FAILED(hr)) return false;

        hr = dxgiOutput->GetDesc(&outputDesc);
        if (FAILED(hr)) return false;

        width = outputDesc.DesktopCoordinates.right - outputDesc.DesktopCoordinates.left;
        height = outputDesc.DesktopCoordinates.bottom - outputDesc.DesktopCoordinates.top;

        // QI for Output 1
        ComPtr<IDXGIOutput1> dxgiOutput1;
        hr = dxgiOutput.As(&dxgiOutput1);
        if (FAILED(hr)) return false;

        // Create desktop duplication
        hr = dxgiOutput1->DuplicateOutput(d3dDevice.Get(), deskDupl.GetAddressOf());
        if (FAILED(hr)) return false;

        initialized = true;
        return true;
    }

    void releaseResources() {
        if (deskDupl) deskDupl.Reset();
        if (d3dContext) d3dContext.Reset();
        if (d3dDevice) d3dDevice.Reset();
        initialized = false;
    }

    bool captureScreen(std::vector<BYTE>& buffer) {
        if (!initialized && !initialize()) return false;

        // Acquire next frame
        ComPtr<IDXGIResource> desktopResource;
        DXGI_OUTDUPL_FRAME_INFO frameInfo;
        HRESULT hr = deskDupl->AcquireNextFrame(1000, &frameInfo, desktopResource.GetAddressOf());
        
        if (hr == DXGI_ERROR_WAIT_TIMEOUT) {
            return false; // No new frame
        }
        
        if (FAILED(hr)) {
            // Handle error - try to reinitialize
            releaseResources();
            if (!initialize()) return false;
            return captureScreen(buffer);
        }

        // Get texture
        ComPtr<ID3D11Texture2D> desktopTexture;
        hr = desktopResource.As(&desktopTexture);
        if (FAILED(hr)) {
            deskDupl->ReleaseFrame();
            return false;
        }

        // Create staging texture for CPU access
        D3D11_TEXTURE2D_DESC textureDesc;
        desktopTexture->GetDesc(&textureDesc);
        
        textureDesc.Usage = D3D11_USAGE_STAGING;
        textureDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        textureDesc.BindFlags = 0;
        textureDesc.MiscFlags = 0;
        
        ComPtr<ID3D11Texture2D> stagingTexture;
        hr = d3dDevice->CreateTexture2D(&textureDesc, nullptr, stagingTexture.GetAddressOf());
        if (FAILED(hr)) {
            deskDupl->ReleaseFrame();
            return false;
        }

        // Copy to staging texture
        d3dContext->CopyResource(stagingTexture.Get(), desktopTexture.Get());

        // Map texture to get data
        D3D11_MAPPED_SUBRESOURCE mappedResource;
        hr = d3dContext->Map(stagingTexture.Get(), 0, D3D11_MAP_READ, 0, &mappedResource);
        if (FAILED(hr)) {
            deskDupl->ReleaseFrame();
            return false;
        }

        // Copy data to buffer
        buffer.resize(height * width * 4); // RGBA format
        
        // Copy data row by row
        for (int y = 0; y < height; y++) {
            memcpy(
                buffer.data() + y * width * 4,
                static_cast<BYTE*>(mappedResource.pData) + y * mappedResource.RowPitch,
                width * 4
            );
        }

        // Unmap and release
        d3dContext->Unmap(stagingTexture.Get(), 0);
        deskDupl->ReleaseFrame();

        return true;
    }

    int getWidth() const { return width; }
    int getHeight() const { return height; }
};

class D3DScreenMonitor {
private:
    D3DScreenCapture capture;
    bool running = false;
    DWORD interval = 1000; // ms
    std::vector<BYTE> previousFrame;
    int width = 0;
    int height = 0;
    
public:
    D3DScreenMonitor() : 
        width(capture.getWidth()), 
        height(capture.getHeight()) {
    }
    
    void startMonitoring(DWORD intervalMs, std::function<void(const std::vector<BYTE>&)> onChange) {
        interval = intervalMs;
        running = true;
        
        // Get initial frame
        std::vector<BYTE> initialFrame;
        if (capture.captureScreen(initialFrame)) {
            previousFrame = std::move(initialFrame);
        }
        
        // Create monitoring thread
        std::thread monitorThread([this, onChange]() {
            while (running) {
                std::vector<BYTE> currentFrame;
                
                if (capture.captureScreen(currentFrame)) {
                    // If we have a previous frame to compare with
                    if (!previousFrame.empty() && compareFrames(previousFrame, currentFrame)) {
                        onChange(currentFrame);
                    }
                    
                    previousFrame = std::move(currentFrame);
                }
                
                Sleep(interval);
            }
        });
        
        monitorThread.detach();
    }
    
    void stopMonitoring() {
        running = false;
    }
    
private:
    // Compare two frames to detect changes - optimized for performance
    bool compareFrames(const std::vector<BYTE>& frame1, const std::vector<BYTE>& frame2) {
        if (frame1.size() != frame2.size()) return true;
        
        // Check only subset of pixels for performance (sampling)
        int diffCount = 0;
        int threshold = 10; // Sensitivity threshold
        int pixelStep = 20; // Sample every 20th pixel for speed
        
        for (size_t i = 0; i < frame1.size(); i += pixelStep * 4) {
            if (i + 2 >= frame1.size()) break;
            
            // RGB comparison (ignore alpha)
            if (abs(frame1[i] - frame2[i]) > 5 || 
                abs(frame1[i+1] - frame2[i+1]) > 5 || 
                abs(frame1[i+2] - frame2[i+2]) > 5) {
                diffCount++;
                if (diffCount > threshold) return true;
            }
        }
        
        return false;
    }
};

// DLP screen monitor that triggers on specific events
class DLPScreenMonitor {
private:
    D3DScreenCapture capture;
    bool running = false;
    std::thread monitorThread;
    
    // DLP rules
    bool detectClipboardChanges = true;
    bool detectSensitiveWindows = true;
    std::vector<std::wstring> sensitiveWindowTitles = {
        L"Password", L"Credential", L"Secret", L"Confidential", L"SSN", 
        L"Credit Card", L"Banking", L"Admin", L"Manager"
    };
    
public:
    void startDLPMonitoring(std::function<void(const std::string&, const std::vector<BYTE>&)> onViolation) {
        running = true;
        
        monitorThread = std::thread([this, onViolation]() {
            DWORD lastClipboardSequence = 0;
            
            while (running) {
                // Monitor for sensitive windows
                if (detectSensitiveWindows) {
                    HWND foregroundWindow = GetForegroundWindow();
                    if (foregroundWindow) {
                        wchar_t windowTitle[256];
                        GetWindowTextW(foregroundWindow, windowTitle, 256);
                        
                        for (const auto& sensitiveTitle : sensitiveWindowTitles) {
                            if (wcsstr(windowTitle, sensitiveTitle.c_str())) {
                                std::vector<BYTE> screenData;
                                if (capture.captureScreen(screenData)) {
                                    std::string reason = "Sensitive window detected: ";
                                    reason += "Window with title containing '";
                                    
                                    // Convert wide string to narrow string
                                    char narrowTitle[256];
                                    WideCharToMultiByte(CP_ACP, 0, sensitiveTitle.c_str(), -1, 
                                                     narrowTitle, 256, NULL, NULL);
                                    
                                    reason += narrowTitle;
                                    reason += "'";
                                    
                                    onViolation(reason, screenData);
                                }
                                break;
                            }
                        }
                    }
                }
                
                // Monitor clipboard changes
                if (detectClipboardChanges) {
                    DWORD currentSequence = GetClipboardSequenceNumber();
                    if (lastClipboardSequence != 0 && currentSequence != lastClipboardSequence) {
                        // Clipboard content changed
                        std::vector<BYTE> screenData;
                        if (capture.captureScreen(screenData)) {
                            onViolation("Clipboard content changed", screenData);
                        }
                    }
                    lastClipboardSequence = currentSequence;
                }
                
                Sleep(500); // Check every 500ms
            }
        });
        
        monitorThread.detach();
    }
    
    void stopDLPMonitoring() {
        running = false;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
    }
};

// Example usage
int main() {
    // Initialize COM for the thread
    CoInitialize(NULL);
    
    // Example 1: Basic Direct3D screen capture
    D3DScreenCapture capture;
    std::vector<BYTE> screenData;
    
    if (capture.captureScreen(screenData)) {
        std::cout << "Screen captured! " << screenData.size() << " bytes of data." << std::endl;
        // Here you could save or process the data
    }
    
    // Example 2: Screen monitoring
    D3DScreenMonitor monitor;
    int changeCount = 0;
    
    std::cout << "Starting screen monitoring with Direct3D. Press Enter to stop..." << std::endl;
    
    monitor.startMonitoring(250, [&changeCount](const std::vector<BYTE>& frameData) {
        changeCount++;
        std::cout << "Screen change detected! (#" << changeCount << ")" << std::endl;
        
        // Process screen changes here
    });
    
    // Example 3: DLP monitoring
    DLPScreenMonitor dlpMonitor;
    int violationCount = 0;
    
    std::cout << "Starting DLP monitoring. Press Enter to stop..." << std::endl;
    
    dlpMonitor.startDLPMonitoring([&violationCount](const std::string& reason, const std::vector<BYTE>& frameData) {
        violationCount++;
        std::cout << "DLP VIOLATION! (#" << violationCount << "): " << reason << std::endl;
        
        // Here you would typically:
        // 1. Log the violation
        // 2. Save the screenshot as evidence
        // 3. Alert security team
        // 4. Block the action if possible
    });
    
    // Wait for Enter to stop
    std::cin.get();
    
    monitor.stopMonitoring();
    dlpMonitor.stopDLPMonitoring();
    
    std::cout << "Monitoring stopped. Detected " << changeCount << " screen changes and " 
              << violationCount << " DLP violations." << std::endl;
    
    // Clean up COM
    CoUninitialize();
    
    return 0;
}