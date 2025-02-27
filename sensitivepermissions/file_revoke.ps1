param (
    [string]$filePathList
)

# Get the current user
$currentUser = whoami

# Function to restore file permissions to inherited defaults
function Restore-FilePermissions {
    param (
        [string]$filePath
    )
    
    try {
        # Reset the file's permissions to its inherited defaults
        icacls $filePath /reset
        
        # Remove any specific deny entries for the current user
        icacls $filePath /remove:d $currentUser
        
        # Remove any specific allow entries for the current user
        icacls $filePath /remove:g $currentUser
        
        Write-Host "Successfully restored default permissions for: $filePath"
        return $true
    }
    catch {
        Write-Host "Error restoring permissions for $filePath`: $_" -ForegroundColor Red
        return $false
    }
}

# Verify that the file list exists
if (-not (Test-Path -Path $filePathList)) {
    Write-Host "Error: File list not found at $filePathList" -ForegroundColor Red
    exit 1
}

# Read file paths from the provided file
$filePaths = Get-Content -Path $filePathList -ErrorAction SilentlyContinue

# --- Note on Monitoring Jobs ---
# Background monitoring jobs started by the enforce script (via Start-Job)
# are session-specific. If this revoke script runs in a new session,
# Get-Job will not return them.
#
# Recommended solution:
# 1. Modify the enforce script to record job IDs in a file.
# 2. In this script, read the job IDs and stop them using Stop-Job.
#
# Alternatively, if running in the same session, you can try:
# $monitoringJobs = Get-Job | Where-Object { $_.Command -match "Monitor-File" }
# if ($monitoringJobs) {
#     $monitoringJobs | ForEach-Object {
#         Stop-Job -Id $_.Id -Force -ErrorAction SilentlyContinue
#         Remove-Job -Id $_.Id -Force -ErrorAction SilentlyContinue
#         Write-Host "Stopped monitoring job ID: $($_.Id)"
#     }
# }
# else {
#     Write-Host "No monitoring jobs found."
# }

# Process each file to restore its permissions
$successCount = 0
$failCount = 0

foreach ($filePath in $filePaths) {
    if (Test-Path -Path $filePath) {
        $result = Restore-FilePermissions -filePath $filePath
        if ($result) {
            $successCount++
        }
        else {
            $failCount++
        }
    }
    else {
        Write-Host "Warning: File not found - $filePath" -ForegroundColor Yellow
        $failCount++
    }
}

# Final summary of the revocation process
Write-Host "`nProtection Removal Summary:" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host "Files processed successfully: $successCount" -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "Files with errors: $failCount" -ForegroundColor Red
}
Write-Host "`nFile protection revoked. If any monitoring processes persist, "
Write-Host "please ensure they are terminated manually or consider a system reboot." -ForegroundColor Cyan
