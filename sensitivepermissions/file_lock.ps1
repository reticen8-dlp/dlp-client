param(
    [string]$filePathList
)

# Get the current user (this will be locked out)
$currentUser = whoami

# Function to completely lock a file against the specified user
function Set-Permissions {
    param(
        [string]$filePath,
        [string]$user
    )
    
    Write-Host "Locking file: $filePath for user: $user" -ForegroundColor Yellow

    # Remove inherited permissions so that no inherited rights remain
    icacls $filePath /inheritance:r

    # Remove any existing permissions for the user
    icacls $filePath /remove $user

    # Change the owner to Administrators to prevent the user from reclaiming ownership
    icacls $filePath /setowner "Administrators"

    # Deny all permissions for the user (F = Full control)
    icacls $filePath /deny $user:(F)
}

# Function to monitor a file's ACL and reapply the lock if any changes are detected
function Monitor-File {
    param(
        [string]$filePath,
        [string]$user
    )
    while ($true) {
        Start-Sleep -Seconds 5  # Check every 5 seconds

        # Retrieve the ACL lines for the file that mention the user
        $aclOutput = icacls $filePath | Select-String -Pattern $user

        # Check if the expected deny entry (with Full control) is missing
        if ($aclOutput -notmatch "DENY.*\(F\)") {
            Write-Host "Detected permission change on $filePath. Reapplying lock..." -ForegroundColor Red
            Set-Permissions -filePath $filePath -user $user
            Write-Host "Permissions reset for $filePath" -ForegroundColor Red
        }
    }
}

# Read file paths from the specified list
$filePaths = Get-Content -Path $filePathList

# Apply the lockdown and start monitoring each file
foreach ($filePath in $filePaths) {
    Set-Permissions -filePath $filePath -user $currentUser
    Start-Job -ScriptBlock {
        param($path, $user)
        Monitor-File -filePath $path -user $user
    } -ArgumentList $filePath, $currentUser
}
