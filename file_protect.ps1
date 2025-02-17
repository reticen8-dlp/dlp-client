param (
    [string]$filePathList
)

# Get the current user
$currentUser    = whoami

# Function to set permissions for a single file
function Set-Permissions {
    param (
        [string]$filePath,
        [string]$user
    )

    # Remove existing permissions for the user
    icacls $filePath /remove $user

    # Grant read and execute permissions
    icacls $filePath /grant "${user}:(R,X)"

    # Deny delete, rename, and move permissions
    icacls $filePath /deny "${user}:(D)"
}

# Function to monitor permissions for a single file
function Monitor-File {
    param (
        [string]$filePath,
        [string]$user
    )

    while ($true) {
        Start-Sleep -Seconds 5  # Check every 5 seconds

        # Check current permissions
        $permissions = icacls $filePath | Select-String -Pattern $user   

        if ($permissions -notmatch "R") {
            # Reset permissions if they have changed
            Set-Permissions -filePath $filePath -user $user   
            Write-Host "Permissions reset for $filePath"
        }
    }
}

# Read file paths from the temporary file
$filePaths = Get-Content -Path $filePathList

# Set permissions for each file and start monitoring
foreach ($filePath in $filePaths) {
    Set-Permissions -filePath $filePath -user $currentUser   
    Start-Job -ScriptBlock { param($path, $user) Monitor-File -filePath $path -user $user } -ArgumentList $filePath, $currentUser 
}