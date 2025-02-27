Add-Type -AssemblyName System.Runtime.WindowsRuntime

# Define an Await helper for WinRT async operations.
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]

function Await-Task($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    return $netTask.Result
}

# Load the Clipboard class (Windows 10, version 1809+ with clipboard history enabled)
$null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType=WindowsRuntime]

# Get the clipboard history asynchronously.
$historyOp = [Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync()
$historyResult = Await-Task $historyOp ([Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult])

# Build an array of text entries (ignore non‐text items).
$textItems = @()
foreach ($item in $historyResult.Items) {
    if ($item.Content.Contains([Windows.ApplicationModel.DataTransfer.StandardDataFormats]::Text)) {
        $textOp = $item.Content.GetTextAsync()
        $text = Await-Task $textOp ([string])
        # Build a custom object with the item's unique Id and its text.
        $obj = [PSCustomObject]@{
            Id   = $item.Id
            Text = $text
        }
        $textItems += $obj
    }
}
# Output as JSON.
$textItems | ConvertTo-Json
