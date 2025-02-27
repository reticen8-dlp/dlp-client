param(
    [Parameter(Mandatory=$true)]
    [string]$ItemId
)

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.ApplicationModel.DataTransfer.Clipboard, Windows.ApplicationModel.DataTransfer, ContentType=WindowsRuntime]

# Retrieve current clipboard history.
$historyOp = [Windows.ApplicationModel.DataTransfer.Clipboard]::GetHistoryItemsAsync()
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
function Await-Task($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    return $netTask.Result
}
$historyResult = Await-Task $historyOp ([Windows.ApplicationModel.DataTransfer.ClipboardHistoryItemsResult])

# Find the item with the matching Id.
$itemToDelete = $historyResult.Items | Where-Object { $_.Id -eq $ItemId }

if ($null -eq $itemToDelete) {
    Write-Error "No clipboard item found with Id $ItemId"
    exit 1
}

# Delete the item.
[Windows.ApplicationModel.DataTransfer.Clipboard]::DeleteItemFromHistory($itemToDelete)
