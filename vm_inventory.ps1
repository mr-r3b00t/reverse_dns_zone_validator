# Ignore invalid SSL/TLS certificates globally for this PowerCLI session
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false

# Check for existing VI Server connections
if ($global:DefaultVIServers.Count -gt 0) {
    Write-Host "Already connected to the following server(s):" -ForegroundColor Green
    $global:DefaultVIServers | ForEach-Object { Write-Host "  - $($_.Name) (User: $($_.User))" }
    Write-Host "Using existing connection(s)..."`n
}
else {
    # No existing connection - prompt for server name/IP
    $server = Read-Host "Enter the vCenter or ESXi server name or IP address"

    # Use current Windows credentials (prefill username, prompt only for password)
    $cred = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" -Message "Enter password for $server"

    # Connect to the server
    try {
        Connect-VIServer -Server $server -Credential $cred -ErrorAction Stop
        Write-Host "`nSuccessfully connected to $server" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to $server. Error: $($_.Exception.Message)"
        exit  # Stop script if connection fails
    }
}

# Define the output CSV path (change if desired)
$csvPath = "C:\Temp\AllVMs.csv"

# Ensure the directory exists
$csvDir = Split-Path $csvPath -Parent
if (-not (Test-Path $csvDir)) {
    New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
}

# Retrieve and store the VM data (processed once for efficiency)
$vmData = Get-VM | 
    Select-Object `
        Name,
        @{Name="HostName"; Expression={ $_.Guest.HostName }},
        PowerState,
        @{Name="IPAddress"; Expression={ ($_.Guest.IPAddress | Where-Object { $_ -ne $null -and $_ -notmatch '^169\.254\.' -and $_ -notmatch '^fe80::' }) -join ", " }},
        @{Name="ToolsVersion"; Expression={ $_.ExtensionData.Guest.ToolsVersion }},
        @{Name="ToolsStatus"; Expression={ $_.ExtensionData.Guest.ToolsStatus }},
        Notes,
        @{Name="Folder"; Expression={ if ($_.Folder) { $_.Folder.Name } else { "No Folder" } }}

# Display on screen
Write-Host "VM Inventory (displayed on screen):`n" -ForegroundColor Cyan
$vmData | Format-Table -AutoSize

# Export to CSV
$vmData | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "`nExported $($vmData.Count) VMs to CSV: $csvPath" -ForegroundColor Green
