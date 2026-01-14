# PowerShell Script to Install Requested Admin Modules
# Run this script in an elevated PowerShell session (Run as Administrator) for best results.
# - RSAT tools (AD, DNS, DHCP) require admin privileges.
# - Gallery modules install to CurrentUser scope (no admin needed for them, but admin is fine too).
# - Restart PowerShell (or log off/on) after running for modules to be fully available.

# Trust PowerShell Gallery (avoids prompts)
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted

# Install modules from PowerShell Gallery
Write-Host "Installing modules from PowerShell Gallery..."

Install-Module -Name Microsoft.Entra -Scope CurrentUser -Force -AllowClobber
# Microsoft Entra ID management (official module as of 2025+)

Install-Module -Name VMware.PowerCLI -Scope CurrentUser -Force -AllowClobber
# VMware PowerCLI

Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
# Exchange Online PowerShell

Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
# Required for advanced Microsoft Defender for Endpoint management (use Microsoft.Graph.Security cmdlets; select beta profile with Select-MgProfile -Name "beta" for some features)
# Note: There is no dedicated standalone official module for Defender for Endpoint tenant management - Microsoft.Graph provides the supported cmdlets.

# Install RSAT tools for AD, DNS, and DHCP PowerShell modules
Write-Host "Installing RSAT tools for Active Directory, DNS, and DHCP modules..."

$os = Get-CimInstance -ClassName Win32_OperatingSystem

if ($os.ProductType -eq 1) {
    # Windows Client (Desktop OS)
    Write-Host "Detected Windows client OS - installing via Windows Capabilities..."

    $capabilities = @(
        "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"  # Active Directory module + tools
        "Rsat.AD.PowerShell~~~~0.0.1.0"                 # AD PowerShell (if separate in your version)
        "Rsat.Dhcp.Tools~~~~0.0.1.0"                     # DHCP Server module
        "Rsat.Dns.Tools~~~~0.0.1.0"                      # DNS Server module (may vary by Windows version)
        "Rsat.ServerManager.Tools~~~~0.0.1.0"           # Additional management tools
    )

    foreach ($cap in $capabilities) {
        $item = Get-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue
        if ($item -and $item.State -ne "Installed") {
            Add-WindowsCapability -Online -Name $cap -ErrorAction SilentlyContinue
        }
    }
}
else {
    # Windows Server
    Write-Host "Detected Windows Server OS - installing via Windows Features..."

    $features = @(
        "RSAT-AD-PowerShell"
        "RSAT-ADDS"          # Full AD DS tools
        "RSAT-DHCP"
        "RSAT-DNS-Server"
    )

    foreach ($feature in $features) {
        $item = Get-WindowsFeature -Name $feature -ErrorAction SilentlyContinue
        if ($item -and -not $item.Installed) {
            Install-WindowsFeature -Name $feature -IncludeManagementTools
        }
    }
}

Write-Host "Installation complete!"
Write-Host "Notes:"
Write-Host "- Some capability/feature names may not exist on your specific Windows version - they will be skipped automatically."
Write-Host "- For Defender for Endpoint, connect with Connect-MgGraph and use the security-related cmdlets."
Write-Host "- Test the modules by running Import-Module <ModuleName> or using a cmdlet (e.g., Get-ADUser, Get-DhcpServerv4Scope, etc.)."
