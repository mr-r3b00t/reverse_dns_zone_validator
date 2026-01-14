# PowerShell Script to Enumerate Authorized DHCP Servers and List All Active IPv4 Leases + All Reservations
# Requirements:
# - Run on a domain-joined machine
# - Run as a user with DHCP Administrators rights (or Domain Admin)
# - Windows 10/11/Server 2012 or later
# - The RSAT DHCP tools (DhcpServer module) MUST be installed

# Check if the DhcpServer module is available
if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
    Write-Error @"
The required DhcpServer PowerShell module is not installed on this machine.

To install it (requires Administrator rights and internet access on most systems):

- On Windows 10/11 or Windows Server with Desktop Experience:
    Add-WindowsCapability -Online -Name Rsat.Dhcp.Tools~~~~0.0.1.0

- On Windows Server (including Core):
    Install-WindowsFeature RSAT-DHCP

After installation, restart PowerShell and re-run this script.

Script cannot continue without the module.
"@
    exit
}

Import-Module DhcpServer

$AllLeases = @()

# Get all authorized DHCP servers in the Active Directory domain
$AuthorizedServers = Get-DhcpServerInDC

if ($AuthorizedServers.Count -eq 0) {
    Write-Host "No authorized DHCP servers found in the domain." -ForegroundColor Red
    exit
}

$totalServers = $AuthorizedServers.Count
$serverIndex = 0

foreach ($Server in $AuthorizedServers) {
    $serverIndex++
    $ComputerName = $Server.DnsName
    if (-not $ComputerName) {
        $ComputerName = $Server.IPAddress.ToString()
    }

    # Update progress bar for servers (fixed variable parsing issue with ${})
    $percentComplete = ($serverIndex / $totalServers) * 100
    Write-Progress -Activity "Processing Authorized DHCP Servers" `
                   -Status "Server ${serverIndex} of ${totalServers}: ${ComputerName}" `
                   -PercentComplete $percentComplete

    Write-Host "Processing DHCP Server: $ComputerName" -ForegroundColor Cyan

    try {
        $Scopes = Get-DhcpServerv4Scope -ComputerName $ComputerName -ErrorAction Stop

        foreach ($Scope in $Scopes) {
            Write-Host "  Scope: $($Scope.ScopeId) - $($Scope.Name)" -ForegroundColor Yellow

            # Collect reservations first (store full object keyed by IP for easy lookup)
            $ReservationsHash = @{}
            $Reservations = @()
            try {
                $Reservations = Get-DhcpServerv4Reservation -ComputerName $ComputerName -ScopeId $Scope.ScopeId -ErrorAction SilentlyContinue
                foreach ($Res in $Reservations) {
                    $ReservationsHash[$Res.IPAddress.ToString()] = $Res
                }
            }
            catch {
                Write-Warning "    Could not retrieve reservations for scope $($Scope.ScopeId)"
            }

            # Track leased IPs
            $LeasedIPsHash = @{}

            # Get active leases for this scope
            $Leases = Get-DhcpServerv4Lease -ComputerName $ComputerName -ScopeId $Scope.ScopeId -ErrorAction Stop

            foreach ($Lease in $Leases) {
                $ipStr = $Lease.IPAddress.ToString()
                $LeasedIPsHash[$ipStr] = $true

                $IsReserved = $ReservationsHash.ContainsKey($ipStr)

                # Approximate lease start = last time the lease was issued/renewed
                $ApproxStart = $Lease.LeaseExpiryTime - $Scope.LeaseDuration

                $AllLeases += [PSCustomObject]@{
                    DhcpServer       = $ComputerName
                    ScopeId          = $Scope.ScopeId.ToString()
                    ScopeName        = $Scope.Name
                    Status           = if ($IsReserved) { "Active Reserved" } else { "Active Dynamic" }
                    IPAddress        = $ipStr
                    HostName         = if ($Lease.HostName) { $Lease.HostName } else { "(No hostname)" }
                    ClientId         = $Lease.ClientId
                    LeaseStartApprox = $ApproxStart
                    LeaseEnd         = $Lease.LeaseExpiryTime
                    IsReservation    = $IsReserved
                    HasActiveLease   = $true
                    Description      = $Lease.Description
                }
            }

            # Add reservations that have no active lease
            foreach ($ResIP in $ReservationsHash.Keys) {
                if (-not $LeasedIPsHash.ContainsKey($ResIP)) {
                    $Reservation = $ReservationsHash[$ResIP]

                    $AllLeases += [PSCustomObject]@{
                        DhcpServer       = $ComputerName
                        ScopeId          = $Scope.ScopeId.ToString()
                        ScopeName        = $Scope.Name
                        Status           = "Reserved Inactive"
                        IPAddress        = $ResIP
                        HostName         = if ($Reservation.Name -and $Reservation.Name.Trim()) { $Reservation.Name.Trim() } else { "(No reservation name)" }
                        ClientId         = $Reservation.ClientId
                        LeaseStartApprox = $null
                        LeaseEnd         = $null
                        IsReservation    = $true
                        HasActiveLease   = $false
                        Description      = $Reservation.Description
                    }
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to query DHCP server ${ComputerName}: $_"
    }
}

# Complete the progress bar
Write-Progress -Activity "Processing Authorized DHCP Servers" -Completed

# Process and output results
if ($AllLeases.Count -eq 0) {
    Write-Host "No leases or reservations found on any authorized DHCP servers." -ForegroundColor Red
}
else {
    # Sort and select columns in a logical order for display/CSV
    $SortedLeases = $AllLeases |
        Sort-Object DhcpServer, ScopeId, IPAddress |
        Select-Object DhcpServer, ScopeId, ScopeName, Status, IPAddress, HostName, ClientId, `
                      LeaseStartApprox, LeaseEnd, IsReservation, HasActiveLease, Description

    # Display on screen
    $SortedLeases | Format-Table -AutoSize

    # Export to CSV in the current directory with a timestamped filename
    $CsvPath = ".\AllDhcpLeasesAndReservations_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    $SortedLeases | Export-Csv -Path $CsvPath -NoTypeInformation

    Write-Host "Results also exported to CSV: $CsvPath" -ForegroundColor Green
}

# Notes:
# - Progress bar and warning message fixed: used ${variable} to properly delimit variables when immediately followed by a colon.
# - Now includes ALL reservations (active or inactive).
# - Status column for quick identification.
# - Everything else remains the same.
