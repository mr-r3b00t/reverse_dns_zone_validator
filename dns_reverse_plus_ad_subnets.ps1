Import-Module DnsServer

# Try to import ActiveDirectory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adAvailable = $true
    Write-Host "ActiveDirectory module loaded - AD Sites and Services subnets will be included." -ForegroundColor Green
} catch {
    Write-Host "ActiveDirectory module not available or error loading it - AD Sites and Services subnets will be skipped." -ForegroundColor Yellow
    $adAvailable = $false
}

# === Configuration ===
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

$exportFolder = Join-Path $scriptDir "DNSExports"
if (-not (Test-Path $exportFolder)) {
    New-Item -Path $exportFolder -ItemType Directory | Out-Null
    Write-Host "Created export folder: $exportFolder" -ForegroundColor Cyan
}

# Prompt for DNS server
$inputServer = Read-Host -Prompt "Enter DNS server name or IP (leave blank or '.' for local server)"
if ([string]::IsNullOrWhiteSpace($inputServer) -or $inputServer -eq ".") {
    $DnsServer = $null
    $targetDisplay = "local server"
} else {
    $DnsServer = $inputServer.Trim()
    $targetDisplay = $DnsServer
}

$commonParams = @{}
if ($DnsServer) { $commonParams['ComputerName'] = $DnsServer }

# Reverse Zone Parsing
function Get-ReverseZoneCidr {
    param ($Zone)
    if (-not $Zone.ZoneName.EndsWith('.in-addr.arpa', [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
    $zonePart = $Zone.ZoneName -replace '\.in-addr\.arpa$', ''
    $labels = $zonePart -split '\.'
    if ($labels.Count -lt 1 -or $labels.Count -gt 4) { return $null }

    $octets = @()
    for ($i = $labels.Count - 1; $i -ge 0; $i--) {
        $octets += $labels[$i]
    }
    $octets += @('0') * (4 - $labels.Count)

    $network = $octets -join '.'
    $prefix = 8 * $labels.Count
    [PSCustomObject]@{
        ZoneName = $Zone.ZoneName
        Network  = $network
        Prefix   = $prefix
        CIDR     = "$network/$prefix"
    }
}

# Byte-by-byte CIDR check
function Test-IPInNetwork {
    param (
        [string]$IP,
        [string]$Network,
        [int]$Prefix
    )

    $ipBytes = ([System.Net.IPAddress]$IP).GetAddressBytes()
    $netBytes = ([System.Net.IPAddress]$Network).GetAddressBytes()

    $fullBytes = [math]::Floor($Prefix / 8)
    $remainder = $Prefix % 8

    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($ipBytes[$i] -ne $netBytes[$i]) { return $false }
    }

    if ($remainder -gt 0) {
        $mask = (255 -shl (8 - $remainder)) -band 255
        if (($ipBytes[$fullBytes] -band $mask) -ne ($netBytes[$fullBytes] -band $mask)) { return $false }
    }

    return $true
}

# Internal tests
Write-Host "Running internal tests for logic correctness..." -ForegroundColor Cyan

$testZones = @(
    [PSCustomObject]@{ZoneName="0.168.192.in-addr.arpa"},
    [PSCustomObject]@{ZoneName="168.192.in-addr.arpa"},
    [PSCustomObject]@{ZoneName="10.in-addr.arpa"},
    [PSCustomObject]@{ZoneName="1.0.10.in-addr.arpa"},
    [PSCustomObject]@{ZoneName="5.4.3.2.in-addr.arpa"}
)
$testParsed = $testZones | ForEach-Object { Get-ReverseZoneCidr $_ }
$expectedCIDRs = @("192.168.0.0/24","192.168.0.0/16","10.0.0.0/8","10.0.1.0/24","2.3.4.5/32")

$parsePass = $true
for ($i = 0; $i -lt $testParsed.Count; $i++) {
    if ($testParsed[$i].CIDR -ne $expectedCIDRs[$i]) {
        Write-Host ("Parsing test FAILED: {0} -> {1} (expected {2})" -f $testZones[$i].ZoneName, $testParsed[$i].CIDR, $expectedCIDRs[$i]) -ForegroundColor Red
        $parsePass = $false
    }
}

$testIPs = @("192.168.0.10","192.168.1.10","10.0.1.10","10.1.0.10","1.2.3.4","2.3.4.5")
$coveragePass = $true
foreach ($ip in $testIPs) {
    $covered = $false
    foreach ($rev in $testParsed) {
        if (Test-IPInNetwork -IP $ip -Network $rev.Network -Prefix $rev.Prefix) { $covered = $true; break }
    }
    $shouldBeCovered = $ip -notin @("1.2.3.4")
    if ($covered -ne $shouldBeCovered) {
        Write-Host ("Coverage test FAILED for IP {0}: detected as {1}" -f $ip, $(if($covered){"covered"}else{"uncovered"})) -ForegroundColor Red
        $coveragePass = $false
    }
}

if ($parsePass -and $coveragePass) {
    Write-Host "All internal tests PASSED - logic is correct." -ForegroundColor Green
} else {
    Write-Host "Some internal tests failed - review above." -ForegroundColor Red
}

# Reverse zones from DNS
$reverseZones = Get-DnsServerZone @commonParams | Where-Object { $_.IsReverseLookupZone -and $_.ZoneName -like '*.in-addr.arpa' }
$reverseNetworks = $reverseZones | ForEach-Object { Get-ReverseZoneCidr $_ } | Sort-Object CIDR
$effectiveReverse = $reverseNetworks | Where-Object { $_.Prefix -ne 8 }

Write-Host ("`nAll DNS reverse zones found ({0} total):" -f $reverseNetworks.Count) -ForegroundColor Green
if ($reverseNetworks) {
    $reverseNetworks | Format-Table ZoneName, CIDR -AutoSize
    $revPath = Join-Path $exportFolder "DNS_ReverseZones.csv"
    $reverseNetworks | Export-Csv -Path $revPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported DNS reverse zones to $revPath"
}

Write-Host ("`nEffective DNS reverse zones used for coverage ({0} zones, ignoring /8):" -f $effectiveReverse.Count) -ForegroundColor Cyan
if ($effectiveReverse) {
    $effectiveReverse | Format-Table ZoneName, CIDR -AutoSize
}

# AD Sites and Services subnets
$adSubnetsParsed = @()
if ($adAvailable) {
    try {
        $adSubnets = Get-ADReplicationSubnet -Filter * -Properties Name, Site
        if ($adSubnets) {
            Write-Host ("`nFound {0} AD subnets in Sites and Services." -f $adSubnets.Count) -ForegroundColor Green
            $adPath = Join-Path $exportFolder "AD_SitesAndServices_Subnets.csv"
            $adSubnets | Select-Object Name, Site | Export-Csv -Path $adPath -NoTypeInformation -Encoding UTF8
            Write-Host "Exported AD subnets to $adPath"

            # Parse for CIDR checking
            $adSubnetsParsed = $adSubnets | ForEach-Object {
                if ($_.Name -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
                    [PSCustomObject]@{
                        SubnetCIDR = $_.Name
                        SiteDN     = $_.Site
                        Network    = $matches[1]
                        Prefix     = [int]$matches[2]
                        SiteName   = if ($_.Site) { ($_.Site -split ',')[0] -replace '^CN=' } else { "" }
                    }
                }
            }
        } else {
            Write-Host "No AD subnets found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Error retrieving AD subnets: $($_.Exception.Message)" -ForegroundColor Red
        $adAvailable = $false
    }
}

# Forward zones processing
$forwardZones = Get-DnsServerZone @commonParams | Where-Object { -not $_.IsReverseLookupZone }

$results = @()
$totalRecordsProcessed = 0
$zoneCount = $forwardZones.Count
$zoneIndex = 0

if ($zoneCount -eq 0) {
    Write-Host "`nNo forward zones found." -ForegroundColor Yellow
} else {
    foreach ($zone in $forwardZones) {
        $zoneIndex++
        $percent = [math]::Round(($zoneIndex / $zoneCount) * 100)

        Write-Progress -Activity "Processing Forward Zones" -Status ("Zone {0} of {1}: {2}" -f $zoneIndex, $zoneCount, $zone.ZoneName) -PercentComplete $percent -Id 0

        $records = @(Get-DnsServerResourceRecord @commonParams -ZoneName $zone.ZoneName -RRType A -ErrorAction SilentlyContinue)

        if ($records.Count -gt 0) {
            $recordCount = $records.Count
            $recIdx = 0
            foreach ($record in $records) {
                $recIdx++
                $totalRecordsProcessed++
                $recPercent = [math]::Round(($recIdx / $recordCount) * 100)

                Write-Progress -Activity "Processing records in $($zone.ZoneName)" -Status ("Record {0} of {1} (Total: {2})" -f $recIdx, $recordCount, $totalRecordsProcessed) -PercentComplete $recPercent -Id 1 -ParentId 0

                $ip = $record.RecordData.IPv4Address.IPAddressToString
                $hostName = $record.HostName
                $fqdn = if ($hostName -eq '@') { $zone.ZoneName } else { "$hostName.$($zone.ZoneName)" }

                # DNS reverse zone (most specific, ignoring /8)
                $matchingRev = $effectiveReverse | Where-Object { Test-IPInNetwork -IP $ip -Network $_.Network -Prefix $_.Prefix }
                $coveringReverseZone = if ($matchingRev) { ($matchingRev | Sort-Object Prefix -Descending | Select-Object -First 1).ZoneName } else { "" }

                # AD subnet (most specific)
                $adSubnetCIDR = ""
                $adSiteName = ""
                if ($adSubnetsParsed) {
                    $matchingAD = $adSubnetsParsed | Where-Object { Test-IPInNetwork -IP $ip -Network $_.Network -Prefix $_.Prefix }
                    if ($matchingAD) {
                        $best = $matchingAD | Sort-Object Prefix -Descending | Select-Object -First 1
                        $adSubnetCIDR = $best.SubnetCIDR
                        $adSiteName = $best.SiteName
                    }
                }

                $results += [PSCustomObject]@{
                    FQDN                = $fqdn
                    IPAddress           = $ip
                    CoveringReverseZone = $coveringReverseZone
                    ADSubnetCIDR        = $adSubnetCIDR
                    ADSiteName          = $adSiteName
                }
            }
            Write-Progress -Id 1 -Activity "Processing records" -Completed
        }
    }
    Write-Progress -Id 0 -Activity "Processing Forward Zones" -Completed
}

# Main export
if ($results.Count -gt 0) {
    $mainPath = Join-Path $exportFolder "Forward_A_Records_With_Mappings.csv"
    $results | Sort-Object FQDN, IPAddress | Export-Csv -Path $mainPath -NoTypeInformation -Encoding UTF8
    Write-Host ("`nExported {0} records with DNS reverse and AD subnet mappings to:`n{1}" -f $results.Count, $mainPath) -ForegroundColor Green
} else {
    Write-Host "`nNo A records found in forward zones." -ForegroundColor Yellow
}

# Summaries
$reverseUncovered = $results | Where-Object { $_.CoveringReverseZone -eq "" }
Write-Host ("`nIPs without non-/8 DNS reverse zone coverage: {0}" -f $reverseUncovered.Count)
if ($reverseUncovered.Count -gt 0) {
    $revUncPath = Join-Path $exportFolder "Uncovered_Reverse.csv"
    $reverseUncovered | Export-Csv -Path $revUncPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $revUncPath"
}

$adUncovered = $results | Where-Object { $_.ADSubnetCIDR -eq "" }
Write-Host ("IPs not in any AD Sites and Services subnet: {0}" -f $adUncovered.Count)
if ($adUncovered.Count -gt 0) {
    $adUncPath = Join-Path $exportFolder "Uncovered_AD_Subnets.csv"
    $adUncovered | Export-Csv -Path $adUncPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $adUncPath"
}

$bothUncovered = $results | Where-Object { $_.CoveringReverseZone -eq "" -and $_.ADSubnetCIDR -eq "" }
Write-Host ("IPs missing BOTH reverse zone coverage and AD subnet: {0}" -f $bothUncovered.Count)
if ($bothUncovered.Count -gt 0) {
    $bothPath = Join-Path $exportFolder "Missing_Both.csv"
    $bothUncovered | Export-Csv -Path $bothPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported to $bothPath"
}
