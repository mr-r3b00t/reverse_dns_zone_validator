Import-Module DnsServer

# === Configuration ===
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

$exportFolder = Join-Path $scriptDir "DNSExports"
if (-not (Test-Path $exportFolder)) {
    New-Item -Path $exportFolder -ItemType Directory | Out-Null
    Write-Host "Created export folder: $exportFolder" -ForegroundColor Cyan
}

# Prompt for server
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

# Byte-by-byte CIDR check (robust)
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
Write-Host "Running internal tests..." -ForegroundColor Cyan

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
        Write-Host ("Parsing FAILED: {0} -> {1} (expected {2})" -f $testZones[$i].ZoneName, $testParsed[$i].CIDR, $expectedCIDRs[$i]) -ForegroundColor Red
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
        Write-Host ("Coverage FAILED for IP {0}: detected as {1}" -f $ip, $(if($covered){"covered"}else{"uncovered"})) -ForegroundColor Red
        $coveragePass = $false
    }
}

if ($parsePass -and $coveragePass) {
    Write-Host "All internal tests PASSED." -ForegroundColor Green
} else {
    Write-Host "Some tests failed." -ForegroundColor Red
}

# Reverse zones
$reverseZones = Get-DnsServerZone @commonParams | Where-Object { $_.IsReverseLookupZone -and $_.ZoneName -like '*.in-addr.arpa' }
$reverseNetworks = $reverseZones | ForEach-Object { Get-ReverseZoneCidr $_ } | Sort-Object CIDR

$effectiveReverse = $reverseNetworks | Where-Object { $_.Prefix -ne 8 }

Write-Host ("`nAll reverse zones ({0} total):" -f $reverseNetworks.Count) -ForegroundColor Green
if ($reverseNetworks) {
    $reverseNetworks | Format-Table ZoneName, CIDR -AutoSize
    $revPath = Join-Path $exportFolder "ReverseZones_Ranges.csv"
    $reverseNetworks | Export-Csv -Path $revPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported all reverse zones to $revPath"
}

Write-Host ("`nEffective reverse zones for coverage ({0} zones):" -f $effectiveReverse.Count) -ForegroundColor Cyan
if ($effectiveReverse) {
    $effectiveReverse | Format-Table ZoneName, CIDR -AutoSize
}

# Forward zones - collect A records with covering reverse zone
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

        Write-Progress -Activity "Processing Forward Zones" `
                       -Status ("Zone {0} of {1}: {2}" -f $zoneIndex, $zoneCount, $zone.ZoneName) `
                       -PercentComplete $percent -Id 0

        $records = @(Get-DnsServerResourceRecord @commonParams -ZoneName $zone.ZoneName -RRType A -ErrorAction SilentlyContinue)

        if ($records.Count -gt 0) {
            $recordCount = $records.Count
            $recIdx = 0
            foreach ($record in $records) {
                $recIdx++
                $totalRecordsProcessed++
                $recPercent = [math]::Round(($recIdx / $recordCount) * 100)

                Write-Progress -Activity "Processing records in $($zone.ZoneName)" `
                               -Status ("Record {0} of {1} (Total: {2})" -f $recIdx, $recordCount, $totalRecordsProcessed) `
                               -PercentComplete $recPercent -Id 1 -ParentId 0

                $ip = $record.RecordData.IPv4Address.IPAddressToString
                $hostName = $record.HostName
                $fqdn = if ($hostName -eq '@') { $zone.ZoneName } else { "$hostName.$($zone.ZoneName)" }

                # Find all matching effective reverse zones, pick the most specific (highest prefix)
                $matching = $effectiveReverse | Where-Object { Test-IPInNetwork -IP $ip -Network $_.Network -Prefix $_.Prefix }
                $coveringZone = ""
                if ($matching) {
                    $coveringZone = ($matching | Sort-Object Prefix -Descending | Select-Object -First 1).ZoneName
                }

                $results += [PSCustomObject]@{
                    FQDN               = $fqdn
                    IPAddress          = $ip
                    CoveringReverseZone = $coveringZone
                }
            }
            Write-Progress -Id 1 -Activity "Processing records" -Completed
        }
    }
    Write-Progress -Id 0 -Activity "Processing Forward Zones" -Completed
}

# Export main CSV with FQDN, IP, and CoveringReverseZone (empty if not covered)
if ($results.Count -gt 0) {
    $mainCsvPath = Join-Path $exportFolder "Forward_A_Records_With_Reverse_Mapping.csv"
    $results | Sort-Object FQDN, IPAddress | Export-Csv -Path $mainCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host ("`nExported {0} forward A records with reverse zone mapping to:`n{1}" -f $results.Count, $mainCsvPath) -ForegroundColor Green
    Write-Host "Column 'CoveringReverseZone' shows the reverse zone name that covers the IP (most specific match). Empty = not covered (ignoring /8 zones)." -ForegroundColor Cyan
} else {
    Write-Host "`nNo A records found." -ForegroundColor Yellow
}

# Uncovered summary and export
$uncovered = $results | Where-Object { $_.CoveringReverseZone -eq "" }

Write-Host ("`nCoverage check complete on {0}:" -f $targetDisplay) -ForegroundColor Green
Write-Host "A records processed: $totalRecordsProcessed"
Write-Host "Uncovered IPs (no non-/8 reverse zone): $($uncovered.Count)"

if ($uncovered.Count -gt 0) {
    Write-Host "`nUncovered A records:" -ForegroundColor Red
    $uncovered | Format-Table FQDN, IPAddress -AutoSize

    $uncPath = Join-Path $exportFolder "Uncovered_IPs.csv"
    $uncovered | Export-Csv -Path $uncPath -NoTypeInformation -Encoding UTF8
    Write-Host "Exported uncovered to $uncPath"
} else {
    Write-Host "`nAll A records are covered by at least one non-/8 reverse zone." -ForegroundColor Green
}
