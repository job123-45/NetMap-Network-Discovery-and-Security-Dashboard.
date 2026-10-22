$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

Write-Host 'NetMap Windows-first workflow' -ForegroundColor Cyan
Write-Host "This helper scans only the private IPv4 assigned to this computer's default-route interface."

$python = Get-Command py -ErrorAction SilentlyContinue
if (-not $python) { throw 'Python launcher (py) not found. Install Python 3.10+ and reopen this terminal.' }
$nmap = Get-Command nmap -ErrorAction SilentlyContinue
if (-not $nmap) { throw 'Nmap not found. Install it from https://nmap.org/download.html, reopen PowerShell, and retry.' }

$routes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric
$localIp = $null
foreach ($route in $routes) {
    $candidate = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
        Select-Object -First 1
    if ($candidate) {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($candidate.IPAddress, [ref]$parsed)) {
            $b = $parsed.GetAddressBytes()
            $isPrivate = ($b[0] -eq 10) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31)
            if ($isPrivate) { $localIp = $candidate.IPAddress; break }
        }
    }
}
if (-not $localIp) { throw 'Could not safely identify a private IPv4 on the default-route interface. No scan was run; do not guess a target IP.' }

Write-Host "Target (this computer only): $localIp" -ForegroundColor Yellow
Write-Host 'Ports: 135,139,445,3389,8000,8080 | Scan type: TCP connect'
$confirm = Read-Host 'Type SELF to scan this computer, or anything else to cancel'
if ($confirm -cne 'SELF') { Write-Host 'Cancelled. No scan was run.'; exit 0 }

New-Item -ItemType Directory -Force -Path 'scans','outputs' | Out-Null
& py 'netmap.py' scan $localIp --scan-type connect --ports '135,139,445,3389,8000,8080' --xml 'scans/windows-own-pc.xml'
if ($LASTEXITCODE -ne 0) { throw 'Nmap scan did not complete successfully. See the error above.' }
& py 'netmap.py' report 'scans/windows-own-pc.xml' --csv 'outputs/windows-own-pc.csv' --html 'outputs/windows-own-pc.html' --hosts-csv 'outputs/windows-own-pc-hosts.csv'
if ($LASTEXITCODE -ne 0) { throw 'Report generation failed.' }
Write-Host ''
Write-Host 'Done. Open outputs\windows-own-pc.html in your browser.' -ForegroundColor Green
Write-Host 'Actual scan XML: scans\windows-own-pc.xml'
