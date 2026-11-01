<# Capture only after confirming that the selected interface sees both directions of the IoT.
Does not reconfigure the router, enable monitor mode, or execute attacks.
#>
param(
    [Parameter(Mandatory=$true)][string]$Interface,
    [Parameter(Mandatory=$true)][string]$IoTAddress,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$SessionId,
    [Parameter(Mandatory=$true)][string]$CapturePoint,
    [int]$Minutes = 30,
    [string]$Dumpcap = 'C:\Program Files\Wireshark\dumpcap.exe',
    [string]$OutputRoot = (Join-Path $PSScriptRoot '..\data\local_captures')
)
$ErrorActionPreference = 'Stop'
$parsedAddress = $null
if (-not [System.Net.IPAddress]::TryParse($IoTAddress, [ref]$parsedAddress)) {
    throw 'IoTAddress must be a literal IPv4 or IPv6 address.'
}
if ($Minutes -lt 1 -or $Minutes -gt 1440) { throw 'Minutes must be 1..1440.' }
if (-not (Test-Path -LiteralPath $Dumpcap -PathType Leaf)) { throw 'Install Wireshark/Npcap or supply the dumpcap path.' }
$sessionPath = Join-Path ([System.IO.Path]::GetFullPath($OutputRoot)) $SessionId
if (Test-Path -LiteralPath $sessionPath) { throw 'Session already exists. Choose a new ID.' }
New-Item -ItemType Directory -Path $sessionPath -Force | Out-Null
$meta = [ordered]@{
    session_id=$SessionId; iot_ip=$IoTAddress; capture_point=$CapturePoint
    interface=$Interface; start_utc=[DateTime]::UtcNow.ToString('o')
    duration_requested_minutes=$Minutes; label='unknown'; verified_benign=$false
    note='Observational capture. Absence of known attack is not proof of benign traffic.'
}
$meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $sessionPath 'session.json') -Encoding utf8
'start_utc,end_utc,activity,label,evidence' | Set-Content -LiteralPath (Join-Path $sessionPath 'events.csv') -Encoding utf8
# Full packet lengths retained; no payload truncation that changes feature extraction.
# New file every five minutes; no ring overwrite. Stop after the requested duration.
& $Dumpcap -i $Interface -f "host $IoTAddress" -b 'duration:300' -a "duration:$($Minutes*60)" -w (Join-Path $sessionPath 'traffic.pcapng')
$captureExitCode = $LASTEXITCODE
$meta['end_utc'] = [DateTime]::UtcNow.ToString('o')
$meta['dumpcap_exit_code'] = $captureExitCode
$meta | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $sessionPath 'session.json') -Encoding utf8
Get-ChildItem -LiteralPath $sessionPath -Filter '*.pcapng' | Get-FileHash -Algorithm SHA256 |
    Select-Object Path,Hash | Export-Csv -LiteralPath (Join-Path $sessionPath 'sha256.csv') -NoTypeInformation
if ($captureExitCode -ne 0) { throw "Capture failed with exit code $captureExitCode. Inspect the saved session." }
Write-Output "Capture saved to $sessionPath. Verify visibility, packet loss, device identity and event labels before evaluation."
