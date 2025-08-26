[CmdletBinding()]
param(
  [ValidateSet('quick','full','custom')] [string]$ScanType = 'quick',
  [string]$Path,
  [string]$Arg1,
  [int]$MaxWaitSeconds=900,
  [string]$LogPath="$env:TEMP\DefenderScan-script.log",
  [string]$ARLog='C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference='Stop'
$EventLog='Microsoft-Windows-Windows Defender/Operational'
$HostName=$env:COMPUTERNAME
$ScanMap=@{ quick='QuickScan'; full='FullScan'; custom='CustomScan' }
$LogMaxKB=100; $LogKeep=5; $WaitStep=5
$runStart=Get-Date

# === Arg1 Override ===
if ($Arg1) {
    if ($Arg1 -in $ScanMap.Keys) { $ScanType = $Arg1 }
    elseif (Test-Path $Arg1) { $ScanType = 'custom'; $Path = $Arg1 }
}

# === Logging Function ===
function Write-Log {
  param([string]$Message,[ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level='INFO')
  $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line="[$ts][$Level] $Message"
  switch($Level){
    'ERROR'{Write-Host $line -ForegroundColor Red}
    'WARN'{Write-Host $line -ForegroundColor Yellow}
    'DEBUG'{if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')){Write-Verbose $line}}
    default{Write-Host $line}
  }
  Add-Content -Path $LogPath -Value $line -Encoding utf8
}

# === Rotate Logs ===
function Rotate-Log {
  if(Test-Path $LogPath -PathType Leaf){
    if((Get-Item $LogPath).Length/1KB -gt $LogMaxKB){
      for($i=$LogKeep-1;$i -ge 0;$i--){
        $old="$LogPath.$i";$new="$LogPath."+($i+1)
        if(Test-Path $old){Rename-Item $old $new -Force}
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

# === Timestamp Helper ===
function Now-Timestamp {
  return (Get-Date).ToString('yyyy-MM-dd HH:mm:sszzz')
}

# === NDJSON Writer ===
function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp=Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

Rotate-Log
Write-Log "=== SCRIPT START : Defender Scan ($ScanType) ==="

$ts = Now-Timestamp
$lines = @()

try {
  # === Pre-check Defender Status ===
  $status=Get-MpComputerStatus
  if($status.AntivirusScanInProgress -or $status.FullScanRunning){
    throw "A Defender scan is already running."
  }

  # === Prepare Scan Parameters ===
  if($ScanType -eq 'custom'){
    if(-not(Test-Path $Path)){throw "Path not found: $Path"}
    if(-not(Get-Item $Path).PSIsContainer){throw "CustomScan requires a directory"}
    if($Path -notmatch '\\$'){$Path += '\'}
    $scanParams=@{ScanPath=$Path;ScanType='CustomScan'}
  } else {
    $scanParams=@{ScanType=$ScanMap[$ScanType]}
  }

  # === Start Scan ===
  Write-Log "Launching $($ScanMap[$ScanType]) path=$Path" 'INFO'
  Start-MpScan @scanParams
  $startTime=Get-Date

  # === Monitor Events ===
  $events=@();$elapsed=0
  while($elapsed -lt $MaxWaitSeconds){
    Start-Sleep $WaitStep;$elapsed += $WaitStep
    $new=Get-WinEvent -LogName $EventLog -MaxEvents 20 -ErrorAction SilentlyContinue |
         Where-Object { $_.TimeCreated -ge $startTime -and $_.Id -in 1000,1001,1116,1117 }
    if($new){$events += $new}
    if($events | Where-Object { $_.Id -eq 1001 }){break}
    if(($events | Where-Object { $_.Id -eq 1117 }) -and $elapsed -ge 60){break}
  }

  # === Parse Results ===
  $items=0;$threats=0;$names=@();$statusTag='unknown_or_timed_out'
  $evt1001=$events | Where-Object { $_.Id -eq 1001 } | Select-Object -First 1
  if($evt1001){
    $xml=[xml]$evt1001.ToXml()
    $items=[int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ItemsScanned' } | ForEach-Object { $_.'#text' })
    $threats=[int]($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ThreatsFound' } | ForEach-Object { $_.'#text' })
  }
  $names=$events | Where-Object { $_.Id -in 1116,1117 } | ForEach-Object {
    ([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'ThreatName' } | ForEach-Object { $_.'#text' }
  } | Sort-Object -Unique
  if($names){$threats=$names.Count}
  $statusTag=if($names){'detections_found'}elseif($evt1001){'clean'}else{'unknown_or_timed_out'}

  # === Threat Details ===
  foreach($n in $names){
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'defender_scan'
      copilot_action = $true
      type           = 'detection'
      threat_name    = $n
    } | ConvertTo-Json -Compress -Depth 4)
  }

  # === Summary Object (Always First) ===
  $summary=[pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'defender_scan'
    copilot_action = $true
    type           = 'summary'
    scan_type      = $ScanMap[$ScanType]
    target_path    = if($ScanType -eq 'custom'){$Path}else{$null}
    items_scanned  = $items
    threats_found  = $threats
    detections     = $names
    status         = $statusTag
    duration_s     = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  }

  $lines = @(( $summary | ConvertTo-Json -Compress -Depth 5 )) + $lines
  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err=[pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'defender_scan'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur=[int]((Get-Date)-$runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
