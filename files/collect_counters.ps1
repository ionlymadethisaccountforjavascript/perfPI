<#
.SYNOPSIS
  Sample Windows per-process performance counters for one PID into a CSV,
  time-aligned (UTC) with IDLEBEACON's event log.

.EXAMPLE
  .\collect_counters.ps1 -TargetPid 12345 -Out counters.csv -DurationSec 1800
  .\collect_counters.ps1 -TargetProcess python -IncludeHost

.NOTES
  These are Windows OS *software* counters, not hardware PMU counters. For true
  HPCs (cycles, instructions, cache-misses) use Intel PCM/VTune or ETW PMC
  sampling via WPR. Sampling floor here is ~1 s, so sub-second beacon bursts are
  smeared - prefer max/sum aggregation over per-window means (see README).

  '% Processor Time' for a process can exceed 100 on multi-core machines;
  divide by $env:NUMBER_OF_PROCESSORS for a 0-100 figure.
#>
[CmdletBinding()]
param(
    [int]    $TargetPid = 0,
    [string] $TargetProcess = "",
    [string] $Out = "counters.csv",
    [int]    $IntervalSec = 1,
    [int]    $DurationSec = 0,      # 0 = run until Ctrl-C
    [switch] $IncludeHost
)

if ($TargetPid -eq 0 -and $TargetProcess -eq "") {
    throw "Give -TargetPid or -TargetProcess."
}
if ($TargetPid -eq 0) {
    $p = Get-Process -Name $TargetProcess -ErrorAction Stop | Select-Object -First 1
    $TargetPid = $p.Id
    Write-Host "Resolved '$TargetProcess' -> PID $TargetPid"
}

# Process V2 (recent Windows builds) puts the PID in the instance name, which
# removes the classic 'name#1' ambiguity. Fall back to Process if absent.
$setName = "Process"
if (Get-Counter -ListSet "Process V2" -ErrorAction SilentlyContinue) { $setName = "Process V2" }
Write-Host "Using counter set: $setName"

function Resolve-Instance([int]$wantPid, [string]$set) {
    $samples = (Get-Counter "\$set(*)\ID Process" -ErrorAction Stop).CounterSamples
    foreach ($s in $samples) {
        if ([int]$s.CookedValue -eq $wantPid) { return $s.InstanceName }
    }
    return $null
}

$instance = Resolve-Instance $TargetPid $setName
if (-not $instance) { throw "No counter instance found for PID $TargetPid (is it running?)" }
Write-Host "Instance: $instance"

$procCounters = @(
    "% Processor Time", "% User Time", "% Privileged Time",
    "IO Read Bytes/sec", "IO Write Bytes/sec", "IO Other Bytes/sec",
    "IO Read Operations/sec", "IO Write Operations/sec", "IO Other Operations/sec",
    "Working Set", "Working Set - Private", "Private Bytes", "Virtual Bytes",
    "Page Faults/sec", "Thread Count", "Handle Count", "Pool Paged Bytes",
    "Pool Nonpaged Bytes", "ID Process"
)
$paths = $procCounters | ForEach-Object { "\$setName($instance)\$_" }

if ($IncludeHost) {
    $nic = (Get-Counter -ListSet "Network Interface").PathsWithInstances |
           Where-Object { $_ -like "*Bytes Total/sec*" }
    $paths += $nic
    $paths += @("\TCPv4\Segments Sent/sec", "\TCPv4\Segments Received/sec",
                "\TCPv4\Connections Established",
                "\Memory\Available MBytes", "\System\Context Switches/sec")
}

Write-Host "Sampling $($paths.Count) counters every ${IntervalSec}s -> $Out"
Write-Host "Note: Process IO counters include file, network and device I/O."

$deadline = if ($DurationSec -gt 0) { (Get-Date).AddSeconds($DurationSec) } else { [DateTime]::MaxValue }
$first = $true
$n = 0

while ((Get-Date) -lt $deadline) {
    try {
        $sample = Get-Counter -Counter $paths -MaxSamples 1 -ErrorAction Stop
    }
    catch {
        # Instance name can shift when processes start/stop - re-resolve once.
        $instance = Resolve-Instance $TargetPid $setName
        if (-not $instance) { Write-Warning "PID $TargetPid gone. Stopping."; break }
        $paths = $procCounters | ForEach-Object { "\$setName($instance)\$_" }
        continue
    }

    $row = [ordered]@{
        ts        = [double](Get-Date -UFormat %s)      # UTC epoch seconds
        ts_iso    = (Get-Date).ToUniversalTime().ToString("o")
        pid       = $TargetPid
        instance  = $instance
    }
    foreach ($s in $sample.CounterSamples) {
        $leaf = ($s.Path -split "\\")[-1]
        $key = ($leaf -replace "[^a-zA-Z0-9]", "_")
        if ($s.InstanceName -and $s.Path -notlike "*$setName*") {
            $key = "$key`_$($s.InstanceName -replace '[^a-zA-Z0-9]','_')"
        }
        $row[$key] = $s.CookedValue
    }

    # Guard against instance reuse by a different process.
    if ($row["ID_Process"] -and [int]$row["ID_Process"] -ne $TargetPid) {
        $instance = Resolve-Instance $TargetPid $setName
        if (-not $instance) { Write-Warning "PID $TargetPid gone. Stopping."; break }
        $paths = $procCounters | ForEach-Object { "\$setName($instance)\$_" }
        continue
    }

    $obj = [PSCustomObject]$row
    if ($first) { $obj | Export-Csv -Path $Out -NoTypeInformation; $first = $false }
    else        { $obj | Export-Csv -Path $Out -NoTypeInformation -Append }

    $n++
    if ($n % 30 -eq 0) { Write-Host "$n samples..." }
    Start-Sleep -Seconds $IntervalSec
}

Write-Host "Done. $n samples written to $Out"
