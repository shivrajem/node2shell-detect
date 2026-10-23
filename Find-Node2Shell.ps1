<#
.SYNOPSIS
    Find Node.js (and Bun) installs affected by Node2Shell (CVE-2026-111497) on Windows.

.DESCRIPTION
    Run elevated:  .\Find-Node2Shell.ps1 -AccountName "<account name>" -AccountRegion "<account region>"
    Account name and region are required and are written on every row. PowerShell asks for them
    when they are left out. Allowed characters: letters, digits, spaces and . _ - ( ) /  (up to 64).

    Looks for node.exe and bun.exe in PATH, running processes, IIS iisnode settings
    (applicationHost.config) and common install roots (Program Files, nvm-windows, fnm, Volta,
    Scoop, Chocolatey, user .bun folders). Reads each version from file metadata, or from
    --version when the file has none.

    Status values:
      AFFECTED_EOL        end-of-life Node.js line (25, 23, 20 and older): no fix, upgrade
      AFFECTED            below the fixed release for its line
      NOT_AFFECTED        at or above the fixed release
      REVIEW_NO_FIX_DATA  no fixed release known for this line
      UNKNOWN_VERSION     version could not be read

    Exit code when run locally: 0 nothing affected, 1 needs review, 2 affected.
#>
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = 'Account name these results belong to')]
    [ValidatePattern('^[A-Za-z0-9 ._()/-]{1,64}$')]
    [string]$AccountName,

    [Parameter(Mandatory, Position = 1, HelpMessage = 'Account region these results belong to')]
    [ValidatePattern('^[A-Za-z0-9 ._()/-]{1,64}$')]
    [string]$AccountRegion
)

# First fixed release per Node.js major line (security releases of 21 Oct 2026).
# Other lines below the newest fixed one (25, 23, 20 and older) are end-of-life with no fix.
# Bun bundles the same Brotli decoder and is fixed in $BunFixed.
# Confirm against https://nodejs.org/en/blog/vulnerability before relying on the results.
$FixedMap = @{ 22 = '22.23.4'; 24 = '24.22.1'; 26 = '26.12.1' }
$BunFixed = '1.4.4'

$ErrorActionPreference = 'SilentlyContinue'
$HostName = $env:COMPUTERNAME
$OsName = (Get-CimInstance Win32_OperatingSystem).Caption

# ---------- helpers ----------

function Get-Runtime([string]$Path) {
    if ((Split-Path -Leaf $Path) -match '^bun') { 'bun' } else { 'node' }
}

function Get-RuntimeVersion([string]$Path) {
    $pv = (Get-Item -LiteralPath $Path).VersionInfo.ProductVersion
    if ($pv -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    $out = & $Path --version 2>$null | Select-Object -First 1
    if ($out -match '(\d+\.\d+\.\d+)') { return $Matches[1] }
    return $null
}

function Get-Classification([string]$Runtime, [string]$Version) {
    if (-not $Version) { return 'UNKNOWN_VERSION', 'could not read version' }
    if ($Runtime -eq 'bun') {
        if ([version]$Version -lt [version]$BunFixed) { return 'AFFECTED', "below fixed Bun $BunFixed" }
        return 'NOT_AFFECTED', "at or above fixed Bun $BunFixed"
    }
    $maj = [int]$Version.Split('.')[0]
    if ($FixedMap.ContainsKey($maj)) {
        if ([version]$Version -lt [version]$FixedMap[$maj]) { return 'AFFECTED', "below fixed $($FixedMap[$maj])" }
        return 'NOT_AFFECTED', "at or above fixed $($FixedMap[$maj])"
    }
    if ($maj -lt ($FixedMap.Keys | Measure-Object -Maximum).Maximum) {
        return 'AFFECTED_EOL', "Node.js $maj is end-of-life with no fix: upgrade to a fixed line"
    }
    return 'REVIEW_NO_FIX_DATA', "no fixed version known for Node.js $maj"
}

# ---------- discovery ----------

$found = [System.Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
function Add-Candidate([string]$Path, [string]$Note = '') {
    if (-not $Path) { return }
    $Path = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    if ($found.ContainsKey($full)) {
        if ($Note -and $found[$full] -notmatch [regex]::Escape($Note)) { $found[$full] = ($found[$full], $Note | Where-Object { $_ }) -join '; ' }
    } else {
        $found[$full] = $Note
    }
}

$namePattern = '^(node|bun)\.exe$'

# PATH
Get-Command node.exe, bun.exe -All | ForEach-Object { Add-Candidate $_.Source 'in PATH' }

# Running processes
$procs = Get-CimInstance Win32_Process | Where-Object ExecutablePath
$procs | Where-Object { (Split-Path -Leaf $_.ExecutablePath) -match $namePattern } |
    ForEach-Object { Add-Candidate $_.ExecutablePath 'running process' }

# IIS iisnode (default node.exe is %ProgramFiles%\nodejs\node.exe)
$appHost = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (Test-Path $appHost) {
    [xml]$cfg = Get-Content -LiteralPath $appHost -Raw
    $cmd = $cfg.configuration.'system.webServer'.iisnode.nodeProcessCommandLine
    if ($cmd) { Add-Candidate ($cmd -replace '^\s*"?([^"]+?\.exe)"?.*$', '$1') 'IIS iisnode' }
    elseif ($cfg.configuration.'system.webServer'.iisnode) { Add-Candidate "$env:ProgramFiles\nodejs\node.exe" 'IIS iisnode' }
}

# Common install roots
$roots = @(
    "$env:ProgramFiles\nodejs", "${env:ProgramFiles(x86)}\nodejs", 'C:\nvm4w\nodejs', 'C:\node*', 'C:\tools\node*',
    'C:\Users\*\AppData\Roaming\nvm\v*', 'C:\Users\*\AppData\Roaming\fnm\node-versions\*\installation',
    'C:\Users\*\AppData\Local\Volta\tools\image\node\*', 'C:\Users\*\scoop\apps\nodejs*\*',
    'C:\Users\*\.bun\bin', "$env:ProgramData\chocolatey\lib\nodejs*\tools", "$env:ProgramData\chocolatey\bin"
)
foreach ($r in $roots) {
    Get-Item -Path $r | Where-Object PSIsContainer | ForEach-Object {
        Get-ChildItem -LiteralPath $_.FullName -Depth 1 -File |
            Where-Object { $_.Name -match $namePattern } | ForEach-Object { Add-Candidate $_.FullName }
    }
}

# ---------- report ----------

$runningPaths = @($procs | ForEach-Object ExecutablePath)
$results = foreach ($path in $found.Keys) {
    $rt = Get-Runtime $path
    $ver = Get-RuntimeVersion $path
    $status, $note = Get-Classification $rt $ver
    $extra = $found[$path]
    $running = if ($runningPaths -contains $path) { 'yes' } else { 'no' }
    if ($extra) { $note = "$note; $extra" }
    [pscustomobject]@{
        AccountName   = $AccountName
        AccountRegion = $AccountRegion
        Host    = $HostName
        OS      = $OsName
        Runtime = $rt
        Source  = 'binary'
        Path    = $path
        Version = if ($ver) { $ver } else { '?' }
        Status  = $status
        Running = $running
        Note    = $note
    }
}

if (-not $results) {
    $results = [pscustomobject]@{
        AccountName = $AccountName; AccountRegion = $AccountRegion
        Host = $HostName; OS = $OsName; Runtime = ''; Source = 'none'; Path = ''; Version = ''
        Status = 'NO_NODE_FOUND'; Running = ''; Note = 'no Node.js or Bun found in common locations'
    }
}

$results

$worst = 0
foreach ($r in $results) {
    if ($r.Status -like 'AFFECTED*') { $worst = 2 }
    elseif ($r.Status -match '^(REVIEW|UNKNOWN)' -and $worst -lt 1) { $worst = 1 }
}
if (-not $PSSenderInfo) { exit $worst }
