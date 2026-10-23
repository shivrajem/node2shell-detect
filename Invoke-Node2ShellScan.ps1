<#
.SYNOPSIS
    Run Find-Node2Shell.ps1 on every host in windows_hosts.txt over WinRM and write one merged CSV.

.DESCRIPTION
    .\Invoke-Node2ShellScan.ps1 -AccountName "<account name>" -AccountRegion "<account region>"
    Account name and region are required and are written on every row and in the output file name.
    PowerShell asks for them when they are left out. Allowed characters: letters, digits, spaces
    and . _ - ( ) /  (up to 64).
    Put one host per line in windows_hosts.txt next to this script. Runs with your current Windows credentials.
    Writes node2shell_windows_<account>_<region>_<timestamp>.csv in the current folder.
#>
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = 'Account name these results belong to')]
    [ValidatePattern('^[A-Za-z0-9 ._()/-]{1,64}$')]
    [string]$AccountName,

    [Parameter(Mandatory, Position = 1, HelpMessage = 'Account region these results belong to')]
    [ValidatePattern('^[A-Za-z0-9 ._()/-]{1,64}$')]
    [string]$AccountRegion
)

$hostsFile = Join-Path $PSScriptRoot 'windows_hosts.txt'
if (-not (Test-Path $hostsFile)) { Write-Error "Create $hostsFile with one host per line."; exit 64 }

$hosts = Get-Content -LiteralPath $hostsFile | ForEach-Object Trim | Where-Object { $_ -and -not $_.StartsWith('#') }
$script = Join-Path $PSScriptRoot 'Find-Node2Shell.ps1'
$tag = ("{0}_{1}" -f $AccountName, $AccountRegion) -replace '[^A-Za-z0-9._-]', '_'
$outFile = ".\node2shell_windows_${tag}_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
$columns = 'AccountName', 'AccountRegion', 'Host', 'OS', 'Runtime', 'Source', 'Path', 'Version', 'Status', 'Running', 'Note'

$results = @(Invoke-Command -ComputerName $hosts -FilePath $script -ArgumentList $AccountName, $AccountRegion -ThrottleLimit 32 -ErrorAction SilentlyContinue -ErrorVariable remoteErrors |
    Select-Object ($columns + 'PSComputerName'))

$answered = @($results | ForEach-Object PSComputerName | Sort-Object -Unique)
$unreachable = foreach ($h in $hosts | Where-Object { $answered -notcontains $_ }) {
    $err = $remoteErrors | Where-Object { $_.TargetObject -eq $h -or $_.OriginInfo.PSComputerName -eq $h } | Select-Object -First 1
    [pscustomobject]@{
        AccountName = $AccountName; AccountRegion = $AccountRegion
        Host = $h; OS = ''; Runtime = ''; Source = 'none'; Path = ''; Version = ''
        Status = 'UNREACHABLE'; Running = ''
        Note = if ($err) { $err.Exception.Message -replace '\s+', ' ' } else { 'no response' }
    }
}

$all = @($results | Select-Object $columns) + @($unreachable)
$all | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

Write-Host "Results: $((Resolve-Path $outFile).ProviderPath)"
$all | Group-Object Status | Sort-Object Name | Format-Table Count, Name -AutoSize
$all | Where-Object Status -like 'AFFECTED*' | Sort-Object Host | Format-Table Host, Path, Version, Status, Running -AutoSize
