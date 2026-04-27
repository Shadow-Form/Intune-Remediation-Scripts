<#
.SYNOPSIS
  Minimal Intune detection template: machine-path scan + (optional) registry scan.

.DESCRIPTION
  Scans one or more machine-wide paths to detect an installed app, reads the file version,
  compares against an expected minimum, and returns Intune-friendly exit codes:

    Exit 0 → Compliant (installed >= expected)
    Exit 1 → Needs remediation (missing, malformed, outdated, or error) — unless you opt out

  A small JSON summary is written to stdout to aid troubleshooting.
  Logging is intentionally simple (single write, no retry).

.PARAMETER AppDisplayName
  Friendly app name used in log file naming and JSON output.
  Consumed by:
    - Get-SafeFileName (derives log path)
    - Write-Log (messages)
    - Optional registry scan (display name match)
    - JSON output (AppName)

.PARAMETER MachinePaths
  Absolute paths or path patterns in machine scope (files or directories).
  Consumed by:
    - Machine scan block (enumerates candidates)
    - Get-FileVersionSafe (collects version)

.PARAMETER ExpectedVersion
  Minimum version required for compliance.
  Consumed by:
    - Compare-Versions (evaluation)
    - JSON output (ExpectedVersion)

.PARAMETER UseRegistryScan
  Boolean to enable Uninstall registry scanning using AppDisplayName as a filter.
  Default: $false (off)
  Consumed by:
    - Registry scan block (DisplayVersion collection)

.PARAMETER TriggerRemediationForMissingApp
  Boolean to control exit code when the app is not found or no valid instance is detected.
  Default: $true (trigger remediation)
  Consumed by:
    - Early “no findings” decision
    - Final “NotInstalled” decision after evaluation

.PARAMETER VerboseMode
  Boolean to enable verbose output without passing -Verbose.
  Default: $false
  Consumed by:
    - Initial verbosity configuration for Write-Verbose calls.
#>

[CmdletBinding(SupportsShouldProcess = $false)]
param(
  # AppDisplayName → used by Get-SafeFileName, Write-Log, registry matching, JSON
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$AppDisplayName,

  # MachinePaths → used by machine scan → Get-FileVersionSafe
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string[]]$MachinePaths,

  # ExpectedVersion → compared in evaluation via Compare-Versions
  [Parameter(Mandatory = $true)]
  [ValidateNotNullOrEmpty()]
  [string]$ExpectedVersion,

  # UseRegistryScan → guards registry scan block in main (default: off)
  [bool]$UseRegistryScan = $false,

  # TriggerRemediationForMissingApp → controls exit code when not found or no valid instance (default: on)
  [bool]$TriggerRemediationForMissingApp = $true,

  # AllowLocalLogging → when $true detection will write a local log; default is $false to remain read-only
  [bool]$AllowLocalLogging = $false,

  # VerboseMode → enables verbose flow without -Verbose (default: off)
  [bool]$VerboseMode = $false
)

# Honor either -Verbose (native) or VerboseMode (compat boolean)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
  $VerbosePreference = 'Continue'
}

# Require a modern PowerShell and enable strict mode for safer scripts
#Requires -Version 5.1
Set-StrictMode -Version Latest

# --- Log path is always derived from AppDisplayName (no parameter) ---
function Get-SafeFileName {
  <#
    PURPOSE
      Produce a Windows-safe filename from AppDisplayName.
    USED BY
      Log path derivation (C:\Logs\Detect-<App>.log)
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
  )
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  $clean = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
  $clean = $clean.Trim().TrimEnd('.').TrimEnd()
  if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
  return $clean
}

$LogFile = "C:\Logs\Detect-$(Get-SafeFileName -Name $AppDisplayName).log"

function Write-Log {
  <#
    PURPOSE
      Writes a single log line (no retry). If directory is missing, create it once.
    USED BY
      Machine/registry scan notes and evaluation summary.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Message
  )

  Write-Verbose $Message

  if (-not $AllowLocalLogging) { return }
  if (-not $LogFile) { return }
  $dir = Split-Path -Path $LogFile
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    try { New-Item -Path $dir -ItemType Directory -Force | Out-Null } catch { Write-Verbose "Failed to create log directory $dir: $_" }
  }

  try {
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
  }
  catch {
    Write-Verbose "Failed to write to log file $LogFile: $_"
  }
}

# --- Version helpers kept small and readable ---
function Format-Version {
  <#
    PURPOSE
      Normalize a version string (commas→dots, trim text, extract the first dotted numeric sequence).
    USED BY
      Compare-Versions and the evaluation loop.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [string]$v
  )
  $v = ($v -replace ',', '.').Trim()
  if ($v -match '([0-9]+(?:\.[0-9]+)*)') { $v = $matches[1] } else { $v = '0' }
  $parts = $v.Split('.')
  while ($parts.Count -lt 4) { $parts += '0' }
  $parts -join '.'
}

function Compare-Versions {
  <#
    PURPOSE
      Return $true when Installed >= Expected; else $false.
    USED BY
      Evaluation loop determining compliant vs outdated.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Installed,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Expected
  )

  $iv = Format-Version $Installed
  $ev = Format-Version $Expected

  $a = $iv.Split('.') | ForEach-Object { $n = 0; [int]::TryParse($_, [ref]$n) | Out-Null; $n }
  $b = $ev.Split('.') | ForEach-Object { $n = 0; [int]::TryParse($_, [ref]$n) | Out-Null; $n }

  $max = [Math]::Max($a.Count, $b.Count)
  for ($i = 0; $i -lt $max; $i++) {
    $ai = if ($i -lt $a.Count) { $a[$i] } else { 0 }
    $bi = if ($i -lt $b.Count) { $b[$i] } else { 0 }
    if ($ai -gt $bi) { return $true }
    if ($ai -lt $bi) { return $false }
  }
  return $true
}

function Get-FileVersionSafe {
  <#
    PURPOSE
      Read ProductVersion/FileVersion and normalize punctuation.
    USED BY
      Machine scan (file candidates) and registry file references (if present).
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )
  try {
    $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    return ($version -replace ',', '.').Trim()
  }
  catch {
    Write-Verbose "Failed to read version info for $Path: $_"
    return ''
  }
}

# --- Minimal registry scan (optional) ---
function Get-RegistryAppEntries {
  <#
    PURPOSE
      Return Uninstall entries whose DisplayName contains AppDisplayName.
    USED BY
      Optional registry scan (DisplayVersion feeds evaluation).
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName
  )

  $roots = @(
    @{Hive = 'HKLM'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' },
    @{Hive = 'HKLM'; Path = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
    @{Hive = 'HKCU'; Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' }
  )

  $results = @()
  foreach ($r in $roots) {
    $base = "$($r.Hive):\$($r.Path)"
    try {
      Get-ChildItem -Path $base -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
          if ($p -and $p.DisplayName -and $p.DisplayName -like "*$DisplayName*") {
            $results += [pscustomobject]@{
              RegistryPath    = $_.PSPath
              DisplayName     = $p.DisplayName
              DisplayVersion  = $p.DisplayVersion
              InstallLocation = $p.InstallLocation
              DisplayIcon     = $p.DisplayIcon
              Scope           = ($_.PSPath -like 'HKEY_CURRENT_USER*') ? 'User' : 'Machine'
            }
          }
        }
        catch { Write-Verbose "Registry entry read failed for $($_.PSPath): $_" }
      }
    }
    catch { Write-Verbose "Failed to enumerate registry path $base: $_" }
  }
  return $results
}

# --- Output object and defaults ---
$Out = @{
  AppName         = $AppDisplayName
  FilePath        = ""
  ExpectedVersion = $ExpectedVersion
  DetectedVersion = ""
  InstallScope    = ""
  Status          = "NotDetected"
}

# --- Machine scan (single pass) ---
$findings = @()

foreach ($path in $MachinePaths) {
  $candidates = @()
  try {
    if (Test-Path -LiteralPath $path) {
      $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
      if ($item -and $item.PSIsContainer) {
        $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
      }
      else {
        $candidates = @($path)
      }
    }
    else {
      $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
    }
  }
  catch { Write-Verbose "Failed enumerating $path: $_" }

  foreach ($candidate in $candidates) {
    if (-not (Test-Path -LiteralPath $candidate)) { continue }
    $ver = Get-FileVersionSafe -Path $candidate
    Write-Log "[$AppDisplayName] Machine version '$ver' from '$candidate'"
    $findings += [pscustomobject]@{ Source = 'File'; Path = $candidate; Version = $ver; Scope = 'Machine' }
  }
}

# --- Optional registry scan (single pass) ---
if ($UseRegistryScan) {
  try {
    $reg = Get-RegistryAppEntries -DisplayName $AppDisplayName
    foreach ($r in $reg) {
      Write-Log "[$AppDisplayName] Registry '$($r.RegistryPath)' version '$($r.DisplayVersion)'"
      $findings += [pscustomobject]@{ Source = 'Registry'; Path = $r.RegistryPath; Version = $r.DisplayVersion; Scope = ($r.Scope) }
    }
  }
  catch {
    Write-Log "[$AppDisplayName] Registry scan failed: $_"
  }
}

# --- Early decision: nothing found ---
if ($findings.Count -eq 0) {
  $Out.Status = 'NotInstalled'
  Write-Log "[$AppDisplayName] No instances found."

  $Out | ConvertTo-Json -Compress | Out-Host
  if ($TriggerRemediationForMissingApp) { exit 1 } else { exit 0 }
}

# --- Evaluate (first meaningful finding wins) ---
$malformed = $null
$outdated = $null
$ok = $null

foreach ($f in $findings) {
  $raw = $f.Version
  $fmt = Format-Version $raw

  if ([string]::IsNullOrWhiteSpace($raw) -or ($fmt -notmatch '^\d+(\.\d+)*$')) {
    if (-not $malformed) { $malformed = $f }
    continue
  }

  try {
    if (Compare-Versions -Installed $fmt -Expected $ExpectedVersion) {
      if (-not $ok) { $ok = $f }
    }
    else {
      if (-not $outdated) { $outdated = $f }
    }
  }
  catch {
    if (-not $malformed) { $malformed = $f }
  }
}

if ($malformed) {
  $Out.FilePath = $malformed.Path
  $Out.DetectedVersion = $malformed.Version
  $Out.InstallScope = $malformed.Scope
  $Out.Status = 'MalformedVersion'
  Write-Log "[$AppDisplayName] Malformed version at '$($malformed.Path)': '$($malformed.Version)'"
  $Out | ConvertTo-Json -Compress | Out-Host
  exit 1
}

if ($outdated) {
  $Out.FilePath = $outdated.Path
  $Out.DetectedVersion = $outdated.Version
  $Out.InstallScope = $outdated.Scope
  $Out.Status = if ($outdated.Scope -eq 'User') { 'UserScopeOutdated' } else { 'Outdated' }
  Write-Log "[$AppDisplayName] Outdated at '$($outdated.Path)': '$($outdated.Version)'"
  $Out | ConvertTo-Json -Compress | Out-Host
  exit 1
}

if ($ok) {
  $Out.FilePath = $ok.Path
  $Out.DetectedVersion = $ok.Version
  $Out.InstallScope = $ok.Scope
  $Out.Status = 'Compliant'
  Write-Log "[$AppDisplayName] Compliant at '$($ok.Path)': '$($ok.Version)'"
  $Out | ConvertTo-Json -Compress | Out-Host
  exit 0
}

# --- No meaningful instance after evaluation ---
$Out.Status = 'NotInstalled'
Write-Log "[$AppDisplayName] No valid instances detected after evaluation."
$Out | ConvertTo-Json -Compress | Out-Host

# Explicit final exit to ensure Intune receives expected code
if ($TriggerRemediationForMissingApp) { exit 1 } else { exit 0 }
