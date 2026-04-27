<#
.SYNOPSIS
  Minimal Intune remediation template: install/upgrade app to a minimum version with one InstallerArgs parameter.

.DESCRIPTION
  Installs or upgrades an application to at least the expected version:
    - Detects version via machine paths (optional registry scan).
    - Acquires installer (URL or pre-staged local path, single attempt).
    - Uses a single InstallerArgs string for MSI or EXE; optional "<PATH>" is replaced with the actual installer path.
      * MSI: runs msiexec.exe; template appends /l*v "<InstallerLogPath>" automatically.
      * EXE: runs the installer executable directly with the provided arguments.
    - Verifies post-install and returns Intune-friendly exit codes:
        0 = Fixed / UpToDate
        1 = Needs remediation / Error

  Kept intentionally approachable for workshops:
    - Machine-only detection by default
    - Optional registry scan
    - No per-user scanning
    - No retry wrappers or process-stopping code
    - Simple logs and compact JSON

.PARAMETER AppDisplayName
  Friendly app name used for logs and JSON.
  Consumed by:
    - Get-SafeFileName (derives C:\Logs\Install-<App>.log and %TEMP%\<App>-install.log)
    - Write-Log (message prefix)
    - JSON output (AppName)

.PARAMETER MachineExePaths
  Absolute paths or patterns (files/directories) in machine scope.
  Consumed by:
    - IsExpectedVersionInstalled (machine scan → Get-FileVersionSafe)
    - Post-install verification

.PARAMETER ExpectedVersion
  Minimum acceptable version; installed >= expected ⇒ compliant/fixed.
  Consumed by:
    - Compare-Versions (evaluation)
    - JSON output (ExpectedVersion)

.PARAMETER InstallerType
  Explicit installer type ('msi'|'exe').
  Consumed by:
    - Installer execution path selection (msiexec vs exe)

.PARAMETER InstallerArgs
  Single argument string applied to MSI or EXE.
  Consumed by:
    - MSI: passed to msiexec.exe (after replacing optional "<PATH>")
    - EXE: passed to installer executable (after replacing optional "<PATH>")
  NOTE:
    - If your args need a path (MSI typically does), include "<PATH>" and it will be replaced with the quoted local installer path.
    - Example (MSI): '/i "<PATH>" /qn /norestart ALLUSERS=1'
    - Example (EXE): '/S /NORESTART' (no path needed)

.PARAMETER InstallerUrl
  HTTP(S) URL for installer (MSI/EXE). If empty, script uses InstallerLocalPath.

.PARAMETER InstallerLocalPath
  Pre-staged local path or download target path. Used for execution and "<PATH>" replacement.

.PARAMETER UseRegistryScan
  Boolean to scan Uninstall registry entries (DisplayName contains AppDisplayName).
  Default: $false. Consumed by:
    - Registry scan block (DisplayVersion only)

.PARAMETER VerboseMode
  Boolean to enable verbose output without passing -Verbose.
  Consumed by:
    - Initial verbosity configuration (Write-Verbose)
#>

[CmdletBinding(SupportsShouldProcess=$false)]
param(
  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$AppDisplayName,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string[]]$MachineExePaths,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ExpectedVersion,

  [Parameter(Mandatory=$true)]
  [ValidateSet('msi','exe')]
  [ValidateNotNullOrEmpty()]
  [string]$InstallerType,

  [Parameter(Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$InstallerArgs,

  [Parameter()]
  [string]$InstallerUrl = "",

  [Parameter()]
  [string]$InstallerSha256 = "",

  [Parameter()]
  [bool]$RequireAuthenticode = $false,

  [Parameter()]
  [string]$InstallerLocalPath = "",

  [Parameter()]
  [bool]$UseRegistryScan = $false,

  [Parameter()]
  [bool]$VerboseMode = $false
)

# Enable verbose if requested (without requiring -Verbose)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
  $VerbosePreference = 'Continue'
}

# Require modern PowerShell and stricter behaviour
#Requires -Version 5.1
Set-StrictMode -Version Latest

# --- Fixed defaults (baked in) ---
$InstallerPolicyPath = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'

# --- Helpers: safe name, logging, version formatting/comparison ---
function Get-SafeFileName {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
  )
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  $clean   = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
  $clean   = $clean.Trim().TrimEnd('.').TrimEnd()
  if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
  return $clean
}

$__safe = Get-SafeFileName -Name $AppDisplayName
$LogFile = "C:\Logs\Install-$__safe.log"
$InstallerLogPath = Join-Path $env:TEMP "$__safe-install.log"

function Write-Log {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Message
  )
  Write-Verbose $Message
  try {
    $dir = Split-Path -Path $LogFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      try { New-Item -Path $dir -ItemType Directory -Force | Out-Null } catch { Write-Verbose "Failed creating log dir $dir: $_" }
    }
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
  } catch { Write-Verbose "Failed to write to log $LogFile: $_" }
}

function Format-Version {
  [CmdletBinding()]
  param([string]$v)
  $v = ($v -replace ',', '.').Trim()
  if ($v -match '([0-9]+(?:\.[0-9]+)*)') { $v = $matches[1] } else { $v = '0' }
  $parts = $v.Split('.')
  while ($parts.Count -lt 4) { $parts += '0' }
  $parts -join '.'
}

function Compare-Versions {
  [CmdletBinding()]
  param([string]$Installed,[string]$Expected)
  $iv = Format-Version $Installed
  $ev = Format-Version $Expected

  $a = $iv.Split('.') | ForEach-Object { $n = 0; [int]::TryParse($_, [ref]$n) | Out-Null; $n }
  $b = $ev.Split('.') | ForEach-Object { $n = 0; [int]::TryParse($_, [ref]$n) | Out-Null; $n }

  $max = [Math]::Max($a.Count, $b.Count)
  for ($i=0; $i -lt $max; $i++) {
    $ai = if ($i -lt $a.Count) { $a[$i] } else { 0 }
    $bi = if ($i -lt $b.Count) { $b[$i] } else { 0 }
    if ($ai -gt $bi) { return $true }
    if ($ai -lt $bi) { return $false }
  }
  return $true
}

function Get-FileVersionSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )
  try {
    $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    return ($version -replace ',', '.').Trim()
  } catch { Write-Verbose "Failed reading version from $Path: $_"; return '' }
}

# --- Optional registry scan (DisplayVersion only) ---
function Get-RegistryAppVersions {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName
  )
  $roots = @(
    @{Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'},
    @{Hive='HKLM'; Path='SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'},
    @{Hive='HKCU'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'}
  )
  $versions = @()
  foreach ($r in $roots) {
    $base = "$($r.Hive):\$($r.Path)"
    try {
      Get-ChildItem -Path $base -ErrorAction SilentlyContinue | ForEach-Object {
        try {
          $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
          if ($p -and $p.DisplayName -and $p.DisplayName -like "*$DisplayName*") {
            if ($p.DisplayVersion) { $versions += $p.DisplayVersion }
          }
        } catch { Write-Log "Registry entry read failed for $($_.PSPath): $_" }
      }
    } catch { Write-Log "Failed to enumerate registry path $base: $_" }
  }
  return $versions
}

# --- Machine-only detection; registry optional ---
function Test-ExpectedVersionInstalled {
  [CmdletBinding()]
  param()

  foreach ($p in $MachineExePaths) {
    $candidates = @()
    try {
      if (Test-Path -LiteralPath $p) {
        $item = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
        if ($item -and $item.PSIsContainer) {
          $candidates = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
        } else {
          $candidates = @($p)
        }
      } else {
        $candidates = Get-ChildItem -Path $p -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
      }
    } catch { Write-Log "Failed enumerating path $p: $_" }

    foreach ($c in $candidates) {
      if (-not (Test-Path -LiteralPath $c)) { continue }
      $v = Get-FileVersionSafe -Path $c
      Write-Log "[$AppDisplayName] Machine version '$v' from '$c'"
      try {
        if (Compare-Versions -Installed $v -Expected $ExpectedVersion) {
          $script:detectedFilePath = $c
          return $true
        }
      } catch { Write-Log "Version compare failed ($v vs $ExpectedVersion): $_" }
    }
  }

  if ($UseRegistryScan) {
    foreach ($rv in (Get-RegistryAppVersions -DisplayName $AppDisplayName)) {
      Write-Log "[$AppDisplayName] Registry DisplayVersion '$rv'"
      try {
        if (Compare-Versions -Installed $rv -Expected $ExpectedVersion) { return $true }
      } catch { Write-Log "Registry version compare failed: $_" }
    }
  }

  return $false
}

# --- Intune output object ---
$Out = @{
  AppName           = $AppDisplayName
  ExpectedVersion   = $ExpectedVersion
  DetectedVersion   = ""
  Status            = "Unknown"
  InstallerType     = $InstallerType
  InstallerPath     = ""
  InstallerExitCode = ""
  InstallerLog      = ""
}

# --- Parameter sanity ---
if ([string]::IsNullOrWhiteSpace($ExpectedVersion) -or $MachineExePaths.Count -eq 0) {
  $Out.Status = "InvalidParameters"
  Write-Log "Invalid parameters: ExpectedVersion and at least one machine path are required."
  $Out | ConvertTo-Json -Compress | Out-Host
  exit 1
}

# --- Main (minimal) ---
$origDisableMsi = $null
try {
  Write-Log "Starting remediation for '$AppDisplayName' (expected $ExpectedVersion)"

  # Early success
  if (Test-ExpectedVersionInstalled) {
    $Out.DetectedVersion = if ($script:detectedFilePath) { Get-FileVersionSafe -Path $script:detectedFilePath } else { "" }
    $Out.Status = "UpToDate"
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 0
  }

  # Prepare local path
  if ([string]::IsNullOrWhiteSpace($InstallerLocalPath)) {
    # If URL provided, derive a sensible local name; else fall back to temp bin
    try {
      if (-not [string]::IsNullOrWhiteSpace($InstallerUrl)) {
        $uri  = [System.Uri]$InstallerUrl
        $name = [System.IO.Path]::GetFileName($uri.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($name)) { $name = "$__safe-installer.bin" }
        $InstallerLocalPath = Join-Path $env:TEMP $name
      } else {
        $InstallerLocalPath = Join-Path $env:TEMP "$__safe-installer.bin"
      }
    } catch {
      $InstallerLocalPath = Join-Path $env:TEMP "$__safe-installer.bin"
    }
  }

  # Acquire installer (single attempt)
  if (-not [string]::IsNullOrWhiteSpace($InstallerUrl)) {
    try {
      Write-Log "Downloading installer from $InstallerUrl"
      if (-not $InstallerUrl.ToLowerInvariant().StartsWith('https://')) {
        Write-Log "Refusing to download installer over non-HTTPS URL: $InstallerUrl"
        $Out.Status = "DownloadFailed"
        $Out | ConvertTo-Json -Compress | Out-Host
        exit 1
      }
      Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerLocalPath
      Write-Log "Download complete: '$InstallerLocalPath'"

      if (-not [string]::IsNullOrWhiteSpace($InstallerSha256)) {
        try {
          $hash = (Get-FileHash -Path $InstallerLocalPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
          if ($hash -ne $InstallerSha256.ToLowerInvariant()) {
            Write-Log "Installer SHA256 mismatch: expected $InstallerSha256, got $hash"
            $Out.Status = "DownloadFailed"
            $Out | ConvertTo-Json -Compress | Out-Host
            exit 1
          }
          Write-Log "Installer SHA256 verified."
        } catch { Write-Log "Hash verification failed: $_"; $Out.Status = "DownloadFailed"; $Out | ConvertTo-Json -Compress | Out-Host; exit 1 }
      }

      if ($RequireAuthenticode) {
        try {
          $sig = Get-AuthenticodeSignature -FilePath $InstallerLocalPath -ErrorAction Stop
          if ($sig.Status -ne 'Valid') { Write-Log "Authenticode signature invalid: $($sig.Status)"; $Out.Status = "DownloadFailed"; $Out | ConvertTo-Json -Compress | Out-Host; exit 1 }
          Write-Log "Authenticode signature is valid."
        } catch { Write-Log "Authenticode check failed: $_"; $Out.Status = "DownloadFailed"; $Out | ConvertTo-Json -Compress | Out-Host; exit 1 }
      }
    } catch {
      $Out.Status = "DownloadFailed"
      $Out | ConvertTo-Json -Compress | Out-Host
      exit 1
    }
  } else {
    if (-not (Test-Path -LiteralPath $InstallerLocalPath)) {
      $Out.Status = "InstallerNotFound"
      $Out | ConvertTo-Json -Compress | Out-Host
      exit 1
    }
  }

  $Out.InstallerPath = $InstallerLocalPath

  # Prepare args: replace optional <PATH> with quoted local path
  $args = $InstallerArgs
  if ($args -match '<PATH>') { $args = $args.Replace('<PATH>', ('"' + $InstallerLocalPath + '"')) }

  # Validate InstallerType vs file extension and warn if mismatched
  try {
    if ($InstallerType -eq 'msi' -and -not $InstallerLocalPath.ToLowerInvariant().EndsWith('.msi')) {
      Write-Log "Warning: InstallerType is 'msi' but installer file does not end with .msi: $InstallerLocalPath"
    }
    if ($InstallerType -eq 'exe' -and -not $InstallerLocalPath.ToLowerInvariant().EndsWith('.exe')) {
      Write-Log "Warning: InstallerType is 'exe' but installer file does not end with .exe: $InstallerLocalPath"
    }
  } catch { Write-Verbose "Installer file check failed: $_" }

  # Temporarily allow MSI (minimal policy tweak)
  if ($InstallerType -eq 'msi') {
    try {
      $origDisableMsi = Get-ItemPropertyValue -Path $InstallerPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue
      if (-not (Test-Path $InstallerPolicyPath)) { New-Item -Path $InstallerPolicyPath -Force | Out-Null }
      Set-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -Value 0
      Write-Log "Set DisableMSI=0 for MSI install."
    } catch { Write-Log "Failed to set DisableMSI: $_" }
  }

  # Run installer (minimal)
  $exit = $null
  if ($InstallerType -eq 'msi') {
    # Append installer engine logging automatically
    $msiArgs = "$args /l*v `"$InstallerLogPath`""
    Write-Log "MSI: msiexec.exe $msiArgs"
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
    $exit = $p.ExitCode
  } else {
    Write-Log "EXE: `"$InstallerLocalPath`" $args"
    $p = Start-Process -FilePath $InstallerLocalPath -ArgumentList $args -Wait -PassThru -NoNewWindow
    $exit = $p.ExitCode
  }

  $Out.InstallerExitCode = $exit
  $Out.InstallerLog      = $InstallerLogPath

  # Verify regardless of exit code (reboot-required cases)
  if (Test-ExpectedVersionInstalled) {
    $Out.DetectedVersion = if ($script:detectedFilePath) { Get-FileVersionSafe -Path $script:detectedFilePath } else { "" }
    $Out.Status = "Fixed"
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 0
  } else {
    $Out.Status = "InstallFailedOrNotDetected"
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 1
  }

} catch {
  Write-Log "Error: $_"
  $Out.Status = "Error"
  $Out | ConvertTo-Json -Compress | Out-Host
  exit 1
} finally {
  # Restore MSI policy if changed
  try {
    if ($origDisableMsi -ne $null) {
      Set-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -Value $origDisableMsi
      Write-Log "Restored DisableMSI=$origDisableMsi"
    } else {
      Remove-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue
      Write-Log "Removed temporary DisableMSI override"
    }
  } catch { Write-Log "Failed to restore DisableMSI: $_" }
}
