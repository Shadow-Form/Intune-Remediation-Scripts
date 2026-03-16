<#
.SYNOPSIS
    Universal Intune remediation script template for app installation/upgrade to a minimum version.

.DESCRIPTION
    Remediates an application by:
      - Detecting installed versions in machine scope (and optionally per-user scope).
      - Acquiring an installer (download or pre-staged local path) and inferring MSI/EXE.
      - Optionally stopping running processes prior to install.
      - Temporarily relaxing MSI policy (DisableMSI=0) when needed.
      - Executing a silent install with optional arguments + installer logging.
      - Verifying the post-install state.
      - Performing optional cleanup (remove per-user installs, orphaned uninstall entries).
      - Optionally writing a marker file for compliance tracking.

    Outputs a compact JSON object and returns Intune-friendly exit codes:
        Exit 0 → Fixed/UpToDate (installed version >= expected)
        Exit 1 → Needs attention (download/installer failure, not detected, or error)

.PARAMETER AppDisplayName
    Friendly app name used across logging, matching, and output.
    Consumed by:
      - Get-SafeFileName (derives LogFile/InstallerLogPath names)
      - Write-Log (prefixes messages)
      - Uninstall-PerUserAppByName / Remove-OrphanUninstallEntries (name match)
      - JSON output (AppName)
      - Summary messages

.PARAMETER MachineExePaths
    Absolute paths or patterns (files/directories) searched in machine scope.
    Consumed by:
      - IsExpectedVersionInstalled (machine scan → Get-FileVersionInfoSafe)
      - Post-install verification

.PARAMETER PerUserRelativeExePaths
    Relative executable paths under C:\Users\<profile> (SYSTEM context).
    Consumed by:
      - Get-PerUserAppPaths (resolves candidates across profiles)
      - IsExpectedVersionInstalled (user scan)
      - Uninstall-PerUserAppByName (cleanup decision context)

.PARAMETER ExpectedVersion
    Minimum acceptable version; installed >= expected ⇒ compliant/fixed.
    Consumed by:
      - Compare-Versions (evaluation)
      - Remove-OrphanUninstallEntries (keep newer entries)
      - JSON output (ExpectedVersion)
      - Summary messages

.PARAMETER InstallerUrl
    HTTP(S) URL to the installer (MSI/EXE).
    Consumed by:
      - Get-DefaultInstallerLocalPath (file name derivation)
      - Get-Installer (download attempts)
      - Determine-InstallerType (extension fallback)

.PARAMETER InstallerLocalPath
    Pre-staged installer path or download target path.
    Consumed by:
      - Get-Installer (download or use existing file)
      - Determine-InstallerType (extension)
      - Installer execution (command building)

.PARAMETER InstallerType
    Explicit installer type ('msi'|'exe'|''), overrides detection by extension.
    Consumed by:
      - Determine-InstallerType (short-circuit when provided)
      - Installer execution block (MSI vs EXE path)

.PARAMETER MsiBaseArguments
    Base MSI args (use <PATH> placeholder; replaced with quoted InstallerLocalPath).
    Consumed by:
      - MSI command building (Start-Process msiexec.exe)
      - Installer logging switch (/l*v "<InstallerLogPath>")

.PARAMETER ExeBaseArguments
    Base EXE args (silent switches; vendor-specific).
    Consumed by:
      - EXE command building (Start-Process <exe>)

.PARAMETER AdditionalArguments
    Extra arguments appended to MSI/EXE base strings.
    Consumed by:
      - Installer execution (both MSI and EXE)

.PARAMETER LogFile
    Remediation log file path; derived from AppDisplayName if omitted.
    Consumed by:
      - Write-Log (file writing)
      - Pre-log directory creation

.PARAMETER InstallerLogPath
    Installer engine log path; derived from AppDisplayName if omitted.
    Consumed by:
      - MSI /l*v "<InstallerLogPath>"
      - EXE logging if vendor supports (not enforced by script)

.PARAMETER MaxRetries
    Download retries when acquiring the installer.
    Consumed by:
      - Get-Installer (attempt count)

.PARAMETER RetryDelaySeconds
    Delay between download retries (seconds).
    Consumed by:
      - Get-Installer (sleep between attempts)

.PARAMETER InstallerPolicyPath
    MSI policy registry path for DisableMSI.
    Consumed by:
      - MSI pre-install step (Set-ItemProperty DisableMSI=0)
      - finally block (restore original value or remove override)

.PARAMETER StopProcessesBeforeInstall
    Whether to stop running processes by name/pattern before installation.
    Consumed by:
      - Pre-install step calling Stop-RunningProcesses (guarded by this flag)

.PARAMETER ProcessNamePattern
    Wildcard pattern for processes to stop (derived from AppDisplayName if omitted).
    Consumed by:
      - Stop-RunningProcesses (process selection)

.PARAMETER GracefulTimeout
    Seconds to wait after CloseMainWindow before force-stopping.
    Consumed by:
      - Stop-RunningProcesses (graceful close window)

.PARAMETER MaxForceRetries
    Maximum attempts to Stop-Process -Force if still present.
    Consumed by:
      - Stop-RunningProcesses (force loop)

.PARAMETER MarkerFileRoot
    Directory for compliance marker files.
    Consumed by:
      - Marker file creation (post-install)

.PARAMETER CreateMarkerFile
    Whether to write a marker file after success.
    Consumed by:
      - Marker file creation (post-install guard)

.PARAMETER RemovePerUserInstallsAfterMachineInstall
    Remove user-scope installs after machine-wide success or when already up-to-date.
    Consumed by:
      - Post-install cleanup (Uninstall-PerUserAppByName guard)

.PARAMETER CleanupOrphanedUninstallEntries
    Remove orphaned/older uninstall registry entries for the app.
    Consumed by:
      - Post-install cleanup (Remove-OrphanUninstallEntries guard)

.PARAMETER VerboseMode
    Enable verbose output without passing -Verbose (friendly for Intune).
    Consumed by:
      - Initial verbosity configuration (sets $VerbosePreference)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    <#
    PURPOSE
      Friendly app name used across logging, registry matching, and JSON.
    USED BY
      - Get-SafeFileName (log path derivation)
      - Write-Log (message prefix)
      - Get-RegistryAppEntries/Uninstall-PerUserAppByName (name match)
      - Output JSON (AppName) and summary messages
    #>
    [Parameter(Mandatory=$true)]
    [string]$AppDisplayName,

    <#
    PURPOSE
      Absolute paths or path patterns (files/directories) to check in machine scope.
    USED BY
      - IsExpectedVersionInstalled (machine scan → Get-FileVersionInfoSafe)
      - Post-install verification
    #>
    [Parameter(Mandatory=$true)]
    [string[]]$MachineExePaths,

    <#
    PURPOSE
      Relative EXE paths under C:\Users\<profile> to detect per-user installs (SYSTEM context).
    USED BY
      - IsExpectedVersionInstalled (per-user scan via Get-PerUserAppPaths)
      - Optional removal of per-user installs after machine-wide remediation
    #>
    [Parameter()]
    [string[]]$PerUserRelativeExePaths = @(),

    <#
    PURPOSE
      Minimum compliant version; installed >= expected → compliant/fixed.
    USED BY
      - Compare-Versions (evaluation)
      - JSON output (ExpectedVersion)
    #>
    [Parameter(Mandatory=$true)]
    [string]$ExpectedVersion,

    <#
    PURPOSE
      HTTP(S) URL for installer (MSI/EXE). If empty, script relies on pre-staged InstallerLocalPath.
    USED BY
      - Get-DefaultInstallerLocalPath (file name)
      - Get-Installer (download)
      - Determine-InstallerType (extension)
    #>
    [Parameter()]
    [string]$InstallerUrl = "",

    <#
    PURPOSE
      Pre-staged local path for installer, or target path for downloaded file.
    USED BY
      - Get-Installer (download or use as-is)
      - Determine-InstallerType (extension)
      - Installer execution command-building
    #>
    [Parameter()]
    [string]$InstallerLocalPath = "",

    <#
    PURPOSE
      Explicit installer type (msi/exe). If empty, inferred from InstallerUrl/InstallerLocalPath extension.
    USED BY
      - Determine-InstallerType (override)
      - Installer execution (MSI vs EXE path)
    #>
    [Parameter()]
    [ValidateSet('msi','exe','')]
    [string]$InstallerType = "",

    <#
    PURPOSE
      Base MSI install args. <PATH> will be replaced with quoted InstallerLocalPath.
    USED BY
      - MSI command building (Start-Process msiexec.exe)
    DEFAULT
      /i <PATH> /qn /norestart ALLUSERS=1
    #>
    [Parameter()]
    [string]$MsiBaseArguments = "/i <PATH> /qn /norestart ALLUSERS=1",

    <#
    PURPOSE
      Base EXE install args (silent). Vendor-specific.
    USED BY
      - EXE command building (Start-Process <exe>)
    DEFAULT
      /s
    #>
    [Parameter()]
    [string]$ExeBaseArguments = "/s",

    <#
    PURPOSE
      Extra arguments appended to MSI/EXE base arguments.
    USED BY
      - Installer execution (both MSI and EXE)
    #>
    [Parameter()]
    [string]$AdditionalArguments = "",

    <#
    PURPOSE
      Log file path for remediation script. Derived from AppDisplayName if omitted.
    USED BY
      - Write-Log (file path)
    DEFAULT
      C:\Logs\Install-<App>.log
    #>
    [Parameter()]
    [string]$LogFile = "",

    <#
    PURPOSE
      Installer engine log path. Derived from AppDisplayName if omitted.
    USED BY
      - MSI /l*v switch
      - EXE logging (if supported by vendor args)
    DEFAULT
      %TEMP%\<App>-install.log
    #>
    [Parameter()]
    [string]$InstallerLogPath = "",

    <#
    PURPOSE
      Download/retry policy for acquiring installer.
    USED BY
      - Get-Installer (download attempts)
    DEFAULTS
      MaxRetries = 3, RetryDelaySeconds = 5
    #>
    [Parameter()]
    [int]$MaxRetries = 3,
    [Parameter()]
    [int]$RetryDelaySeconds = 5,

    <#
    PURPOSE
      MSI policy path used to temporarily set DisableMSI=0 (if executing MSI).
    USED BY
      - MSI pre-install step (Set-ItemProperty DisableMSI=0)
      - finally block (restore/remove override)
    DEFAULT
      HKLM:\Software\Policies\Microsoft\Windows\Installer
    #>
    [Parameter()]
    [string]$InstallerPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer",

    <#
    PURPOSE
      Stop running processes that might lock files (app binaries, updaters) before install.
    USED BY
      - Stop-RunningProcesses (pre-install)
    DEFAULTS
      StopProcessesBeforeInstall = $false
      ProcessNamePattern derived from AppDisplayName if empty
      GracefulTimeout = 10, MaxForceRetries = 5
    #>
    [Parameter()]
    [bool]$StopProcessesBeforeInstall = $false,
    [Parameter()]
    [string]$ProcessNamePattern = "",
    [Parameter()]
    [int]$GracefulTimeout = 10,
    [Parameter()]
    [int]$MaxForceRetries = 5,

    <#
    PURPOSE
      Compliance marker file written on success.
    USED BY
      - Marker file creation (post-install)
    DEFAULTS
      MarkerFileRoot = C:\ProgramData\PatchyMcPatchface
      CreateMarkerFile = $true
    #>
    [Parameter()]
    [string]$MarkerFileRoot = "C:\ProgramData\PatchyMcPatchface",
    [Parameter()]
    [bool]$CreateMarkerFile = $true,

    <#
    PURPOSE
      Remove per-user installs after machine-wide success or when expected already present.
    USED BY
      - Uninstall-PerUserAppByName (post-install cleanup)
    #>
    [Parameter()]
    [bool]$RemovePerUserInstallsAfterMachineInstall = $true,

    <#
    PURPOSE
      Remove orphaned/older uninstall registry entries after remediation.
    USED BY
      - Remove-OrphanUninstallEntries (post-install cleanup)
    #>
    [Parameter()]
    [bool]$CleanupOrphanedUninstallEntries = $true,

    <#
    PURPOSE
      Enable verbose output without passing -Verbose.
    USED BY
      - Initial verbosity configuration for Write-Verbose logs across the script.
    #>
    [Parameter()]
    [bool]$VerboseMode = $false
)

# Honor either -Verbose (native) or VerboseMode (compat boolean)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# ======================================================================
# Utilities & Logging
# ======================================================================

function Get-SafeFileName {
    <#
    PURPOSE
      Produce a Windows-safe filename from AppDisplayName.
    USED BY
      - LogFile derivation (C:\Logs\Install-<App>.log)
      - InstallerLogPath derivation (%TEMP%\<App>-install.log)
      - Marker file naming
    #>
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean   = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    $clean   = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# Derive log paths if omitted
$__safeName = Get-SafeFileName -Name $AppDisplayName
if ([string]::IsNullOrWhiteSpace($LogFile))          { $LogFile = "C:\Logs\Install-$__safeName.log" }
if ([string]::IsNullOrWhiteSpace($InstallerLogPath)) { $InstallerLogPath = Join-Path $env:TEMP "$__safeName-install.log" }

# Derive a default ProcessNamePattern if omitted
if (-not $PSBoundParameters.ContainsKey('ProcessNamePattern') -or [string]::IsNullOrWhiteSpace($ProcessNamePattern)) {
    $ProcessNamePattern = "*$((($AppDisplayName -replace '\s+', '')).ToLower())*"
}

function Write-Log {
    <#
    PURPOSE
      Writes timestamped messages to verbose output and log file.
    USED BY
      - All scan/installer/cleanup phases
    DETAILS
      Creates log directory if needed; minimal handling on write failures.
    #>
    param([string]$Message)
    Write-Verbose $Message
    try {
        $dir = Split-Path -Path $LogFile
        if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    } catch { }
}

# ======================================================================
# Version & Detection Helpers
# ======================================================================

function Format-Version {
    <#
    PURPOSE
      Normalize version strings to a dotted 4-part format.
    USED BY
      - Compare-Versions
      - Evaluation of detected versions (validity check)
    #>
    param([string]$v)
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
      - IsExpectedVersionInstalled and final evaluation
    #>
    param([string]$Installed,[string]$Expected)
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

function Get-FileVersionInfoSafe {
    <#
    PURPOSE
      Read ProductVersion/FileVersion and normalize punctuation.
    USED BY
      - Machine/per-user detection
      - Post-install verification
    #>
    param([string]$Path)
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    ($version -replace ',', '.').Trim()
}

function Get-PerUserAppPaths {
    <#
    PURPOSE
      Resolve relative paths under C:\Users\<profile> for non-system profiles.
    USED BY
      - IsExpectedVersionInstalled (per-user scan)
    DETAILS
      Expands directories/wildcards to return file candidates.
    #>
    param(
        [string[]]$RelativeExePaths,
        [string[]]$Exclusions = @('Public','Default','Default User','All Users','WDAGUtilityAccount')
    )
    if (-not $RelativeExePaths -or $RelativeExePaths.Count -eq 0) { return @() }
    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }

    $results = @()
    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $Exclusions -notcontains $_.Name } |
        ForEach-Object {
            $home = $_.FullName
            foreach ($rel in $RelativeExePaths) {
                $searchPath = Join-Path $home $rel
                try {
                    if (Test-Path -LiteralPath $searchPath) {
                        $item = Get-Item -LiteralPath $searchPath -ErrorAction SilentlyContinue
                        if ($item -and $item.PSIsContainer) {
                            Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue |
                                ForEach-Object { $results += $_.FullName }
                        } else {
                            $results += $searchPath
                        }
                    } else {
                        Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue |
                            ForEach-Object { $results += $_.FullName }
                    }
                } catch { }
            }
        }
    return $results
}

function IsExpectedVersionInstalled {
    <#
    PURPOSE
      Check machine and per-user locations for a compliant version.
    USED BY
      - Early exit (UpToDate)
      - Post-install verification
    DETAILS
      Sets $script:detectedFilePath when a compliant instance is found.
    #>
    foreach ($p in $MachineExePaths) {
        # expand candidates from file/dir/pattern
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
        } catch { }

        foreach ($candidate in $candidates) {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }
            $ver = Get-FileVersionInfoSafe -Path $candidate
            Write-Log "[$AppDisplayName] Machine version '$ver' from '$candidate'"
            try {
                if (Compare-Versions -Installed $ver -Expected $ExpectedVersion) {
                    $script:detectedFilePath = $candidate
                    return $true
                }
            } catch { Write-Log "Version comparison failed ($ver vs $ExpectedVersion): $_" }
        }
    }

    if ($PerUserRelativeExePaths.Count -gt 0) {
        foreach ($u in (Get-PerUserAppPaths -RelativeExePaths $PerUserRelativeExePaths)) {
            if (-not (Test-Path -LiteralPath $u)) { continue }
            $ver = Get-FileVersionInfoSafe -Path $u
            Write-Log "[$AppDisplayName] User version '$ver' from '$u'"
            try {
                if (Compare-Versions -Installed $ver -Expected $ExpectedVersion) {
                    $script:detectedFilePath = $u
                    return $true
                }
            } catch { Write-Log "Version comparison failed ($ver vs $ExpectedVersion): $_" }
        }
    }
    return $false
}

# ======================================================================
# Installer Acquisition & Execution Helpers
# ======================================================================

function Get-DefaultInstallerLocalPath {
    <#
    PURPOSE
      Choose a sensible local file name under %TEMP% based on URL or AppName.
    USED BY
      - Pre-download path setup
    #>
    param([string]$Url,[string]$AppName)
    if ([string]::IsNullOrWhiteSpace($Url)) { return Join-Path $env:TEMP ("$AppName-installer.bin") }
    try {
        $uri = [System.Uri]$Url
        $name = [System.IO.Path]::GetFileName($uri.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($name)) { return Join-Path $env:TEMP ("$AppName-installer.bin") }
        return Join-Path $env:TEMP $name
    } catch { return Join-Path $env:TEMP ("$AppName-installer.bin") }
}

function Get-Installer {
    <#
    PURPOSE
      Download installer or confirm pre-staged path exists. Retries on transient failures.
    USED BY
      - Main remediation flow before execution
    #>
    param([string]$Url,[string]$LocalPath,[int]$MaxRetries,[int]$DelaySec)
    if ([string]::IsNullOrWhiteSpace($Url)) {
        if (-not [string]::IsNullOrWhiteSpace($LocalPath) -and (Test-Path -LiteralPath $LocalPath)) {
            Write-Log "Using pre-staged installer '$LocalPath'"
            return $true
        }
        Write-Log "No URL and local installer path missing; cannot proceed."
        return $false
    }
    $attempt = 0
    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            Write-Log "Downloading installer (attempt $attempt) from $Url"
            Invoke-WebRequest -Uri $Url -OutFile $LocalPath -UseBasicParsing
            Write-Log "Download complete: '$LocalPath'"
            return $true
        } catch {
            Write-Log "Download attempt $attempt failed: $_"
            if ($attempt -lt $MaxRetries) {
                Write-Log "Waiting $DelaySec seconds before retrying"
                Start-Sleep -Seconds $DelaySec
            }
        }
    }
    return $false
}

function Determine-InstallerType {
    <#
    PURPOSE
      Decide MSI vs EXE based on explicit parameter or file extension.
    USED BY
      - Main remediation flow (command construction)
    #>
    param([string]$Type,[string]$Url,[string]$LocalPath)
    if (-not [string]::IsNullOrWhiteSpace($Type)) { return $Type.ToLowerInvariant() }
    $candidate = $LocalPath
    if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $Url }
    if ([string]::IsNullOrWhiteSpace($candidate)) { return "" }
    if ($candidate.ToLowerInvariant().EndsWith(".msi")) { return "msi" }
    if ($candidate.ToLowerInvariant().EndsWith(".exe")) { return "exe" }
    return ""
}

function Stop-RunningProcesses {
    <#
    PURPOSE
      Close matching processes gracefully, then force-stop if still present.
    USED BY
      - Pre-install step when StopProcessesBeforeInstall = $true
    #>
    param([string]$Pattern,[int]$GracefulSec,[int]$ForceRetries)
    Write-Log "Checking processes matching '$Pattern'"
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $Pattern }
    foreach ($p in $procs) {
        try {
            if ($PSCmdlet.ShouldProcess($p.Name, "CloseMainWindow")) {
                $null = $p.CloseMainWindow()
                Start-Sleep -Seconds $GracefulSec
            }
            if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
                Write-Log "Process '$($p.Name)' exited gracefully."
                continue
            }
            for ($i=1; $i -le $ForceRetries; $i++) {
                Write-Log "Force stopping '$($p.Name)' attempt $i"
                if ($PSCmdlet.ShouldProcess($p.Name, "Stop-Process -Force")) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds 2
                if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) { break }
            }
        } catch { Write-Log "Failed to stop process '$($p.Name)': $_" }
    }
}

# ======================================================================
# Optional Cleanup Helpers
# ======================================================================

function Uninstall-PerUserAppByName {
    <#
    PURPOSE
      Attempt to uninstall user-scope installs (HKU) matching DisplayName.
    USED BY
      - Post-install cleanup when RemovePerUserInstallsAfterMachineInstall = $true
    #>
    param([string]$AppName)
    try {
        $found = $false
        Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
            $sid = $_.PSChildName
            $root = "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            if (-not (Test-Path $root)) { return }

            Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                if ($props.DisplayName -and ($props.DisplayName -like "*$AppName*")) {
                    $found = $true
                    $cmd = $props.UninstallString
                    if ($cmd) {
                        Write-Log "Uninstalling per-user '$($props.DisplayName)' for SID $sid"
                        $silentMsiexec = ($cmd -match 'msiexec\.exe') -and ($cmd -match '/qn|/quiet')
                        $silentExe     = ($cmd -notmatch 'msiexec\.exe') -and ($cmd -match '/S|/silent|/quiet')

                        if ($cmd -match 'msiexec\.exe' -or $cmd -match '/I|/X\{') {
                            $run = $cmd + ($(if (-not $silentMsiexec) { ' /qn' } else { '' }))
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $run" -Wait -NoNewWindow
                        } else {
                            $run = $cmd + ($(if (-not $silentExe) { ' /S' } else { '' }))
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $run" -Wait -NoNewWindow
                        }
                    }
                }
            }
        }
        if (-not $found) { Write-Log "No per-user uninstall entries found for '$AppName'." }
    } catch { Write-Log "Per-user uninstall error: $_" }
}

function Remove-OrphanUninstallEntries {
    <#
    PURPOSE
      Remove orphaned or older uninstall registry entries for the app.
    USED BY
      - Post-install cleanup when CleanupOrphanedUninstallEntries = $true
    #>
    param(
        [string]$AppName,
        [string]$ExpectedVersion,
        [string]$ProtectedPath = ""
    )

    $roots = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
            $key = $_
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -and ($props.DisplayName -like "*$AppName*")) {
                $version   = $props.DisplayVersion
                $uninstall = $props.UninstallString

                if ($version) {
                    try {
                        if (Compare-Versions -Installed $version -Expected $ExpectedVersion) {
                            Write-Log "Keeping uninstall entry: $($props.DisplayName) ($version)"
                            return
                        }
                    } catch { Write-Log "Version comparison failed for $($props.DisplayName): $_" }
                }

                # Attempt silent uninstall, else remove key
                if ($uninstall) {
                    Write-Log "Attempting uninstall for $($props.DisplayName): $uninstall"
                    try {
                        if ($uninstall -match 'msiexec') {
                            $run = $uninstall
                            if ($run -notmatch '/qn|/quiet') { $run = "$run /qn" }
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c $run" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                        } else {
                            if ($uninstall -match '"?([A-Za-z]:\\[^\"]+\.exe)"?') {
                                $exe = $matches[1]
                                $argsPart = $uninstall -replace [regex]::Escape($matches[0]), ''
                                if ($argsPart -notmatch '/S|/silent|/quiet') { $argsPart = "$argsPart /S" }
                                Start-Process -FilePath $exe -ArgumentList $argsPart -Wait -NoNewWindow -ErrorAction SilentlyContinue
                            } else {
                                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstall" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                            }
                        }
                    } catch { Write-Log "Uninstall attempt failed for $($props.DisplayName): $_" }
                }

                if (Test-Path -LiteralPath $key.PSPath) {
                    Write-Log "Removing registry key: $($key.PSPath)"
                    if ($PSCmdlet.ShouldProcess($key.PSPath, "Remove registry uninstall key")) {
                        try {
                            Remove-Item -LiteralPath $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                        } catch { Write-Log "Failed to remove $($key.PSPath): $_" }
                    }
                }
            }
        }
    }
}

# ======================================================================
# Intune Output & Parameter Sanity
# ======================================================================

$intuneOutput = @{
    AppName           = $AppDisplayName
    ExpectedVersion   = $ExpectedVersion
    DetectedVersion   = ""
    Status            = "Unknown"
    InstallerType     = ""
    InstallerPath     = ""
    InstallerExitCode = ""
    InstallerLog      = ""
}

if ([string]::IsNullOrWhiteSpace($ExpectedVersion) -or ($MachineExePaths.Count -eq 0 -and $PerUserRelativeExePaths.Count -eq 0)) {
    $intuneOutput.Status = "InvalidParameters"
    Write-Log "Invalid parameters: ExpectedVersion and at least one detection path are required."
    $intuneOutput | ConvertTo-Json -Compress; exit 1
}

# ======================================================================
# Main Remediation Flow
# ======================================================================

$originalDisableMsi = $null
try {
    Write-Log "Starting remediation for '$AppDisplayName' (expected $ExpectedVersion)"

    # Early success?
    if (IsExpectedVersionInstalled) {
        $intuneOutput.DetectedVersion = (Get-FileVersionInfoSafe -Path $script:detectedFilePath)
        $intuneOutput.Status = "UpToDate"
        Write-Log "Already up-to-date ($($intuneOutput.DetectedVersion) >= $ExpectedVersion)."
        # Optional cleanup even when already compliant:
        if ($RemovePerUserInstallsAfterMachineInstall) { Uninstall-PerUserAppByName -AppName $AppDisplayName }
        if ($CleanupOrphanedUninstallEntries) { Remove-OrphanUninstallEntries -AppName $AppDisplayName -ExpectedVersion $ExpectedVersion -ProtectedPath $script:detectedFilePath }
        if ($CreateMarkerFile) {
            $markerDir = $MarkerFileRoot
            if (-not (Test-Path $markerDir)) { New-Item -Path $markerDir -ItemType Directory -Force | Out-Null }
            New-Item -Path (Join-Path $markerDir "$__safeName-$ExpectedVersion.marker") -ItemType File -Force | Out-Null
        }
        $intuneOutput | ConvertTo-Json -Compress; exit 0
    }

    # Prepare installer local path
    if ([string]::IsNullOrWhiteSpace($InstallerLocalPath)) {
        $InstallerLocalPath = Get-DefaultInstallerLocalPath -Url $InstallerUrl -AppName $__safeName
    }

    # Retrieve installer (download or use pre-staged)
    if (-not (Get-Installer -Url $InstallerUrl -LocalPath $InstallerLocalPath -MaxRetries $MaxRetries -DelaySec $RetryDelaySeconds)) {
        $intuneOutput.Status = "DownloadFailed"
        Write-Log "Failed to get installer."
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

    # Determine installer type
    $type = Determine-InstallerType -Type $InstallerType -Url $InstallerUrl -LocalPath $InstallerLocalPath
    if ([string]::IsNullOrWhiteSpace($type)) {
        $intuneOutput.Status = "InstallerTypeUnknown"
        Write-Log "Cannot determine installer type (msi/exe)."
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }
    $intuneOutput.InstallerType = $type
    $intuneOutput.InstallerPath = $InstallerLocalPath

    # Optional: stop processes
    if ($StopProcessesBeforeInstall) {
        Stop-RunningProcesses -Pattern $ProcessNamePattern -GracefulSec $GracefulTimeout -ForceRetries $MaxForceRetries
    }

    # MSI policy (only for MSI)
    if ($type -eq "msi") {
        try {
            $originalDisableMsi = Get-ItemPropertyValue -Path $InstallerPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue
            if (-not (Test-Path $InstallerPolicyPath)) { New-Item -Path $InstallerPolicyPath -Force | Out-Null }
            Set-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -Value 0
            Write-Log "Temporarily set DisableMSI = 0 for MSI install."
        } catch { Write-Log "Failed to set DisableMSI: $_" }
    }

    # Build arguments and run installer
    $exitCode = $null
    if ($type -eq "msi") {
        $msiArgs = $MsiBaseArguments.Replace("<PATH>", ('"' + $InstallerLocalPath + '"')).Trim()
        $msiArgs = "$msiArgs /l*v `"$InstallerLogPath`""
        if (-not [string]::IsNullOrWhiteSpace($AdditionalArguments)) { $msiArgs = "$msiArgs $AdditionalArguments" }
        Write-Log "Running MSI: msiexec.exe $msiArgs"
        if ($PSCmdlet.ShouldProcess($AppDisplayName, "Install MSI")) {
            $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
            $exitCode = $p.ExitCode
        }
    } else {
        $exeArgs = $ExeBaseArguments.Trim()
        if (-not [string]::IsNullOrWhiteSpace($AdditionalArguments)) { $exeArgs = "$exeArgs $AdditionalArguments" }
        Write-Log "Running EXE: `"$InstallerLocalPath`" $exeArgs"
        if ($PSCmdlet.ShouldProcess($AppDisplayName, "Install EXE")) {
            $p = Start-Process -FilePath $InstallerLocalPath -ArgumentList $exeArgs -Wait -PassThru -NoNewWindow
            $exitCode = $p.ExitCode
        }
    }

    Write-Log "Installer exit code: $exitCode (log: $InstallerLogPath)"
    $intuneOutput.InstallerExitCode = $exitCode
    $intuneOutput.InstallerLog      = $InstallerLogPath

    # Verify installation regardless of exit code (handles reboot-required scenarios)
    $finalDetected = $null
    if (IsExpectedVersionInstalled) { $finalDetected = (Get-FileVersionInfoSafe -Path $script:detectedFilePath) }

    # Cleanup tasks
    if ($RemovePerUserInstallsAfterMachineInstall) { Uninstall-PerUserAppByName -AppName $AppDisplayName }
    if ($CleanupOrphanedUninstallEntries) { Remove-OrphanUninstallEntries -AppName $AppDisplayName -ExpectedVersion $ExpectedVersion -ProtectedPath $script:detectedFilePath }
    if ($CreateMarkerFile) {
        $markerDir = $MarkerFileRoot
        if (-not (Test-Path $markerDir)) { New-Item -Path $markerDir -ItemType Directory -Force | Out-Null }
        New-Item -Path (Join-Path $markerDir "$__safeName-$ExpectedVersion.marker") -ItemType File -Force | Out-Null
    }

    # Remove downloaded installer if URL was used
    if (-not [string]::IsNullOrWhiteSpace($InstallerUrl)) {
        Remove-Item -Path $InstallerLocalPath -Force -ErrorAction SilentlyContinue
        Write-Log "Removed downloaded installer."
    }

    if ($finalDetected) {
        $intuneOutput.DetectedVersion = $finalDetected
        $intuneOutput.Status = "Fixed"
        Write-Log "Remediation succeeded: $finalDetected >= $ExpectedVersion"
        $intuneOutput | ConvertTo-Json -Compress; exit 0
    } else {
        $intuneOutput.Status = "InstallFailedOrNotDetected"
        Write-Log "Expected version not detected after remediation."
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

} catch {
    Write-Log "An error occurred: $_"
    $intuneOutput.Status = "Error"
    $intuneOutput | ConvertTo-Json -Compress
    exit 1
} finally {
    # Restore MSI policy if changed
    try {
        if ($originalDisableMsi -ne $null) {
            Set-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -Value $originalDisableMsi
            Write-Log "Restored DisableMSI=$originalDisableMsi"
        } else {
            Remove-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue
            Write-Log "Removed temporary DisableMSI override"
        }
    } catch { Write-Log "Failed to restore DisableMSI: $_" }
}
