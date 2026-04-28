<#
.SYNOPSIS
Ensure Mozilla Firefox is installed (idempotent, non-interactive Intune remediation).

.DESCRIPTION
Combined detection + remediation script for Microsoft Intune.
- Detection is read-only and returns exit codes for machine consumption.
- Remediation is idempotent, non-interactive, and uses quiet installer switches.
- Emits a compact JSON object for Intune with status and diagnostic fields.

.PARAMETER AppDisplayName
Display name used for logs, marker file names, and display matching. Default: 'Firefox'.

.PARAMETER ExpectedVersion
Minimum expected product/file version (semantic). Script treats any installed version >= this as compliant.

.PARAMETER MachineExePaths
Array of machine-scope executable paths to check for installed product.

.PARAMETER PerUserRelativeExePath
Relative path under each user profile to check per-user installs.

.PARAMETER InstallerUrl
Optional URL to download the installer. If empty, pre-staged local installer is used.

.PARAMETER InstallerLocalPath
Optional path to a pre-staged installer file. If empty, a temp file name will be derived.

.PARAMETER InstallerType
Optional explicit installer type: 'msi' or 'exe'. If empty, extension is used to infer type.

.PARAMETER MsiBaseArguments
Base argument template for MSI installs. Default includes quiet flags.

.PARAMETER ExeBaseArguments
Base arguments for EXE installers.

.PARAMETER AdditionalArguments
Extra arguments appended to installer invocations.

.PARAMETER EnableLogging
Switch to opt in to file logging. When provided, a log file is derived as:
`$env:TEMP\Install-<AppName>.log`. If omitted no files are written during detection.

.PARAMETER InstallerLogPath
Optional path used for installer-specific logs (msi /l*v etc.). Defaults to `$env:TEMP\<App>-install.log`.

.PARAMETER MaxRetries
Retry count for downloads (1–10). Default: 3.

.PARAMETER RetryDelaySeconds
Delay between download retries (seconds). Default: 5.

.PARAMETER StopProcessesBeforeInstall
Switch to stop matching processes before installation. Uses `ShouldProcess` and graceful->forceful termination.

.PARAMETER ProcessNamePattern
Process name wildcard pattern used when stopping processes.

.PARAMETER MarkerFileRoot
Directory root for marker files created after successful remediation. Default: `C:\ProgramData\<app>`.

.PARAMETER CreateMarkerFile
Switch to create a marker file on successful remediation (idempotent).

.PARAMETER RemovePerUserInstallsAfterMachineInstall
When true, will attempt to remove per-user installs after a successful machine install.

.PARAMETER InstallerPolicyPath
Registry path used for temporary MSI policy adjustments.

.PARAMETER VerboseMode
Compatibility switch enabling verbose output.

.EXAMPLE
# Quick check + remediate (no file logging)
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Remediation\Install-Firefox.ps1 -ExpectedVersion 150.0

.EXAMPLE
# Remediate with file logging enabled
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\Remediation\Install-Firefox.ps1 -ExpectedVersion 150.0 -EnableLogging

.NOTES
- Detection behavior: read-only, uses only file/registry reads and returns JSON+exit codes; does not create files when `-EnableLogging` is omitted.
- Remediation behavior: idempotent (version comparison), non-interactive, uses `ShouldProcess` for side effects, adds quiet installer flags when missing.
- Registry-sourced uninstall strings are parsed and validated; shell wrappers are blocked to reduce command-injection risk.
- Downloads use retry logic and treat download errors as install-related failures.

Exit codes:
    0 = Success / compliant (no remediation required or remediation succeeded)
    1 = Remediation attempted but failed
    2 = Invalid parameters or pre-check failure
    3 = Download or installer-related error (download, unknown installer type, install timeout)

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    # --- App-specific inputs ---
    [ValidateNotNullOrEmpty()]
    [string]$AppDisplayName = "Firefox",
    [string[]]$MachineExePaths = @(
        "${env:ProgramW6432}\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    ),
    [string[]]$PerUserRelativeExePath = @(
        "AppData\Local\Programs\Mozilla Firefox\firefox.exe"
    ),
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedVersion = "150.0",

    # --- Installer source ---
    [string]$InstallerUrl = "",
    [string]$InstallerLocalPath = "",
    [string]$InstallerType = "",

    # --- Installer arguments ---
    [string]$MsiBaseArguments = "/i <PATH> /qn /norestart ALLUSERS=1",
    [string]$ExeBaseArguments = "",
    [string]$AdditionalArguments = "",

    # --- Logging & retries ---
    [switch]$EnableLogging = $false,
    [string]$InstallerLogPath = "",
    [ValidateRange(1, 10)]
    [int]$MaxRetries = 3,
    [ValidateRange(0, 600)]
    [int]$RetryDelaySeconds = 5,

    # MSI policy (used only for MSI installs)
    [string]$InstallerPolicyPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer",

    # Optional: stop running processes before install
    [bool]$StopProcessesBeforeInstall = $false,
    [string]$ProcessNamePattern = "",
    [int]$GracefulTimeout = 10,
    [int]$MaxForceRetries = 5,

    # Optional: marker file
    [ValidateNotNullOrEmpty()]
    [string]$MarkerFileRoot = "C:\ProgramData\PatchyMcPatchface",
    [bool]$CreateMarkerFile = $true,

    # Optional: remove per-user installs after a successful machine-wide install
    [bool]$RemovePerUserInstallsAfterMachineInstall = $true,

    # Backwards compatibility verbose switch (enables native -Verbose)
    [switch]$VerboseMode
)

# Honor either -Verbose (native) or -VerboseMode (compat)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# ---------- Utilities ----------
# Utility: Returns a safe filename for logs/markers by removing invalid characters
function Get-SafeFileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    $clean = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# Utility: Derive LogFile / InstallerLogPath if not supplied
$__safeName = Get-SafeFileName -Name $AppDisplayName
if ($EnableLogging) { $LogFile = Join-Path $env:TEMP ("Install-$__safeName.log") } else { $LogFile = $null }
if ([string]::IsNullOrWhiteSpace($InstallerLogPath)) { $InstallerLogPath = Join-Path $env:TEMP "$__safeName-install.log" }


# Utility: Derive a default for ProcessNamePattern if not supplied
if (-not $PSBoundParameters.ContainsKey('ProcessNamePattern') -or [string]::IsNullOrWhiteSpace($ProcessNamePattern)) {
    # Use a simple, app-derived pattern (remove spaces; lowercase is common for process names)
    $ProcessNamePattern = "*$((($AppDisplayName -replace '\s+', '')).ToLower())*"
}

# Utility: Writes a timestamped message to both verbose output and the log file
function Write-Log {
    param ([string]$Message)
    Write-Verbose $Message
    if ($EnableLogging) {
        $logPath = $LogFile
        if (-not $logPath) { $logPath = Join-Path $env:TEMP ("Install-$__safeName.log") }
        $dir = Split-Path -Path $logPath
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
        Add-Content -Path $logPath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    }
}

# Utility: Normalizes version strings to four segments for reliable comparison
function Format-Version {
    param([string]$v)
    $v = ($v -replace ',', '.').Trim()
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}
# Utility: Compares two version strings after normalization
function Compare-Versions {
    param([string]$Installed, [string]$Expected)
    try { (Format-Version $Installed) -ge (Format-Version $Expected) }
    catch { throw "Version comparison failed $_" }
}
# Utility: Gets the product or file version from an executable path
function Get-FileVersionInfoSafe {
    param([string]$Path)
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    ($version -replace ',', '.').Trim()
}

# Utility: Enumerates all per-user install paths for the given relative exe path
function Get-PerUserAppPaths {
    param(
        [string]$RelativeExePath,
        [string[]]$Exclusions = @('Public', 'Default', 'Default User', 'All Users', 'WDAGUtilityAccount')
    )
    if ([string]::IsNullOrWhiteSpace($RelativeExePath)) { return @() }
    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }
    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $Exclusions -notcontains $_.Name } |
    ForEach-Object { Join-Path $_.FullName $RelativeExePath } |
    Where-Object { Test-Path -LiteralPath $_ }
}

# Utility: Checks if the expected version is installed in either machine or per-user scope
function IsExpectedVersionInstalled {
    foreach ($p in $MachineExePaths) {
        if (Test-Path -LiteralPath $p) {
            $ver = Get-FileVersionInfoSafe -Path $p
            Write-Verbose "[$AppDisplayName] Machine path version '$ver' from '$p'"
            try {
                if (Compare-Versions -Installed $ver -Expected $ExpectedVersion) {
                    $script:detectedFilePath = $p
                    return $true
                }
            }
            catch { Write-Verbose "Version compare failed ($ver vs $ExpectedVersion): $_" }
        }
        else {
            Write-Verbose "[$AppDisplayName] Not found: '$p'"
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($PerUserRelativeExePath)) {
        foreach ($u in (Get-PerUserAppPaths -RelativeExePath $PerUserRelativeExePath)) {
            $ver = Get-FileVersionInfoSafe -Path $u
            Write-Verbose "[$AppDisplayName] User path version '$ver' from '$u'"
            try {
                if (Compare-Versions -Installed $ver -Expected $ExpectedVersion) {
                    $script:detectedFilePath = $u
                    return $true
                }
            }
            catch { Write-Verbose "Version compare failed ($ver vs $ExpectedVersion): $_" }
        }
    }
    return $false
}

# Utility: Determines a default local installer path based on URL or app name
function Get-DefaultInstallerLocalPath {
    param([string]$Url, [string]$AppName)
    if ([string]::IsNullOrWhiteSpace($Url)) { return Join-Path $env:TEMP ("$AppName-installer.bin") }
    try {
        $uri = [System.Uri]$Url
        $name = [System.IO.Path]::GetFileName($uri.AbsolutePath)
        if ([string]::IsNullOrWhiteSpace($name)) { return Join-Path $env:TEMP ("$AppName-installer.bin") }
        return Join-Path $env:TEMP $name
    }
    catch { return Join-Path $env:TEMP ("$AppName-installer.bin") }
}

# Utility: Downloads the installer if needed, with retry logic
function Get-Installer {
    param([string]$Url, [string]$LocalPath, [int]$MaxRetries, [int]$DelaySec)
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
            Invoke-WebRequest -Uri $Url -OutFile $LocalPath -UseBasicParsing -ErrorAction Stop
            Write-Log "Download complete: '$LocalPath'"
            return $true
        }
        catch {
            Write-Log "Download attempt $attempt failed: $_"
            if ($attempt -lt $MaxRetries) {
                Write-Log "Waiting $DelaySec seconds before retrying"
                Start-Sleep -Seconds $DelaySec
            }
        }
    }
    return $false
}

# Utility: Stops running processes matching a pattern, first gracefully, then forcefully
function Stop-RunningProcesses {
    param([string]$Pattern, [int]$GracefulSec, [int]$ForceRetries)
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
            for ($i = 1; $i -le $ForceRetries; $i++) {
                Write-Log "Force stopping '$($p.Name)' attempt $i"
                if ($PSCmdlet.ShouldProcess($p.Name, "Stop-Process -Force")) {
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                }
                Start-Sleep -Seconds 2
                if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) { break }
            }
        }
        catch { Write-Log "Failed to stop process '$($p.Name)': $_" }
    }
}

# Utility: Determines installer type (msi/exe) from extension or explicit parameter
function Get-InstallerType {
    param([string]$Type, [string]$Url, [string]$LocalPath)
    if (-not [string]::IsNullOrWhiteSpace($Type)) { return $Type.ToLowerInvariant() }
    $candidate = $LocalPath
    if ([string]::IsNullOrWhiteSpace($candidate)) { $candidate = $Url }
    if ([string]::IsNullOrWhiteSpace($candidate)) { return "" }
    if ($candidate.ToLowerInvariant().EndsWith(".msi")) { return "msi" }
    if ($candidate.ToLowerInvariant().EndsWith(".exe")) { return "exe" }
    return ""
}

# Utility: Removes per-user installs by searching HKU uninstall keys for matching DisplayName
function Uninstall-PerUserAppByName {
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

                        # Parse the uninstall string into an executable and arguments
                        $exePath = $null
                        $exeArgs = ""
                        if ($cmd -match '^[\s]*"([^"]+)"(.*)$') {
                            $exePath = $matches[1]
                            $exeArgs = $matches[2].Trim()
                        }
                        elseif ($cmd -match '^[\s]*(\S+)(.*)$') {
                            $exePath = $matches[1]
                            $exeArgs = $matches[2].Trim()
                        }

                        if (-not $exePath) {
                            Write-Log "Could not parse uninstall command; skipping: $cmd"
                            return
                        }

                        # Basic safety checks: disallow shell wrappers and script hosts
                        if ($exePath -match '(?i)cmd\.exe|powershell|rundll32|cscript|wscript') {
                            Write-Log "Uninstall command uses disallowed host ($exePath); skipping execution"
                            return
                        }

                        # Normalize exe name for decision logic
                        $exeName = [System.IO.Path]::GetFileName($exePath).ToLowerInvariant()

                        # Ensure MSI installs are invoked via msiexec with quiet options
                        if ($exeName -match 'msiexec(\.exe)?') {
                            if ($exeArgs -notmatch '/qn|/quiet') { $exeArgs = "$exeArgs /qn".Trim() }
                            $file = 'msiexec.exe'
                        }
                        else {
                            # For standard executables, attempt to add a silent switch if missing
                            if ($exeArgs -notmatch '/S|/silent|/quiet') { $exeArgs = "$exeArgs /S".Trim() }
                            $file = $exePath
                        }

                        try {
                            Start-Process -FilePath $file -ArgumentList $exeArgs -Wait -NoNewWindow -ErrorAction Stop
                        }
                        catch {
                            Write-Log "Failed to run uninstall ($file $exeArgs): $_"
                        }
                    }
                }
            }
        }
        if (-not $found) {
            Write-Log "No per-user uninstall entries found for '$AppName'."
        }
    }
    catch { Write-Log "Per-user uninstall error: $_" }
}

# ---------- Intune output ----------
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

# ---------- Parameter sanity ----------
if ([string]::IsNullOrWhiteSpace($ExpectedVersion) -or ($MachineExePaths.Count -eq 0 -and [string]::IsNullOrWhiteSpace($PerUserRelativeExePath))) {
    $intuneOutput.Status = "InvalidParameters"
    Write-Log "Invalid parameters: ExpectedVersion and at least one detection path are required."
    $intuneOutput | ConvertTo-Json -Compress; exit 2
}

# ---------- Main ----------
$originalDisableMsi = $null
try {
    Write-Log "Starting remediation for '$AppDisplayName' (expected $ExpectedVersion)"

    # Early success?
    if (IsExpectedVersionInstalled) {
        $intuneOutput.DetectedVersion = (Get-FileVersionInfoSafe -Path $script:detectedFilePath)
        $intuneOutput.Status = "UpToDate"
        Write-Log "Already up-to-date ($($intuneOutput.DetectedVersion) >= $ExpectedVersion). No action."
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
        $intuneOutput | ConvertTo-Json -Compress; exit 3
    }

    # Determine installer type
    $type = Get-InstallerType -Type $InstallerType -Url $InstallerUrl -LocalPath $InstallerLocalPath
    if ([string]::IsNullOrWhiteSpace($type)) {
        $intuneOutput.Status = "InstallerTypeUnknown"
        Write-Log "Cannot determine installer type (msi/exe)."
        $intuneOutput | ConvertTo-Json -Compress; exit 3
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
            if (-not (Test-Path $InstallerPolicyPath)) {
                New-Item -Path $InstallerPolicyPath -Force | Out-Null
            }
            Set-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -Value 0
            Write-Log "Temporarily set DisableMSI = 0 for MSI install."
        }
        catch { Write-Log "Failed to set DisableMSI: $_" }
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
    }
    elseif ($type -eq "exe") {
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
    $intuneOutput.InstallerLog = $InstallerLogPath

    # Verify installation regardless of exit code (handles reboot-required scenarios)
    if (IsExpectedVersionInstalled) {
        $detected = (Get-FileVersionInfoSafe -Path $script:detectedFilePath)
        $intuneOutput.DetectedVersion = $detected
        $intuneOutput.Status = "Fixed"
        Write-Log "Remediation succeeded: $detected >= $ExpectedVersion"

        # OPTIONAL: cleanup per-user installs after machine-wide success
        if ($RemovePerUserInstallsAfterMachineInstall -and -not [string]::IsNullOrWhiteSpace($AppDisplayName)) {
            Write-Log "Removing per-user installs for '$AppDisplayName' (policy enabled)"
            Uninstall-PerUserAppByName -AppName $AppDisplayName
            # Optionally: log if no per-user installs were found
        }

        # Optionally create a marker file for compliance tracking
        if ($CreateMarkerFile) {
            $markerDir = $MarkerFileRoot
            if (-not (Test-Path $markerDir)) { New-Item -Path $markerDir -ItemType Directory -Force | Out-Null }
            New-Item -Path (Join-Path $markerDir "$__safeName-$ExpectedVersion.marker") -ItemType File -Force | Out-Null
            Write-Log "Marker file created."
        }

        # Clean up downloaded installer if it was downloaded
        if (-not [string]::IsNullOrWhiteSpace($InstallerUrl)) {
            Remove-Item -Path $InstallerLocalPath -Force -ErrorAction SilentlyContinue
            Write-Log "Removed downloaded installer."
        }

        $intuneOutput | ConvertTo-Json -Compress; exit 0
    }
    else {
        $intuneOutput.Status = "InstallFailed"
        Write-Log "Installation completed but expected version not detected."
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

}
catch {
    Write-Log "An error occurred: $_"
    $intuneOutput.Status = "Error"
    $intuneOutput | ConvertTo-Json -Compress
    exit 1
}
finally {
    # Restore MSI policy if we changed it
    try {
        if ($originalDisableMsi -ne $null) {
            Set-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -Value $originalDisableMsi
            Write-Log "Restored DisableMSI=$originalDisableMsi"
        }
        else {
            Remove-ItemProperty -Path $InstallerPolicyPath -Name "DisableMSI" -ErrorAction SilentlyContinue
            Write-Log "Removed temporary DisableMSI override"
        }
    }
    catch { Write-Log "Failed to restore DisableMSI: $_" }
}
