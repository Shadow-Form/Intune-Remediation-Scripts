<#
.SYNOPSIS
    Detects whether an application (SAP Lumira) is installed and meets the expected version.

.DESCRIPTION
    Scans machine-scoped paths and optional per-user profile paths to locate the application's
    executable, normalizes the discovered version, and compares it against an expected minimum.
    Emits a compact JSON object to stdout describing the result and returns exit codes used by
    Intune remediation workflows.

.PARAMETER AppDisplayName
    Friendly application name used in logs and JSON output.

.PARAMETER MachinePaths
    One or more absolute machine-scoped paths to check for the application executable.

.PARAMETER PerUserRelativePath
    Relative path under each user profile (resolved under C:\Users) to discover per-user installs.

.PARAMETER ExpectedVersion
    Minimum acceptable version. If any detected instance is >= this value the script reports compliant.

.PARAMETER RegistryUninstallKeys
    Optional array of full Uninstall registry key paths to inspect for the application's
    installation metadata (for example: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}`).
    When supplied the script will read `DisplayVersion` (or fallbacks) from these keys.

.PARAMETER RegistryDisplayNames
    Optional array of exact `DisplayName` values (case-insensitive) to match when
    inspecting registry uninstall entries. When supplied the registry lookup will only
    return a version if the entry's `DisplayName` exactly equals one of these values.

.PARAMETER LogFile
    Optional path to a log file when logging is enabled.

.PARAMETER EnableLogging
    Boolean flag. When `$true` the script may write a local log file; default is `$false` (read-only).

.PARAMETER MaxRetries
    Number of attempts for the main scan operation.

.PARAMETER RetryDelay
    Seconds to wait between scan retries.

.PARAMETER TriggerRemediationForMissingApp
    When `$true` the script returns a non-zero exit code if the app is missing (triggers remediation).

.PARAMETER VerboseMode
    Compatibility switch: when present sets verbose preference when `-Verbose` isn't provided.

.EXAMPLE
    # Check SAP Lumira version (no file logging)
    powershell -NoProfile -NonInteractive -File .\Detection\Detect-SAPLumira.ps1 -ExpectedVersion 25.0.1

.EXAMPLE
    # Enable local file logging
    powershell -NoProfile -NonInteractive -File .\Detection\Detect-SAPLumira.ps1 -ExpectedVersion 25.0.1 -EnableLogging $true

.NOTES
    Detection behavior: read-only by default. To opt in to file logging pass `-EnableLogging $true` and
    optionally `-LogFile` to control the path. Output is a compact JSON object and the script uses
    exit codes intended for Intune remediations:

        0 = Compliant (installed version >= expected)
        1 = Non-compliant (missing, malformed version, comparison error, or outdated)

    This file intentionally contains no tenant-specific or internal identifiers.

    Logging: When `-EnableLogging $true` and `-LogFile` is not supplied the script derives a
    default log file at `Join-Path -Path $env:TEMP -ChildPath ("Detect-<SafeAppName>.log")`.
    Logs are written via the `Write-LogEntry` helper; detection scripts remain read-only unless
    `-EnableLogging` is explicitly provided.
#>

[CmdletBinding(SupportsShouldProcess = $false)]
param (
    # --- App-specific parameters (set these per application) ---
    [string]$AppDisplayName = "SAPLumira",
    [string[]]$MachinePaths = @(
        "${env:ProgramFiles}\SAP Lumira\Lumira Designer\SapLumiraDesigner.exe"
    ),
    # Relate paths under each user profile; if empty or null, per-user search is skipped
    [string[]]$PerUserRelativePath = @(
        ""
    ),
    [string]$ExpectedVersion = "25.0.1",

    # Optional: explicit registry uninstall key paths to inspect (full paths, e.g. HKLM:\...\{GUID})
    [string[]]$RegistryUninstallKeys = @(
        "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SAP Lumira Designer"
    ),
    # Optional: explicit DisplayName values to match exactly (case-insensitive). When supplied,
    # the registry search will only return entries whose DisplayName equals one of these values.
    [string[]]$RegistryDisplayNames = @(
        "SAP Lumira Designer"
    ),

    # --- Common controls ---
    [string]$LogFile,
    [bool]$EnableLogging = $false,
    [int]$MaxRetries = 3,
    [int]$RetryDelay = 5,
    [bool]$TriggerRemediationForMissingApp = $true,
    [int]$MaxLogRetries = 5,
    [int]$LogRetryDelay = 2,

    # --- Backwards compatibility: enable verbose if this is supplied ---
    [switch]$VerboseMode
)

# Honor either -Verbose (native) or -VerboseMode (compat)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# ---------- Helpers to build a safe, per-app log file ----------
function Get-SafeFileName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    # Trim trailing dots/spaces that Windows disallows
    $clean = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# Make logging opt-in for detection scripts: only derive a default log file when explicitly enabled
if ($EnableLogging) {
    if (-not $PSBoundParameters.ContainsKey('LogFile') -or [string]::IsNullOrWhiteSpace($LogFile)) {
        $__safeName = Get-SafeFileName -Name $AppDisplayName
        $LogFile = Join-Path -Path $env:TEMP -ChildPath ("Detect-$__safeName.log")
    }
}
else {
    $LogFile = $null
}

# ---------- Logging ----------
function Write-LogEntry {
    param ([string]$Message)
    # Console verbose (native)
    Write-Verbose $Message

    # Detection must remain read-only by default. Only write files when explicitly enabled.
    if (-not $EnableLogging -or -not $LogFile) { return }

    $logDirectory = Split-Path -Path $LogFile
    if (-not (Test-Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }

    for ($i = 1; $i -le $MaxLogRetries; $i++) {
        try {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
            break
        }
        catch [System.IO.IOException] {
            if ($i -eq $MaxLogRetries) {
                Write-Verbose "Failed to write to log file after $MaxLogRetries attempts $LogFile"
                throw
            }
            Start-Sleep -Seconds $LogRetryDelay
        }
    }
}

# ---------- Utilities ----------
function New-DirectoryIfMissing {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)
    if (-not (Test-Path $DirectoryPath)) {
        New-Item -Path $DirectoryPath -ItemType Directory -Force | Out-Null
    }
}

function Invoke-OperationRetry {
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][int]$MaxRetries, [Parameter(Mandatory = $true)][int]$RetryDelay, [Parameter(Mandatory = $true)][scriptblock]$Operation)
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-LogEntry "Attempt $i of $MaxRetries"
            & $Operation
            return $true
        }
        catch {
            Write-LogEntry "Attempt $i failed $_"
            if ($i -lt $MaxRetries) {
                Start-Sleep -Seconds $RetryDelay
            }
            else {
                return $false
            }
        }
    }
}

function Format-Version {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$v)
    $v = ($v -replace ',', '.').Trim()
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}

function Compare-Versions {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$InstalledVersion, [Parameter(Mandatory = $true)][string]$ExpectedVersion)
    try {
        (Format-Version $InstalledVersion) -ge (Format-Version $ExpectedVersion)
    }
    catch {
        throw "Version comparison failed $_"
    }
}

function Get-FileVersionInfoSafe {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $vi = (Get-Item -LiteralPath $Path).VersionInfo

    $pv = ($vi.ProductVersion -replace ',', '.').Trim()
    $fv = ($vi.FileVersion -replace ',', '.').Trim()

    $isNumeric = { param($s) return -not [string]::IsNullOrWhiteSpace($s) -and ($s -match '^[0-9]+(\.[0-9]+)*$') }

    if (& $isNumeric $pv) { return $pv }
    if (& $isNumeric $fv) { return $fv }

    if (-not [string]::IsNullOrWhiteSpace($pv)) { return $pv }
    if (-not [string]::IsNullOrWhiteSpace($fv)) { return $fv }

    return ''
}

# Attempts to locate the installed version from common Uninstall registry keys.
# If a matching DisplayName or InstallLocation is found, returns the corresponding
# DisplayVersion (or other version-like value). Returns empty string when not found.
function Get-RegistryVersionForApp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$AppDisplayName,
        [Parameter(Mandatory = $false)][string]$FilePath,
        [string[]]$RegistryKeys = @(),
        [string[]]$RegistryDisplayNames = @()
    )

    # If specific registry uninstall key paths were provided, inspect those first.
    if ($RegistryKeys -and $RegistryKeys.Count -gt 0) {
        foreach ($key in $RegistryKeys) {
            if (-not (Test-Path -LiteralPath $key)) { continue }
            try {
                $props = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            }
            catch { continue }

            $displayName = $props.DisplayName
            $displayVersion = $props.DisplayVersion
            if (-not $displayVersion) { $displayVersion = $props.Version }
            if (-not $displayVersion) { $displayVersion = $props.ReleaseVersion }

            if ($RegistryDisplayNames -and $RegistryDisplayNames.Count -gt 0) {
                foreach ($candidate in $RegistryDisplayNames) {
                    if ($displayName -ieq $candidate) {
                        if ($displayVersion) { return ($displayVersion -replace ',', '.').Trim() }
                    }
                }
            }
            else {
                if ($displayVersion) { return ($displayVersion -replace ',', '.').Trim() }
            }
        }

        return ''
    }

    # Otherwise, enumerate common uninstall roots but require exact DisplayName matches
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        foreach ($sub in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            try {
                $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop
            }
            catch {
                continue
            }

            $displayName = $props.DisplayName
            $displayVersion = $props.DisplayVersion
            if (-not $displayVersion) { $displayVersion = $props.Version }
            if (-not $displayVersion) { $displayVersion = $props.ReleaseVersion }
            $installLocation = $props.InstallLocation

            if ($displayName) {
                if ($RegistryDisplayNames -and $RegistryDisplayNames.Count -gt 0) {
                    foreach ($candidate in $RegistryDisplayNames) {
                        if ($displayName -ieq $candidate) {
                            if ($displayVersion) { return ($displayVersion -replace ',', '.').Trim() }
                        }
                    }
                }
                else {
                    if ($displayName -ieq $AppDisplayName) {
                        if ($displayVersion) { return ($displayVersion -replace ',', '.').Trim() }
                    }
                }
            }

            if ($installLocation -and $FilePath) {
                try {
                    $normalizedInstall = (Join-Path -Path $installLocation -ChildPath '')
                    if ($FilePath -like "$normalizedInstall*") {
                        if ($displayVersion) { return ($displayVersion -replace ',', '.').Trim() }
                    }
                }
                catch { }
            }
        }
    }

    return ''
}

function Get-PerUserAppPaths {
    param(
        [string]$RelativePath,
        [string[]]$Exclusions = @('Public', 'Default', 'Default User', 'All Users', 'WDAGUtilityAccount')
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { return @() }

    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }

    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $Exclusions -notcontains $_.Name } |
    ForEach-Object { Join-Path $_.FullName $RelativePath } |
    Where-Object { Test-Path -LiteralPath $_ }
}

# ---------- Output object ----------
$intuneOutput = @{
    AppName         = $AppDisplayName
    FilePath        = ""
    ExpectedVersion = $ExpectedVersion
    DetectedVersion = ""
    InstallScope    = ""
    Status          = "NotDetected"
}

# ---------- Main ----------
try {
    if ($EnableLogging -and $LogFile) { New-DirectoryIfMissing -DirectoryPath (Split-Path -Path $LogFile -Parent) }

    $operationSucceeded = Invoke-OperationRetry -MaxRetries $MaxRetries -RetryDelay $RetryDelay -Operation {
        $found = $false

        # 1) Machine paths (and current-context LocalAppData if provided)
        foreach ($path in $MachinePaths) {
            if (Test-Path -LiteralPath $path) {
                $found = $true

                # Prefer registry-based version when available; fall back to file version
                $registryVersion = Get-RegistryVersionForApp -AppDisplayName $AppDisplayName -FilePath $path -RegistryKeys $RegistryUninstallKeys -RegistryDisplayNames $RegistryDisplayNames
                if (-not [string]::IsNullOrWhiteSpace($registryVersion)) {
                    $normalizedVersion = $registryVersion
                    Write-LogEntry "[$AppDisplayName] Detected version '$normalizedVersion' from registry for '$path'"
                }
                else {
                    $normalizedVersion = Get-FileVersionInfoSafe -Path $path
                    Write-LogEntry "[$AppDisplayName] Detected version '$normalizedVersion' from file '$path' (registry not found)"
                }

                $intuneOutput.FilePath = $path
                $intuneOutput.DetectedVersion = $normalizedVersion
                $intuneOutput.InstallScope = if ($path -like "$env:LocalAppData*") { "User" } else { "Machine" }

                if ([string]::IsNullOrWhiteSpace($normalizedVersion) -or ($normalizedVersion -notmatch '^\d+(\.\d+)*$')) {
                    $intuneOutput.Status = "MalformedVersion"
                    Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }

                try {
                    if (Compare-Versions -InstalledVersion $normalizedVersion -ExpectedVersion $ExpectedVersion) {
                        $intuneOutput.Status = "Compliant"
                        Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                                $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 0
                    }
                    else {
                        $intuneOutput.Status = if ($intuneOutput.InstallScope -eq "User") { "UserScopeOutdated" } else { "Outdated" }
                        Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                                $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 1
                    }
                }
                catch {
                    $intuneOutput.Status = "ComparisonError"
                    Write-LogEntry "[$AppDisplayName] Version comparison failed: $_"
                    Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }
            }
        }

        # 2) Per-user installs across profiles (SYSTEM context)
        if (-not $found -and -not [string]::IsNullOrWhiteSpace($PerUserRelativePath)) {
            $perUserHits = Get-PerUserAppPaths -RelativePath $PerUserRelativePath
            foreach ($uPath in $perUserHits) {
                # Prefer registry-based version when available; fall back to file version
                $registryVersion = Get-RegistryVersionForApp -AppDisplayName $AppDisplayName -FilePath $uPath -RegistryKeys $RegistryUninstallKeys -RegistryDisplayNames $RegistryDisplayNames
                if (-not [string]::IsNullOrWhiteSpace($registryVersion)) {
                    $normalizedVersion = $registryVersion
                    Write-LogEntry "[$AppDisplayName] Detected per-user version '$normalizedVersion' from registry for '$uPath'"
                }
                else {
                    $normalizedVersion = Get-FileVersionInfoSafe -Path $uPath
                    Write-LogEntry "[$AppDisplayName] Detected per-user version '$normalizedVersion' from file '$uPath' (registry not found)"
                }

                $intuneOutput.FilePath = $uPath
                $intuneOutput.DetectedVersion = $normalizedVersion
                $intuneOutput.InstallScope = "User"

                if ([string]::IsNullOrWhiteSpace($normalizedVersion) -or ($normalizedVersion -notmatch '^\d+(\.\d+)*$')) {
                    $intuneOutput.Status = "MalformedVersion"
                    Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }

                try {
                    if (Compare-Versions -InstalledVersion $normalizedVersion -ExpectedVersion $ExpectedVersion) {
                        $intuneOutput.Status = "Compliant"
                        Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                                $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 0
                    }
                    else {
                        $intuneOutput.Status = "UserScopeOutdated"
                        Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                                $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 1
                    }
                }
                catch {
                    $intuneOutput.Status = "ComparisonError"
                    Write-LogEntry "[$AppDisplayName] Version comparison failed: $_"
                    Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }
            }
        }

        Write-LogEntry "[$AppDisplayName] No executable found in machine paths or any user profile."
        throw "FileNotFound"
    }

    # After retries, still not found
    if (-not $operationSucceeded) {
        $intuneOutput.Status = "NotInstalled"
        Write-LogEntry "[$AppDisplayName] Not installed on this system."

        if ($TriggerRemediationForMissingApp) {
            Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                    $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
            $intuneOutput | ConvertTo-Json -Compress; exit 1
        }
        else {
            Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                    $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
            $intuneOutput | ConvertTo-Json -Compress; exit 0
        }
    }

}
catch {
    $intuneOutput.Status = "Error"
    Write-LogEntry "[$AppDisplayName] An unexpected error occurred: $_"
    Write-LogEntry ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
    $intuneOutput | ConvertTo-Json -Compress; exit 1
}
