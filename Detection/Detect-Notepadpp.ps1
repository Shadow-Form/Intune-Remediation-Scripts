<#
.SYNOPSIS
Detects whether Notepad++ is installed and meets the expected minimum version.

.DESCRIPTION
Scans machine-scoped executable paths, per-user profile locations, and Windows Uninstall
registry entries to locate Notepad++. The script reads file Product/FileVersion metadata,
normalizes and compares detected versions to the supplied `-ExpectedVersion`, and writes a
compact JSON object to stdout describing the result. Detection is read-only by default;
local file logging only occurs when `-EnableLogging` is true or a `-LogFile` is provided.

.PARAMETER AppDisplayName
Friendly application name used in logs and JSON output. Default: Notepad++

.PARAMETER MachinePaths
One or more absolute machine-scoped paths or glob patterns to scan for the executable.

.PARAMETER PerUserRelativePath
Relative path(s) under each user profile (under C:\Users) to detect per-user installs.

.PARAMETER ExpectedVersion
Minimum acceptable version string. Instances with numeric versions greater than or
equal to this value are considered compliant.

.PARAMETER TriggerRemediationForMissingApp
When `$true` the script will return a non-zero exit code if the app is not found.

.PARAMETER EnableLogging
When `$true` the script may derive and write a local log file. Default: `$false` (read-only).

.PARAMETER LogFile
Optional explicit log file path. If supplied, logs are written to this file even if the
default log path would otherwise be used.

.PARAMETER MaxRetries
Number of attempts for the main scan operation. Default: 3

.PARAMETER RetryDelay
Seconds to wait between scan retries. Default: 5

.EXAMPLE
# Simple detection (no file logging)
powershell -NoProfile -NonInteractive -File .\Detection\Detect-Notepadpp.ps1 -ExpectedVersion 8.9.4

.EXAMPLE
# Enable local file logging to a chosen path
powershell -NoProfile -NonInteractive -File .\Detection\Detect-Notepadpp.ps1 -ExpectedVersion 8.9.4 -EnableLogging $true -LogFile C:\Temp\Detect-Notepadpp.log

.NOTES
- Output: compact JSON written to stdout. Exit codes: 0 = Compliant, 1 = Non-compliant or Error.
- Detection scripts are read-only by default; do not enable logging in production unless needed.
- Last Updated : 2026-04-29
#>

[CmdletBinding(SupportsShouldProcess = $false)]
param (
    # --- App-specific parameters  ---
    [string]$AppDisplayName = "Notepad++",
    [string[]]$MachinePaths = @(
        "${env:ProgramW6432}\Notepad++\notepad++.exe",
        "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"
    ),
    [string[]]$PerUserRelativePath = @(
        "AppData\Local\Programs\Notepad++\notepad++.exe"
    ),
    [string]$ExpectedVersion = "8.9.4",

    # --- Common controls ---
    [bool]$TriggerRemediationForMissingApp = $false,
    [bool]$EnableLogging = $false,
    [int]$MaxRetries = 3,
    [int]$RetryDelay = 5,
    [string]$LogFile,
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
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    # Trim trailing dots/spaces that Windows disallows
    $clean = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# If caller didn't supply -LogFile, derive a robust default from AppDisplayName
# Only derive a default when logging is explicitly enabled; detection scripts are read-only by default.
if ($PSBoundParameters.ContainsKey('LogFile') -and -not [string]::IsNullOrWhiteSpace($LogFile)) {
    # Use supplied LogFile
}
elseif ($EnableLogging) {
    $safeName = Get-SafeFileName -Name $AppDisplayName
    $LogFile = "C:\Logs\Detect-$safeName.log"
}
else {
    $LogFile = $null
}

# ---------- Logging ----------
function Write-Log {
    param ([string]$Message)

    # Console verbose (native)
    Write-Verbose $Message

    # Respect explicit logging opt-in
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
    param([string]$DirectoryPath)
    if (-not (Test-Path $DirectoryPath)) {
        New-Item -Path $DirectoryPath -ItemType Directory -Force | Out-Null
    }
}

function Invoke-OperationRetry {
    param ([int]$MaxRetries, [int]$RetryDelay, [scriptblock]$Operation)
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-Log "Attempt $i of $MaxRetries"
            & $Operation
            return $true
        }
        catch {
            Write-Log "Attempt $i failed $_"
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
    param([string]$v)
    $v = ($v -replace ',', '.').Trim()
    # Extract the first numeric dotted sequence from strings like "Release 0.83" or "v1.2.3-beta"
    if ($v -match '([0-9]+(?:\.[0-9]+)*)') { $v = $matches[1] } else { $v = '0' }
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}

function Compare-Versions {
    param([string]$InstalledVersion, [string]$ExpectedVersion)
    try {
        $iv = Format-Version $InstalledVersion
        $ev = Format-Version $ExpectedVersion

        # Safely parse each component to integer; non-numeric components become 0
        $a = $iv.Split('.') | ForEach-Object {
            $num = 0
            [int]::TryParse($_, [ref]$num) | Out-Null
            $num
        }
        $b = $ev.Split('.') | ForEach-Object {
            $num = 0
            [int]::TryParse($_, [ref]$num) | Out-Null
            $num
        }

        $max = if ($a.Count -gt $b.Count) { $a.Count } else { $b.Count }
        for ($i = 0; $i -lt $max; $i++) {
            $ai = if ($i -lt $a.Count) { $a[$i] } else { 0 }
            $bi = if ($i -lt $b.Count) { $b[$i] } else { 0 }
            if ($ai -gt $bi) { return $true }
            if ($ai -lt $bi) { return $false }
        }

        return $true
    }
    catch {
        throw "Version comparison failed $_"
    }
}

function Get-FileVersionInfoSafe {
    param([string]$Path)
    $vi = (Get-Item -LiteralPath $Path).VersionInfo
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    ($version -replace ',', '.').Trim()
}

function Get-PerUserAppPaths {
    param(
        [string]$RelativePath,
        [string[]]$Exclusions = @('Public', 'Default', 'Default User', 'All Users', 'WDAGUtilityAccount')
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { return @() }

    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }

    # Expand wildcards in the relative path for each user profile (supports patterns like jre* )
    $results = @()
    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { $Exclusions -notcontains $_.Name } |
    ForEach-Object {
        $searchPath = Join-Path $_.FullName $RelativePath
        try {
            Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue | ForEach-Object { $results += $_.FullName }
        }
        catch {
            # Ignore errors and continue to next profile
        }
    }

    return $results
}

# ---------- Registry detection for Windows 'Uninstall' keys ----------
function Get-RegistryAppEntries {
    param([string]$DisplayName)

    $roots = @(
        @{Hive = 'HKLM'; Path = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'; Scope = 'Machine' },
        @{Hive = 'HKLM'; Path = 'SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'; Scope = 'Machine' },
        @{Hive = 'HKCU'; Path = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall'; Scope = 'User' }
    )

    $results = @()
    foreach ($r in $roots) {
        $base = "$($r.Hive):\\$($r.Path)"
        try {
            Get-ChildItem -Path $base -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    $props = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                    if (-not $props) { return }
                    $dn = $props.DisplayName
                    if (-not $dn) { return }
                    if ($dn -like "*$DisplayName*") {
                        $results += [pscustomobject]@{
                            RegistryPath    = $_.PSPath
                            DisplayName     = $dn
                            DisplayVersion  = $props.DisplayVersion
                            InstallLocation = $props.InstallLocation
                            DisplayIcon     = $props.DisplayIcon
                            Scope           = $r.Scope
                        }
                    }
                }
                catch {
                    # ignore individual key errors
                }
            }
        }
        catch {
            # ignore root access errors
        }
    }

    return $results
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
    if ($LogFile) { New-DirectoryIfMissing -DirectoryPath (Split-Path -Path $LogFile) }

    $operationSucceeded = Invoke-OperationRetry -MaxRetries $MaxRetries -RetryDelay $RetryDelay -Operation {
        $found = $false
        $findings = @()

        # 1) Machine paths (and current-context LocalAppData if provided)
        foreach ($path in $MachinePaths) {
            $candidates = @()
            try {
                $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
            }
            catch {
                # ignore and fall back to literal check
            }

            if (($candidates.Count -eq 0) -and (Test-Path -LiteralPath $path)) { $candidates = @($path) }

            foreach ($candidate in $candidates) {
                if (-not (Test-Path -LiteralPath $candidate)) { continue }
                $found = $true

                $rawVersion = Get-FileVersionInfoSafe -Path $candidate
                Write-Log "[$AppDisplayName] Detected version '$rawVersion' from '$candidate'"

                $findings += [pscustomobject]@{
                    Source  = 'File'
                    Path    = $candidate
                    Version = $rawVersion
                    Scope   = if ($candidate -like "$env:LocalAppData*") { 'User' } else { 'Machine' }
                }
            }
        }

        # 2) Per-user installs across profiles (SYSTEM context)
        if (-not [string]::IsNullOrWhiteSpace($PerUserRelativePath)) {
            $perUserHits = Get-PerUserAppPaths -RelativePath $PerUserRelativePath
            foreach ($uPath in $perUserHits) {
                if (-not (Test-Path -LiteralPath $uPath)) { continue }
                $found = $true

                $rawVersion = Get-FileVersionInfoSafe -Path $uPath
                Write-Log "[$AppDisplayName] Detected per-user version '$rawVersion' from '$uPath'"

                $findings += [pscustomobject]@{
                    Source  = 'File'
                    Path    = $uPath
                    Version = $rawVersion
                    Scope   = 'User'
                }
            }
        }

        # 3) Registry uninstall entries (may be orphaned)
        try {
            $regHits = Get-RegistryAppEntries -DisplayName $AppDisplayName
            foreach ($r in $regHits) {
                $found = $true
                $version = $r.DisplayVersion
                $displayIcon = $r.DisplayIcon
                $pathCandidate = $null
                if ($displayIcon) { $pathCandidate = $displayIcon -replace '\"' } elseif ($r.InstallLocation) { $pathCandidate = $r.InstallLocation }

                Write-Log "[$AppDisplayName] Detected registry entry '$($r.RegistryPath)' version '$version'"

                $findings += [pscustomobject]@{
                    Source        = 'Registry'
                    Path          = $r.RegistryPath
                    FileReference = $pathCandidate
                    Version       = $version
                    Scope         = if ($r.Scope -eq 'User') { 'UserRegistry' } else { 'MachineRegistry' }
                }
            }
        }
        catch {
            Write-Log "[$AppDisplayName] Registry scan failed: $_"
        }

        if (-not $found) {
            Write-Log "[$AppDisplayName] No executable or registry entry found."
            throw "FileNotFound"
        }

        # Operation succeeded — return true to avoid retrying further
        return $true
    }

    # After a successful scan, evaluate all findings and decide final status
    if (-not $operationSucceeded) {
        $intuneOutput.Status = "NotInstalled"
        Write-Log "[$AppDisplayName] Not installed on this system."

        if ($TriggerRemediationForMissingApp) {
            $msg = ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                    $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
            Write-Log $msg
            $intuneOutput | ConvertTo-Json -Compress; exit 1
        }
        else {
            $msg = ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                    $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
            Write-Log $msg
            $intuneOutput | ConvertTo-Json -Compress; exit 0
        }
    }

    # Gather findings from the scan (rebuild same way as inside the operation)
    # Note: we reconstruct $findings by re-running the same quick scans to capture objects in this scope
    $findings = @()
    foreach ($path in $MachinePaths) {
        $candidates = @()
        try { $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } } catch {}
        if (($candidates.Count -eq 0) -and (Test-Path -LiteralPath $path)) { $candidates = @($path) }
        foreach ($candidate in $candidates) {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }
            $rawVersion = Get-FileVersionInfoSafe -Path $candidate
            $findings += [pscustomobject]@{ Source = 'File'; Path = $candidate; Version = $rawVersion; Scope = if ($candidate -like "$env:LocalAppData*") { 'User' } else { 'Machine' } }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($PerUserRelativePath)) {
        $perUserHits = Get-PerUserAppPaths -RelativePath $PerUserRelativePath
        foreach ($uPath in $perUserHits) {
            if (-not (Test-Path -LiteralPath $uPath)) { continue }
            $rawVersion = Get-FileVersionInfoSafe -Path $uPath
            $findings += [pscustomobject]@{ Source = 'File'; Path = $uPath; Version = $rawVersion; Scope = 'User' }
        }
    }
    try {
        $regHits = Get-RegistryAppEntries -DisplayName $AppDisplayName
        foreach ($r in $regHits) {
            $version = $r.DisplayVersion
            $displayIcon = $r.DisplayIcon
            $pathCandidate = $null
            if ($displayIcon) { $pathCandidate = $displayIcon -replace '\"' } elseif ($r.InstallLocation) { $pathCandidate = $r.InstallLocation }
            $findings += [pscustomobject]@{ Source = 'Registry'; Path = $r.RegistryPath; FileReference = $pathCandidate; Version = $version; Scope = if ($r.Scope -eq 'User') { 'UserRegistry' } else { 'MachineRegistry' } }
        }
    }
    catch {
        Write-Log "[$AppDisplayName] Registry re-scan failed: $_"
    }

    # Evaluate findings: prefer to surface any MalformedVersion or Outdated instance (remediation)
    $firstMalformed = $null
    $firstOutdated = $null
    $firstCompliant = $null

    foreach ($f in $findings) {
        $raw = $f.Version
        $formatted = Format-Version $raw
        if ([string]::IsNullOrWhiteSpace($raw) -or ($formatted -notmatch '^\d+(\.\d+)*$')) {
            if (-not $firstMalformed) { $firstMalformed = $f }
            continue
        }

        try {
            $isAtLeast = Compare-Versions -InstalledVersion $formatted -ExpectedVersion $ExpectedVersion
        }
        catch {
            if (-not $firstMalformed) { $firstMalformed = $f }
            continue
        }

        if (-not $isAtLeast) {
            if (-not $firstOutdated) { $firstOutdated = $f }
        }
        else {
            if (-not $firstCompliant) { $firstCompliant = $f }
        }
    }

    if ($firstMalformed) {
        $intuneOutput.FilePath = $firstMalformed.Path
        $intuneOutput.DetectedVersion = $firstMalformed.Version
        $intuneOutput.InstallScope = $firstMalformed.Scope
        $intuneOutput.Status = 'MalformedVersion'
        Write-Log "[$AppDisplayName] Malformed version detected: $($firstMalformed.Path) => $($firstMalformed.Version)"
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

    if ($firstOutdated) {
        $intuneOutput.FilePath = $firstOutdated.Path
        $intuneOutput.DetectedVersion = $firstOutdated.Version
        $intuneOutput.InstallScope = $firstOutdated.Scope
        $intuneOutput.Status = if ($firstOutdated.Scope -like '*User*') { 'UserScopeOutdated' } else { 'Outdated' }
        Write-Log "[$AppDisplayName] Outdated instance detected: $($firstOutdated.Path) => $($firstOutdated.Version)"
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

    if ($firstCompliant) {
        $intuneOutput.FilePath = $firstCompliant.Path
        $intuneOutput.DetectedVersion = $firstCompliant.Version
        $intuneOutput.InstallScope = $firstCompliant.Scope
        $intuneOutput.Status = 'Compliant'
        Write-Log "[$AppDisplayName] Compliant instance detected: $($firstCompliant.Path) => $($firstCompliant.Version)"
        $intuneOutput | ConvertTo-Json -Compress; exit 0
    }

    # If we get here, nothing meaningful was found
    $intuneOutput.Status = 'NotInstalled'
    Write-Log "[$AppDisplayName] No valid instances detected after evaluation."
    if ($TriggerRemediationForMissingApp) { $intuneOutput | ConvertTo-Json -Compress; exit 1 } else { $intuneOutput | ConvertTo-Json -Compress; exit 0 }

}
catch {
    $intuneOutput.Status = "Error"
    Write-Log "[$AppDisplayName] An unexpected error occurred: $_"
    $msg = ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
    Write-Log $msg
    $intuneOutput | ConvertTo-Json -Compress; exit 1
}
