[<#
.SYNOPSIS
Detects whether an application (Snagit) is installed and meets the expected version.

.DESCRIPTION
Scans machine-scoped paths, per-user profile paths, and optionally Windows Uninstall registry
entries to locate the application and collect a version. Normalizes and compares the detected
version against an expected minimum, writes structured JSON to stdout, and returns Intune
compatible exit codes.

.PARAMETER AppDisplayName
Friendly application name used in logs, registry matching, and JSON output.

.PARAMETER MachinePaths
One or more machine-scoped paths or glob patterns searched for the application executable.

.PARAMETER PerUserRelativePath
Relative path under each user profile to detect per-user installations.

.PARAMETER ExpectedVersion
Minimum acceptable version string used to determine compliance.

.PARAMETER LogFile
Optional path to write script logs when logging is enabled.

.PARAMETER AllowLocalLogging
When `$true` the script may derive and write a local log file (default: `$false`). Detection
    remains read-only unless this parameter is true or a `-LogFile` is explicitly supplied.

    .PARAMETER MaxRetries
    Number of attempts for the main scan operation.

    .PARAMETER RetryDelay
    Seconds to wait between retries.

    .PARAMETER TriggerRemediationForMissingApp
    When `$true` the script returns a non-zero exit code if the app is not found.

    .PARAMETER VerboseMode
    Compatibility switch enabling verbose output when `-Verbose` isn't used.

.EXAMPLE
    powershell -NoProfile -NonInteractive -File .\Detection\Detect-Snagit.ps1 -ExpectedVersion 26.0.1

.EXAMPLE
    powershell -NoProfile -NonInteractive -File .\Detection\Detect-Snagit.ps1 -ExpectedVersion 26.0.1 -LogFile C:\Logs\snagit.log

#.NOTES
    Detection scripts are read-only by default; they will not create files unless a log file is
    explicitly enabled. Output is JSON and the expected exit codes are:

        0 = Compliant
        1 = Non-compliant (missing, malformed version, comparison error, or outdated)

    These scripts are safe for use in Intune remediations but should be validated in a test group
    before wide deployment. No internal tenant data or identifiers are contained in this script.

    Last Updated : 2026-04-29
    Notes        : `ScriptBuildId` is derived at runtime from the script file timestamp; do not
                   hard-code date identifiers in the header.
#>

[CmdletBinding(SupportsShouldProcess=$false)]
param (
    # --- App-specific parameters (set these per application) ---
    [string]$AppDisplayName                 = "Snagit",
    [string[]]$MachinePaths                 = @(
        "${env:ProgramW6432}\TechSmith\Snagit*\SnagPriv.exe",
        "${env:ProgramFiles(x86)}\TechSmith\Snagit*\SnagPriv.exe"
    ),
    # RELATIVE paths under each user profile; you can include multiples.
    [string[]]$PerUserRelativePath          = @(
        "AppData\Local\Programs\TechSmith\Snagit\SnagPriv.exe"
    ),
    [string]$ExpectedVersion                = "26.1.1",

    # --- Common controls ---
    [bool]$TriggerRemediationForMissingApp  = $false,
    [int]$MaxRetries                        = 3,
    [int]$RetryDelay                        = 5,
    [string]$LogFile,
    [bool]$AllowLocalLogging = $false,
    [int]$MaxLogRetries                     = 5,
    [int]$LogRetryDelay                     = 2,

    # --- Behavior toggles ---
    # If ANY instance meets/exceeds ExpectedVersion, prefer 'Compliant'
    [bool]$PreferCompliantIfAnyInstanceCompliant = $false,

    # --- Backwards compatibility: enable verbose if this is supplied ---
    [switch]$VerboseMode
)

# Honor either -Verbose (native) or -VerboseMode (compat)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# Require modern PowerShell and enable strict mode to surface issues early
#Requires -Version 5.1
Set-StrictMode -Version Latest

# Derive a simple build stamp from the script file timestamp instead of hard-coding a date
try {
    $ScriptFile = $MyInvocation.MyCommand.Path
    if ($ScriptFile) {
        $ScriptBuildId = (Get-Item -LiteralPath $ScriptFile).LastWriteTimeUtc.ToString('yyyy-MM-ddTHHmmZ')
    } else {
        $ScriptBuildId = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ')
    }
} catch {
    $ScriptBuildId = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHHmmZ')
}
Write-Verbose "BuildId = $ScriptBuildId"
Write-Verbose "ScriptPath = $($MyInvocation.MyCommand.Path)"

# ---------- PREVENT STALE FUNCTION COLLISIONS ----------
# Remove ANY previously defined functions with old names in the current session
'Get-PerUserAppPath','Get-PerUserAppPaths' | ForEach-Object {
    try { Remove-Item "Function:\$_" -ErrorAction SilentlyContinue } catch {}
}

# ---------- Helpers to build a safe, per-app log file ----------
function Get-SafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean   = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    $clean   = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# Determine LogFile only when explicitly requested. Detection should be read-only by default.
if ($PSBoundParameters.ContainsKey('LogFile') -and -not [string]::IsNullOrWhiteSpace($LogFile)) {
    # Use supplied LogFile
} elseif ($AllowLocalLogging) {
    $safeName = Get-SafeFileName -Name $AppDisplayName
    $LogFile  = Join-Path -Path 'C:\Logs' -ChildPath ("Detect-$safeName.log")
} else {
    $LogFile = $null
}

# ---------- Logging ----------
function Write-LogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )
    Write-Verbose $Message
    if (-not $LogFile) { return }

    $logDirectory = Split-Path -Path $LogFile -Parent
    try {
        if (-not (Test-Path -LiteralPath $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        }
    } catch {
        Write-Verbose "Failed to ensure log directory '$logDirectory': $_"
        throw
    }

    for ($i = 1; $i -le $MaxLogRetries; $i++) {
        try {
            Add-Content -LiteralPath $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
            break
        } catch [System.IO.IOException] {
            if ($i -eq $MaxLogRetries) {
                Write-Verbose "Failed to write to log file after $MaxLogRetries attempts $LogFile"
                throw
            }
            Start-Sleep -Seconds $LogRetryDelay
        } catch {
            Write-Verbose "Unexpected error writing log: $_"
            throw
        }
    }
}

# ---------- Utilities ----------
function New-DirectoryIfMissing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DirectoryPath
    )
    try {
        if (-not (Test-Path -LiteralPath $DirectoryPath)) {
            New-Item -Path $DirectoryPath -ItemType Directory -Force | Out-Null
        }
    } catch {
        Write-Verbose "Failed to create directory '$DirectoryPath': $_"
        throw
    }
}

function Invoke-OperationRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1,50)]
        [int]$MaxRetries,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0,600)]
        [int]$RetryDelay,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation
    )
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-LogEntry "Attempt $i of $MaxRetries"
            & $Operation
            return $true
        } catch {
            Write-LogEntry "Attempt $i failed $_"
            if ($i -lt $MaxRetries) {
                Start-Sleep -Seconds $RetryDelay
            } else {
                return $false
            }
        }
    }
}

function Format-Version {
    param([string]$v)
    $v = ($v -replace ', ', '.').Trim()
    if ($v -match '([0-9]+(?:\.[0-9]+)*)') { $v = $matches[1] } else { $v = '0' }
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}

function Compare-Versions {
    param([string]$InstalledVersion,[string]$ExpectedVersion)
    try {
        $iv = Format-Version $InstalledVersion
        $ev = Format-Version $ExpectedVersion

        $a = $iv.Split('.') | ForEach-Object { $num=0; [int]::TryParse($_,[ref]$num) | Out-Null; $num }
        $b = $ev.Split('.') | ForEach-Object { $num=0; [int]::TryParse($_,[ref]$num) | Out-Null; $num }

        $max = [Math]::Max($a.Count,$b.Count)
        for ($i=0; $i -lt $max; $i++) {
            $ai = if ($i -lt $a.Count) { $a[$i] } else { 0 }
            $bi = if ($i -lt $b.Count) { $b[$i] } else { 0 }
            if ($ai -gt $bi) { return $true }
            if ($ai -lt $bi) { return $false }
        }
        return $true
    } catch {
        throw "Version comparison failed $_"
    }
}

function Get-FileVersionInfoSafe {
    param([string]$Path)
    try {
        $vi = (Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo
    } catch {
        throw "Failed to read file version info for '$Path': $_"
    }
    $version = $vi.ProductVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $vi.FileVersion }
    ($version -replace ', ', '.').Trim()
}

# --- Resolve per-user app paths under each profile (unique name to avoid collisions) ---
function Resolve-PerUserAppPaths {
    param(
        [string]$RelativePath,
        [string[]]$Exclusions = @('Public','Default','Default User','All Users','WDAGUtilityAccount')
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath)) { return @() }

    # Ensure relative (strip any root that was pasted accidentally)
    if ([System.IO.Path]::IsPathRooted($RelativePath)) {
        $idx = $RelativePath.IndexOf('\AppData\')
        if ($idx -ge 0) { $RelativePath = $RelativePath.Substring($idx+1) }
        else { $RelativePath = (Split-Path -Path $RelativePath -NoQualifier) }
    }

    $userRoot = 'C:\Users'
    if (-not (Test-Path -LiteralPath $userRoot)) { return @() }

    $results = @()
    Get-ChildItem -LiteralPath $userRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $Exclusions -notcontains $_.Name } |
        ForEach-Object {
            $searchPath = Join-Path $_.FullName $RelativePath
            try {
                Get-ChildItem -Path $searchPath -File -ErrorAction SilentlyContinue |
                    ForEach-Object { $results += $_.FullName }
            } catch { }
        }

    return $results
}

# ---------- Registry detection for Windows 'Uninstall' keys ----------
function Get-RegistryAppEntries {
    param([string]$DisplayName)

    $roots = @(
        @{Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';              Scope='Machine'},
        @{Hive='HKLM'; Path='SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope='Machine'},
        @{Hive='HKCU'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             Scope='User'}
    )

    $results = @()
    foreach ($r in $roots) {
        $base = "$($r.Hive):\$($r.Path)"
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
                } catch { }
            }
        } catch { }
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
    if ($LogFile) { New-DirectoryIfMissing -DirectoryPath (Split-Path -Path $LogFile -Parent) }

    $operationSucceeded = Invoke-OperationRetry -MaxRetries $MaxRetries -RetryDelay $RetryDelay -Operation {
        $found = $false
        $findings = @()

        # 1) Machine paths
        foreach ($path in $MachinePaths) {
            $candidates = @()
            try {
                $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
            } catch { }

            if (($candidates.Count -eq 0) -and (Test-Path -LiteralPath $path)) { $candidates = @($path) }

            foreach ($candidate in $candidates) {
                if (-not (Test-Path -LiteralPath $candidate)) { continue }
                $found = $true

                $rawVersion = Get-FileVersionInfoSafe -Path $candidate
                Write-LogEntry "[$AppDisplayName] Detected version '$rawVersion' from '$candidate'"

                $findings += [pscustomobject]@{
                    Source  = 'File'
                    Path    = $candidate
                    Version = $rawVersion
                    Scope   = if ($candidate -like "$env:LocalAppData*") { 'User' } else { 'Machine' }
                }
            }
        }

        # 2) Per-user installs across profiles (SYSTEM context) -- non-fatal
        if ($PerUserRelativePath -and $PerUserRelativePath.Count -gt 0) {
            foreach ($rel in $PerUserRelativePath) {
                try {
                    $perUserHits = Resolve-PerUserAppPaths -RelativePath $rel
                    foreach ($uPath in $perUserHits) {
                        if (-not (Test-Path -LiteralPath $uPath)) { continue }
                        $found = $true

                        $rawVersion = Get-FileVersionInfoSafe -Path $uPath
                        Write-LogEntry "[$AppDisplayName] Detected per-user version '$rawVersion' from '$uPath'"

                        $findings += [pscustomobject]@{
                            Source  = 'File'
                            Path    = $uPath
                            Version = $rawVersion
                            Scope   = 'User'
                        }
                    }
                } catch {
                    Write-LogEntry "[$AppDisplayName] Per-user scan skipped due to error: $_"
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

                Write-LogEntry "[$AppDisplayName] Detected registry entry '$($r.RegistryPath)' version '$version'"

                $findings += [pscustomobject]@{
                    Source        = 'Registry'
                    Path          = $r.RegistryPath
                    FileReference = $pathCandidate
                    Version       = $version
                    Scope         = if ($r.Scope -eq 'User') { 'UserRegistry' } else { 'MachineRegistry' }
                }
            }
        } catch {
            Write-LogEntry "[$AppDisplayName] Registry scan failed: $_"
        }

        if (-not $found) {
            Write-LogEntry "[$AppDisplayName] No executable or registry entry found."
            throw "FileNotFound"
        }

        return $true
    }

    if (-not $operationSucceeded) {
        $intuneOutput.Status = "NotInstalled"
        Write-LogEntry "[$AppDisplayName] Not installed on this system."
        $msg = ("Summary: App='{0}'; Scope= { 1 }; File='{2}'; Detected='{3}'; Expected='{4}'; Status= { 5 }" -f `
            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
        Write-LogEntry $msg
        if ($TriggerRemediationForMissingApp) { $intuneOutput | ConvertTo-Json -Compress; exit 1 } else { $intuneOutput | ConvertTo-Json -Compress; exit 0 }
    }

    # Rebuild findings in the current scope
    $findings = @()

    foreach ($path in $MachinePaths) {
        $candidates = @()
        try { $candidates = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } } catch {}
        if (($candidates.Count -eq 0) -and (Test-Path -LiteralPath $path)) { $candidates = @($path) }
        foreach ($candidate in $candidates) {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }
            $rawVersion = Get-FileVersionInfoSafe -Path $candidate
            $findings += [pscustomobject]@{ Source='File'; Path=$candidate; Version=$rawVersion; Scope = if ($candidate -like "$env:LocalAppData*") { 'User' } else { 'Machine' } }
        }
    }

    if ($PerUserRelativePath -and $PerUserRelativePath.Count -gt 0) {
        foreach ($rel in $PerUserRelativePath) {
            try {
                $perUserHits = Resolve-PerUserAppPaths -RelativePath $rel
                foreach ($uPath in $perUserHits) {
                    if (-not (Test-Path -LiteralPath $uPath)) { continue }
                    $rawVersion = Get-FileVersionInfoSafe -Path $uPath
                    $findings += [pscustomobject]@{ Source='File'; Path=$uPath; Version=$rawVersion; Scope='User' }
                }
            } catch {
                Write-LogEntry "[$AppDisplayName] Per-user re-scan skipped due to error: $_"
            }
        }
    }

    try {
        $regHits = Get-RegistryAppEntries -DisplayName $AppDisplayName
        foreach ($r in $regHits) {
            $version = $r.DisplayVersion
            $displayIcon = $r.DisplayIcon
            $pathCandidate = $null
            if ($displayIcon) { $pathCandidate = $displayIcon -replace '\"' } elseif ($r.InstallLocation) { $pathCandidate = $r.InstallLocation }
            $findings += [pscustomobject]@{ Source='Registry'; Path=$r.RegistryPath; FileReference=$pathCandidate; Version=$version; Scope = if ($r.Scope -eq 'User') { 'UserRegistry' } else { 'MachineRegistry' } }
        }
    } catch {
        Write-LogEntry "[$AppDisplayName] Registry re-scan failed: $_"
    }

    # ----- Evaluation (prefer Compliant if any compliant found) -----
    $malformed = @()
    $compliant = @()
    $outdated  = @()

    foreach ($f in $findings) {
        $raw = $f.Version
        $formatted = Format-Version $raw
        if ([string]::IsNullOrWhiteSpace($raw) -or ($formatted -notmatch '^\d+(\.\d+)*$')) {
            $malformed += $f
            continue
        }
        try {
            if (Compare-Versions -InstalledVersion $formatted -ExpectedVersion $ExpectedVersion) {
                $f | Add-Member -NotePropertyName FormattedVersion -NotePropertyValue $formatted -Force
                $compliant += $f
            } else {
                $f | Add-Member -NotePropertyName FormattedVersion -NotePropertyValue $formatted -Force
                $outdated += $f
            }
        } catch {
            $malformed += $f
        }
    }

    if ($PreferCompliantIfAnyInstanceCompliant -and $compliant.Count -gt 0) {
        $pick = $compliant | Sort-Object { Format-Version $_.Version } -Descending | Select-Object -First 1
        $intuneOutput.FilePath        = $pick.Path
        $intuneOutput.DetectedVersion = $pick.Version
        $intuneOutput.InstallScope    = $pick.Scope
        $intuneOutput.Status          = 'Compliant'
        Write-LogEntry "[$AppDisplayName] Compliant instance detected (preferred): $($pick.Path) => $($pick.Version)"
        $intuneOutput | ConvertTo-Json -Compress; exit 0
    }

    if ($outdated.Count -gt 0) {
        $pick = $outdated | Sort-Object { Format-Version $_.Version } -Descending | Select-Object -First 1
        $intuneOutput.FilePath        = $pick.Path
        $intuneOutput.DetectedVersion = $pick.Version
        $intuneOutput.InstallScope    = $pick.Scope
        $intuneOutput.Status          = if ($pick.Scope -like '*User*') { 'UserScopeOutdated' } else { 'Outdated' }
        Write-LogEntry "[$AppDisplayName] Outdated instance detected: $($pick.Path) => $($pick.Version)"
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

    if ($malformed.Count -gt 0) {
        $pick = $malformed | Select-Object -First 1
        $intuneOutput.FilePath        = $pick.Path
        $intuneOutput.DetectedVersion = $pick.Version
        $intuneOutput.InstallScope    = $pick.Scope
        $intuneOutput.Status          = 'MalformedVersion'
        Write-LogEntry "[$AppDisplayName] Malformed version detected: $($pick.Path) => $($pick.Version)"
        $intuneOutput | ConvertTo-Json -Compress; exit 1
    }

    # If we get here, nothing meaningful was found
    $intuneOutput.Status = 'NotInstalled'
    Write-LogEntry "[$AppDisplayName] No valid instances detected after evaluation."
    if ($TriggerRemediationForMissingApp) { $intuneOutput | ConvertTo-Json -Compress; exit 1 } else { $intuneOutput | ConvertTo-Json -Compress; exit 0 }

} catch {
    $intuneOutput.Status = "Error"
    Write-LogEntry "[$AppDisplayName] An unexpected error occurred: $_"
    $msg = ("Summary: App='{ 0 }'; Scope={1}; File=' { 2 }'; Detected=' { 3 }'; Expected=' { 4 }'; Status={5}" -f `
        $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
    Write-LogEntry $msg
    $intuneOutput | ConvertTo-Json -Compress; exit 1
}
