<#
.SYNOPSIS
    Detect presence of consumer or user-scoped Office/OneDrive installs on a device.

.DESCRIPTION
    This detection script inspects the machine-level uninstall registry keys and per-user
    profile folders to determine whether non-enterprise Office packages or a user-installed
    OneDrive are present, and whether OneDrive shows recent user activity.

    Exit codes follow Intune conventions: 0 = compliant/no remediation needed; 1 = remediation
    recommended (non-enterprise apps or personal OneDrive activity detected).

.PARAMETER IncludeUserDetails
    If specified, include per-user details (usernames and counts) in human output. Defaults
    to off to avoid exposing user identifiers in telemetry.

.PARAMETER RecentThresholdDays
    Time window (days) used to classify "recent" OneDrive file activity. Valid range: 1-365.

.PARAMETER UserProfilesPath
    Path to enumerate user profiles (default: C:\Users). Provided to make testing easier.

.EXAMPLE
    .\Detect-O365Bloat.ps1 -RecentThresholdDays 14

.NOTES
    - Non-destructive; read-only. Designed to be run as a detection script in Intune.
    - Avoids exposing usernames by default; use -IncludeUserDetails only when necessary.
#>

param (
    [switch]$IncludeUserDetails,
    [ValidateRange(1, 365)][int]$RecentThresholdDays = 30,
    [ValidateNotNullOrEmpty()][string]$UserProfilesPath = 'C:\Users'
)

# Prefer localized error handling; functions use try/catch for critical reads
$ErrorActionPreference = 'Continue'

# Centralize the uninstall registry path so functions reuse the same source
$UninstallRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'

function Test-O365ProPlusRetail {
    $found = $false
    try {
        # Read the machine uninstall registry; stop on failure and handle below
        $keys = Get-ChildItem -Path $UninstallRegPath -ErrorAction Stop
    }
    catch {
        Write-Verbose ("Failed to read uninstall registry: {0}" -f $_.Exception.Message)
        $keys = @()
    }
    foreach ($key in $keys) {
        if ($key.PSChildName -like 'O365ProPlusRetail*') {
            $found = $true
            break
        }
    }
    return $found
}

function Test-HomeOfficeApps {
    $found = $false
    try {
        # Read the machine uninstall registry; stop on failure and handle below
        $keys = Get-ChildItem -Path $UninstallRegPath -ErrorAction Stop
    }
    catch {
        Write-Verbose ("Failed to read uninstall registry: {0}" -f $_.Exception.Message)
        $keys = @()
    }
    foreach ($key in $keys) {
        if (
            $key.PSChildName -like 'O365HomePremRetail*' -or
            $key.PSChildName -like 'O365HomeBusinessRetail*' -or
            $key.PSChildName -like 'O365PersonalRetail*' -or
            $key.PSChildName -like 'OneNoteFreeRetail*'
        ) {
            $found = $true
            break
        }
    }
    return $found
}

function Test-OneDriveStandalone {
    $found = $false
    try {
        # Read the machine uninstall registry; stop on failure and handle below
        $keys = Get-ChildItem -Path $UninstallRegPath -ErrorAction Stop
    }
    catch {
        Write-Verbose ("Failed to read uninstall registry: {0}" -f $_.Exception.Message)
        $keys = @()
    }
    foreach ($key in $keys) {
        if (
            $key.PSChildName -like 'OneDriveSetup.exe*' -or
            $key.PSChildName -like 'OneDrive*' -or
            $key.PSChildName -like 'OneDrive.exe*'
        ) {
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.InstallLocation -and $props.InstallLocation -match 'C:\\Users\\') {
                $found = $true
                break
            }
        }
    }
    return $found
}

function Get-NonEntOfficeApps {
    $foundApps = @()
    try { $keys = Get-ChildItem -Path $UninstallRegPath -ErrorAction Stop } catch { Write-Verbose ("Failed to read uninstall registry: {0}" -f $_.Exception.Message); $keys = @() }
    foreach ($key in $keys) {
        if (
            $key.PSChildName -like 'O365HomePremRetail*' -or
            $key.PSChildName -like 'O365HomeBusinessRetail*' -or
            $key.PSChildName -like 'O365PersonalRetail*' -or
            $key.PSChildName -like 'OneNoteFreeRetail*'
        ) {
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName) {
                $foundApps += $props.DisplayName
            }
            else {
                $foundApps += $key.PSChildName
            }
        }
        elseif (
            $key.PSChildName -like 'OneDriveSetup.exe*' -or
            $key.PSChildName -like 'OneDrive*' -or
            $key.PSChildName -like 'OneDrive.exe*'
        ) {
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.InstallLocation -and $props.InstallLocation -match 'C:\\Users\\') {
                if ($props.DisplayName) {
                    $foundApps += "$(($props.DisplayName)) (User context: $($props.InstallLocation))"
                }
                else {
                    $foundApps += "$($key.PSChildName) (User context: $($props.InstallLocation))"
                }
            }
        }
    }
    return $foundApps
}

$enterpriseApp = Test-O365ProPlusRetail
$homeApps = Test-HomeOfficeApps
$oneDriveStandalone = Test-OneDriveStandalone
$nonEntOfficeAppsList = Get-NonEntOfficeApps

# Check for personal OneDrive usage (preserve thoroughness: count matching files per user)
$oneDriveUsage = $false
$recentFiles = @()
$recentUserCount = 0

$excludeProfiles = @('Public', 'Default', 'Default User', 'All Users')
$users = @()
try {
    # Enumerate local user profile folders; stop on failure and handle below
    $users = Get-ChildItem -Path $UserProfilesPath -Directory -ErrorAction Stop
}
catch {
    Write-Verbose ("Failed to enumerate profiles: {0}" -f $_.Exception.Message)
    $users = @()
}
$users = $users | Where-Object { $_.Name -notin $excludeProfiles }
foreach ($user in $users) {
    $oneDrivePath = Join-Path $user.FullName 'OneDrive'
    if (Test-Path $oneDrivePath) {
        try {
            # Count matching files without retaining file objects in memory
            $count = Get-ChildItem -Path $oneDrivePath -Recurse -File -ErrorAction Stop |
            Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-$RecentThresholdDays) } |
            Measure-Object | Select-Object -ExpandProperty Count
        }
        catch {
            # Ignore enumeration errors for individual profiles (access denied, junctions, etc.)
            $count = 0
        }
        if ($count -gt 0) {
            $oneDriveUsage = $true
            $recentUserCount++
            if ($IncludeUserDetails) {
                $recentFiles += "$($user.Name): $count recent files"
            }
        }
    }
}

if ($enterpriseApp) {
    if ($homeApps -or $oneDriveStandalone) {
        $appsFoundMsg = ""
        if ($nonEntOfficeAppsList.Count -gt 0) {
            $appsFoundMsg = "Non-enterprise Office apps/OneDrive found: $($nonEntOfficeAppsList -join ', ')"
        }
        if ($oneDriveUsage) {
            if ($IncludeUserDetails) {
                Write-Output "$appsFoundMsg. Personal OneDrive appears to be in use: $($recentFiles -join '; ')"
            }
            else {
                Write-Output "$appsFoundMsg. Personal OneDrive appears to be in use: $recentUserCount user(s) with recent activity"
            }
        }
        else {
            Write-Output "$appsFoundMsg. No recent personal OneDrive usage found."
        }
        exit 1
    }
    else {
        Write-Output "Only enterprise Office apps present. No cleanup needed."
        exit 0
    }
}
else {
    Write-Output "Enterprise Office not detected. Skipping cleanup."
    exit 0
}
