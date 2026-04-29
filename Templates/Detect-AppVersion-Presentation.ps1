<#
    Intune Proactive Remediation – Minimal Detection Script
    -------------------------------------------------------
    This script demonstrates the core PR detection workflow:
    1. Check one or more paths for an app
    2. Read the file version
    3. Compare with the required version
    4. Output JSON and return exit code
#>
    # Logging: Opt-in via `-EnableLogging` (boolean) and optional `-LogFile` parameter.
    # When `-EnableLogging` is true and `-LogFile` is not supplied the script will
    # derive a default at `Join-Path -Path $env:TEMP -ChildPath ("Detect-<SafeAppName>.log")`.

param(
    # The friendly name of the app we are detecting
    [string]$AppDisplayName = "My Application",

    # One or more file paths to check for the app's presence and version (typically .exe or .dll)
    [string[]]$MachinePaths = @(
        "C:\Program Files\MyApp\MyApp.exe",
        "C:\Program Files (x86)\MyApp\MyApp.exe"
    ),

    # The minimum version we consider compliant (typical format: major.minor.build.revision)
    [string]$ExpectedVersion = "1.0.0",

    # If the app is missing:
    #   $true  = remediation should run (exit 1)
    #   $false = skip remediation for missing apps (exit 0)
    [bool]$RemediateIfMissing = $false
    ,
    # Enable local file logging when true; default is false to keep detection read-only
    [bool]$EnableLogging = $false,
    # Optional explicit log file path. When supplied the script writes to this file even if -EnableLogging is not set.
    [string]$LogFile
)

# ------------------------------------------------------------
# Minimal local logger (standardized)
# ------------------------------------------------------------
function Get-SafeFileName {
    param([string]$Name)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $clean = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    $clean = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

function Write-LogEntry {
    param([string]$Message)

    Write-Verbose $Message
    if (-not $EnableLogging) { return }

    if (-not $PSBoundParameters.ContainsKey('LogFile') -or [string]::IsNullOrWhiteSpace($LogFile)) {
        $LogFile = Join-Path -Path $env:TEMP -ChildPath ("Detect-$(Get-SafeFileName -Name $AppDisplayName).log")
    }

    $logDir = Split-Path -Path $LogFile -Parent
    if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
        try { New-Item -Path $logDir -ItemType Directory -Force | Out-Null } catch { }
    }

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    try { Add-Content -LiteralPath $LogFile -Value "$timestamp $Message" } catch { }
}

# ------------------------------------------------------------
# Helper: Normalize a version string for simple comparison
# ------------------------------------------------------------
function Convert-Version {
    param([string]$v)
    if (-not $v) { return "0.0.0.0" }
    $clean = ($v -replace ',', '.').Trim()
    if ($clean -notmatch '\d') { return "0.0.0.0" }
    return $clean
}

# ------------------------------------------------------------
# Helper: Installed >= Expected ?
# ------------------------------------------------------------
function Test-VersionCompliance {
    param($Installed, $Expected)
    try { return ([version]$Installed -ge [version]$Expected) }
    catch { return $false }
}

# ------------------------------------------------------------
# Helper: Retrieve file version safely
# ------------------------------------------------------------
function Get-FileVersion {
    param([string]$Path)
    try {
        $v = (Get-Item $Path).VersionInfo.ProductVersion
        return Convert-Version $v
    }
    catch { return "" }
}

# ------------------------------------------------------------
# Step 1 — Search paths for files and collect version info
# ------------------------------------------------------------
$findings = @()

foreach ($path in $MachinePaths) {
    if (Test-Path $path) {
        $item = Get-Item $path
        if ($item.PSIsContainer) {
            Get-ChildItem $path -File | ForEach-Object {
                $findings += @{ Path = $_.FullName; Version = Get-FileVersion $_.FullName }
            }
        }
        else {
            $findings += @{ Path = $path; Version = Get-FileVersion $path }
        }
    }
}

# ------------------------------------------------------------
# Step 2 — App not found logic (this is where your boolean applies)
# ------------------------------------------------------------
if ($findings.Count -eq 0) {

    @{
        App    = $AppDisplayName
        Status = 'NotInstalled'
    } | ConvertTo-Json -Compress
    Write-LogEntry "Status=NotInstalled Expected=$ExpectedVersion"

    if ($RemediateIfMissing) { exit 1 } else { exit 0 }
}

# ------------------------------------------------------------
# Step 3 — Evaluate first valid version found
# ------------------------------------------------------------
foreach ($f in $findings) {
    if ($f.Version -and (Test-VersionCompliance $f.Version $ExpectedVersion)) {
        @{
            App     = $AppDisplayName
            Status  = 'Compliant'
            Path    = $f.Path
            Version = $f.Version
        } | ConvertTo-Json -Compress
        Write-LogEntry "Status=Compliant Path=$($f.Path) Version=$($f.Version)"
        exit 0
    }
}

# ------------------------------------------------------------
# Step 4 — At least one instance found, but all outdated
# ------------------------------------------------------------
@{
    App      = $AppDisplayName
    Status   = 'Outdated'
    Required = $ExpectedVersion
} | ConvertTo-Json -Compress
Write-LogEntry "Status=Outdated Expected=$ExpectedVersion Path=$($findings[0].Path) Detected=$($findings[0].Version)"
exit 1
