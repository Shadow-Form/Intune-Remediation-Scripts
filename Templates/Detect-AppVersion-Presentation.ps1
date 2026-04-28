<#
    Intune Proactive Remediation – Minimal Detection Script
    -------------------------------------------------------
    This script demonstrates the core PR detection workflow:
    1. Check one or more paths for an app
    2. Read the file version
    3. Compare with the required version
    4. Output JSON and return exit code
#>

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
)

# ------------------------------------------------------------
# Minimal local logger
# ------------------------------------------------------------
function Write-LocalLog {
    param([string]$Message)

    $LogDir = "C:\Logs"
    if (-not (Test-Path $LogDir)) {
        try { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null } catch { }
    }

    $Safe = ($AppDisplayName -replace '[^A-Za-z0-9_-]', '_')
    $LogFile = Join-Path $LogDir ("Detect-$Safe.log")

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
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
    Write-LocalLog "Status=NotInstalled Expected=$ExpectedVersion"

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
        Write-LocalLog "Status=Compliant Path=$($f.Path) Version=$($f.Version)"
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
Write-LocalLog "Status=Outdated Expected=$ExpectedVersion Path=$($findings[0].Path) Detected=$($findings[0].Version)"
exit 1
