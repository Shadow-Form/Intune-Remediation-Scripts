#<
#.SYNOPSIS
Download and install an application installer, then verify the installed version; optional logging to C:\Logs.

#.DESCRIPTION
Downloads a single installer (MSI or EXE), executes it with provided arguments,
verifies the installed version against `-ExpectedVersion`, and emits compact
JSON and exit codes: 0 = Fixed / Installed / UpToDate after install; 1 = Failed
to install or still outdated.

Behavior:
- Script is non-interactive and designed to be idempotent where possible.
- Logging is opt-in via `-EnableLogging`. If `-LogFile` is provided it is used
regardless of `-EnableLogging`.
- Default log file when not supplied: `C:\Logs\Remediate-<SafeAppName>.log`.

.PARAMETER AppDisplayName
Friendly name for logs and JSON.

.PARAMETER MachinePaths
Paths used for post-install verification.

.PARAMETER ExpectedVersion
Minimum required version.

.PARAMETER InstallerType
`msi` or `exe`.

.PARAMETER InstallerArgs
Arguments for the installer (supports `<PATH>` token replacement).

.PARAMETER InstallerUrl
URL to download the installer from (mandatory).

.PARAMETER EnableLogging
Switch to enable local file logging (default: $false).

.PARAMETER LogFile
Optional explicit log file path (overrides default).

.EXAMPLE
PS> .\Remediate-AppVersion-Presentation.ps1 -AppDisplayName 'MyApp' -InstallerUrl 'https://...' -InstallerType 'msi' -InstallerArgs '/i <PATH> /qn' -EnableLogging

.NOTES
Author: Your Name
LastUpdated: 2026-04-30
#>

param(
    # Friendly name for logs and JSON
    [string]$AppDisplayName,

    # One or more paths for post-install version check
    [string[]]$MachinePaths,

    # Required minimum version
    [string]$ExpectedVersion,

    # MSI or EXE installer type
    [ValidateSet('msi', 'exe')]
    [string]$InstallerType,

    # Installer argument string (may contain <PATH> placeholder)
    [string]$InstallerArgs,

    # Single installer source (Azure blob storage, etc.)
    [Parameter(Mandatory = $true)]
    [string]$InstallerUrl
    ,
    # Enable local file logging when true; default is false to avoid noisy remediation runs
    [bool]$EnableLogging = $false,
    # Optional explicit log file path. When supplied the script writes to this file even if -EnableLogging is not set.
    [string]$LogFile
)

# ------------------------------------------------------------
# Minimal local logger (standardized to match detection)
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
    # Honor explicit LogFile even if EnableLogging is not set
    if (-not $EnableLogging -and -not $PSBoundParameters.ContainsKey('LogFile')) { return }

    if (-not $PSBoundParameters.ContainsKey('LogFile') -or [string]::IsNullOrWhiteSpace($LogFile)) {
        $LogFile = Join-Path -Path 'C:\Logs' -ChildPath ("Remediate-$(Get-SafeFileName -Name $AppDisplayName).log")
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
    if (-not $v) { return '0.0.0.0' }
    $v = ($v -replace ',', '.').Trim()
    if ($v -notmatch '\d') { return '0.0.0.0' }
    return $v
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
        $raw = (Get-Item $Path).VersionInfo.ProductVersion
        return Convert-Version $raw
    }
    catch { return '' }
}

# ------------------------------------------------------------
# Helper: Check multiple paths for installed version
# ------------------------------------------------------------
function Get-InstalledVersion {
    param([string[]]$Paths)
    foreach ($p in $Paths) {
        if (Test-Path $p) {
            $item = Get-Item $p
            if ($item.PSIsContainer) {
                $file = Get-ChildItem $p -File -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($file) { return Get-FileVersion $file.FullName }
            }
            else {
                return Get-FileVersion $p
            }
        }
    }
    return ''
}

# ------------------------------------------------------------
# Step 0.1 - Initialize output object (JSON for Intune)
# ------------------------------------------------------------
$Out = @{
    App       = $AppDisplayName
    Status    = "Unknown"
    Required  = $ExpectedVersion
    Installer = @{
        Type = $InstallerType
        Path = ""
        Exit = ""
    }
}

Write-LogEntry "Starting remediation for $AppDisplayName (expected version $ExpectedVersion)"

# ------------------------------------------------------------
# Step 0.2 - Derive a local installer filename automatically
# ------------------------------------------------------------
$FileName = [System.IO.Path]::GetFileName(([System.Uri]$InstallerUrl).AbsolutePath)
if ([string]::IsNullOrWhiteSpace($FileName)) {
    $FileName = "$($AppDisplayName)-installer.bin"
}

$InstallerLocalPath = Join-Path $env:TEMP $FileName

# ------------------------------------------------------------
# Step 1 - Download installer (single attempt)
# ------------------------------------------------------------
Write-LogEntry "Downloading installer from $InstallerUrl"

try {
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerLocalPath -UseBasicParsing
    $Out.Installer.Path = $InstallerLocalPath
}
catch {
    Write-LogEntry "Download failed"
    $Out.Status = "DownloadFailed"
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 1
}

# ------------------------------------------------------------
# Step 2 - Prepare installer arguments (<PATH> replacement)
# ------------------------------------------------------------
$EffectiveArgs = $InstallerArgs
if ($EffectiveArgs -match '<PATH>') {
    $EffectiveArgs = $EffectiveArgs.Replace('<PATH>', ('"' + $InstallerLocalPath + '"'))
}

# ------------------------------------------------------------
# Step 3 - Run installer (simple MSI/EXE branch)
# ------------------------------------------------------------
try {
    if ($InstallerType -eq 'msi') {
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $EffectiveArgs -Wait -PassThru -NoNewWindow
        $Out.Installer.Exit = $proc.ExitCode
    }
    else {
        $proc = Start-Process -FilePath $InstallerLocalPath -ArgumentList $EffectiveArgs -Wait -PassThru -NoNewWindow
        $Out.Installer.Exit = $proc.ExitCode
    }
    Write-LogEntry "Installer finished with exit code $($proc.ExitCode)"
}
catch {
    Write-LogEntry "Installer execution error"
    $Out.Status = "InstallerError"
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 1
}

# ------------------------------------------------------------
# Step 4 - Post-install verification
# ------------------------------------------------------------
$AfterVersion = Get-InstalledVersion -Paths $MachinePaths
Write-LogEntry "Post-install detected version: $AfterVersion"

# ------------------------------------------------------------
# Step 5 - Output (JSON for Intune) and exit code
# ------------------------------------------------------------
if ($AfterVersion -and (Test-VersionCompliance $AfterVersion $ExpectedVersion)) {
    $Out.Status = "Fixed"
    $Out.Version = $AfterVersion
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 0
}

$Out.Status = "InstallFailedOrOutdated"
$Out.Version = $AfterVersion
$Out | ConvertTo-Json -Compress | Out-Host
exit 1
