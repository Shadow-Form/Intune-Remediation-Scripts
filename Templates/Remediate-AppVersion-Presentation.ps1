<#
  Intune Proactive Remediation – Minimal Remediation Script
  ---------------------------------------------------------
  Purpose:
    If this script is running, detection has already determined:
      “The app is missing or outdated — remediation should run.”

  This script:
    1. Downloads the installer from a single URL (Blob storage, etc.)
    2. Executes MSI or EXE with provided arguments
    3. Verifies installation
    4. Outputs JSON and uses clear exit codes:
         0 = Fixed / Installed / UpToDate after install
         1 = Failed to install
#>

param(
    # Friendly name for logs and JSON
    [string]$AppDisplayName,

    # One or more paths for post-install version check
    [string[]]$MachinePaths,

    # Required minimum version
    [string]$ExpectedVersion,

    # MSI or EXE installer type
    [ValidateSet('msi','exe')]
    [string]$InstallerType,

    # Installer argument string (may contain <PATH> placeholder)
    [string]$InstallerArgs,

    # Single installer source (Azure blob storage, etc.)
    [Parameter(Mandatory=$true)]
    [string]$InstallerUrl
)

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
    } catch { return '' }
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
    App      = $AppDisplayName
    Status   = "Unknown"
    Required = $ExpectedVersion
    Installer = @{
        Type = $InstallerType
        Path = ""
        Exit = ""
    }
}

# ------------------------------------------------------------
# Step 0.2 - Derive a local installer filename automatically
# ------------------------------------------------------------
$FileName = [System.IO.Path]::GetFileName(([System.Uri]$InstallerUrl).AbsolutePath)
if ([string]::IsNullOrWhiteSpace($FileName)) {
Name = "$($AppDisplayName)-installer.bin"
}

$InstallerLocalPath = Join-Path $env:TEMP $FileName

# ------------------------------------------------------------
# Step 1 - Download installer (single attempt)
# ------------------------------------------------------------
try {
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerLocalPath -UseBasicParsing
    $Out.Installer.Path = $InstallerLocalPath
}
catch {
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
}
catch {
    $Out.Status = "InstallerError"
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 1
}

# ------------------------------------------------------------
# Step 4 - Post-install verification
# ------------------------------------------------------------
$AfterVersion = Get-InstalledVersion -Paths $MachinePaths

# ------------------------------------------------------------
# Step 5 - Output (JSON for Intune) and exit code
# ------------------------------------------------------------
if ($AfterVersion -and (Test-VersionCompliance $AfterVersion $ExpectedVersion)) {
    $Out.Status  = "Fixed"
    $Out.Version = $AfterVersion
    $Out | ConvertTo-Json -Compress | Out-Host
    exit 0
}

$Out.Status  = "InstallFailedOrOutdated"
$Out.Version = $AfterVersion
$Out | ConvertTo-Json -Compress | Out-Host
exit 1
