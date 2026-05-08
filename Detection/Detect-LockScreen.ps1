<#
.SYNOPSIS
  Full-featured Intune Detection Script for Lock Screen Image Compliance (Device scope)

.DESCRIPTION
  Detects whether a Windows device complies with lock-screen configuration, including:
    - Strict validation of the CSP LockScreenImageUrl (file:/// with triple slash, no leading/trailing whitespace)
    - Path normalization from file URI to NT path
    - Acceptance of Windows lock-screen cache locations (with SHA-256 hash equality check)
    - CSP status verification (LockScreenImageStatus = 1)
    - Policy checks for showing image at sign-in and acrylic blur preference
    - Per-user overrides via SystemProtectedUserData (HideLogonBackgroundImage)
    - OPTIONAL conflict detection of legacy GPOs that might override CSP (Personalization\LockScreenImage; System\DisableLockScreen)
    - Upgraded operator output (summary line even on exit 0, compact failed-checks view, optional detailed table, JSON to file or stdout, quiet mode, color toggle)

.INTUNE BEHAVIOR
  - Exit code 0 = Compliant; Exit code 1 = Needs remediation
  - Optional console output is included even on exit 0 (compact “[OK] Compliant” summary).
  - Use -Quiet to suppress console and rely purely on exit code and (optionally) JSON.

.PARAMETERS
  -Report
      Show a full table of all checks (in addition to the compact summary). Useful for ad-hoc testing.
  -OutJson <path>
      Write machine-readable JSON (Summary + Checks) to the specified file.
  -LocalImagePathOverride <path>
      Override the expected local image path.
  -OutputMode <auto|table|json|both|summary>
      Controls output style:
        auto    = Compact summary; table if -Report; JSON only if -OutJson is set.
        table   = Compact summary + detailed table (no JSON unless -OutJson).
        json    = Compact summary + JSON to stdout (or to -OutJson if provided).
        both    = Compact summary + detailed table + JSON to stdout (or to -OutJson).
        summary = Compact summary only.
      Default: summary
  -Quiet
      Suppress console output; exit code indicates compliance. JSON still written if -OutJson.
  -NoColor
      Disable ANSI colors (useful for collectors that don’t preserve console color).

.EXPECTATIONS (must match remediation)
  - The lock-screen image is delivered to: C:\ProgramData\Compliance\LockScreen\filename.png
  - The device-scoped profile sets: ./Vendor/MSFT/Personalization/LockScreenImageUrl = file:///C:/ProgramData/Compliance/LockScreen/filename.png
  - CSP status is owned by Windows; do NOT force Status=1 via remediation.

.EXAMPLES
  .\Detect-LockScreen.ps1
      Prints “[OK] Compliant (Total:X, Failed:0)” or failed checks; returns exit 0/1.
  .\Detect-LockScreen.ps1 -Report
      Adds a detailed table view.
  .\Detect-LockScreen.ps1 -OutputMode json
      Prints Summary+Checks JSON to stdout (and the compact summary).
  .\Detect-LockScreen.ps1 -OutJson "C:\Temp\LockScreenDetect.json" -Quiet
      Writes JSON to file and prints nothing; use exit code to branch remediation.
#>

param(
    [switch]$Report,
    [string]$OutJson = "",
    [string]$LocalImagePathOverride = "",
    [ValidateSet('auto','table','json','both','summary')]
    [string]$OutputMode = 'summary',
    [switch]$Quiet,
    [switch]$NoColor
)

# ----------------------------------------------------------------------------------------------------------------------
# Configuration (MUST match remediation delivery path)
# ----------------------------------------------------------------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'

# Default local image path used by lock-screen remediation
$LocalImagePathDefault = 'C:\ProgramData\Compliance\LockScreen\filename.png'
$LocalImagePath = if ($LocalImagePathOverride) { $LocalImagePathOverride } else { $LocalImagePathDefault }

# Policy expectations
# - Show background at sign-in: DisableLogonBackgroundImage = 0 (image shown)
# - AcceptNull_LogonBackground: set $true to accept <null> as PASS for this policy
# - Acrylic: $true = expect clear (DisableAcrylicBackgroundOnLogon = 1), $false = expect blur (0 or <null>), $null = no enforcement
$ExpectDisableLogonBackground = 0
$AcceptNull_LogonBackground   = $false
$ExpectDisableAcrylicOnLogon  = $true

# Registry roots
$cspRoot     = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
$polRoot     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$polPersRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
$spudRoot    = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData'

# ----------------------------------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------------------------------
function Get-ItemPropSafe { param([string]$Path) try { Get-ItemProperty -Path $Path -ErrorAction Stop } catch { $null } }
function BoolToPassFail([bool]$b) { if ($b) { 'PASS' } else { 'FAIL' } }

function W([string]$msg,[string]$level='INFO'){
    if ($Quiet) { return } # No console output in Quiet mode
    if ($NoColor) { Write-Host "$msg" ; return }
    switch ($level) {
        'OK'   { Write-Host $msg -ForegroundColor Green }
        'FAIL' { Write-Host $msg -ForegroundColor Red   }
        'WARN' { Write-Host $msg -ForegroundColor Yellow}
        default{ Write-Host $msg }
    }
}

# Normalize a file:// URI to NT path with strict checks
function NormalizeFileUrlToPath([string]$s) {
    if ([string]::IsNullOrWhiteSpace($s)) { return $s }
    $s = $s.Trim()
    if ($s -match '^(?i)file://') {
        # require triple slash for local file URIs: file:///C:/...
        if ($s -notmatch '^(?i)file:///') { return $null }
        $p = $s -replace '^(?i)file://', ''
        if ($p -match '^/') { $p = $p.Substring(1) } # drop the leading slash before drive letter
        $p = $p -replace '/', '\'
        return $p
    }
    return $s
}

# Lint the URI format (triple slash, no whitespace, drive after file:///)
function ValidateFileUrl([string]$url) {
    if ([string]::IsNullOrWhiteSpace($url)) { return @{ Valid=$false; Reason='Null/empty' } }
    $u = $url.Trim()
    if ($u -notmatch '^(?i)file:///')           { return @{ Valid=$false; Reason='Missing triple slash (file:///)' } }
    if ($u -match '^\s')                        { return @{ Valid=$false; Reason='Leading whitespace' } }
    if ($u -notmatch '^(?i)file:///[A-Za-z]:/') { return @{ Valid=$false; Reason='No drive path after file:///' } }
    return @{ Valid=$true; Reason=$null }
}

# Recognize common Windows lock-screen cache locations
function IsWindowsLockCachePath([string]$p) {
    if ([string]::IsNullOrWhiteSpace($p)) { return $false }
    return ($p -like 'C:\Windows\Personalization\LockScreenImage\*' -or
            $p -like 'C:\Windows\Web\Screen\*' -or
            $p -like 'C:\Windows\System32\oobe\info\backgroundimages\*')
}

function SafeHash([string]$path) {
    try { return (Get-FileHash -Algorithm SHA256 -Path $path -ErrorAction Stop).Hash } catch { return $null }
}

# ----------------------------------------------------------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------------------------------------------------------
$catalogue = @()

# 1) Local image file exists
$FileExists = Test-Path -LiteralPath $LocalImagePath
$catalogue += [pscustomobject]@{
    Check    = 'Local image file exists'
    Expected = $LocalImagePath
    Actual   = if ($FileExists) { 'Present' } else { 'Missing' }
    PassFail = BoolToPassFail($FileExists)
}

# 2) CSP values
$csp      = Get-ItemPropSafe -Path $cspRoot
$cspPath  = if ($csp) { $csp.LockScreenImagePath } else { $null }
$cspUrl   = if ($csp) { $csp.LockScreenImageUrl }  else { $null }
$cspStat  = if ($csp) { $csp.LockScreenImageStatus } else { $null }

# Strict URL format check + normalized path
$cspUrlCheck = ValidateFileUrl $cspUrl
$cspUrlNorm  = if ($cspUrlCheck.Valid) { NormalizeFileUrlToPath $cspUrl } else { $null }

# Path check: allow local path OR recognized Windows cache path (with hash equality)
$cachePathOk = $false
if (IsWindowsLockCachePath $cspPath) {
    $cachePathOk = Test-Path -LiteralPath $cspPath
    if ($cachePathOk -and $FileExists) {
        $srcHash   = SafeHash $LocalImagePath
        $cacheHash = SafeHash $cspPath
        if ($srcHash -and $cacheHash -and ($srcHash -eq $cacheHash)) { $cachePathOk = $true } else { $cachePathOk = $false }
    }
}
$cspPathOk = ($cspPath -eq $LocalImagePath) -or $cachePathOk
$cspUrlOk  = ($cspUrlNorm -eq $LocalImagePath)
$cspStatOk = ($cspStat -eq 1)

$catalogue += [pscustomobject]@{
    Check    = 'CSP: LockScreenImageUrl (format)'
    Expected = 'Valid file:/// URI (no leading/trailing spaces, triple slash, drive path)'
    Actual   = if ($cspUrlCheck.Valid) { 'Valid' } else { "Invalid: $($cspUrlCheck.Reason)" }
    PassFail = BoolToPassFail($cspUrlCheck.Valid)
}
$catalogue += [pscustomobject]@{
    Check    = 'CSP: LockScreenImageUrl (normalized path equals LocalImagePath)'
    Expected = $LocalImagePath
    Actual   = if ($cspUrl) { $cspUrl } else { '<null>' }
    PassFail = BoolToPassFail($cspUrlOk)
}
$catalogue += [pscustomobject]@{
    Check    = 'CSP: LockScreenImagePath'
    Expected = "$LocalImagePath OR recognized Windows cache path (hash-equal)"
    Actual   = $cspPath
    PassFail = BoolToPassFail($cspPathOk)
}
$catalogue += [pscustomobject]@{
    Check    = 'CSP: LockScreenImageStatus'
    Expected = '1 (success)'
    Actual   = if ($null -eq $cspStat) { '<null>' } else { [string]$cspStat }
    PassFail = BoolToPassFail($cspStatOk)
}

# 3) Sign-in background policy
$pol           = Get-ItemPropSafe -Path $polRoot
$polHideVal    = if ($pol) { $pol.DisableLogonBackgroundImage } else { $null }
$signInImageOk = if ($AcceptNull_LogonBackground -and $null -eq $polHideVal) { $true } else { ($polHideVal -eq $ExpectDisableLogonBackground) }

$catalogue += [pscustomobject]@{
    Check    = 'Policy: DisableLogonBackgroundImage'
    Expected = if ($AcceptNull_LogonBackground) { "0 or <null>" } else { "0" }
    Actual   = if ($null -eq $polHideVal) { '<null>' } else { [string]$polHideVal }
    PassFail = BoolToPassFail($signInImageOk)
}

# 4) Acrylic blur preference (tri-state enforcement)
$polBlurVal = if ($pol) { $pol.DisableAcrylicBackgroundOnLogon } else { $null }
if ($ExpectDisableAcrylicOnLogon -eq $true) {
    $blurOk = ($polBlurVal -eq 1)
    $catalogue += [pscustomobject]@{
        Check    = 'Policy: DisableAcrylicBackgroundOnLogon'
        Expected = '1 (clear background)'
        Actual   = if ($null -eq $polBlurVal) { '<null>' } else { [string]$polBlurVal }
        PassFail = BoolToPassFail($blurOk)
    }
} elseif ($ExpectDisableAcrylicOnLogon -eq $false) {
    $blurOk = ($polBlurVal -eq 0 -or $null -eq $polBlurVal)
    $catalogue += [pscustomobject]@{
        Check    = 'Policy: DisableAcrylicBackgroundOnLogon'
        Expected = '0 or <null>'
        Actual   = if ($null -eq $polBlurVal) { '<null>' } else { [string]$polBlurVal }
        PassFail = BoolToPassFail($blurOk)
    }
} else {
    # $null -> do not enforce acrylic; still surface info as PASS
    $catalogue += [pscustomobject]@{
        Check    = 'Policy: DisableAcrylicBackgroundOnLogon (not enforced)'
        Expected = '<not enforced>'
        Actual   = if ($null -eq $polBlurVal) { '<null>' } else { [string]$polBlurVal }
        PassFail = 'PASS'
    }
}

# 5) Per-user overrides (SPUD): HideLogonBackgroundImage = 1 blocks the background
$perUserOk = $true
$offSids = @()
if (Test-Path $spudRoot) {
    Get-ChildItem -Path $spudRoot -ErrorAction SilentlyContinue | ForEach-Object {
        $sidLock = Join-Path $_.PSPath 'AnyoneRead\LockScreen'
        if (Test-Path $sidLock) {
            $val = (Get-ItemProperty -Path $sidLock -Name 'HideLogonBackgroundImage' -ErrorAction SilentlyContinue).HideLogonBackgroundImage
            if ($null -ne $val -and $val -eq 1) {
                $perUserOk = $false
                $offSids += $_.PSChildName
            }
        }
    }
}
$catalogue += [pscustomobject]@{
    Check    = 'Per-user: HideLogonBackgroundImage'
    Expected = 'All SIDs = 0 or <null>'
    Actual   = if ($offSids.Count -gt 0) { "Off for SIDs: $($offSids -join ', ')" } else { 'All On/<null>' }
    PassFail = BoolToPassFail($perUserOk)
}

# 6) OPTIONAL: Conflicting legacy GPOs that can override CSP
$polPers     = Get-ItemPropSafe -Path $polPersRoot
$gpoLockImg  = if ($polPers) { $polPers.LockScreenImage } else { $null }
if ($gpoLockImg) {
    $catalogue += [pscustomobject]@{
        Check    = 'Conflict: GPO LockScreenImage (Personalization)'
        Expected = 'Not present'
        Actual   = $gpoLockImg
        PassFail = 'FAIL'
    }
}
$polDisableLock = if ($pol) { $pol.DisableLockScreen } else { $null }
if ($null -ne $polDisableLock -and $polDisableLock -eq 1) {
    $catalogue += [pscustomobject]@{
        Check    = 'Conflict: DisableLockScreen'
        Expected = '0 or <null>'
        Actual   = [string]$polDisableLock
        PassFail = 'FAIL'
    }
}

# ----------------------------------------------------------------------------------------------------------------------
# Aggregate compliance
# ----------------------------------------------------------------------------------------------------------------------
$failCount = ($catalogue | Where-Object { $_.PassFail -eq 'FAIL' }).Count
$summary = [pscustomobject]@{
    Device        = $env:COMPUTERNAME
    Timestamp     = (Get-Date).ToString('s')
    LocalImagePath= $LocalImagePath
    TotalChecks   = $catalogue.Count
    FailedChecks  = $failCount
    Compliant     = ($failCount -eq 0)
}

# ----------------------------------------------------------------------------------------------------------------------
# Output selection logic
# ----------------------------------------------------------------------------------------------------------------------
$printTable   = $false
$printJson    = $false
$printSummary = $true

switch ($OutputMode) {
    'table'   { $printTable = $true;  $printJson = $false; $printSummary = $true }
    'json'    { $printTable = $false; $printJson  = $true;  $printSummary = $true }
    'both'    { $printTable = $true;  $printJson  = $true;  $printSummary = $true }
    'summary' { $printTable = $false; $printJson  = $false; $printSummary = $true }
    default   { $printTable = $Report; $printJson = [string]::IsNullOrWhiteSpace($OutJson) -eq $false }
}

# Compact summary (always unless -Quiet)
if (-not $Quiet -and $printSummary) {
    if ($summary.Compliant) {
        W ("[OK] Compliant  (Total: {0}, Failed: {1})" -f $summary.TotalChecks, $summary.FailedChecks) 'OK'
    } else {
        W ("[FAIL] Needs remediation  (Total: {0}, Failed: {1})" -f $summary.TotalChecks, $summary.FailedChecks) 'FAIL'
        # Show failed checks only (compact)
        $failed = $catalogue | Where-Object { $_.PassFail -eq 'FAIL' }
        foreach ($row in $failed) {
            W (" - {0}: Expected [{1}] | Actual [{2}]" -f $row.Check, $row.Expected, $row.Actual) 'WARN'
        }
    }
}

# Detailed table if requested
if (-not $Quiet -and $printTable) {
    $catalogue | Format-Table -AutoSize | Out-String | Write-Host
}

# JSON: to file if -OutJson; else to stdout when OutputMode=json or both
if ($OutJson) {
    try {
        [pscustomobject]@{ Summary=$summary; Checks=$catalogue } |
            ConvertTo-Json -Depth 5 | Set-Content -Path $OutJson -Encoding UTF8
    } catch {
        W ("WARN: failed to write JSON: {0}" -f $_.Exception.Message) 'WARN'
    }
} elseif ($printJson -and -not $Quiet) {
    [pscustomobject]@{ Summary=$summary; Checks=$catalogue } |
        ConvertTo-Json -Depth 5 | Write-Output
}

# ----------------------------------------------------------------------------------------------------------------------
# Intune exit code
# ----------------------------------------------------------------------------------------------------------------------
if ($summary.Compliant) { exit 0 } else { exit 1 }
