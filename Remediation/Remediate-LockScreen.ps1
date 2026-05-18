<#
.SYNOPSIS
  Intune Remediation: download lock-screen image, set ACL/ownership,
  apply PersonalizationCSP + sign-in policies, clean up per-user overrides, and log robustly.

.EXIT CODES
  0 = success
  2 = error
#>

$ErrorActionPreference = 'Stop'

# =========================
# CONFIGURATION
# =========================
$ImageUrlRaw = ""
[string]$LocalImageName = ""
[bool]  $Overwrite = $true
[bool]  $SetOwnership = $true
[string]$AzureAdOwnerExpected = ""
[bool] $ForceShowImageAtSignIn = $true
[bool] $DisableAcrylicBlurOnLogon = $true

$RootDir = "C:\ProgramData\Compliance"
$ImageDir = Join-Path $RootDir "LockScreen"
$LogDirPrimary = Join-Path $RootDir "Logs"
$LogFileName = "LockScreen_Remediation.log"
$LocalImagePath = Join-Path $ImageDir $LocalImageName
$LogDir = $LogDirPrimary
$LogPath = Join-Path $LogDir $LogFileName

# =========================
# LOGGING HELPERS
# =========================
function Initialize-Log {
    param([string]$LogDir, [string]$LogPath)
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        "LOG-INIT" | Out-File -FilePath (Join-Path $LogDir "write.test") -Encoding UTF8 -Append -Force
        Remove-Item (Join-Path $LogDir "write.test") -Force -ErrorAction Ignore
    }
    catch {
        $fallback = Join-Path $env:TEMP "ComplianceLogs"
        if (-not (Test-Path $fallback)) { New-Item -ItemType Directory -Path $fallback -Force | Out-Null }
        $script:LogDir = $fallback
        $script:LogPath = Join-Path $fallback ([System.IO.Path]::GetFileName($LogPath))
        return
    }
    $script:LogDir = $LogDir
    $script:LogPath = $LogPath
}
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$ts [$Level] $Message"
    Write-Output $line
    try { Add-Content -Path $script:LogPath -Value $line -Encoding UTF8 } catch { }
}

# =========================
# UTILITY HELPERS
# =========================
function New-DirectoryIfMissing { param([string]$Path) if (-not (Test-Path -Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }
function Set-RequiredAcl {
    param([string]$TargetPath)
    try {
        $item = Get-Item -LiteralPath $TargetPath -ErrorAction Stop
        $isDirectory = $item.PSIsContainer
        $acl = Get-Acl -LiteralPath $TargetPath
        function Add-IfMissing {
            param($AclObj, $Identity, $Rights, $Inheritance, $Propagation)
            $existing = $AclObj.Access | Where-Object { $_.IdentityReference -eq $Identity -and $_.FileSystemRights -eq $Rights }
            if (-not $existing) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Rights, $Inheritance, $Propagation, [System.Security.AccessControl.AccessControlType]::Allow)
                $AclObj.AddAccessRule($rule) | Out-Null
                return $true
            }
            return $false
        }
        if ($isDirectory) {
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $propagation = [System.Security.AccessControl.PropagationFlags]::None
        }
        else {
            $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
            $propagation = [System.Security.AccessControl.PropagationFlags]::None
        }
        $changed = $false
        $changed = Add-IfMissing $acl 'NT AUTHORITY\SYSTEM' 'ReadAndExecute' $inheritance $propagation -or $changed
        $changed = Add-IfMissing $acl 'Users' 'ReadAndExecute' $inheritance $propagation -or $changed
        if ($changed) { Set-Acl -LiteralPath $TargetPath -AclObject $acl; Write-Log "ACL normalized for ${TargetPath}" }
        return $true
    }
    catch { Write-Log "ACL error on ${TargetPath}: $($_.Exception.Message)" "WARN"; return $false }
}
function Set-Ownership-IfNeeded {
    param([string]$FilePath, [bool]$SetOwnership, [string]$AzureAdUserExpected = "")
    if (-not $SetOwnership) { return $true }
    try {
        $currentOwner = (Get-Acl $FilePath).Owner
        Write-Log "Current owner: ${currentOwner}"
        $acceptableOwners = @('NT AUTHORITY\SYSTEM'); if ($AzureAdUserExpected) { $acceptableOwners += $AzureAdUserExpected }
        if ($acceptableOwners -contains $currentOwner) { Write-Log "Ownership already acceptable."; return $true }
        Write-Log "Changing owner to SYSTEM and granting Administrators for ${FilePath}"
        & takeown /F $FilePath /A | Out-Null
        & icacls $FilePath /setowner "SYSTEM" | Out-Null
        & icacls $FilePath /grant "BUILTIN\Administrators:(F)" | Out-Null
        Write-Log "New owner: $((Get-Acl $FilePath).Owner)"; return $true
    }
    catch { Write-Log "Ownership change failed: $($_.Exception.Message)" "WARN"; return $false }
}
function ToFileUrl([string]$path) { if ([string]::IsNullOrWhiteSpace($path)) { return $path }; $p = $path -replace '\\', '/'; if ($p -match '^[A-Za-z]:') { $p = "/$p" }; return "file://$p" }

# =========================
# MAIN
# =========================
try {
    Initialize-Log -LogDir $LogDir -LogPath $LogPath
    Write-Log "Log path: ${script:LogPath}"
    $Transcript = Join-Path $script:LogDir ("LockScreen_Remediation_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".trace.txt")
    Start-Transcript -Path $Transcript -Append -ErrorAction SilentlyContinue
    New-DirectoryIfMissing $ImageDir
    Write-Log "WhoAmI: $(whoami)"

    # Build request URL by decoding HTML entities (so SAS parameters use plain '&')
    $ImageUrlRaw = $ImageUrlRaw.Trim()
    try { Add-Type -AssemblyName System.Web } catch { }
    $RequestUrl = if ([type]::GetType('System.Web.HttpUtility')) {
        [System.Web.HttpUtility]::HtmlDecode($ImageUrlRaw)
    }
    else {
        # Fallback: simple replace
        ($ImageUrlRaw -replace '&amp;', '&')
    }

    # Sanitize URL for logs (redact only the signature value)
    $LogUrlSanitized = ($RequestUrl -replace 'sig=[^&]+', 'sig=REDACTED')
    Write-Log "Using URL (sanitized): ${LogUrlSanitized}"
    Write-Log "Target image path: ${LocalImagePath}"

    # Download with retry (use decoded RequestUrl)
    $exists = Test-Path $LocalImagePath
    if (-not $exists -or $Overwrite) {
        $maxAttempts = 6; $delay = 2; $headers = @{'x-ms-version' = '2020-10-02' }
        for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $RequestUrl -OutFile $LocalImagePath -UseBasicParsing -Headers $headers -ErrorAction Stop
                Write-Log "Downloaded image successfully on attempt $attempt."
                break
            }
            catch {
                $resp = $_.Exception.Response; $status = if ($resp) { [int]$resp.StatusCode }else { 0 }
                $xms = if ($resp) { $resp.Headers['x-ms-error-code'] }else { $null }
                Write-Log "Download failed (attempt $attempt): HTTP=$status; x-ms-error-code=$xms" "WARN"
                if ($status -in 409, 500, 502, 503, 504) { Start-Sleep -Seconds $delay; $delay = [Math]::Min(30, $delay * 2); continue }else { throw }
            }
        }
        if (-not(Test-Path $LocalImagePath)) { Write-Log "Image not found after retries." "ERROR"; throw }
    }

    # Read test to catch corrupt/partial files
    try {
        $fs = [System.IO.File]::OpenRead($LocalImagePath)
        $fs.Close()
        Write-Log "Downloaded image passed read test."
    }
    catch {
        Write-Log "Downloaded file failed read test: $($_.Exception.Message)" "ERROR"
        throw
    }

    Set-RequiredAcl $ImageDir | Out-Null
    Set-RequiredAcl $LocalImagePath | Out-Null
    Set-Ownership-IfNeeded $LocalImagePath $SetOwnership $AzureAdOwnerExpected | Out-Null
    Set-RequiredAcl $LocalImagePath | Out-Null

    # Registry apply
    $cspRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP'
    if (-not(Test-Path $cspRoot)) { New-Item -Path $cspRoot -Force | Out-Null }
    $fileUrl = ToFileUrl $LocalImagePath
    New-ItemProperty -Path $cspRoot -Name 'LockScreenImagePath' -PropertyType String -Value $LocalImagePath -Force | Out-Null
    New-ItemProperty -Path $cspRoot -Name 'LockScreenImageUrl'  -PropertyType String -Value $fileUrl        -Force | Out-Null
    # NOTE: You chose to keep Status write; detector will validate final CSP state
    New-ItemProperty -Path $cspRoot -Name 'LockScreenImageStatus' -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Log "Applied PersonalizationCSP registry for lock screen image."

    $polRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if (-not(Test-Path $polRoot)) { New-Item -Path $polRoot -Force | Out-Null }
    if ($ForceShowImageAtSignIn) {
        New-ItemProperty -Path $polRoot -Name 'DisableLogonBackgroundImage' -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Log "Set DisableLogonBackgroundImage=0"
    }
    if ($DisableAcrylicBlurOnLogon) {
        New-ItemProperty -Path $polRoot -Name 'DisableAcrylicBackgroundOnLogon' -PropertyType DWord -Value 1 -Force | Out-Null
        Write-Log "Set DisableAcrylicBackgroundOnLogon=1"
    }

    # Clean up per-user overrides for HideLogonBackgroundImage
    $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SystemProtectedUserData'
    if (Test-Path $root) {
        Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
            $sidLock = Join-Path $_.PSPath 'AnyoneRead\LockScreen'
            if (Test-Path $sidLock) {
                $name = 'HideLogonBackgroundImage'
                $val = (Get-ItemProperty -Path $sidLock -Name $name -ErrorAction SilentlyContinue).$name
                if ($null -ne $val -and $val -ne 0) {
                    Set-ItemProperty -Path $sidLock -Name $name -Value 0 -ErrorAction SilentlyContinue
                    Write-Log "Reset per-user HideLogonBackgroundImage for SID $($_.PSChildName)"
                }
            }
        }
    }

    Write-Log "Remediation completed successfully."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Log "Unhandled error: $($_.Exception.Message)" "ERROR"
    Stop-Transcript | Out-Null
    exit 2
}
