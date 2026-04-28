[CmdletBinding(SupportsShouldProcess=$false)]
param (
    # --- App-specific parameters (set these per application) ---
    [string]$AppDisplayName                 = "Firefox",
    [string[]]$MachinePaths                 = @(
        "${env:ProgramW6432}\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
        ),
    # Relate paths under each user profile; if empty or null, per-user search is skipped
        [string[]]$PerUserRelativePath          = @(
        "AppData\Local\Programs\Mozilla Firefox\firefox.exe"
        ),
    [string]$ExpectedVersion                = "150.0",

    # --- Common controls ---
    [string]$LogFile,
    [int]$MaxRetries                        = 3,
    [int]$RetryDelay                        = 5,
    [bool]$TriggerRemediationForMissingApp  = $false,
    [int]$MaxLogRetries                     = 5,
    [int]$LogRetryDelay                     = 2,

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
    $clean   = -join ($Name.ToCharArray() | ForEach-Object { if ($invalid -contains $_) { '_' } else { $_ } })
    # Trim trailing dots/spaces that Windows disallows
    $clean   = $clean.Trim().TrimEnd('.').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($clean)) { $clean = 'Application' }
    return $clean
}

# If caller didn't supply -LogFile, derive a robust default from AppDisplayName
if (-not $PSBoundParameters.ContainsKey('LogFile') -or [string]::IsNullOrWhiteSpace($LogFile)) {
    $safeName = Get-SafeFileName -Name $AppDisplayName
    $LogFile  = "C:\Logs\Detect-$safeName.log"
}

# ---------- Logging ----------
function Write-Log {
    param ([string]$Message)

    # Console verbose (native)
    Write-Verbose $Message

    if (-not $LogFile) { return }

    $logDirectory = Split-Path -Path $LogFile
    if (-not (Test-Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
    }

    for ($i = 1; $i -le $MaxLogRetries; $i++) {
        try {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
            break
        } catch [System.IO.IOException] {
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
    param ([int]$MaxRetries,[int]$RetryDelay,[scriptblock]$Operation)
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-Log "Attempt $i of $MaxRetries"
            & $Operation
            return $true
        } catch {
            Write-Log "Attempt $i failed $_"
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
    $v = ($v -replace ',', '.').Trim()
    $parts = $v.Split('.')
    while ($parts.Count -lt 4) { $parts += '0' }
    $parts -join '.'
}

function Compare-Versions {
    param([string]$InstalledVersion,[string]$ExpectedVersion)
    try {
        (Format-Version $InstalledVersion) -ge (Format-Version $ExpectedVersion)
    } catch {
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
        [string[]]$Exclusions = @('Public','Default','Default User','All Users','WDAGUtilityAccount')
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
    New-DirectoryIfMissing -DirectoryPath (Split-Path -Path $LogFile)

    $operationSucceeded = Invoke-OperationRetry -MaxRetries $MaxRetries -RetryDelay $RetryDelay -Operation {
        $found = $false

        # 1) Machine paths (and current-context LocalAppData if provided)
        foreach ($path in $MachinePaths) {
            if (Test-Path -LiteralPath $path) {
                $found = $true

                $normalizedVersion = Get-FileVersionInfoSafe -Path $path
                Write-Log "[$AppDisplayName] Detected version '$normalizedVersion' from '$path'"

                $intuneOutput.FilePath        = $path
                $intuneOutput.DetectedVersion = $normalizedVersion
                $intuneOutput.InstallScope    = if ($path -like "$env:LocalAppData*") { "User" } else { "Machine" }

                if ([string]::IsNullOrWhiteSpace($normalizedVersion) -or ($normalizedVersion -notmatch '^\d+(\.\d+)*$')) {
                    $intuneOutput.Status = "MalformedVersion"
                    Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                        $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }

                try {
                    if (Compare-Versions -InstalledVersion $normalizedVersion -ExpectedVersion $ExpectedVersion) {
                        $intuneOutput.Status = "Compliant"
                        Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 0
                    } else {
                        $intuneOutput.Status = if ($intuneOutput.InstallScope -eq "User") { "UserScopeOutdated" } else { "Outdated" }
                        Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 1
                    }
                } catch {
                    $intuneOutput.Status = "ComparisonError"
                    Write-Log "[$AppDisplayName] Version comparison failed: $_"
                    Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                        $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }
            }
        }

        # 2) Per-user installs across profiles (SYSTEM context)
        if (-not $found -and -not [string]::IsNullOrWhiteSpace($PerUserRelativePath)) {
            $perUserHits = Get-PerUserAppPaths -RelativePath $PerUserRelativePath
            foreach ($uPath in $perUserHits) {
                $normalizedVersion = Get-FileVersionInfoSafe -Path $uPath
                Write-Log "[$AppDisplayName] Detected per-user version '$normalizedVersion' from '$uPath'"

                $intuneOutput.FilePath        = $uPath
                $intuneOutput.DetectedVersion = $normalizedVersion
                $intuneOutput.InstallScope    = "User"

                if ([string]::IsNullOrWhiteSpace($normalizedVersion) -or ($normalizedVersion -notmatch '^\d+(\.\d+)*$')) {
                    $intuneOutput.Status = "MalformedVersion"
                    Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                        $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }

                try {
                    if (Compare-Versions -InstalledVersion $normalizedVersion -ExpectedVersion $ExpectedVersion) {
                        $intuneOutput.Status = "Compliant"
                        Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 0
                    } else {
                        $intuneOutput.Status = "UserScopeOutdated"
                        Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                            $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                        $intuneOutput | ConvertTo-Json -Compress; exit 1
                    }
                } catch {
                    $intuneOutput.Status = "ComparisonError"
                    Write-Log "[$AppDisplayName] Version comparison failed: $_"
                    Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                        $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
                    $intuneOutput | ConvertTo-Json -Compress; exit 1
                }
            }
        }

        Write-Log "[$AppDisplayName] No executable found in machine paths or any user profile."
        throw "FileNotFound"
    }

    # After retries, still not found
    if (-not $operationSucceeded) {
        $intuneOutput.Status = "NotInstalled"
        Write-Log "[$AppDisplayName] Not installed on this system."

        if ($TriggerRemediationForMissingApp) {
            Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
            $intuneOutput | ConvertTo-Json -Compress; exit 1
        } else {
            Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
                $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
            $intuneOutput | ConvertTo-Json -Compress; exit 0
        }
    }

} catch {
    $intuneOutput.Status = "Error"
    Write-Log "[$AppDisplayName] An unexpected error occurred: $_"
    Write-Log ("Summary: App='{0}'; Scope={1}; File='{2}'; Detected='{3}'; Expected='{4}'; Status={5}" -f `
        $intuneOutput.AppName, $intuneOutput.InstallScope, $intuneOutput.FilePath, $intuneOutput.DetectedVersion, $intuneOutput.ExpectedVersion, $intuneOutput.Status)
    $intuneOutput | ConvertTo-Json -Compress; exit 1
}
