# Intune Proactive Remediations - Detection (User context; silent)

<#
.SYNOPSIS
Verifies a named VPN connection is present in the Azure VPN Client per-user phonebook.

.DESCRIPTION
This read-only detection script checks whether the Azure VPN Client (per-user Appx
installation) has a rasphone.pbk in its LocalState and whether that file contains a
connection section matching `-ExpectedConnectionName`.

The script is intended for Intune Proactive Remediations. It follows these conventions:
- Read-only by default (no system changes).
- Exit code `0` means compliant; `1` means remediation is required.

.PARAMETER ExpectedConnectionName
The exact connection name to search for inside rasphone.pbk. Replace the default placeholder before use.

.PARAMETER PfnPrefix
Package family name prefix used to discover the per-user Azure VPN Client package.
Default: 'Microsoft.AzureVpn_'.

.PARAMETER EnableLogging
When `$true` enables optional local logging for troubleshooting (disabled by default).

.PARAMETER LogFile
Optional path to a local log file when `-EnableLogging` is used.

.PARAMETER VerboseMode
Compatibility switch: when present sets verbose preference if `-Verbose` isn't supplied.

.EXAMPLE
# Run detection with defaults (no file logging)
powershell -NoProfile -NonInteractive -File .\Detection\Detect-AVPNClientConfig.ps1

.NOTES
- Exit codes: `0` = Compliant / no remediation; `1` = Non-compliant / remediation required.
- Keep output minimal for Intune processing; use `-EnableLogging` to opt into file logs.
- TODO: Replace the `ExpectedConnectionName` default placeholder with your environment value before deployment; do not commit environment-specific names.
#>
[CmdletBinding(SupportsShouldProcess = $false)]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ExpectedConnectionName = 'REPLACE_WITH_CONNECTION_NAME',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$PfnPrefix = 'Microsoft.AzureVpn_',

    # Logging controls (detection remains read-only unless enabled)
    [Parameter(Mandatory = $false)]
    [bool]$EnableLogging = $false,

    [Parameter(Mandatory = $false)]
    [string]$LogFile,

    # Backwards-compatible switch to enable verbose output when -Verbose isn't supplied
    [switch]$VerboseMode
)

# Honor either -Verbose (native) or -VerboseMode (compat)
if ($VerboseMode -and -not $PSBoundParameters.ContainsKey('Verbose')) {
    $VerbosePreference = 'Continue'
}

# Set a safe error action for script execution
$ErrorActionPreference = 'Stop'

function Write-DetectionResult {
    param(
        [int]$Code,
        [string]$Message
    )
    Write-Output $Message
    exit $Code
}
# Helper: consistent exit path used by Intune detection scripts
# Use this to emit a single machine-friendly string and exit with the expected code.

function Test-AVPNClientConfig {

    # Main detection routine. Returns via Write-DetectionResult with 0/1 exit codes.

    try {
        $userApps = Get-AppxPackage
    }
    # 1) Enumerate per-user Appx packages to detect a per-user Azure VPN Client install
    catch {
        Write-Verbose "Failed to enumerate per-user Appx packages: $($_.Exception.Message)"
        Write-DetectionResult 0 'Compliant: cannot determine Azure VPN Client install; skipping remediation.'
    }

    $azureVpnApp = $userApps | Where-Object { $_.PackageFamilyName -like "$PfnPrefix*" } | Select-Object -First 1
    # Select the first package whose PackageFamilyName matches the expected prefix

    if ($null -eq $azureVpnApp) {
        Write-DetectionResult 0 'Compliant: Azure VPN Client not installed for this user; skipping remediation.'
    }

    try {
        $pfName = $azureVpnApp.PackageFamilyName
        if ($null -ne $pfName) {
            $localState = Join-Path $env:LOCALAPPDATA ("Packages\$pfName\LocalState")
            $phonebook = Join-Path $localState 'rasphone.pbk'
        }
        else {
            $phonebook = $null
        }
    }
    # 2) Derive the app's LocalState path from the discovered package family name
    catch {
        Write-Verbose "Failed to build LocalState/Phonebook path: $($_.Exception.Message)"
        $phonebook = $null
    }

    if ($null -eq $phonebook -or -not (Test-Path -LiteralPath $phonebook)) {
        Write-DetectionResult 1 "Not compliant: Phonebook not found; connection '$ExpectedConnectionName' not present."
    }

    try {
        $pattern = [regex]::Escape($ExpectedConnectionName)
        $found = Select-String -Path $phonebook -Pattern "(?i)^\[$pattern\]$" -Quiet
    }
    # 3) If the phonebook is missing the connection cannot exist — report non-compliant
    catch {
        Write-Verbose "Failed to read phonebook: $($_.Exception.Message)"
        $found = $false
    }

    if ($found) {
        Write-DetectionResult 0 "Compliant: Connection '$ExpectedConnectionName' present in phonebook."
    }
    else {
        Write-DetectionResult 1 "Not compliant: Connection '$ExpectedConnectionName' missing in phonebook."
    }
    # 4) Emit final result: 0 = compliant, 1 = remediation required
}

# Execute detection (script entry)
Test-AVPNClientConfig
