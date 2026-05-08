<#
.SYNOPSIS
    Detects whether AVD Time Zone Redirection is enabled on the host.

.DESCRIPTION
    Checks for the presence of the AVD agent service and the registry value
    `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEnableTimeZoneRedirection`.
    Exit codes: 0 = compliant (or not an AVD host), 1 = non-compliant (remediation recommended).

.NOTES
    Read-only detection script intended for Intune use. Diagnostic details are written
    with `Write-Verbose` to avoid leaking noise in normal runs.
#>

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$regName = "fEnableTimeZoneRedirection"

# Gate to AVD: if the AVD agent service isn't present, treat as compliant
try {
    $avdAgent = Get-Service -Name "RdAgent" -ErrorAction Stop
}
catch {
    Write-Verbose ("RdAgent service not found or inaccessible: {0}" -f $_.Exception.Message)
    $avdAgent = $null
}

if (-not $avdAgent) {
    Write-Output "Not an AVD session host; detection treated as compliant."
    exit 0
}

try {
    $current = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
    if ($current -eq 1) {
        Write-Output "Compliant: fEnableTimeZoneRedirection=1"
        exit 0
    }
    else {
        Write-Output "Non-compliant: fEnableTimeZoneRedirection=$current"
        exit 1
    }
}
catch {
    Write-Verbose ("Registry read failed: {0}" -f $_.Exception.Message)
    Write-Output "Non-compliant: fEnableTimeZoneRedirection missing"
    exit 1
}
