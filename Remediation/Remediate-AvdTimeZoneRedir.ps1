<#
.SYNOPSIS
  Remediates AVD time-zone redirection by enabling the `fEnableTimeZoneRedirection` policy.

.DESCRIPTION
  Idempotently sets `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEnableTimeZoneRedirection` to 1.
  The script gates to AVD hosts (checks for the `RdAgent` service) and exits immediately when not running on AVD.

  Supports `-WhatIf`/`-Confirm` via `SupportsShouldProcess` to allow safe testing.

.NOTES
  - Exit codes: 0 = success/already-compliant, 1 = failure
  - Requires machine-level privileges to write HKLM policies.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$regName = "fEnableTimeZoneRedirection"

# Gate to AVD: only proceed on hosts with the RdAgent service present
try {
    $rdAgent = Get-Service -Name 'RdAgent' -ErrorAction Stop
}
catch {
    Write-Verbose ("RdAgent service not present or inaccessible: {0}" -f $_.Exception.Message)
    Write-Output 'Not an AVD session host; remediation skipped.'
    exit 0
}

# If already compliant, do nothing
try {
    $current = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
}
catch {
    $current = $null
}

if ($current -eq 1) {
    Write-Output 'Already compliant: fEnableTimeZoneRedirection=1'
    exit 0
}

# Apply remediation (idempotent)
$actionTarget = "$regPath\$regName"
if ($PSCmdlet.ShouldProcess($actionTarget, 'Set value to 1')) {
    try {
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        }
        New-ItemProperty -Path $regPath -Name $regName -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
        Write-Output "Set $regName=1"
    }
    catch {
        Write-Output ("Failed to write registry value: {0}" -f $_.Exception.Message)
        exit 1
    }
}
else {
    Write-Output 'WhatIf: remediation not performed.'
    exit 0
}

# Refresh policy to make the setting effective for new sessions
try {
    $gp = Start-Process -FilePath 'gpupdate' -ArgumentList '/force' -NoNewWindow -Wait -PassThru -ErrorAction Stop
    if ($gp.ExitCode -eq 0) { Write-Verbose 'Policy refreshed (gpupdate /force) succeeded.' } else { Write-Verbose "gpupdate returned exit code $($gp.ExitCode)" }
}
catch {
    Write-Verbose ("gpupdate failed: {0}" -f $_.Exception.Message)
}

# Optional: restart AVD agent services to nudge immediate behavior (use ShouldProcess)
foreach ($svcName in @('WindowsAzureGuestAgent', 'RdAgent')) {
    try {
        $svc = Get-Service -Name $svcName -ErrorAction Stop
    }
    catch {
        continue
    }
    if ($svc.Status -eq 'Running') {
        if ($PSCmdlet.ShouldProcess($svcName, 'Restart service')) {
            try {
                Restart-Service -Name $svcName -Force -ErrorAction Stop
                Write-Verbose ("Restarted {0}" -f $svcName)
            }
            catch {
                Write-Verbose ("Failed to restart {0}: {1}" -f $svcName, $_.Exception.Message)
            }
        }
    }
}

# --- Post-remediation verification ---
try {
    $current = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).$regName
    if ($current -eq 1) {
        Write-Output 'Verification passed: fEnableTimeZoneRedirection=1'
        exit 0
    }
    else {
        Write-Output "Verification failed: fEnableTimeZoneRedirection=$current (expected 1)"
        exit 1
    }
}
catch {
    Write-Output ("Verification failed: cannot read {0}\{1} — {2}" -f $regPath, $regName, $_.Exception.Message)
    exit 1
}
