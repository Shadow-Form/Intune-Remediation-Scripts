
# Templates Overview

This directory contains reusable, production-quality templates for building **Microsoft Intune detection and remediation scripts**. These templates are designed to give you a solid, consistent foundation while still being flexible enough for customization.

All templates follow Intune-friendly conventions:
- Structured JSON output
- Consistent exit codes (0 = compliant, 1 = needs remediation)
- Clear parameter usage and documentation
- Support for both machine-level and user-level scenarios (where applicable)

---

## Detection Templates

### 1. **Detect-AppVersion-Full.ps1**
A comprehensive detection script template supporting advanced scenarios.

**Includes:**
- Machine-path scanning
- Per-user profile scanning (SYSTEM context)
- Windows Uninstall registry scanning
- Version normalization and comparison
- Robust logging with retries
- Retry logic for file/registry enumeration
- Detailed comments that explain which functions use each parameter

**Best for:**
- Production deployments
- Complex application layouts
- Scenarios requiring registry-based detection or multiple install scopes

---

### 2. **Detect-AppVersion-Minimal.ps1**
A streamlined detection template optimized for hands-on sessions, workshops, or simple applications.

**Simplifications:**
- Machine-path scanning only (default)
- Optional registry scan (boolean)
- Simplified logging (single write, no retry)
- No retry wrapper around main scan
- No per-user scanning
- Direct boolean parameters (Intune‑friendly)
- Clear, minimal control flow

**Best for:**
- Learning and onboarding
- Workshop/lab sessions
- Simple applications with predictable install locations

---

## Remediation Templates

### 1. **Remediate-AppVersion-Full.ps1** *(coming soon)*
A full remediation script template with:
- Version-aware upgrade logic
- Logging
- Retry handling
- Support for machine and per-user remediation paths
- Compatible with both full and minimal detection templates

### 2. **Remediate-AppVersion-Minimal.ps1** *(coming soon)*
A simplified remediation script intended for hands-on tutorials. Pairs naturally with the minimal detection template.

---

## Intended Usage

Each template is designed to serve as a starting point:
- Update **AppDisplayName**, **MachinePaths**, and **ExpectedVersion**
- Add product-specific install or update logic in remediation templates
- Use the template as-is or extend sections for advanced needs

---

## Directory Structure

```
/Templates
    Detect-AppVersion-Full.ps1
    Detect-AppVersion-Minimal.ps1
    Remediate-AppVersion-Full.ps1     (coming soon)
    Remediate-AppVersion-Minimal.ps1  (coming soon)
    Templates_README.md               (this file)
```

---

If you would like guidance customizing a template, pairing detection/remediation scripts, or want an example for a specific application, feel free to open an Issue.
