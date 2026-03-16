
# Templates Overview

This directory contains reusable, production-quality templates for building **Microsoft Intune detection and remediation scripts**. They provide a consistent, maintainable structure while remaining flexible enough for customization.

All templates follow Intune-friendly conventions:
- Structured JSON output
- Consistent exit codes (0 = compliant, 1 = needs remediation)
- Clear parameter usage with descriptive comments
- Version comparison based on normalized version strings
- Machine-level and per-user logic (where applicable
- Verbose-mode boolean parameter

---

## Detection Templates

### **Detect-AppVersion-Full.ps1**
A complete detection script template supporting advanced scenarios.

**Includes:**
- Machine-path scanning (file or directory patterns)
- Per-user profile scanning (SYSTEM context)
- Windows Uninstall registry scanning
- Version normalization and comparison helpers
- Logging with retries
- Retry wrapper for file/registry enumeration
- Detailed comments mapping parameters to functions

**Best for:**
- Production deployments
- Complex application layouts
- Mixed machine/per-user install footprints
- Scenarios requiring registry-based detection

### **Detect-AppVersion-Minimal.ps1**
A streamlined detection template optimized for hands-on sessions, workshops, or simple applications.

**Simplifications:**
- Machine-path scanning only by default, with optional registry scan
- No per-user scanning
- No retry wrapper around main scan
- Simple single-pass logging
- Minimal control flow

**Best for:**
- Learning and onboarding
- Workshop/lab sessions
- Simple applications with predictable install locations

---

## Remediation Templates

### **Remediate-AppVersion-Full.ps1**
A full-featured remediation engine capable of handling complex install/upgrade logic.

**Includes:**
- Machine and per-user isntall detection
- Download or pre-staged installer support
- MSI/EXE detection and argument handling
- Silent install execution with installer log generation
- Process termination logic (graceful or forced)
- MSI policy temporary override (DisableMSI=0)
- Cleanup options:
    - Per-user uninstall removal
    - Orphaned uninstall registry entry cleanup
    - Marker file creation
- Detailed comments mapping parameters to functions

**Best for:**
- Production deployments
- Complex or multi-scope applications
- Environments requiring registry hygiene or per-user cleanup
- Apps requiring process termination before install

### **Remediate-AppVersion-Minimal.ps1**
A streamlined remediation template optimized for hands-on sessions, workshops, or simple applications.

**Simplifications:**
- Machine-path scanning only by default, with optional registry scan
- Single install attempt (no retries)
- One unified `InstallerArgs` parameter for MSI/EXE
- No process stopping logic
- No per-user scanning or cleanup
- No orphaned uninstall registry cleanup
- Derived directory locations
- Compact control flow

**Best for:**
- Learning and onboarding
- Workshop/lab sessions
- Simple applications with predictable install locations

---

## Intended Usage

Use these templates as a starting point for creating Intune-friendly detection/remediation packages:
- Set `AppDisplayName`, `MachineExePaths`, and `ExpectedVersion`
- Provide installer source information for remediation templates
- Customize detection depth (registry, per-user, machine-only)
- Choose the *full* or *minimal* variant based on complexity and audience
- Keep detection scripts idempotent and remediation scripts repeatable

---

## Directory Structure

```
/Templates
    Detect-AppVersion-Full.ps1
    Detect-AppVersion-Minimal.ps1
    Remediate-AppVersion-Full.ps1
    Remediate-AppVersion-Minimal.ps1
    README.md               (this file)
```

---

If you would like guidance customizing a template, pairing detection/remediation scripts, or want an example for a specific application, feel free to open an Issue.
