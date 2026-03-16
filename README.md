
# Intune-Remediation-Scripts

<!-- Badge Section -->
<p>
  <img src="https://raw.githubusercontent.com/homarr-labs/dashboard-icons/main/svg/powershell.svg" width="20" />
  <img src="https://img.shields.io/badge/PowerShell-5391FE?style=flat" />
</p>

<p>
  <img src="https://raw.githubusercontent.com/homarr-labs/dashboard-icons/main/svg/microsoft-intune.svg" width="20" />
  <img src="https://img.shields.io/badge/Intune-2D7DDF?style=flat" />
</p>

<p>
  <img src="https://raw.githubusercontent.com/homarr-labs/dashboard-icons/main/svg/microsoft-windows.svg" width="20" />
  <img src="https://img.shields.io/badge/Windows-0078D6?style=flat" />
</p>

<p>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat" />
</p>

<p>
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat" />
</p>

---

## Overview
This repository provides a curated collection of **Microsoft Intune remediation scripts** designed to support enterprise endpoint administrators and automation engineers. The scripts are written in **PowerShell** and organized into **detection** and **remediation** components that align with Intune's remediation framework.

These resources were originally assembled for a conference session and serve as a reference library for demonstrations, hands-on labs, and real-world deployment scenarios.

---

## Repository Structure

- [Detection](./Detection) — Scripts used to determine compliance or configuration state.
- [Remediation](./Remediation) — Scripts that correct issues identified by the detection logic.
- [Templates](./Templates) — Reusable foundations for creating new detection/remediation scripts.
- [Examples](./Examples) — Supplemental reference scripts and session materials.

```text
/Detection        # Intune detection scripts
/Remediation      # Intune remediation scripts
/Templates        # Starter templates for building your own scripts
/Examples         # Additional helpers, demos, or extras used in the session
```

---

## How to Use These Scripts

1. Identify the script you want to deploy.
2. Download it using **Raw** view or clone the repository.
3. In Intune, go to:
   - **Devices** → **Remediations** → **Create remediation**
4. Upload the detection and remediation scripts as required.
5. Assign to a test group, verify behavior, then deploy more broadly.

---

## Execution Behavior

- **Detection scripts** should exit with:
  - `0` → Compliant
  - `1` → Non-compliant
- **Remediation scripts** should correct the state and return `0` on success.

Testing locally is recommended:
```powershell
# Run detection
pwsh .\Detect-Something.ps1
$LASTEXITCODE

# Run remediation
pwsh .\Remediate-Something.ps1
```

---

## Requirements
- Windows 10/11 device managed through Microsoft Intune
- Appropriate Intune permissions to create and deploy remediations
- PowerShell (5.x or 7.x depending on script requirements)
- Additional module requirements documented in individual script headers

---

## Conference Release
A tagged **Release** is available containing the exact scripts used during the session. This ensures attendees can easily follow demos or reproduce the workflows shown.

---

## Disclaimer
All scripts are provided **as-is** without warranty. Validate functionality in a controlled environment before deploying to production systems.

---

## Feedback & Contributions
Feedback, suggestions, and contributions are welcome. Please open an **Issue** or submit a **Pull Request** if you would like to recommend improvements or add new remediation examples.

---

## License
This project is licensed under the **MIT License**.
