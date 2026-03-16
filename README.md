# Intune-Remediation-Scripts

!PowerShell Badge
!Intune Badge
!Windows Badge
!License: MIT
!Status: Active

Welcome!  
This repository contains a collection of **PowerShell-based Microsoft Intune remediation scripts**, including both **detection** and **remediation** logic. These scripts are meant to help IT admins diagnose and resolve common issues on Windows devices managed through Intune.

This repository accompanies my conference session and serves as the single location for downloading all the templates, examples, and demo scripts referenced during the presentation.

---

## Repository Structure

```
/Detection        # Intune detection scripts
/Remediation      # Intune remediation scripts
/Templates        # Starter templates for building your own scripts
/Examples         # Additional helpers, demos, or extras used in the session
```

---

## How to Use These Scripts

1. Browse to the script you want.
2. Download it using the **Raw** button or GitHub's file viewer.
3. In Intune, navigate to:
   - Devices → Remediations → Create remediation
4. Upload the detection and remediation scripts accordingly.
5. Test thoroughly before deploying to production.

---

## Requirements

- Windows 10/11 device managed by Microsoft Intune  
- Permissions in Intune to create and deploy remediations  
- PowerShell  
- Some scripts may require specific modules or OS components; these will be noted in the script header

---

## Conference Release

A tagged **Release** is available so you can download the exact scripts demonstrated during the session.  
Check the **Releases** section of this repository.

---

## Disclaimer

All scripts are provided **as‑is**, with no warranties or guarantees.  
Always validate and test in a non‑production environment prior to rollout.

---

## Feedback & Contributions

If you encounter issues, have suggestions, or want to request additional Intune remediation examples, feel free to open an **Issue** or submit a **Pull Request**.

---

## License

This repository is licensed under the **MIT License**.
