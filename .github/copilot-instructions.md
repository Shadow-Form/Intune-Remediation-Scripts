# Global Copilot Instructions for Intune-Remediation-Scripts

## Contributor Note
This document defines coding, style, and safety standards for contributors working on this repository.  It intentionally contains **no private organizational information** such as secrets, credentials, identifiers, or internal intrastructure references.
Contributors must ensure all commits **continue to avoid including sensitive or environment-specific data**, including (but not limited to):
- Secrets, tokens, API keys,
- Tenant IDs, subscription IDs, object IDs
- Internal URLs (SharePoint, Intune tenant endpoints, internal APIs)
- Credentials or credential paths
- Internal module names, private PSRepositories
- Device names, user identities, IP addresses
- Logs containing sensitive data, registry keys unique to your org
- Proprietary configuration baselines or architectural details

---

## Scope
These instructions apply to all Copilot interactions when this repository is open in VS Code. They define style, security, and behavior expectations for **PowerShell detection and remediation** scripts intended for Microsoft Intune.

---

## Repository Context
- Language: **PowerShell** only.
- Purpose: Detection and remediation for endpoint configuration/compliance via Intune.
- Audience: Public, community-facing. **Do not** reveal internal tenant data, secrets, or proprietary infrastructure.

---

## PowerShell Standards
- Use **advanced functions** where appropriate (`[CmdletBinding()]`, `param()`), with clear parameter types and validation.
- Follow **Verb-Noun** naming, using approved PowerShell verbs; PascalCase for functions/parameters.
- Prefer explicit cmdlet names (no aliases) and **named parameters** (no positional).
- Include **comment-based help** headers (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES`).
- Use consistent formatting:
  - Indentation and whitespace around pipes (`|`).
  - Splatting for long parameter lists.
  - Final newline; trim trailing whitespace.
- Error handling:
  - Use `try { } catch { }` with meaningful error messages.
  - Avoid `-ErrorAction SilentlyContinue` unless justified and documented.

---

## Intune Remediation Conventions
- **Detection** scripts:
  - Read-only: **must not** change system state.
  - Output is minimal and machine-readable.
  - Exit code **0** for compliant; **non-zero** when remediation is required.
- **Remediation** scripts:
  - **Idempotent**: safe to run multiple times; check state before changes.
  - Non-interactive: no prompts; unattended execution.
  - Use safe paths and clean up temporary artifacts.
  - Minimal logging—no sensitive details.

---

## Security & Privacy Guardrails
- **Never** commit secrets, tokens, tenant IDs, internal URLs, or proprietary module references.
- Avoid risky patterns (`Invoke-Expression` with untrusted input, executing downloaded code, plain HTTP).
- Validate inputs (`[ValidateSet()]`, `[ValidatePattern()]`, etc.).
- Keep logs minimal; do not write sensitive values.

---

## Documentation Expectations
- Every script includes comment-based help.
- README entries (when applicable) summarize:
  - Purpose, prerequisites, and assumptions.
  - Detection behavior and exit codes.
  - Remediation approach and idempotence.
  - Known caveats.

---

## Review Checklist (used by custom agents and human reviewers)
- [ ] Advanced function structure & help header present
- [ ] Verb-Noun naming & correct casing
- [ ] No aliases / positional parameters
- [ ] Proper error handling & clear messages
- [ ] Detection is read-only with correct exit codes
- [ ] Remediation is idempotent & non-interactive
- [ ] No secrets / internal identifiers / sensitive URLs
- [ ] Minimal logging; sanitized outputs
- [ ] Consistent formatting (pipes, splatting, trailing whitespace trimmed)

---

## Do Not
- Do not reference internal systems, endpoints, or organization-specific identifiers.
- Do not include interactive prompts or GUI elements.
- Do not rely on environment-specific assumptions without documenting them.
