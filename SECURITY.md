# Security Policy

We take the security of OCSF Console IR seriously. Please follow this policy to report vulnerabilities responsibly.

## Supported Versions

We maintain the latest main branch. Report issues against the current codebase.

## Reporting a Vulnerability

- Do NOT open a public GitHub issue for suspected vulnerabilities.
- Use GitHub Security Advisories (preferred) to privately disclose:
  - Go to the repository page → Security → Report a vulnerability.
- Alternatively, you may contact the maintainers via the repository's Security Advisories private channel.

Please include:
- A clear description of the issue and potential impact
- Steps to reproduce (PoC, affected configuration)
- Environment details (OS, Go version, build info)
- Any suggested remediation

We aim to acknowledge within 72 hours and provide a timeline for remediation after triage.

## Disclosure Process

1. Triage: We confirm the issue and assess severity.
2. Fix: We implement and test a patch.
3. Coordination: We may request more details and coordinate disclosure.
4. Release: We publish a fix and release notes with appropriate credit.
5. Advisory: We publish a security advisory with CVSS (if applicable).

## Scope

- Vulnerabilities in the core CLI, TUI, internal packages, and official plugins (plugins/*).
- Misconfigurations or unsafe defaults that materially increase security risk.

## Out of Scope (non-exhaustive)

- Social engineering attacks
- DoS requiring unrealistic resource exhaustion or non-default flags
- Vulnerabilities only present in unsupported/modified builds

## Safe Harbor

We support responsible security research conducted in good faith. Do not exfiltrate data, cause disruption, or access accounts/data you do not own. Follow applicable laws.

## Public Communication

We publish advisories and fixes through GitHub Releases and Security Advisories. Please wait for coordinated disclosure before public blogging or tweeting about an issue.
