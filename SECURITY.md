# Security policy

## Reporting a vulnerability

Please report a suspected sandbox escape or other vulnerability **privately**
through GitHub's private vulnerability reporting:
<https://github.com/hupe1980/procage/security/advisories/new>.

Do not open a public issue, pull request or discussion for an escape. Include
the OS and version (macOS build or Linux kernel release), the procage version,
and the smallest policy and program that show the problem.

## Scope

What procage is meant to defend against, and what it does not, is described
in the [threat model](THREAT_MODEL.md). It also lists the known escape
classes and their status. Reports about out-of-scope classes (for example
kernel or OS service bugs) are still welcome, but may be answered with a
pointer to the upstream vendor.

## Supported versions

| Version | Supported |
|---|---|
| 0.0.x | No sandboxing API and nothing enforced; there is nothing to fix yet |

Security fixes start with the first release that enforces a policy.
