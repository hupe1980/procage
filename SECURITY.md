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
in the [threat model](crates/procage/THREAT_MODEL.md). It also lists the known escape
classes and their status. Reports about out-of-scope classes (for example
kernel or OS service bugs) are still welcome, but may be answered with a
pointer to the upstream vendor.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| Earlier | No |

Before 1.0 only the latest minor version gets fixes; there are no backports.
The supported OS releases are exactly those with a green CI lane, listed
with their build or kernel and tier in the README's
[tested releases](README.md#%EF%B8%8F-platforms).

## What to expect

You can expect an acknowledgement within a week. A confirmed escape gets an
entry in the threat model (a new class or an open variant) and a canary in
the escape suite.
