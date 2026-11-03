## Security Convergence — 040-path-resolution

Commit `43faa47` · 2026-11-03T12:24:25Z

| Metric | Value |
|---|---|
| Threats (active) | 12 |
| Open blocking threats | 0  |
| Security requirements | 10 |
| verified | 10 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount` | A hook in the child replaces each planned path (protect, hidden directory, hidden file, cover and pin, socket cover) with a link or a renamed-in directory; against 0.4.0 every kind escaped, now each spawn is refused; the racing canary (r33_racing_a_planted_link_never_moves_a_mount, 10,000 and 20,000 attempts) leaves the protected file unchanged. |
| SR-002 | verified | test | `crates/procage/tests/escape_linux.rs::r33_a_planted_link_or_directory_cannot_move_a_mount` | Each link plant fails with MountMoved naming the planned path and the link, including the pin whose path became a link into the writable workspace; the moved-aside object stays untouched. |
| SR-003 | verified | test | `crates/procage/tests/escape_linux.rs::r33_racing_a_planted_link_never_moves_a_mount` | Declared objects are recorded when the cage is made; the child opens the canonical path without following links, compares device and inode and mounts on that descriptor; the renamed-in directory plants are refused and the racing swap never exposes the protected file. |
| SR-004 | verified | review | `crates/procage/src/linux/sys.rs:1090` | The T1 probe mounts its /tmp with openat2, open_tree, mount_setattr, fsopen, fsmount and move_mount; when a non-recursive clone failed with EINVAL during development the host measured T2 (userns_errno 22), so a host without the calls is not T1; the child sequence passes no path name to a mount call except the root propagation change. |
| SR-005 | verified | test | `crates/procage/tests/spawn_linux.rs::t1_mounts_from_a_busy_multithreaded_parent` | 1,000 T1 spawns of a policy with every mount kind from four threads while four more allocate and lock all complete; the sequence in sys.rs issues system calls only on parent-prepared buffers, and the unsafe_confined audit passes. |
| SR-006 | verified | test | `crates/procage/tests/spawn_linux.rs::a_socket_removed_during_the_spawn_does_not_fail_it` | A cover whose object was removed is skipped (the held descriptor shows no link left) while a moved one fails; MountMoved names the path and link in the r33 canary; the spawn and escape suites pass on T1 and T2 in Docker and on Linux 5.15 and 7.3.1. |
| SR-007 | verified | test | `crates/procage/tests/spelling_macos.rs::every_spelling_enforces_on_the_default_volume` | On the default volume a deny in another case or Unicode form, through two links, for a leaf created later and through the data-volume firmlink denies the file; an allow in another case reaches it. |
| SR-008 | verified | test | `crates/procage/tests/spelling_macos.rs::a_case_sensitive_volume_refuses_allows_and_keeps_denies` | On a case-sensitive APFS image, read, write and exec rules, an allowed socket and a bound grant are refused with CaseSensitive naming the path, and a deny for a also denies A; escape_macos r37 is the class canary. |
| SR-009 | verified | test | `crates/procage/tests/spelling_macos.rs::a_case_sensitive_volume_refuses_allows_and_keeps_denies` | The matrix covers both volume kinds, case and NFC/NFD, nested links, a missing leaf and the firmlink; the image helper asserts hdiutil create and attach, so a lane that cannot make it fails; CI run 41632414082 (43faa47) ran both spelling tests and the R-37 canary green on the macos-26 and xcode-27 lanes; site linux.md names case-folding directories untested. |
| SR-010 | verified | review | `site/content/docs/macos.md:28` | The macOS guide states exactly the measured cases, the Linux guide names case-folding untested, and THREAT_MODEL.md lists R-33 with both canaries and R-37 with its canary. |
