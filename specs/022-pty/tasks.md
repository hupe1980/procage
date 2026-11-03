# Tasks: A fresh pseudo-terminal for interactive runs

## Phase 1: Foundational

- [X] T001 [SR-003] `open_terminal()` in both `sys` modules: `posix_openpt` close-on-exec, `grantpt`, `unlockpt`, the device name, the device opened close-on-exec, the size set to 80 by 24; `set_size`; `testing::open_pty` moves onto it — crates/procage/src/macos/sys.rs, crates/procage/src/linux/sys.rs
- [X] T002 [SR-007] Public `Pty` handle (Read/Write, also on `&Pty`; AsFd, AsRawFd, `From<Pty> for OwnedFd`, `device`, `set_size`), rustdoc stating the output is untrusted and unfiltered — crates/procage/src/pty.rs, crates/procage/src/lib.rs
- [X] T003 [SR-004] `Session::Terminal`: `setsid` then `ioctl(0, TIOCSCTTY, 0)` in both child sequences — crates/procage/src/macos/sys.rs, crates/procage/src/linux/sys.rs

## Phase 2: User Story 1 — Run an interactive program caged (P1)

- [X] T004 [SR-001] [SR-002] Lowering: with `Tty::NewPty`, independent of the base, macOS allows read, write-data and ioctl on `(extension "procage.tty")` and `/dev/tty`; Linux allows `/dev/tty` read, write, `IOCTL_DEV`; the terminal-injection class stays; lowering fixtures — crates/procage-policy/src/lower/macos.rs, crates/procage-policy/src/lower/linux.rs
- [X] T005 [SR-001] [SR-003] [SR-006] [US1] macOS spawn: remove the refusal; open the pair, stdio to the device, the `procage.tty` extension for the device, `Session::Terminal`; parent copies closed after spawn; `Child::take_pty`; exec and exec_session refuse — crates/procage/src/macos/mod.rs, crates/procage/src/macos/child.rs
- [X] T006 [SR-001] [SR-003] [SR-006] [US1] Linux spawn: the same, with a Landlock rule for exactly the device next to the bound grants — crates/procage/src/linux/mod.rs, crates/procage/src/linux/spawn.rs, crates/procage/src/linux/child.rs
- [X] T007 [US1] `AsyncChild::take_pty` — crates/procage/src/async_child.rs
- [X] T008 [SR-001] [SR-005] [SR-006] [SR-008] [US1] Caged tests on every lane: shell (`sh -i`, isatty, controlling terminal), REPL (`python3 -i`), full-screen (`vi` or `top`), run end kills a background job and the controller reads EOF/EIO, no base still usable, exec/exec_session refused — crates/procage/tests/pty.rs
- [X] T009 [SR-001] [SR-002] R-22 canaries with `Tty::NewPty`: TIOCSTI on the own terminal fails, waived reaches only the controller; another terminal cannot be opened — crates/procage/tests/escape_macos.rs, crates/procage/tests/escape_linux.rs
- [X] T010 [SR-003] [SR-004] Two concurrent runs from two threads: neither child holds a controller or the other's terminal; a spawn test from a busy multithreaded parent uses `Tty::NewPty` on both OSes — crates/procage/tests/pty.rs

## Phase 3: Polish

- [X] T011 [SR-008] Docs: README limits, THREAT_MODEL (does-not list, R-22 evidence), site macOS/Linux terminal sections, CHANGELOG 0.5.0 Unreleased entry; `just` recipes include the new tests — README.md, crates/procage/THREAT_MODEL.md, site/content/docs/{macos,linux}.md, CHANGELOG.md, justfile
- [X] T012 `just ci`, `just linux-t1`, `just linux`, `just kernel`; quickstart; status Implemented; commit on `main` — specs/022-pty/{spec,quickstart}.md

## Phase 4: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-03 (commit 50c8ab6).

- [X] T013 [SR-008] Add a test for SR-008 (An interactive shell, a REPL and a full-screen program MUST run caged through Tty::NewPty in tests on every macOS and Linux lane, and the docs MUST claim no more than those tests show) — touchpoints: README.md, crates/procage/THREAT_MODEL.md, crates/procage/tests/pty.rs [converge: implemented-unverified; The shell, REPL and full-screen tests pass on macOS 26.6.2 and in containers on Linux 7.0 (T1, T2), and ci.yml and kernel-lane.sh run them on every lane, but no CI lane has run this commit yet.]
