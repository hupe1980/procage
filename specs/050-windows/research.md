# Research: Windows backend

Written 2026-11-07, from the published sources and Microsoft's open-source
MXC repository (MIT; read at its `main` of that day). No Windows host was
available to this record before planning. Every claim below marked
**[source]** comes from documentation or source code, not from a caged test.
Each one becomes a kernel fact (KF-W) on the Windows lane before any
enforcement claim relies on it (constitution III). Where a decision depends
on a measurement, the decision rule is stated with it.

## R1. The OS mechanism

**Decision**: the process security environment (PSEC), and nothing else.

**[source]** `processmodel.dll` exports these functions, under the API set
`api-win-appmodel-processmodel~securityenvironment`:

```c
HRESULT CreateProcessSecurityEnvironment(LPCVOID spec, DWORD size,
        PROCESS_SECURITY_ENVIRONMENT_FLAGS flags, HPROCESS_SECURITY_ENVIRONMENT *out);
HRESULT QueryProcessSecurityEnvironmentSupport(UINT64 *support_flags);
HRESULT IsProcessSecurityEnvironmentVersionSupported(DWORD major, BOOLEAN *available, DWORD *minor);
void    CloseProcessSecurityEnvironment(HPROCESS_SECURITY_ENVIRONMENT env);
```

The handle is passed to `CreateProcessW` through
`PROC_THREAD_ATTRIBUTE_SECURITY_ENVIRONMENT` in a `STARTUPINFOEXW`. The child
is a BaseContainer, an AppContainer created by the OS from the
specification. Support flags: `FS_DENY` (0x1, schema 1.0),
`FS_ENUMERATE` (0x4, 1.1), `NETWORK_INGRESS` (0x8, 1.1). A terminate-on-close
flag exists, but MXC does not publish its value. procage does not use it;
the job holds the lifetime (R6).

**Minimum builds [source]**: Windows 11 24H2 26100.9278 and 25H2 26200.9278
(KB5120998, August 2026). 26H2 26300.9550 and 26H1 28000.2804. Hosting
loopback servers inside the container, and connecting to low-integrity
listeners, need 26100.9550 / 26200.9550 (KB5124010, September 2026).

**Alternatives rejected**:

- **Restricted token plus a synthetic SID** (Codex "unelevated"). Reads stay
  open, writes need ACEs planted on the user's trees, and directories that
  grant Everyone write stay writable. This fails SR-005 by construction.
- **Dedicated local users plus firewall rules** (Codex "elevated"). Needs
  an administrator at setup. This is a harness decision, not a library one.
- **AppContainer through `CreateAppContainerProfile` and
  `SECURITY_CAPABILITIES`**. File access needs ACEs for the container SID
  on each path (the same residue problem), and loopback needs an
  administrator-only exemption.
- **The MXC SDK** (`mxc-sdk` crate). An engine with its own JSON contract
  and backends. procage's lowering would no longer be the only translation
  of a policy, and the dependency is far larger than the interface. Its
  source remains the reference implementation that procage's behaviour is
  compared with.

## R2. The specification format

**Decision**: encode the vendored schema
`ProcessSecurityEnvironment.fbs` (file identifier `PSEC`, root
`ProcessSecurityEnvironment`, version 1.1; SHA-256 recorded in the
crate) with the `flatbuffers` runtime builder, written by hand per table.
Keep no generated code and no `flatc` in the build. The schema text is
vendored under its MIT licence with its provenance.

**[source]** Fields of the root table, in slot order:

1. `version` (major, minor), required;
2. `capabilities` (string);
3. `disallow_win32k_system_calls`;
4. `ui_restrictions` (`JOB_OBJECT_UILIMIT_*` bits);
5. `fs_read_write`, `fs_read_only`, `fs_deny` (string lists);
6. `network_policy`:
   - `proxy.url`;
   - `egress`: a default action, plus allow and deny endpoint rules of
     subnets with exceptions and protocol/port ranges;
   - `allowed_appcontainer_peer`;
   - `ingress`: a default action and `host_loopback`;
7. `fs_enumerate` (1.1).

The schema's evolution rules forbid reordering or removing slots.

**Rationale**: about 12 tables. A hand-written builder is reviewable line by
line against the schema. A round-trip test decodes with the `flatbuffers`
verifier and reads each slot back (SR-004).

**Alternatives**: `flatc`-generated Rust (adds a code generator to the
build and to the review surface for no gain); a hand-rolled FlatBuffers
writer (reimplements alignment and vtables, which the crate already does).

## R3. Loading the interface

**Decision**: `LoadLibraryExW("processmodel.dll", NULL,
LOAD_LIBRARY_SEARCH_SYSTEM32)`, then `GetProcAddress` for the four exports.
The API set is checked first with `IsApiSetImplemented`. Resolution happens
once per process (`OnceLock`) before any spawn, and the module is never
freed. A missing export means `Unsupported`. Never a search path (SR-006).

## R4. Measurements the plan depends on (Windows lane, before enforcement claims)

Each item is a KF-W fact in `procage-kernel-facts`, run on every Windows
lane. The decision rule says what the lowering does with each outcome.

| Id | Question | Decision rule |
|---|---|---|
| KF-W1 | Does a read-only path (no `Exec` rule) refuse `CreateProcessW` of an `.exe` under it? | refuses → `Exec::Granted` is exact (read-only paths without `Exec` get a deny-execute form if the schema has one; else see KF-W2); runs → `exec-where-readable` approximation |
| KF-W2 | Does the OS base allow executing system binaries (`cmd.exe`, `git.exe` under Program Files)? | expected yes; recorded as part of the Windows base |
| KF-W3 | `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` (`PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`) combined with the security environment: does the child fail to create processes? | yes → `Exec::Never` lowers; no or creation fails → gap |
| KF-W4 | `fs_read_write` parent plus `fs_read_only` child: is the child path read-only? | yes → `Protect` lowers as read-only; no → `Protect` uses `fs_deny` for writes where possible, else gap |
| KF-W5 | `fs_read_only` (or the base) parent plus `fs_deny` child: is the child invisible (open, enumerate)? | yes on hosts with `FS_DENY` → `Hide` lowers; else gap |
| KF-W6 | Alias classes against a denied or read-only path: 8.3 name, case, `::$DATA` and named streams, `\\?\`, `\\.\`, `\\?\GLOBALROOT`, junction, directory symlink, file symlink, hard link created by the child | each refused → claimed; any reachable → that class is a documented gap and the lowering refuses policies that rely on it (R-classes in the threat model) |
| KF-W7 | Rename of a read-write root, and of an ancestor of a protected path | refused → `RenameAnchors` enforced; else gap |
| KF-W8 | The Windows base: list what a container can read and execute on a clean image | recorded per build as `windows-base-1`; `explain` reports it |
| KF-W9 | Named pipes: `\\.\pipe\docker_engine`, `\\.\pipe\openssh-ssh-agent`, a pipe the test creates with the default DACL | refused → `ServiceHandoff` and `ContainerEngines` enforced; reachable → `fs_deny` on the pipe path if the OS honours it, else gap |
| KF-W10 | COM activation of an out-of-process server, and `schtasks /create` through the Task Scheduler RPC | refused → enforced; else gap |
| KF-W11 | Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and to the Startup folder | refused → `Persistence` enforced; else gap |
| KF-W12 | `OpenProcess` of a same-user process outside the run; `SendInput`; `PostMessage` to a window outside the job; `WriteConsoleInput` with `Tty::Inherit` | refused → `ProcessAccess` and `TerminalInjection` enforced (UI disabled); the console case confirms the waiver rule |
| KF-W13 | Egress: no capability → connect to public IP and to `127.0.0.1` listener; `Ip` rules allow a subnet; host loopback with `host_loopback: deny` | as R5 |
| KF-W14 | The proxy mapping without a peer identity: a direct connection to an unrelated loopback port | refused on builds that report `identitylessLoopbackProxy` → `Proxy` lowers there; else gap |
| KF-W15 | Job: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` plus no breakaway; the child created with `PROC_THREAD_ATTRIBUTE_JOB_LIST` together with the security environment | works → the child is in the job from creation; fails → assign the suspended child before resume (still before its first instruction) |
| KF-W16 | Verification from the parent: `GetTokenInformation(TokenIsAppContainer)`, the container SID, and `IsProcessInJob` on the suspended child | the check the backend runs before `ResumeThread` |
| KF-W17 | Two environments from the same specification at once: are their container identities distinct? | distinct → per-spawn grants are isolated (SR-012); shared → one environment per run is required anyway, and the canary proves isolation |
| KF-W18 | An unrelated BitLocker-locked volume (reported MXC failure) | typed failure or success; never weaker |
| KF-W19 | A junction and a directory symbolic link created by a standard user inside a writable tree: does `FILE_FLAG_OPEN_REPARSE_POINT` report them on every component, and can the child create them without privilege? | the walk in R7 relies on it; if creation needs no privilege (junctions do not), the refusal is required, and the canary in T023 proves it |

## R5. Network mapping

**[source]**, from MXC's ProcessContainer networking guide (GA contract):

| procage | Capabilities | Egress | Ingress / loopback | Condition |
|---|---|---|---|---|
| `None` | none | default deny | default deny, `host_loopback: deny` | always |
| `Ip` | `internetClient` and `privateNetworkClientServer` (connect to and listen on any address, as the IR defines `Ip`) | default allow | default allow, `host_loopback: allow` | builds with `NETWORK_INGRESS` and 26100.9550+; else gap |
| `All` | both | default allow | default allow, `host_loopback: allow` | builds with `NETWORK_INGRESS` |
| `Loopback(ports)` | none | default deny | `host_loopback: allow` | builds with `NETWORK_INGRESS` and 26100.9550+; ports other than `Any` → gap (no per-port loopback rule) |
| `Proxy` | `privateNetworkClientServer` | default deny, allow only the proxy endpoint | default allow, `host_loopback: allow` (identity-less proxy) | KF-W14 holds |

`ipc.unix_sockets` → gap (AF_UNIX exists on Windows, but the OS policy has no
socket-path rule). `no_unix_sockets` → enforced only if KF-W9 covers AF_UNIX
paths, otherwise gap.

## R6. Process creation, hygiene and lifetime

**Decision**, in order, in the parent:

1. Probe (once per process).
2. Build the environment from the plan and per-spawn grants: one per spawn.
3. Create a job with `KILL_ON_JOB_CLOSE`, no `BREAKAWAY_OK` and no
   `SILENT_BREAKAWAY_OK`, the limits (`ACTIVE_PROCESS`, `JOB_TIME`; the IR
   has no memory limit) and the UI limits (with
   `disallow_win32k_system_calls` when the UI is disabled).
4. Build an attribute list:
   - `SECURITY_ENVIRONMENT`;
   - `HANDLE_LIST` (stdio pipes and declared handles, each made
     inheritable for the call only);
   - `JOB_LIST` if KF-W15 holds;
   - `CHILD_PROCESS_POLICY` for `Exec::Never` if KF-W3 holds;
   - `MITIGATION_POLICY` for the Win32k disable.
5. Call `CreateProcessW` with `bInheritHandles = TRUE` (required for the
   handle list, which limits it), `EXTENDED_STARTUPINFO_PRESENT |
   CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP`,
   `CREATE_NO_WINDOW` for `Tty::None`, an explicit environment block, and
   the command line built by procage's own quoting (the inverse of
   `CommandLineToArgvW`).
6. Verify the child (KF-W16). On failure, call `TerminateProcess` and return
   `SpawnError::Apply`.
7. Call `ResumeThread`.
8. `Child` owns the process, thread, job and environment handles. Dropping
   it closes the job, which kills the tree, and then the environment.

**Rationale**: everything is prepared before creation and no procage code
runs in the child (constitution IV, 2.4.0). The handle list closes the
classic race in which another thread's inheritable handle leaks into the
child.

**Parent death**: when the parent dies, its last handle to the job closes
and `KILL_ON_JOB_CLOSE` kills the run. No watchdog is needed.

## R7. Paths in the IR

**Decision**: Windows paths use a portable spelling inside `AbsPath`:
`C:\work\ws` ↔ `/C:/work/ws` (drive letter upper-cased, separators
`/`; the same convention as `file:///C:/` URIs). `procage::windows` offers
`AbsPath` conversion from `std::path::Path`. In the parent it resolves each
path without following any link the child could have planted (constitution
V):

- Walk the path one component at a time from the drive root. Open each
  component relative to its parent's handle (`NtCreateFile` with
  `RootDirectory`, or `CreateFileW` on the joined path) with
  `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`, and read
  `FILE_ATTRIBUTE_REPARSE_POINT` from the handle.
- A reparse point (junction, symbolic link, mount point) **inside a tree
  the policy makes writable** refuses the spawn with `GrantError::Link`.
  A reparse point outside writable trees (for example a system-created
  junction such as `Documents and Settings`) is resolved, because the child
  cannot have planted it.
- The long, canonical spelling comes from `GetFinalPathNameByHandleW` on
  the handle of the last component, which was opened without following.
- `subst` and mapped drive letters resolve to their target first
  (`QueryDosDeviceW`).
- Per-spawn grants are resolved again at every spawn; a cached resolution
  is never reused for a grant.

UNC, `\\?\`, device and volume GUID paths in a policy are rejected (a
gap). Removable drives are treated as fixed ones. A non-UTF-8 path (an unpaired surrogate)
is a gap, since the specification's strings are UTF-8.

**Case**: Windows paths are case-insensitive by default. Comparisons made by
procage itself on the Windows target (deny-within-allow ordering, `explain`,
`diff`) fold case with the OS's upcase table. A directory with per-directory
case sensitivity enabled is refused, as R-37 does on macOS.

**Alternatives**: a new path type in the IR (breaks every consumer for one
backend); native backslash strings in `AbsPath` (breaks the type's
invariant on every other target).

## R8. Hard-deny data on Windows

New frozen lists in `procage_policy::presets`, versioned like the others:

- `SECRETS_WINDOWS`, relative to `%USERPROFILE%`: `.ssh`, `.aws`, `.azure`,
  `.config\gcloud`, `.docker\config.json`, `.kube`, `.npmrc`, `.pypirc`,
  `.netrc`, `.git-credentials`, `AppData\Roaming\gh`,
  `AppData\Roaming\GitHub CLI`, plus the agent credential files the
  other lists name.
- `PERSISTENCE_WINDOWS`: the Startup folder. The `Run` and `RunOnce`
  registry keys are not paths, and are enforced only by KF-W11.
- `ENGINE_PIPES_WINDOWS`: `docker_engine`, `dockerDesktopLinuxEngine`,
  `podman-machine-default`.
- `SERVICE_PIPES_WINDOWS`: `openssh-ssh-agent`.

These are lowered to `fs_deny` (on hosts with `FS_DENY`) where the OS honours
pipe paths (KF-W9). Otherwise the class is a gap.

## R9. CI

**[source]** GitHub's `windows-11-arm` image reported 10.0.26200 build 9168
on 2026-08-30. That is below 26200.9278, and later images were not checked.
The `windows-2025` image is Windows Server (26100) and is not assumed to
carry the feature.

**Decision**: a `windows` job on `windows-11-arm`:

- Its first step prints the build and runs the probe.
- If the probe reports no feature, the job fails (SR-013).
- If the hosted image lags, the lane runs on a self-hosted Windows 11
  arm64 runner with the same labels until it catches up.
- x64 is claimed only when an x64 Windows 11 lane exists.

## R10. Dependencies

- `windows-sys` (Microsoft's raw bindings, no runtime, MIT/Apache) for the
  documented Win32 surface: processes, jobs, attributes, tokens, files. It
  is gated to `cfg(windows)` and pinned in the workspace. The PSEC exports
  are not in it, and are hand-declared as function pointer types.
- `flatbuffers` (Google, Apache-2.0) for the builder. It is gated to
  `cfg(windows)`, `default-features = false` where the builder allows.
- Both go through `cargo-deny`. No other new dependency.
