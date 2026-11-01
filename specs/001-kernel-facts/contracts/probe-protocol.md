# Contract: `kf-probe` step protocol

`kf-probe <step> [args…]` performs exactly one step and exits. The runner starts
it with `std::process::Command`:

- absolute path from `CARGO_BIN_EXE_kf-probe`;
- `env_clear()`, plus only the keys a step documents;
- stdin `/dev/null`, stdout piped, stderr piped (diagnostics only, never parsed);
- a timeout: 30 s by default, 120 s for compile-heavy steps. A timed-out child is
  killed (SIGKILL) and reported as `exit=timeout`.

## Output

Zero or more lines on stdout, each:

```text
kf <key>=<value> [<key>=<value> …]
```

- Keys match `[a-z][a-z0-9_]*`.
- Values match `[A-Za-z0-9_.:/+-]*`. That covers integers, `errno` as a number,
  byte counts, `0`/`1`, and fixed tokens such as `T2` or `26.6.2`. Values never
  contain file contents or environment values (SR-014). A path is printed only
  if the step created it.
- Lines that don't start with `kf ` are ignored. Later keys override earlier
  ones.

## Exit status

| Status | Meaning |
|---|---|
| 0 | the step ran; observations are valid (a *denied* action is still exit 0, with `errno=…`) |
| 2 | usage error (unknown step or bad args) |
| 3 | setup failure, before the observed action (e.g. symbol missing → `kf missing=<symbol>`) |
| signal | e.g. SIGABRT from libsandbox; the runner records `exit=signal:6` as an observation (SR-006) |

## Common keys

| Key | Meaning |
|---|---|
| `rc` | return value of the observed call |
| `errno` | errno after the call (0 if none) |
| `bytes` | bytes read or written |
| `sandboxed` | `sandbox_check(getpid(), NULL, 0)` |
| `size` | compiled bytecode length |
| `err_line`, `err_col` | parsed from the compile error |
| `err_kind` | `none`, `unset_param`, `ip_host`, `data_too_long`, `other` |
| `missing` | name of an unresolved symbol |

## Steps (macOS)

| Step | Args | Used by |
|---|---|---|
| `osinfo` | — | header: `product=`, `build=`, `arch=` |
| `selfcheck` | — | precheck, M05, M06, M12 |
| `symbols` | — | M01 |
| `compile` | `<case>` | M02, M03, M04, M13, M14, M15, M16 |
| `compile-rules` | `<shape> <n>` | M17, M24, M27, M28, bisection |
| `apply-selfcheck` | — | M05 |
| `apply-then-spawn` | — | M06 (spawns `selfcheck`) |
| `read` | `control\|literal-etc\|literal-private\|control-users\|deny-users` (paths are fixed per variant) | M07, M21 |
| `tmp-create` | `<variant> <dir>` | M08 |
| `nest` | `<scratch>` | M09 |
| `compile-inside` | — | M10 |
| `setuid-exec` | `control\|caged` | M11 (`/usr/bin/sudo -n -V`, 10 s timeout) |
| `no-sandbox-exec` | `control\|escape` | M12 (execs `kf-probe selfcheck`) |
| `patha-contention` | `<trials> apply\|control` | M18, M23 |
| `fd-parent` / `fd-child` | `<scratch>` / `<fd>` | M19 |
| `ext-parent` / `ext-child` | `<scratch> apply-first\|consume-first` / same, token on stdin | M20, M25 |
| `check-oracle` | `<scratch>` | M22 |
| `tiocsti` / `tiocsti-child` | `control\|caged` / `<pty> control\|caged` (child: `setsid`, reports `ctty_before_errno`) | M26 |

## Steps (Linux)

| Step | Args | Used by |
|---|---|---|
| `osinfo` | — | `kernel=`, `arch=` |
| `measure` | `landlock\|seccomp\|userns\|uid_map\|tmpfs\|ro_bind\|fresh_proc\|netns\|apparmor` (`seccomp` also reports `actions`) | probe → tier, L01, L02, L12 |
| `landlock-write` | `<scratch>` | L06 |
| `landlock-devnull` | `<scratch> rule\|no-rule` | L08 |
| `userns` | — | L03 |
| `ro-bind` / `tmpfs` | `<scratch>` | L04, L05 |
| `netns` | — | L07 |
| `nested-undo` | `<scratch>` | L09 |
| `nested-uidmap` | `<scratch>` | L10 |
| `mount-after-landlock` | `<scratch>` | L11 |
| `proc-mount` / `proc-inner` | — (`proc-inner` runs as PID 1 of the new PID namespace) | L13, `measure fresh_proc` |

Each enforcement step has a `control` variant, which performs the same action
without the restriction and must succeed (SR-002).
