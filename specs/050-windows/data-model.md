# Data model: Windows backend

## `Target::Windows { features: WindowsFeatures }` (procage-policy)

| Field | Type | Source |
|---|---|---|
| `schema_minor` | `u16` | `IsProcessSecurityEnvironmentVersionSupported(1, …)` |
| `fs_deny` | `bool` | support flag 0x1 |
| `fs_enumerate` | `bool` | support flag 0x4 |
| `ingress` | `bool` | support flag 0x8 |
| `loopback_host` | `bool` | probe: build ≥ 26100.9550 / 26200.9550 and a self-test |
| `identityless_proxy` | `bool` | probe (KF-W14) |
| `exec_on_read_only` | `ExecSemantics::{Refused, Allowed}` | KF-W1 fixture for the tested build |

Validation: major version 1 only. Any other major version is
`Unsupported::UntestedVersion`.

## `WindowsPlan` (procage-policy, pure)

| Field | Type | Notes |
|---|---|---|
| `read_only` | `Vec<AbsPath>` | `/X:/…` spelling, sorted, deduplicated |
| `read_write` | `Vec<AbsPath>` | |
| `deny` | `Vec<AbsPath>` | `Hide`, hard-deny paths |
| `capabilities` | `Vec<WindowsCapability>` | `InternetClient`, `PrivateNetworkClientServer` |
| `egress` | `EgressPolicy { default: Action, allow: Vec<EndpointRule>, deny: Vec<EndpointRule> }` | from `Network` |
| `ingress` | `IngressPolicy { default: Action, host_loopback: Action }` | |
| `proxy` | `Option<ProxyEndpoint { addr: Ipv4Addr::LOCALHOST or ::1, port }>` | `Network::Proxy` only |
| `ui` | `UiPolicy { win32k_disabled: bool, limits: u32 }` | disabled by default; `JOB_OBJECT_UILIMIT_*` |
| `child_process` | `ChildProcess::{Allowed, Restricted}` | `Exec::Never` |
| `job` | `JobLimits { active_processes, job_time_100ns }` | from `rlimits.nproc`, `rlimits.cpu_seconds` |
| `console` | `Console::{Hidden, Inherit}` | from `Tty` |
| `base` | `WindowsBase::V1` | recorded |
| `degradations`, `waivers` | as on the other plans | |

## `WindowsBase::V1` (procage-policy `base.rs`)

The measured list of what the OS lets every container read and execute
on a clean image (KF-W8), keyed by the build it was measured on. `explain`
answers "allowed by the Windows base" for paths in it. A change found on a
later build becomes `V2`; `V1` is never edited.

## `windows::Cage`, `windows::Child` (procage)

- `Cage { plan: WindowsPlan, encoded_base: Arc<[u8]>, options }`: the plan,
  and the specification encoded without per-spawn grants (P-2).
- `Child { process: OwnedHandle, job: OwnedHandle, env: SecurityEnvironment,
  pid, receipt_state }`, where `SecurityEnvironment` is closed on drop
  after the job.
- Lifecycle: `Prepared → Created (suspended) → Verified → Running → Exited
  | Killed`. A failed verification goes `Created → Terminated` and
  returns an error; the target never runs.

## Hard-deny data (procage-policy `presets.rs`, frozen v1)

`SECRETS_WINDOWS`, `PERSISTENCE_WINDOWS`, `ENGINE_PIPES_WINDOWS`,
`SERVICE_PIPES_WINDOWS` (research R8). Each class's Windows verdict
(enforced, gap) is a table in `lowering.md`, checked by a fixture test.
