# Contract: public API changes (0.2.0)

## procage-policy

```rust
#[non_exhaustive]
pub enum HardDenyClass {
    // … existing twelve …
    /// Container engines' control sockets (Docker, Podman, containerd,
    /// BuildKit, Incus/LXD; on macOS Docker Desktop, Colima, OrbStack, Lima,
    /// Rancher Desktop, Podman machine): connect denied.
    ContainerEngines, // "container-engines"
}

// Construct::HdContainerEngines ("hd-container-engines")
// Construct::SPAWN_SNAPSHOT += [HdServiceHandoff, HdContainerEngines]

pub mod presets {
    pub const ENGINE_HOME: &[&str];          // macOS, relative to every user home
    pub const ENGINE_SYSTEM: &[&str];        // macOS
    pub const SERVICE_SOCKETS_LINUX: &[&str];
    pub const SERVICE_SOCKET_DIRS_LINUX: &[&str];
    pub const SERVICE_RUNTIME_LINUX: &[&str];
    pub const SERVICE_RUNTIME_DIRS_LINUX: &[&str];
    pub const SERVICE_ABSTRACT_LINUX: &[&str];
    pub const ENGINE_SOCKETS_LINUX: &[&str];
    pub const ENGINE_SOCKET_DIRS_LINUX: &[&str];
    pub const ENGINE_RUNTIME_LINUX: &[&str];
    pub const ENGINE_RUNTIME_DIRS_LINUX: &[&str];
    pub fn linux_socket_paths(class: HardDenyClass) -> Option<SocketPaths>;
}

pub mod linux {
    pub struct SocketPaths {
        pub class: HardDenyClass,
        pub system: Vec<AbsPath>,
        pub system_dirs: Vec<AbsPath>,
        pub runtime: Vec<String>,
        pub runtime_dirs: Vec<String>,
        pub abstract_prefixes: Vec<String>,
    }
    pub struct LinuxPlan { /* … */ pub service_sockets: Vec<SocketPaths> }
}
```

## procage (Linux)

```rust
impl CageOptions {
    /// Adds a runtime directory (like `XDG_RUNTIME_DIR`) whose service and
    /// engine sockets the cage keeps out of reach.
    pub fn with_runtime_dir(self, dir: impl Into<PathBuf>) -> Self;
}
```

Errors: `SpawnError::Lower(LowerError::Gaps(_))` from `Cage::new`/`fit` (and
from `spawn` on T2 when a socket appeared after the cage was made), one gap
per found socket: construct `hd-service-handoff` or `hd-container-engines`,
kind `Unsupported` (T2, abstract without ABI 6) or `Approximation` (T1),
subject the resolved path or `@name`.
