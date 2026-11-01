# Data model

- **`HardDenyClass::ContainerEngines`** — name `container-engines`; last in
  `HardDenyClass::ALL`. `HardDenyClass::ServiceHandoff` keeps its name; its
  Linux meaning grows (buses, service manager).
- **`Construct::HdContainerEngines`** — `hd-container-engines`;
  `Construct::SPAWN_SNAPSHOT` gains `HdServiceHandoff` and
  `HdContainerEngines` (the T1 approximation).
- **`linux::SocketPaths`** — `{ class, system: Vec<AbsPath>, system_dirs:
  Vec<AbsPath>, runtime: Vec<String>, runtime_dirs: Vec<String>,
  abstract_prefixes: Vec<String> }`; frozen data from `presets`.
- **`LinuxPlan::service_sockets: Vec<SocketPaths>`** — the socket classes in
  force that the policy can reach; empty otherwise.
- **Gap subjects** — a found socket's or directory's resolved path, or
  `@<abstract name>`.
- **`linux::CageOptions::with_runtime_dir(path)`** — adds a runtime directory
  to the discovery.
