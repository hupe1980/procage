# Data model: Consumer API

- `crate::unix::cleared(&Command) -> Option<bool>` (internal).
- `macos::Unsupported::EnvClear`, `linux::Unsupported::EnvClear` (new unit
  variants): passthrough cannot be used because `env_clear` is unobservable.
- `procage::native`: alias of `procage::macos` or `procage::linux`.
- `LowerOptions::accept_spawn_masks(self) -> Self`.
