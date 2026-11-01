# Data model: The escape suite

## Escape class (catalog row, unchanged columns)

`Id | Class | Description | Platforms | Disposition | Status | Evidence | Observed on`

- **Status** gains `partial`. Allowed per disposition:
  - `mitigate`: planned, partial, mitigated, retired;
  - `detect`: planned, partial, detected, retired;
  - `harness`: documented, retired.
- **Evidence**: `—` or a comma-separated list of `tests/escape_macos.rs::rNN_…`
  or `tests/escape_linux.rs::rNN_…`. Each must exist, must not be ignored, and
  must be prefixed with the row's id.

## Canary

- A function in `tests/escape_macos.rs` (platform macOS) or
  `tests/escape_linux.rs` (platform Linux) whose name is `r<NN>_<words>`,
  where `<NN>` is the id's number.
- **Active**: a plain `#[test]`.
- **Open**: `#[test]` plus `#[ignore = "open: R-NN …"]`. The gate reads the
  attribute lines directly above the `fn`.

## Open variant note

- Under `### Open variants` in the `## Escape classes` section:
  `- **R-NN** <what is open, on which platform>`.
- Required for every `partial` row. Allowed for `planned` rows.

## Lane result (quickstart only, not published)

- Per canary and lane: pass, fail, or open, plus `informative=true|false`
  for syscall canaries.
