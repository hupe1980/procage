# Data model

| Field | Type | Notes |
|---|---|---|
| `version` | `1` | any other refused on read |
| `procage` | string | crate version that made the receipt |
| `policy_digest` | `sha256:<64 hex>` | over the canonical serialised policy |
| `policy` | policy or absent | only with `with_policy_in_receipt` |
| `preset` | `{name, version}` or absent | |
| `base` | `none`/`v1`/`v2`/`v3` | |
| `grants` | list of names | sorted; never paths |
| `backend` | `{system: "macos", apply, os_release, os_build}` or `{system: "linux", tier, landlock_abi, errata, kernel}` | |
| `approximations` | list of `{construct, note}` | accepted degradations |
| `relaxations` | list of `{construct, relaxation, lift, subject?}` | `subject` only with the policy |
| `waivers` | list of class names | |
| `enforced_as_written` | bool | true only if all three lists are empty |
| `violations` | `{coverage, complete, count?, dropped}` | `coverage`: `off`, `observed`, `system-calls`, `unavailable`; `count` only when observed |
| `exit` | `{code?, signal?, ended_by_caller}` | exactly one of code and signal |

Every map refuses unknown fields.
