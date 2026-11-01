# Contract: serialised policy (feature `serde`)

- The top level is `Policy`, written as a map whose first field is
  `"version": 1`. Reading a document with no version, or a version other than
  1, fails with `unsupported policy version`.
- Every map refuses unknown fields. The serde error names the field.
- Enums are externally tagged, in serde's default form, with kebab-case
  variant names. For example: `{"subpath": "/work"}`, `"read"`,
  `{"loopback": "any"}`, `{"loopback": {"list": [8080]}}`.
- Paths:
  - valid UTF-8: a JSON string, `"/work"`;
  - otherwise: an array of byte values, `[47, 255]`.

  Reading accepts either form and validates it with `AbsPath::try_from`.
- Globs, grant names, tags, names and operation names are strings, validated
  on read with the same errors as their constructors.
- `HardDenyClass` and `Construct` are kebab-case strings. An unknown name is a
  read error.

Example:

```json
{
  "version": 1,
  "fs": [{"access": "write", "target": {"subpath": "/work"}},
         {"access": "protect", "target": {"subpath": "/work/.git"}}],
  "net": {"proxy": {"http": 3128, "socks": null}},
  "process": {"exec": "granted", "fork": true, "signals": "self-and-children"},
  "ipc": {"posix_shm": false, "sysv": false},
  "env": {"allowlist": ["PATH", "HOME"]},
  "limits": {"nproc": null, "cpu_seconds": null, "fsize_bytes": null, "nofile": 1024, "core_bytes": 0},
  "tty": "none",
  "waive": [],
  "grants": [{"name": "scratch", "access": "write"}],
  "seatbelt": null,
  "linux": null
}
```
