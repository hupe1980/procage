# Contract: Linux violations

## procage-policy

```rust
pub struct SeccompRule { pub syscall, pub condition, pub action,
    /// Why the rule refuses; None: the policy does not grant it.
    pub reason: Option<DenyReason> }
pub enum DenyReason { HardDeny(_), Protect, Hide, Layer,
    Lifetime,    // "lifetime": setsid/setpgid under Lifetime::Run
    OlderKernel, // "kernel": the truncation guard below Landlock ABI 3
}
impl Condition { pub fn matches(&self, args: &[u64; 6]) -> bool; }
```

## procage

```rust
pub enum DeniedBy { …, Lifetime, OlderKernel }
pub enum Coverage { …, SystemCalls } // Linux: refused system calls, exactly; not Landlock
// Linux Child::violations: complete after the listener hung up and the child was reaped.
// Linux Child::violation_receiver: Some when coverage is SystemCalls.
```

Violation on Linux: `operation` = system call name; `target` = `family AF_INET`
(socket), `command 0x5412` (ioctl), `flags 0x…` (clone, open, openat), else None.
