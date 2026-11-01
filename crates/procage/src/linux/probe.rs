//! The tier probe: what this kernel and its settings let procage use.

use std::sync::OnceLock;

use procage_policy::Tier;

use super::sys;

/// What the probe measured on this host, once per process.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Probe {
    /// The strongest tier available, or `None` when Landlock is missing or
    /// older than tier T2 needs and user namespaces are unavailable.
    pub tier: Option<Tier>,
    /// The Landlock ABI the kernel reports (0: no Landlock).
    pub landlock_abi: u8,
    /// The Landlock errata bitmask.
    pub errata: u32,
    /// `None` when an unprivileged user namespace with mounts works; else
    /// the errno of the first failing step (`EPERM` in a container under
    /// Docker's default seccomp profile, `EACCES` under Ubuntu's AppArmor
    /// restriction).
    pub userns_errno: Option<i32>,
}

/// The namespaces a T1 child unshares (the network one is added unless the
/// policy allows all networking).
pub(crate) const T1_NAMESPACES: libc::c_int =
    libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;

/// Probes the host once and returns the cached result.
///
/// The Landlock version is queried directly; user namespaces and mounts are
/// tried in a throwaway child, so the caller's own namespaces never change.
pub fn probe() -> &'static Probe {
    static PROBE: OnceLock<Probe> = OnceLock::new();
    PROBE.get_or_init(|| {
        let landlock_abi = sys::landlock_abi()
            .ok()
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(0);
        let errata = if landlock_abi > 0 {
            sys::landlock_errata()
        } else {
            0
        };
        let userns_errno = sys::probe_userns(T1_NAMESPACES | libc::CLONE_NEWNET).err();
        let tier = if landlock_abi >= Tier::T1.min_landlock_abi() && userns_errno.is_none() {
            Some(Tier::T1)
        } else if landlock_abi >= Tier::T2.min_landlock_abi() {
            Some(Tier::T2)
        } else {
            None
        };
        Probe {
            tier,
            landlock_abi,
            errata,
            userns_errno,
        }
    })
}
