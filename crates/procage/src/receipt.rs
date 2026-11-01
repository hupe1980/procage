//! Receipts: the record of how one run was caged.
//!
//! A [`Receipt`] says which policy a run had (by digest), from which preset
//! and base, on which backend and tier, on which OS build or kernel, what the
//! cage accepted short of the policy (approximations, `fit` relaxations,
//! waived hard-deny classes), what was reported denied, and how the run
//! ended. A harness stores it with the command's output as evidence that the
//! command ran caged, and in which cage.
//!
//! **What a receipt is not.** It is the caller's own record, unsigned, built
//! from what procage knew in the calling process: not an attestation. Anyone
//! who can write where it is kept can change it, so keep it outside every
//! path a later run may write. On macOS the violation summary is best effort
//! (see [`Coverage::Observed`]): a complete record with no violations does
//! not prove that nothing was denied, and with reporting off the summary
//! says `off`, never "none". `Cage::exec` gives no receipt: the calling
//! process becomes the command.
//!
//! **Host facts.** The backend names the OS release and build (macOS) or the
//! kernel release, tier, Landlock ABI and errata (Linux) of the machine the
//! run was on; store receipts where that is acceptable.
//!
//! **Format.** [`Receipt::to_json`] and [`Receipt::from_json`] use a versioned
//! form (`"version": 1`) with the rules of the policy format: a reader
//! refuses another version and any field it does not know, at any depth,
//! rather than present a receipt it understood only in part.
//!
//! **Privacy.** A receipt holds no environment value, argument, file content
//! or process name. Paths appear only when the cage was built with
//! `CageOptions::with_policy_in_receipt`, which adds the whole policy, every
//! path in it included, and the subjects of the relaxations to each receipt.

use std::sync::Arc;

use procage_policy::{Base, Construct, HardDenyClass, Policy, PresetTag, Relaxed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::violation::{Coverage, Violations};

/// The receipt format version.
const VERSION: u32 = 1;

/// The SHA-256 digest of `policy`'s canonical serialised form, written
/// `sha256:<hex>`.
///
/// The canonical form is the versioned policy format of a copy whose
/// order-insensitive lists are sorted (file rules, grants, Unix-socket paths,
/// the environment lists, the Linux layer); the Seatbelt layer keeps its
/// order, which changes its meaning. Two policies that differ in any rule
/// have different digests; the same policy has the same digest on every
/// system.
pub fn policy_digest(policy: &Policy) -> String {
    let canonical = canonical(policy);
    let json = serde_json::to_vec(&canonical)
        .unwrap_or_else(|_| unreachable!("a policy always serialises: its fields are plain data"));
    let digest = Sha256::digest(&json);
    let mut out = String::from("sha256:");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn canonical(policy: &Policy) -> Policy {
    let mut p = policy.clone();
    p.fs.sort();
    p.fs.dedup();
    p.grants.sort();
    p.grants.dedup();
    p.ipc.unix_sockets.sort();
    p.ipc.unix_sockets.dedup();
    match &mut p.env {
        procage_policy::EnvPolicy::Allowlist(names) => {
            names.sort();
            names.dedup();
        }
        procage_policy::EnvPolicy::Passthrough { deny } => {
            deny.sort();
            deny.dedup();
        }
    }
    if let Some(layer) = &mut p.linux {
        layer.syscalls_deny.sort();
        layer.syscalls_deny.dedup();
        layer.landlock_extra.sort();
        layer.landlock_extra.dedup();
    }
    p
}

/// The record of how one run was caged; see the [module docs](self).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Receipt {
    /// The format version (1).
    pub version: u32,
    /// The procage version that made the receipt.
    pub procage: String,
    /// [`policy_digest`] of the cage's policy (after `fit`).
    pub policy_digest: String,
    /// The policy itself, only with `CageOptions::with_policy_in_receipt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
    /// The preset the policy was built from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<PresetTag>,
    /// The base profile.
    pub base: Base,
    /// The names of the grants bound for this run, sorted (never paths).
    pub grants: Vec<String>,
    /// The backend and the host it ran on.
    pub backend: ReceiptBackend,
    /// Approximations the caller accepted.
    pub approximations: Vec<ReceiptApproximation>,
    /// Constructs `Cage::fit` relaxed.
    pub relaxations: Vec<ReceiptRelaxation>,
    /// Hard-deny classes the policy waived.
    pub waivers: Vec<HardDenyClass>,
    /// True only when nothing was approximated, relaxed or waived.
    pub enforced_as_written: bool,
    /// What the run's violation record held.
    pub violations: ReceiptViolations,
    /// How the run ended.
    pub exit: ReceiptExit,
    /// What the audits found.
    pub audit: ReceiptAudit,
}

/// What a run's audits found: counts and completeness; paths only with the
/// policy included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAudit {
    /// The link check's mode: `refuse`, `report` or `off`.
    pub links_mode: String,
    /// Protected, hidden or class files with another name (report mode).
    pub links: usize,
    /// Whether the link check examined everything.
    pub links_complete: bool,
    /// What the run left behind, with the handoff audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<usize>,
    /// Whether the handoff audit examined everything.
    pub handoff_complete: bool,
    /// Entries the link check and the handoff walks examined.
    pub visited: usize,
    /// The findings' paths, only with the policy included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<ReceiptPath>>,
}

/// A path as the policy format writes it: a string when its bytes are valid
/// UTF-8, otherwise the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReceiptPath {
    /// Valid UTF-8.
    Text(String),
    /// Any other bytes.
    Bytes(Vec<u8>),
}

impl From<&std::path::Path> for ReceiptPath {
    fn from(path: &std::path::Path) -> Self {
        use std::os::unix::ffi::OsStrExt;
        match std::str::from_utf8(path.as_os_str().as_bytes()) {
            Ok(text) => ReceiptPath::Text(text.into()),
            Err(_) => ReceiptPath::Bytes(path.as_os_str().as_bytes().to_vec()),
        }
    }
}

/// The backend of a run and the host it ran on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "system", rename_all = "kebab-case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReceiptBackend {
    /// Seatbelt.
    #[serde(rename = "macos")]
    MacOs {
        /// How the profile was applied (`path-a`).
        apply: String,
        /// `kern.osproductversion`, e.g. `26.6.2`.
        os_release: String,
        /// `kern.osversion`, e.g. `25G83`.
        os_build: String,
    },
    /// Landlock and seccomp, with namespaces on tier T1.
    Linux {
        /// `T1` or `T2`.
        tier: String,
        /// The Landlock ABI the plan was made for.
        landlock_abi: u8,
        /// The kernel's Landlock errata bitmask.
        errata: u32,
        /// `/proc/sys/kernel/osrelease`.
        kernel: String,
    },
}

/// An approximation the caller accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptApproximation {
    /// The construct, as named in the lowering table.
    pub construct: Construct,
    /// What the approximation does.
    pub note: String,
}

/// A construct `Cage::fit` relaxed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptRelaxation {
    /// The construct the host could not enforce.
    pub construct: Construct,
    /// The change made to the policy, in words (the construct carries the
    /// meaning).
    pub relaxation: String,
    /// What would make it enforceable.
    pub lift: ReceiptLift,
    /// The gap's subject (often a path), only with the policy included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// What would make a relaxed construct enforceable; neither means unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptLift {
    /// Tier T1 (user namespaces) lifts it.
    pub tier1: bool,
    /// The lowest Landlock ABI that lifts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub landlock_abi: Option<u8>,
}

/// How much of a run's denials its record can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReceiptCoverage {
    /// Reporting was off.
    Off,
    /// Every logged denial (macOS, best effort).
    Observed,
    /// Every refused system call (Linux, exact).
    SystemCalls,
    /// Reporting could not start or stopped.
    Unavailable,
    /// This platform does not report denials.
    Unsupported,
}

/// What a run's violation record held when the receipt was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptViolations {
    /// The record's coverage.
    pub coverage: ReceiptCoverage,
    /// Why reporting was unavailable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the record was complete.
    pub complete: bool,
    /// How many violations were recorded; absent when nothing was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    /// Reports dropped past the record's cap.
    pub dropped: u64,
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptExit {
    /// The exit code, when the child exited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// The signal, when a signal ended the child.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// True when the caller ended the run (`kill_all`) while it was running.
    pub ended_by_caller: bool,
}

/// A receipt that cannot be read.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReceiptError {
    /// A receipt of a version this reader does not know.
    UnsupportedVersion(u64),
    /// Not a receipt, or a field or value this version does not know.
    Invalid(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::UnsupportedVersion(v) => write!(f, "unsupported receipt version {v}"),
            ReceiptError::Invalid(e) => write!(f, "not a receipt this version can read: {e}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

impl Receipt {
    /// The receipt as JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| unreachable!("a receipt always serialises"))
    }

    /// Reads a receipt; refuses another version and unknown fields.
    pub fn from_json(text: &str) -> Result<Receipt, ReceiptError> {
        let invalid = |e: serde_json::Error| ReceiptError::Invalid(e.to_string());
        let value: serde_json::Value = serde_json::from_str(text).map_err(invalid)?;
        match value.get("version").and_then(serde_json::Value::as_u64) {
            Some(v) if v == u64::from(VERSION) => {}
            Some(v) => return Err(ReceiptError::UnsupportedVersion(v)),
            None => return Err(ReceiptError::Invalid("no version".into())),
        }
        serde_json::from_value(value).map_err(invalid)
    }
}

/// What a cage knows when it is made, shared by its runs.
#[derive(Debug)]
pub(crate) struct CageFacts {
    digest: String,
    policy: Option<Policy>,
    preset: Option<PresetTag>,
    base: Base,
    backend: ReceiptBackend,
    approximations: Vec<ReceiptApproximation>,
    relaxations: Vec<ReceiptRelaxation>,
    waivers: Vec<HardDenyClass>,
}

impl CageFacts {
    pub(crate) fn new(
        policy: &Policy,
        include_policy: bool,
        backend: ReceiptBackend,
        approximations: Vec<ReceiptApproximation>,
        relaxed: &[Relaxed],
    ) -> CageFacts {
        let relaxations = relaxed
            .iter()
            .map(|r| ReceiptRelaxation {
                construct: r.gap.construct,
                relaxation: r.relaxation.to_string(),
                lift: ReceiptLift {
                    tier1: r.lift.tier1,
                    landlock_abi: r.lift.landlock_abi,
                },
                subject: include_policy.then(|| r.gap.subject.clone()).flatten(),
            })
            .collect();
        CageFacts {
            digest: policy_digest(policy),
            policy: include_policy.then(|| policy.clone()),
            preset: policy.preset.clone(),
            base: policy.base,
            backend,
            approximations,
            relaxations,
            waivers: policy.waive.iter().copied().collect(),
        }
    }
}

/// What a run adds to its cage's facts.
#[derive(Debug, Clone)]
pub(crate) struct RunFacts {
    pub(crate) cage: Arc<CageFacts>,
    /// Sorted grant names.
    pub(crate) grants: Vec<String>,
}

impl RunFacts {
    pub(crate) fn new(cage: Arc<CageFacts>, mut grants: Vec<String>) -> RunFacts {
        grants.sort();
        grants.dedup();
        RunFacts { cage, grants }
    }

    /// The receipt of a run that ended with `status`.
    pub(crate) fn receipt(
        &self,
        status: std::process::ExitStatus,
        record: &Violations,
        ended_by_caller: bool,
        audit: &crate::Audit,
    ) -> Receipt {
        use std::os::unix::process::ExitStatusExt;
        let c = &self.cage;
        let (coverage, reason, observed) = match record.coverage() {
            Coverage::Off => (ReceiptCoverage::Off, None, false),
            Coverage::Observed => (ReceiptCoverage::Observed, None, true),
            Coverage::SystemCalls => (ReceiptCoverage::SystemCalls, None, true),
            Coverage::Unavailable(why) => (ReceiptCoverage::Unavailable, Some(why.clone()), false),
            _ => (ReceiptCoverage::Unsupported, None, false),
        };
        Receipt {
            version: VERSION,
            procage: env!("CARGO_PKG_VERSION").into(),
            policy_digest: c.digest.clone(),
            policy: c.policy.clone(),
            preset: c.preset.clone(),
            base: c.base,
            grants: self.grants.clone(),
            backend: c.backend.clone(),
            approximations: c.approximations.clone(),
            relaxations: c.relaxations.clone(),
            waivers: c.waivers.clone(),
            enforced_as_written: c.approximations.is_empty()
                && c.relaxations.is_empty()
                && c.waivers.is_empty(),
            violations: ReceiptViolations {
                coverage,
                reason,
                complete: record.complete(),
                count: observed.then(|| record.len()),
                dropped: record.dropped(),
            },
            exit: ReceiptExit {
                code: status.code(),
                signal: if status.code().is_some() {
                    None
                } else {
                    status.signal()
                },
                ended_by_caller,
            },
            audit: ReceiptAudit {
                links_mode: match audit.mode {
                    crate::LinkAudit::Refuse => "refuse",
                    crate::LinkAudit::Report => "report",
                    _ => "off",
                }
                .into(),
                links: audit.links.len(),
                links_complete: audit.links_complete,
                handoff: audit.handoff.as_ref().map(Vec::len),
                handoff_complete: audit.handoff_complete,
                visited: audit.links_visited + audit.handoff_visited,
                paths: c.policy.is_some().then(|| {
                    audit
                        .links
                        .iter()
                        .map(|f| ReceiptPath::from(f.path.as_path()))
                        .chain(
                            audit
                                .handoff
                                .iter()
                                .flatten()
                                .map(|f| ReceiptPath::from(f.path.as_path())),
                        )
                        .collect()
                }),
            },
        }
    }
}

/// The receipt approximations of a plan's degradations.
pub(crate) fn approximations(
    degradations: &[procage_policy::Degradation],
) -> Vec<ReceiptApproximation> {
    let mut out: Vec<ReceiptApproximation> = degradations
        .iter()
        .map(|d| ReceiptApproximation {
            construct: d.construct,
            note: d.note.into(),
        })
        .collect();
    out.sort_by_key(|a| a.construct);
    out.dedup();
    out
}
