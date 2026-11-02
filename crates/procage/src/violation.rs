//! Violations: the operations the sandbox denied a run, and why.
//!
//! A cage built with `CageOptions::with_violations` reports its denials;
//! `Child::violations` returns the record for one run. Reporting is
//! diagnostic: it shows what was refused so a harness can explain the
//! failure or ask for a grant. Enforcement never depends on it, and an empty
//! record never proves that nothing was denied: Linux reports refused system
//! calls only, and macOS drops some reports under heavy load (see
//! [`Coverage::Observed`]).

// The log parser serves the macOS monitor; Linux keeps it compiled and
// tested.
#![cfg_attr(target_os = "linux", allow(dead_code))]

use std::collections::HashMap;
use std::fmt;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use procage_policy::{DenyReason, HardDenyClass};

/// The most violations a run's record keeps; later ones are only counted.
pub(crate) const CAP: usize = 10_000;

/// How many violations the live receiver buffers before it lags.
pub(crate) const RECEIVER_BOUND: usize = 1024;

/// One operation the sandbox denied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Violation {
    /// The process that was denied (the run's child or a descendant).
    pub pid: u32,
    /// The process name the kernel logged.
    pub process: String,
    /// The denied operation, e.g. `file-read-data` or `mach-lookup`.
    pub operation: String,
    /// What the operation was aimed at (a path, a service name, …), when the
    /// kernel names one.
    pub target: Option<String>,
    /// The kind of rule that denied it.
    pub denied_by: DeniedBy,
    /// When procage received the first report.
    pub received: SystemTime,
    /// How often this process was denied this operation on this target by
    /// this kind of rule (at least 1): identical denials are merged.
    pub repeats: u32,
}

/// The kind of rule that denied an operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeniedBy {
    /// Nothing in the policy allows it (the profile's default).
    NotGranted,
    /// A hard-deny class, data classes included; waiving the class lifts it.
    HardDeny(HardDenyClass),
    /// A `Protect` rule: the path is read-only.
    Protect,
    /// A `Hide` rule: the path is unreadable.
    Hide,
    /// A deny rule of the policy's raw layer (Seatbelt rules on macOS,
    /// `syscalls_deny` on Linux).
    Layer,
    /// Linux `Lifetime::Run`: leaving the run's process group is refused, so
    /// that ending the run reaches every descendant.
    Lifetime,
    /// Linux below Landlock ABI 3: truncation is refused everywhere, because
    /// Landlock cannot confine it on this kernel.
    OlderKernel,
    /// The run's proxy refused the host (feature `proxy`): it is not on the
    /// allowlist, or resolves only to addresses that are not public.
    Allowlist,
    /// A code this version does not know, kept as reported.
    Unknown(String),
}

impl DeniedBy {
    fn of(code: Option<&str>) -> DeniedBy {
        let Some(code) = code else {
            return DeniedBy::NotGranted;
        };
        match DenyReason::from_code(code) {
            Some(reason) => DeniedBy::from_reason(Some(reason)),
            None => DeniedBy::Unknown(code.to_string()),
        }
    }

    /// The kind for a rule's reason; `None`: not granted.
    pub(crate) fn from_reason(reason: Option<DenyReason>) -> DeniedBy {
        match reason {
            None => DeniedBy::NotGranted,
            Some(DenyReason::HardDeny(class)) => DeniedBy::HardDeny(class),
            Some(DenyReason::Protect) => DeniedBy::Protect,
            Some(DenyReason::Hide) => DeniedBy::Hide,
            Some(DenyReason::Layer) => DeniedBy::Layer,
            Some(DenyReason::Lifetime) => DeniedBy::Lifetime,
            Some(DenyReason::OlderKernel) => DeniedBy::OlderKernel,
            Some(other) => DeniedBy::Unknown(other.code()),
        }
    }
}

impl fmt::Display for DeniedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeniedBy::NotGranted => f.write_str("not granted by the policy"),
            DeniedBy::HardDeny(class) => write!(f, "denied by the {class} hard-deny class"),
            DeniedBy::Protect => f.write_str("the path is protected (read-only)"),
            DeniedBy::Hide => f.write_str("the path is hidden"),
            DeniedBy::Layer => f.write_str("denied by a rule of the policy's raw layer"),
            DeniedBy::Lifetime => f.write_str(
                "refused so that descendants stay in the run (Lifetime::Run; Lifetime::Tree allows it)",
            ),
            DeniedBy::OlderKernel => f.write_str(
                "refused because this kernel's Landlock cannot confine truncation (below ABI 3)",
            ),
            DeniedBy::Allowlist => f.write_str("refused by the proxy's allowlist"),
            DeniedBy::Unknown(code) => write!(f, "denied ({code})"),
        }
    }
}

#[cfg(feature = "proxy")]
impl Violation {
    /// A request the run's proxy refused: process `proxy` (pid 0), operation
    /// `network-outbound`, the target `host:port (why)`.
    pub(crate) fn refused(r: &procage_proxy::Refusal) -> Violation {
        Violation {
            pid: 0,
            process: "proxy".into(),
            operation: "network-outbound".into(),
            target: Some(format!("{}:{} ({})", r.host, r.port, r.reason)),
            denied_by: DeniedBy::Allowlist,
            received: SystemTime::now(),
            repeats: 1,
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (pid {}) was denied {}",
            self.process, self.pid, self.operation
        )?;
        if let Some(target) = &self.target {
            write!(f, " {target}")?;
        }
        write!(f, ": {}", self.denied_by)?;
        if self.repeats > 1 {
            write!(f, " (×{})", self.repeats)?;
        }
        Ok(())
    }
}

/// What a record can show.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Coverage {
    /// The cage was built without `CageOptions::with_violations`.
    Off,
    /// Every denial the kernel logs is reported (macOS). Best effort:
    /// identical denials by one process (same operation and target) are
    /// logged once, and under heavy load macOS drops reports before any
    /// reader sees them (measured on 26.6.2: 82 of 640 denials missing from
    /// an independent `log stream` with 16 runs in parallel, none in serial
    /// runs). A [complete](Violations::complete) record holds every denial
    /// that was logged.
    Observed,
    /// Every system call the seccomp filter refuses is reported, exactly;
    /// file, network and signal denials by Landlock are not (Linux).
    SystemCalls,
    /// Reporting could not start or stopped; the reason.
    Unavailable(String),
    /// This platform does not report denials.
    NotObserved,
}

impl fmt::Display for Coverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Coverage::Off => f.write_str("reporting is off for this cage"),
            Coverage::Observed => f.write_str("denials are reported"),
            Coverage::SystemCalls => {
                f.write_str("refused system calls are reported; file and network denials are not")
            }
            Coverage::Unavailable(reason) => write!(f, "reporting is unavailable: {reason}"),
            Coverage::NotObserved => f.write_str("this platform does not report denials"),
        }
    }
}

/// The violations of one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violations {
    list: Vec<Violation>,
    complete: bool,
    coverage: Coverage,
    dropped: u64,
}

impl Violations {
    /// A record without violations, for coverage that reports nothing.
    pub(crate) fn empty(coverage: Coverage) -> Violations {
        Violations {
            list: Vec::new(),
            complete: false,
            coverage,
            dropped: 0,
        }
    }

    /// The violations, in the order they were reported.
    pub fn iter(&self) -> std::slice::Iter<'_, Violation> {
        self.list.iter()
    }

    /// How many violations the record holds.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether the record holds none.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Whether the record holds every denial reported up to the child's
    /// exit: the child has exited and every earlier report was delivered.
    /// What the kernel never reported is not in it (see
    /// [`Coverage::Observed`]).
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// What the record can show.
    pub fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// Violations beyond the record's limit (10,000), counted only.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl IntoIterator for Violations {
    type Item = Violation;
    type IntoIter = std::vec::IntoIter<Violation>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.into_iter()
    }
}

impl<'a> IntoIterator for &'a Violations {
    type Item = &'a Violation;
    type IntoIter = std::slice::Iter<'a, Violation>;

    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

/// What makes two violations the same denial.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Key {
    pid: u32,
    process: String,
    operation: String,
    target: Option<String>,
    denied_by: DeniedBy,
}

impl Key {
    fn of(v: &Violation) -> Key {
        Key {
            pid: v.pid,
            process: v.process.clone(),
            operation: v.operation.clone(),
            target: v.target.clone(),
            denied_by: v.denied_by.clone(),
        }
    }
}

/// A run's record, shared by its handle and whatever collects it.
pub(crate) type Sink = Arc<Mutex<Record>>;

pub(crate) fn lock(sink: &Sink) -> MutexGuard<'_, Record> {
    sink.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where a record sends violations as they arrive.
#[derive(Debug)]
enum Live {
    Std(SyncSender<Violation>),
    #[cfg(feature = "tokio")]
    Tokio(tokio::sync::mpsc::Sender<Violation>),
}

impl Live {
    /// Sends without blocking; `false` once the receiving end is gone.
    fn send(&self, v: Violation) -> bool {
        match self {
            Live::Std(tx) => !matches!(tx.try_send(v), Err(TrySendError::Disconnected(_))),
            #[cfg(feature = "tokio")]
            Live::Tokio(tx) => !matches!(
                tx.try_send(v),
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
            ),
        }
    }
}

/// A run's record while it is collected: the violations so far and the
/// optional live receiver's sender.
#[derive(Debug)]
pub(crate) struct Record {
    violations: Violations,
    /// Where each distinct violation is in the list.
    index: HashMap<Key, usize>,
    cap: usize,
    live: Option<Live>,
    receiver: Option<Receiver<Violation>>,
}

impl Record {
    pub(crate) fn new(coverage: Coverage) -> Record {
        Record::with_cap(coverage, CAP)
    }

    fn with_cap(coverage: Coverage, cap: usize) -> Record {
        let (live, receiver) = sync_channel(RECEIVER_BOUND);
        Record {
            violations: Violations::empty(coverage),
            index: HashMap::new(),
            cap,
            live: Some(Live::Std(live)),
            receiver: Some(receiver),
        }
    }

    /// Adds `v`: merged into an equal one already kept (its count grows);
    /// otherwise kept below the cap, counted above it, and sent to the live
    /// receiver unless it lags or is gone.
    pub(crate) fn push(&mut self, v: Violation) {
        let key = Key::of(&v);
        if let Some(&i) = self.index.get(&key) {
            let kept = &mut self.violations.list[i];
            kept.repeats = kept.repeats.saturating_add(v.repeats);
            return;
        }
        if let Some(live) = &self.live
            && !live.send(v.clone())
        {
            self.live = None;
        }
        if self.violations.list.len() < self.cap {
            self.index.insert(key, self.violations.list.len());
            self.violations.list.push(v);
        } else {
            self.violations.dropped += 1;
        }
    }

    /// The record is complete: every report up to now was delivered. A
    /// record whose reporting stopped stays incomplete. The live receiver
    /// ends.
    pub(crate) fn finish(&mut self) {
        if matches!(
            self.violations.coverage,
            Coverage::Observed | Coverage::SystemCalls
        ) {
            self.violations.complete = true;
        }
        self.live = None;
    }

    /// The run ended: nothing more is sent, and the live receiver ends.
    pub(crate) fn close(&mut self) {
        self.live = None;
    }

    /// Reporting stopped: the record stays incomplete and says why.
    pub(crate) fn interrupt(&mut self, reason: &str) {
        if !self.violations.complete {
            self.violations.coverage = Coverage::Unavailable(reason.to_string());
        }
        self.live = None;
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.violations.complete
    }

    /// The live receiver, once (either this or the stream).
    pub(crate) fn take_receiver(&mut self) -> Option<Receiver<Violation>> {
        self.receiver.take()
    }

    /// The live stream, once (either this or the receiver): it starts with
    /// what the receiver buffered so far, and ends with the receiver's
    /// sender.
    #[cfg(feature = "tokio")]
    pub(crate) fn take_stream(&mut self) -> Option<ViolationStream> {
        let buffered = self.receiver.take()?;
        let (tx, rx) = tokio::sync::mpsc::channel(RECEIVER_BOUND);
        for v in buffered.try_iter() {
            let _ = tx.try_send(v);
        }
        if self.live.is_some() {
            self.live = Some(Live::Tokio(tx));
        }
        Some(ViolationStream { rx })
    }

    pub(crate) fn snapshot(&self) -> Violations {
        self.violations.clone()
    }
}

/// A run's violations as they arrive, on a tokio runtime (feature `tokio`).
///
/// It yields each distinct violation once, as the receiver of
/// `Child::violation_receiver` does, and ends when the run's record is
/// complete or reporting stops. It buffers 1,024 violations; when it lags,
/// later ones are only in `Child::violations`.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub struct ViolationStream {
    rx: tokio::sync::mpsc::Receiver<Violation>,
}

#[cfg(feature = "tokio")]
impl ViolationStream {
    /// The next violation, or `None` once the stream has ended.
    pub async fn next(&mut self) -> Option<Violation> {
        self.rx.recv().await
    }
}

#[cfg(feature = "tokio")]
impl futures_core::Stream for ViolationStream {
    type Item = Violation;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Violation>> {
        self.rx.poll_recv(cx)
    }
}

/// A denial message from the unified log, split into the run marker on its
/// last line and the violation it describes.
///
/// The kernel writes `Sandbox: <name>(<pid>) deny(<n>) <operation>
/// <target>`, then a newline and the denying rule's message: the run marker,
/// a space and a rule code for explicit rules. The marker is taken from the
/// last line only, which the kernel writes after the target, so a target
/// (chosen by the caged code, and possibly containing newlines) cannot
/// change which run a violation belongs to. Everything between the
/// operation and the last line is the target.
pub(crate) fn parse(message: &str, received: SystemTime) -> Option<(&str, Violation)> {
    let (head, last) = message.rsplit_once('\n')?;
    let (marker, code) = match last.split_once(' ') {
        Some((marker, code)) => (marker, Some(code)),
        None => (last, None),
    };
    if marker.is_empty() {
        return None;
    }
    let rest = head.strip_prefix("Sandbox: ")?;
    // `<name>(<pid>) deny(<n>) ` — the first such pattern; a name (at most
    // 32 bytes, chosen by the program) cannot move the marker.
    let (name, pid, after) = (0..rest.len())
        .filter(|&i| rest.as_bytes()[i] == b'(')
        .find_map(|open| {
            let tail = &rest[open + 1..];
            let close = tail.find(')')?;
            let pid: u32 = tail[..close].parse().ok()?;
            let after = tail[close..].strip_prefix(") deny(")?;
            let n_end = after.find(") ")?;
            after[..n_end].parse::<u32>().ok()?;
            Some((&rest[..open], pid, &after[n_end + 2..]))
        })?;
    let (operation, target) = match after.split_once(' ') {
        Some((op, target)) if !target.is_empty() => (op, Some(target.to_string())),
        Some((op, _)) => (op, None),
        None => (after, None),
    };
    if operation.is_empty() {
        return None;
    }
    Some((
        marker,
        Violation {
            pid,
            process: name.to_string(),
            operation: operation.to_string(),
            target,
            denied_by: DeniedBy::of(code),
            received,
            repeats: 1,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "org.procage.run.1f.0123456789abcdef.3";
    const OTHER: &str = "org.procage.run.1f.0123456789abcdef.4";

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH
    }

    #[test]
    fn a_default_denial_is_not_granted() {
        let msg = format!("Sandbox: cat(812) deny(1) file-read-data /Users/a/.zshrc\n{M}");
        let (marker, v) = parse(&msg, now()).unwrap();
        assert_eq!(marker, M);
        assert_eq!(v.pid, 812);
        assert_eq!(v.process, "cat");
        assert_eq!(v.operation, "file-read-data");
        assert_eq!(v.target.as_deref(), Some("/Users/a/.zshrc"));
        assert_eq!(v.denied_by, DeniedBy::NotGranted);
        assert_eq!(
            v.to_string(),
            "cat (pid 812) was denied file-read-data /Users/a/.zshrc: not granted by the policy"
        );
    }

    #[test]
    fn rule_codes_name_the_kind() {
        let cases = [
            ("hide", DeniedBy::Hide),
            ("protect", DeniedBy::Protect),
            ("layer", DeniedBy::Layer),
            ("hd:secrets", DeniedBy::HardDeny(HardDenyClass::Secrets)),
            ("hd:privilege", DeniedBy::HardDeny(HardDenyClass::Privilege)),
            ("future-kind", DeniedBy::Unknown("future-kind".into())),
        ];
        for (code, want) in cases {
            let msg = format!("Sandbox: sh(9) deny(1) file-write-create /w/x\n{M} {code}");
            assert_eq!(parse(&msg, now()).unwrap().1.denied_by, want, "{code}");
        }
    }

    #[test]
    fn names_with_parentheses_and_spaces_parse() {
        let msg = format!(
            "Sandbox: Code Helper (Plugin)(4678) deny(1) mach-lookup com.apple.diagnosticd\n{M}"
        );
        let (_, v) = parse(&msg, now()).unwrap();
        assert_eq!(v.process, "Code Helper (Plugin)");
        assert_eq!(v.pid, 4678);
        assert_eq!(v.target.as_deref(), Some("com.apple.diagnosticd"));
    }

    /// A target cannot carry another run's marker into the last line: the
    /// kernel's own last line wins, and the target keeps its newline.
    #[test]
    fn a_newline_in_the_target_cannot_move_the_violation() {
        let target = format!("/w/x\n{OTHER} hide");
        let msg = format!("Sandbox: cat(5) deny(1) file-read-data {target}\n{M}");
        let (marker, v) = parse(&msg, now()).unwrap();
        assert_eq!(marker, M);
        assert_eq!(v.target.as_deref(), Some(target.as_str()));
        assert_eq!(v.denied_by, DeniedBy::NotGranted);
    }

    #[test]
    fn other_messages_are_ignored() {
        for msg in [
            "Sandbox: cat(5) deny(1) file-read-data /x".to_string(),
            format!("Sandbox: cat(5) allow file-read-data /x\n{M}"),
            format!("1 duplicate report for Sandbox: cat(5) deny(1) file-read-data /x\n{M}"),
            format!("cat(5) deny(1) file-read-data /x\n{M}"),
            format!("Sandbox: cat(x) deny(1) file-read-data /x\n{M}"),
            "Sandbox: cat(5) deny(1) file-read-data /x\n".to_string(),
        ] {
            assert!(parse(&msg, now()).is_none(), "{msg:?}");
        }
    }

    #[test]
    fn an_operation_without_target_parses() {
        let msg = format!("Sandbox: sh(5) deny(1) file-write-setugid\n{M} hd:privilege");
        let (_, v) = parse(&msg, now()).unwrap();
        assert_eq!(v.operation, "file-write-setugid");
        assert_eq!(v.target, None);
    }

    #[test]
    fn the_record_keeps_the_cap_and_counts_the_rest() {
        let mut record = Record::with_cap(Coverage::Observed, 3);
        let rx = record.take_receiver().unwrap();
        let at = |path: usize| {
            let msg = format!("Sandbox: cat(5) deny(1) file-read-data /x{path}\n{M}");
            parse(&msg, now()).unwrap().1
        };
        for path in 0..5 {
            record.push(at(path));
        }
        // A kept entry keeps counting past the cap; a new one is dropped.
        record.push(at(0));
        record.push(at(4));
        let snap = record.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap.dropped(), 3);
        assert_eq!(snap.iter().next().unwrap().repeats, 2);
        assert!(!snap.complete());
        assert_eq!(rx.try_iter().count(), 6);
        assert!(record.take_receiver().is_none());
        record.finish();
        assert!(record.snapshot().complete());
    }

    #[test]
    fn the_receiver_is_bounded_and_never_blocks() {
        let mut record = Record::with_cap(Coverage::Observed, CAP);
        let rx = record.take_receiver().unwrap();
        let at = |path: usize| {
            let msg = format!("Sandbox: cat(5) deny(1) file-read-data /x{path}\n{M}");
            parse(&msg, now()).unwrap().1
        };
        for path in 0..RECEIVER_BOUND + 10 {
            record.push(at(path));
        }
        assert_eq!(rx.try_iter().count(), RECEIVER_BOUND);
        assert_eq!(record.snapshot().len(), RECEIVER_BOUND + 10);
        drop(rx);
        record.push(at(0));
    }

    #[test]
    fn the_receiver_ends_when_the_record_is_complete() {
        let mut record = Record::new(Coverage::Observed);
        let rx = record.take_receiver().unwrap();
        record.push(
            parse(
                &format!("Sandbox: cat(5) deny(1) file-read-data /x\n{M}"),
                now(),
            )
            .unwrap()
            .1,
        );
        record.finish();
        assert_eq!(rx.iter().count(), 1, "the iterator ends");
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn the_stream_takes_over_the_buffer_and_ends() {
        let at = |path: usize| {
            let msg = format!("Sandbox: cat(5) deny(1) file-read-data /x{path}\n{M}");
            parse(&msg, now()).unwrap().1
        };
        let mut record = Record::new(Coverage::Observed);
        record.push(at(0));
        let mut stream = record.take_stream().unwrap();
        assert!(record.take_receiver().is_none() && record.take_stream().is_none());
        for path in 1..RECEIVER_BOUND + 10 {
            record.push(at(path));
        }
        record.close();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let got = rt.block_on(async {
            let mut n = 0;
            while stream.next().await.is_some() {
                n += 1;
            }
            n
        });
        assert_eq!(got, RECEIVER_BOUND, "bounded, never blocking, then ended");
        assert_eq!(record.snapshot().len(), RECEIVER_BOUND + 10);
    }

    /// Only equal denials merge, and the count saturates.
    #[test]
    fn only_equal_denials_merge() {
        let mut record = Record::new(Coverage::Observed);
        let base = |msg: &str| parse(msg, now()).unwrap().1;
        let v = base(&format!("Sandbox: cat(5) deny(1) file-read-data /x\n{M}"));
        let variants = [
            base(&format!("Sandbox: cat(6) deny(1) file-read-data /x\n{M}")),
            base(&format!("Sandbox: dog(5) deny(1) file-read-data /x\n{M}")),
            base(&format!("Sandbox: cat(5) deny(1) file-write-data /x\n{M}")),
            base(&format!("Sandbox: cat(5) deny(1) file-read-data /y\n{M}")),
            base(&format!(
                "Sandbox: cat(5) deny(1) file-read-data /x\n{M} hide"
            )),
        ];
        record.push(v.clone());
        for other in variants.iter().cloned() {
            record.push(other);
        }
        assert_eq!(record.snapshot().len(), 6);
        let mut big = v.clone();
        big.repeats = u32::MAX;
        record.push(big);
        record.push(v);
        let first = record.snapshot().iter().next().unwrap().clone();
        assert_eq!(first.repeats, u32::MAX);
        assert!(first.to_string().ends_with(&format!("(×{})", u32::MAX)));
    }

    #[test]
    fn an_interrupted_record_says_why() {
        let mut record = Record::new(Coverage::Observed);
        record.interrupt("the log stream ended");
        let snap = record.snapshot();
        assert!(!snap.complete());
        assert_eq!(
            snap.coverage(),
            &Coverage::Unavailable("the log stream ended".into())
        );
    }
}
