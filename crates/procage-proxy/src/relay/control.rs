//! The relay control protocol, byte-for-byte compatible with the harness
//! server in `opencode-fs-plugin/src/core/relay-protocol.ts`.
//!
//! ```text
//! frame  := u32be payload length | payload            (1..=4096 bytes)
//! payload := u8 type | body
//!
//! HELLO        (3) := u8 type, u8 version (1), u64 run id, u32 pid
//! HELLO_ACK    (4) := u8 type, u8 version (1), u32 protocol version (1),
//!                      u32 max in-flight, u64 run id
//! DECIDE_REQ   (1) := u8 type, u64 id, u16 resource length, resource UTF-8,
//!                      u16 port, u8 proto (1 TCP, 2 UDP)
//! DECIDE_RESP  (2) := u8 type, u64 id, u8 verdict (0 deny, 1 allow),
//!                      u16 reason length, reason UTF-8
//! ```
//!
//! Every integer is big-endian. The resource is the only network detail the
//! harness sees: a DNS QNAME, TLS SNI, HTTP `Host`, QUIC SNI or an IP
//! literal; no payload, URL, header or descriptor is sent. A malformed,
//! short, oversized, mistyped or late frame closes the connection, and every
//! later flow is refused.
//!
//! Requests are multiplexed by id on one connection: a reader thread routes
//! each response to the request that waits for it, so a slow permission
//! prompt for one flow never blocks another. The in-flight window is bounded
//! by `HELLO_ACK`'s value (at most 64); a full window refuses with `Busy`
//! rather than growing an unbounded queue.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::Resource;

/// The envelope version carried by `HELLO` and `HELLO_ACK`.
pub const MESSAGE_VERSION: u8 = 1;
/// The semantic protocol version announced by `HELLO_ACK`.
pub const PROTOCOL_VERSION: u32 = 1;
/// The largest accepted frame payload.
pub const MAX_FRAME: usize = 4096;
/// The largest reason the harness may send.
pub const MAX_REASON: usize = 512;
/// The largest resource the relay will name.
pub const MAX_RESOURCE: usize = 255;
/// The most requests one connection keeps in flight, whatever the harness
/// allows.
pub const MAX_INFLIGHT: u32 = 64;
/// How many timed-out ids are remembered to ignore their late answers.
const EXPIRED: usize = 256;

const HELLO: u8 = 3;
const HELLO_ACK: u8 = 4;
const DECIDE_REQ: u8 = 1;
const DECIDE_RESP: u8 = 2;

/// One run's id, agreed with the harness and echoed in `HELLO_ACK`.
pub type RunId = u64;

/// The transport a decision is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// TCP (1).
    Tcp,
    /// UDP (2).
    Udp,
}

impl Proto {
    fn code(self) -> u8 {
        match self {
            Proto::Tcp => 1,
            Proto::Udp => 2,
        }
    }

    /// The name used in a refusal.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Why a flow was refused. The harness's reason is free text; these codes
/// classify it for procage's own violation text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Reason {
    /// The harness allowed the flow.
    Ok = 0,
    /// The harness's policy denied it.
    Policy = 1,
    /// No decision arrived before the deadline.
    Timeout = 2,
    /// The control connection ended or broke.
    ControlLost = 3,
    /// A frame was malformed.
    Malformed = 4,
    /// The harness's in-flight window was full.
    Busy = 5,
    /// ECH hides the destination the harness would have to authorize.
    Ech = 6,
    /// A known encrypted-DNS endpoint, or TCP/853.
    Dns = 7,
    /// The relay refuses this flow before asking.
    Blocked = 8,
}

impl Reason {
    /// The reason's wire code (used only in procage's records).
    pub fn code(self) -> u8 {
        self as u8
    }

    fn from_text(text: &str) -> Reason {
        let text = text.to_ascii_lowercase();
        if text.contains("timeout") || text.contains("timed out") {
            Reason::Timeout
        } else if text.contains("inflight") || text.contains("busy") {
            Reason::Busy
        } else {
            Reason::Policy
        }
    }
}

/// What the control socket answered, or the refusal the relay applied when
/// the answer could not be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The flow may be relayed.
    Allow,
    /// The flow must be closed (TCP) or dropped (UDP).
    Deny {
        /// The classified reason.
        reason: Reason,
        /// The harness's own text, bounded to 512 bytes.
        text: String,
    },
}

impl Decision {
    /// Whether the flow may proceed.
    pub fn allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// The refusal reason, if any.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Decision::Allow => None,
            Decision::Deny { reason, .. } => Some(*reason),
        }
    }

    /// The harness's reason text, if it refused.
    pub fn text(&self) -> Option<&str> {
        match self {
            Decision::Allow => None,
            Decision::Deny { text, .. } => Some(text),
        }
    }
}

/// A control-channel failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum ControlError {
    /// The socket could not be reached or the handshake failed.
    Io(io::Error),
    /// The harness speaks another envelope or protocol version.
    Version(u8, u32),
    /// The harness echoed another run id.
    RunId,
    /// A frame was short, oversized, mistyped or malformed.
    Malformed(&'static str),
    /// No answer before the deadline.
    Timeout,
    /// The channel closed, with the reason later flows are refused for.
    Closed(Reason),
    /// The reason text is not valid UTF-8.
    Reason,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::Io(e) => write!(f, "control socket: {e}"),
            ControlError::Version(v, p) => {
                write!(
                    f,
                    "control version {v}/{p} is not {MESSAGE_VERSION}/{PROTOCOL_VERSION}"
                )
            }
            ControlError::RunId => f.write_str("control socket echoed another run id"),
            ControlError::Malformed(why) => write!(f, "malformed control frame: {why}"),
            ControlError::Timeout => f.write_str("control decision deadline passed"),
            ControlError::Closed(reason) => write!(f, "control channel closed ({reason:?})"),
            ControlError::Reason => f.write_str("control reason is not UTF-8"),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ControlError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// One run's control connection. Cloning shares the one connection and its
/// in-flight window; cloning is how threads ask concurrently.
#[derive(Debug)]
pub struct Control {
    inner: Arc<Inner>,
}

impl Clone for Control {
    fn clone(&self) -> Control {
        self.inner.handles.fetch_add(1, Ordering::AcqRel);
        Control {
            inner: self.inner.clone(),
        }
    }
}

#[derive(Debug)]
struct Inner {
    writer: Mutex<UnixStream>,
    pending: Mutex<Pending>,
    next: AtomicU64,
    handles: AtomicUsize,
    dead: AtomicBool,
    run_id: RunId,
    timeout: Duration,
    max_inflight: u32,
}

#[derive(Debug, Default)]
struct Pending {
    map: HashMap<u64, SyncSender<Result<Decision, ControlError>>>,
    expired: VecDeque<u64>,
}

impl Inner {
    fn close(&self, reason: Reason) {
        if self.dead.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(writer) = self.writer.lock() {
            let _ = writer.shutdown(std::net::Shutdown::Both);
        }
        if let Ok(mut pending) = self.pending.lock() {
            for (_, sender) in pending.map.drain() {
                let _ = sender.try_send(Err(ControlError::Closed(reason)));
            }
            pending.expired.clear();
        }
    }
}

impl Control {
    /// Connects to `path`, sends `HELLO` with `run_id` and this process's
    /// pid, and validates `HELLO_ACK`. A failure leaves no usable channel.
    pub fn connect(path: &Path, run_id: RunId, timeout: Duration) -> Result<Control, ControlError> {
        let stream = UnixStream::connect(path).map_err(ControlError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ControlError::Io)?;
        let reader = stream.try_clone().map_err(ControlError::Io)?;
        let (_, control) = hello(stream, run_id, timeout)?;
        // `SO_RCVTIMEO` is per socket, shared by the handshake clone; the
        // reader must block until a frame or shutdown arrives.
        reader.set_read_timeout(None).map_err(ControlError::Io)?;
        let inner = control.inner.clone();
        std::thread::Builder::new()
            .name("procage relay control".into())
            .spawn(move || read_loop(reader, inner))
            .map_err(ControlError::Io)?;
        Ok(control)
    }

    /// The run id this channel carries.
    pub fn run_id(&self) -> RunId {
        self.inner.run_id
    }

    /// The in-flight window the harness allowed (at most [`MAX_INFLIGHT`]).
    pub fn max_inflight(&self) -> u32 {
        self.inner.max_inflight
    }

    /// Whether a previous failure has closed the channel.
    pub fn is_dead(&self) -> bool {
        self.inner.dead.load(Ordering::Acquire)
    }

    /// Closes the channel: the harness sees the run end. Later decisions are
    /// refused as if the connection had failed.
    pub fn close(&self) {
        self.inner.close(Reason::ControlLost);
    }

    /// Asks whether `resource`:`port` over `proto` may be reached. Other
    /// flows may ask at the same time; a slow answer holds only this call.
    pub fn decide(&self, resource: &Resource, port: u16, proto: Proto) -> Decision {
        if self.is_dead() {
            return deny(Reason::ControlLost, "control channel already closed");
        }
        let text = resource.as_str();
        if text.is_empty() || text.len() > MAX_RESOURCE {
            return deny(Reason::Malformed, "resource length");
        }
        if text.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return deny(
                Reason::Malformed,
                "resource has whitespace or a control byte",
            );
        }
        if port == 0 {
            return deny(Reason::Malformed, "port is zero");
        }
        let id = self.inner.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = sync_channel(1);
        {
            let Ok(mut pending) = self.inner.pending.lock() else {
                return deny(Reason::ControlLost, "control pending lock poisoned");
            };
            if pending.map.len() >= self.inner.max_inflight as usize {
                return deny(Reason::Busy, "too many flows waiting for a decision");
            }
            pending.map.insert(id, tx);
        }
        let mut body = Vec::with_capacity(13 + text.len());
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&(text.len() as u16).to_be_bytes());
        body.extend_from_slice(text.as_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        body.push(proto.code());
        let written = match self.inner.writer.lock() {
            Ok(mut writer) => write_frame(&mut writer, DECIDE_REQ, &body),
            Err(_) => Err(io::Error::other("control writer lock poisoned")),
        };
        if let Err(e) = written {
            remove(&self.inner, id);
            let error = ControlError::Io(e);
            let reason = reason_of(&error);
            let text = error.to_string();
            self.inner.close(reason);
            return deny(reason, &text);
        }
        match rx.recv_timeout(self.inner.timeout) {
            Ok(Ok(decision)) => decision,
            Ok(Err(e)) => deny(reason_of(&e), &e.to_string()),
            Err(RecvTimeoutError::Timeout) => {
                remove(&self.inner, id);
                deny(Reason::Timeout, "control decision deadline passed")
            }
            Err(RecvTimeoutError::Disconnected) => {
                remove(&self.inner, id);
                deny(Reason::ControlLost, "control answer channel closed")
            }
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        if self.inner.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.close(Reason::ControlLost);
        }
    }
}

fn deny(reason: Reason, text: &str) -> Decision {
    Decision::Deny {
        reason,
        text: text.to_string(),
    }
}

fn reason_of(error: &ControlError) -> Reason {
    match error {
        ControlError::Timeout => Reason::Timeout,
        ControlError::Closed(reason) => *reason,
        ControlError::Io(_) => Reason::ControlLost,
        ControlError::Version(..)
        | ControlError::RunId
        | ControlError::Malformed(_)
        | ControlError::Reason => Reason::Malformed,
    }
}

/// Performs the handshake on `stream` and returns the harness's in-flight
/// window with a fresh handle (its reader thread starts after this).
fn hello(
    stream: UnixStream,
    run_id: RunId,
    timeout: Duration,
) -> Result<(u32, Control), ControlError> {
    let mut writer = stream;
    let mut body = Vec::with_capacity(13);
    body.push(MESSAGE_VERSION);
    body.extend_from_slice(&run_id.to_be_bytes());
    body.extend_from_slice(&std::process::id().to_be_bytes());
    write_frame(&mut writer, HELLO, &body).map_err(ControlError::Io)?;
    let mut ack_reader = writer.try_clone().map_err(ControlError::Io)?;
    ack_reader
        .set_read_timeout(Some(timeout))
        .map_err(ControlError::Io)?;
    let (kind, body) = read_frame(&mut ack_reader).map_err(map_read_err)?;
    if kind != HELLO_ACK {
        return Err(ControlError::Malformed("expected HELLO_ACK"));
    }
    if body.len() != 17 {
        return Err(ControlError::Malformed("wrong HELLO_ACK size"));
    }
    if body[0] != MESSAGE_VERSION {
        return Err(ControlError::Version(body[0], 0));
    }
    let protocol = u32::from_be_bytes(body[1..5].try_into().expect("4"));
    if protocol != PROTOCOL_VERSION {
        return Err(ControlError::Version(body[0], protocol));
    }
    let max_inflight = u32::from_be_bytes(body[5..9].try_into().expect("4")).clamp(1, MAX_INFLIGHT);
    let echoed = u64::from_be_bytes(body[9..17].try_into().expect("8"));
    if echoed != run_id {
        return Err(ControlError::RunId);
    }
    let inner = Arc::new(Inner {
        writer: Mutex::new(writer),
        pending: Mutex::new(Pending::default()),
        next: AtomicU64::new(1),
        handles: AtomicUsize::new(1),
        dead: AtomicBool::new(false),
        run_id,
        timeout,
        max_inflight,
    });
    Ok((
        max_inflight,
        Control {
            inner: inner.clone(),
        },
    ))
}

/// Reads responses and routes each to its waiting request.
fn read_loop(mut reader: UnixStream, inner: Arc<Inner>) {
    loop {
        let (kind, body) = match read_frame(&mut reader) {
            Ok(frame) => frame,
            Err(e) => {
                let reason = match e.kind() {
                    io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset => {
                        Reason::ControlLost
                    }
                    _ => Reason::Malformed,
                };
                inner.close(reason);
                return;
            }
        };
        if kind != DECIDE_RESP {
            inner.close(Reason::Malformed);
            return;
        }
        match decode_decision(&body) {
            Ok((id, decision)) => {
                let mut pending = match inner.pending.lock() {
                    Ok(pending) => pending,
                    Err(_) => {
                        inner.close(Reason::ControlLost);
                        return;
                    }
                };
                if let Some(sender) = pending.map.remove(&id) {
                    drop(pending);
                    let _ = sender.try_send(Ok(decision));
                } else if pending.expired.contains(&id) {
                    // The request timed out; its late answer is ignored.
                    drop(pending);
                } else {
                    drop(pending);
                    inner.close(Reason::Malformed);
                    return;
                }
            }
            Err(_) => {
                inner.close(Reason::Malformed);
                return;
            }
        }
    }
}
fn decode_decision(body: &[u8]) -> Result<(u64, Decision), ControlError> {
    if body.len() < 11 {
        return Err(ControlError::Malformed("wrong DECIDE_RESP size"));
    }
    let id = u64::from_be_bytes(body[0..8].try_into().expect("8"));
    let verdict = body[8];
    let reason_len = u16::from_be_bytes(body[9..11].try_into().expect("2")) as usize;
    if reason_len > MAX_REASON || body.len() != 11 + reason_len {
        return Err(ControlError::Malformed("DECIDE_RESP reason length"));
    }
    let reason = std::str::from_utf8(&body[11..]).map_err(|_| ControlError::Reason)?;
    match verdict {
        0 => Ok((
            id,
            Decision::Deny {
                reason: Reason::from_text(reason),
                text: reason.to_string(),
            },
        )),
        1 => Ok((id, Decision::Allow)),
        v => Err(ControlError::Malformed(if v == 2 {
            "unknown DECIDE_RESP verdict"
        } else {
            "DECIDE_RESP verdict is not 0 or 1"
        })),
    }
}

fn remove(inner: &Inner, id: u64) {
    let Ok(mut pending) = inner.pending.lock() else {
        return;
    };
    pending.map.remove(&id);
    if pending.expired.len() >= EXPIRED {
        pending.expired.pop_front();
    }
    pending.expired.push_back(id);
}

fn map_read_err(e: io::Error) -> ControlError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => ControlError::Timeout,
        io::ErrorKind::UnexpectedEof => ControlError::Malformed("short frame"),
        io::ErrorKind::InvalidData => ControlError::Malformed("frame size"),
        _ => ControlError::Io(e),
    }
}

fn write_frame(stream: &mut UnixStream, kind: u8, body: &[u8]) -> io::Result<()> {
    let len = 1 + body.len();
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "control frame too large",
        ));
    }
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&(len as u32).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(body);
    stream.write_all(&frame)
}

fn read_frame(stream: &mut UnixStream) -> io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    let len = u32::from_be_bytes(head) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame size",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    let kind = buf[0];
    buf.remove(0);
    Ok((kind, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    fn fake(
        f: impl FnOnce(&mut UnixStream) + Send + 'static,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<()>) {
        let path = std::env::temp_dir().join(format!(
            "procage-relay-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let p = path.clone();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            f(&mut stream);
            let _ = std::fs::remove_file(p);
        });
        (path, handle)
    }

    fn read(stream: &mut UnixStream) -> (u8, Vec<u8>) {
        read_frame(stream).unwrap()
    }

    fn ack(stream: &mut UnixStream, run: u64) {
        let mut body = Vec::new();
        body.push(MESSAGE_VERSION);
        body.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        body.extend_from_slice(&64u32.to_be_bytes());
        body.extend_from_slice(&run.to_be_bytes());
        write_frame(stream, HELLO_ACK, &body).unwrap();
    }

    fn respond(stream: &mut UnixStream, id: u64, verdict: u8, reason: &str) {
        let mut body = Vec::new();
        body.extend_from_slice(&id.to_be_bytes());
        body.push(verdict);
        body.extend_from_slice(&(reason.len() as u16).to_be_bytes());
        body.extend_from_slice(reason.as_bytes());
        write_frame(stream, DECIDE_RESP, &body).unwrap();
    }

    fn request_id(body: &[u8]) -> u64 {
        u64::from_be_bytes(body[0..8].try_into().unwrap())
    }

    const RUN: RunId = 0x0102_0304_0506_0708;

    #[test]
    fn hello_and_decisions_match_the_plugin_bytes() {
        let (path, handle) = fake(|s| {
            let (kind, body) = read(s);
            assert_eq!(kind, HELLO);
            assert_eq!(body[0], 1);
            assert_eq!(u64::from_be_bytes(body[1..9].try_into().unwrap()), RUN);
            assert_eq!(
                u32::from_be_bytes(body[9..13].try_into().unwrap()),
                std::process::id()
            );
            ack(s, RUN);
            let (kind, body) = read(s);
            assert_eq!(kind, DECIDE_REQ);
            let id = request_id(&body);
            let len = u16::from_be_bytes([body[8], body[9]]) as usize;
            assert_eq!(&body[10..10 + len], b"allowed.example");
            assert_eq!(
                u16::from_be_bytes([body[10 + len], body[10 + len + 1]]),
                443
            );
            assert_eq!(body[10 + len + 2], 1);
            respond(s, id, 1, "allowed");
            let (_, body) = read(s);
            respond(s, request_id(&body), 0, "permission denied");
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        assert_eq!(
            control.decide(&Resource::Domain("allowed.example".into()), 443, Proto::Tcp),
            Decision::Allow
        );
        let denied = control.decide(&Resource::Ip("192.0.2.1".parse().unwrap()), 80, Proto::Tcp);
        assert_eq!(denied.reason(), Some(Reason::Policy));
        assert_eq!(denied.text(), Some("permission denied"));
        handle.join().unwrap();
    }

    #[test]
    fn two_requests_resolve_out_of_order() {
        let (path, handle) = fake(|s| {
            let (_, _hello) = read(s);
            ack(s, RUN);
            let (_, slow) = read(s);
            let (_, fast) = read(s);
            let (slow, fast) = (request_id(&slow), request_id(&fast));
            // The fast flow's answer arrives first; the slow one is pending.
            respond(s, fast, 1, "allowed");
            std::thread::sleep(Duration::from_millis(250));
            respond(s, slow, 0, "denied later");
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let start = Instant::now();
        let slow = std::thread::spawn({
            let slow = control.clone();
            move || {
                let at = Instant::now();
                let d = slow.decide(&Resource::Domain("slow.example".into()), 443, Proto::Tcp);
                (at.elapsed(), d)
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        let fast = std::thread::spawn({
            let fast = control.clone();
            move || {
                let at = Instant::now();
                let d = fast.decide(&Resource::Domain("fast.example".into()), 443, Proto::Tcp);
                (at.elapsed(), d)
            }
        });
        let (fast_elapsed, fast_decision) = fast.join().unwrap();
        let (slow_elapsed, slow_decision) = slow.join().unwrap();
        assert_eq!(fast_decision, Decision::Allow);
        assert!(matches!(slow_decision, Decision::Deny { .. }));
        assert!(
            fast_elapsed + Duration::from_millis(100) < slow_elapsed,
            "a pending prompt must not serialize the fast flow: {fast_elapsed:?} vs {slow_elapsed:?}"
        );
        assert!(start.elapsed() >= Duration::from_millis(250));
        handle.join().unwrap();
    }

    #[test]
    fn wrong_run_id_fails_closed() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN + 1);
        });
        let err = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap_err();
        assert!(matches!(err, ControlError::RunId), "{err}");
        handle.join().unwrap();
    }

    #[test]
    fn unknown_id_denies_and_kills_channel() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let _ = read(s);
            respond(s, 999, 1, "allowed");
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let first = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(first.reason(), Some(Reason::Malformed));
        assert!(control.is_dead());
        let second = control.decide(&Resource::Domain("b.example".into()), 443, Proto::Tcp);
        assert_eq!(second.reason(), Some(Reason::ControlLost));
        handle.join().unwrap();
    }

    #[test]
    fn oversized_frame_is_malformed() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let _ = read(s);
            s.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes()).unwrap();
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let decision = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(decision.reason(), Some(Reason::Malformed));
        handle.join().unwrap();
    }

    #[test]
    fn eof_denies_with_control_lost() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let _ = read(s);
            let _ = s.shutdown(std::net::Shutdown::Both);
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let decision = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(decision.reason(), Some(Reason::ControlLost));
        handle.join().unwrap();
    }

    #[test]
    fn a_timed_out_prompt_does_not_block_the_next_flow() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let (_, first) = read(s);
            let (_, second) = read(s);
            respond(s, request_id(&second), 1, "allowed");
            std::thread::sleep(Duration::from_millis(300));
            respond(s, request_id(&first), 1, "late");
        });
        let control = Control::connect(&path, RUN, Duration::from_millis(100)).unwrap();
        let first = control.decide(&Resource::Domain("slow.example".into()), 443, Proto::Tcp);
        assert_eq!(first.reason(), Some(Reason::Timeout));
        let second = control.decide(&Resource::Domain("fast.example".into()), 443, Proto::Tcp);
        assert_eq!(second, Decision::Allow);
        handle.join().unwrap();
    }

    #[test]
    fn reason_is_classified_and_bounded() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let (_, body) = read(s);
            respond(s, request_id(&body), 0, "decision timeout");
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let decision = control.decide(&Resource::Domain("a.example".into()), 53, Proto::Udp);
        assert_eq!(decision.reason(), Some(Reason::Timeout));
        handle.join().unwrap();
    }

    #[test]
    fn close_refuses_later_flows() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
        });
        let control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        control.close();
        let decision = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(decision.reason(), Some(Reason::ControlLost));
        handle.join().unwrap();
    }
}
