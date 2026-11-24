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

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
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

/// A control-channel failure. Any of these permanently disables the channel:
/// a late or partial frame could otherwise be read as the answer to a later
/// request.
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
    /// A response named another request id.
    Id {
        /// The id the request used.
        want: u64,
        /// The id the response named.
        got: u64,
    },
    /// The response's verdict byte is not 0 or 1.
    Verdict(u8),
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
            ControlError::Id { want, got } => {
                write!(f, "control response id {got} is not {want}")
            }
            ControlError::Verdict(v) => write!(f, "control verdict {v} is not 0 or 1"),
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

/// One run's control connection.
#[derive(Debug)]
pub struct Control {
    stream: UnixStream,
    run_id: RunId,
    next: u64,
    dead: Option<Reason>,
    /// The harness's in-flight window; procage serializes requests, so it
    /// only informs the bound.
    pub max_inflight: u32,
}

impl Control {
    /// Connects to `path`, sends `HELLO` with `run_id` and this process's
    /// pid, and validates `HELLO_ACK`. A failure leaves no usable channel.
    pub fn connect(path: &Path, run_id: RunId, timeout: Duration) -> Result<Control, ControlError> {
        let stream = UnixStream::connect(path).map_err(ControlError::Io)?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(ControlError::Io)?;
        let mut control = Control {
            stream,
            run_id,
            next: 1,
            dead: None,
            max_inflight: 1,
        };
        control.hello()?;
        Ok(control)
    }

    /// The run id this channel carries.
    pub fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Whether a previous failure has closed the channel.
    pub fn is_dead(&self) -> bool {
        self.dead.is_some()
    }

    /// Closes the channel: the harness sees the run end. Later decisions are
    /// refused as if the connection had failed.
    pub fn close(&mut self) {
        self.dead = Some(Reason::ControlLost);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Asks whether `resource`:`port` over `proto` may be reached. Any
    /// failure denies with the reason the relay will report, and closes the
    /// channel for good.
    pub fn decide(&mut self, resource: &Resource, port: u16, proto: Proto) -> Decision {
        if let Some(reason) = self.dead {
            return Decision::Deny {
                reason,
                text: "control channel already closed".into(),
            };
        }
        match self.try_decide(resource, port, proto) {
            Ok(decision) => decision,
            Err(e) => {
                let reason = match e {
                    ControlError::Timeout => Reason::Timeout,
                    ControlError::Version(..)
                    | ControlError::RunId
                    | ControlError::Malformed(_)
                    | ControlError::Id { .. }
                    | ControlError::Verdict(_)
                    | ControlError::Reason => Reason::Malformed,
                    ControlError::Io(_) => Reason::ControlLost,
                };
                self.dead = Some(reason);
                let _ = self.stream.shutdown(std::net::Shutdown::Both);
                Decision::Deny {
                    reason,
                    text: e.to_string(),
                }
            }
        }
    }

    fn hello(&mut self) -> Result<(), ControlError> {
        let mut body = Vec::with_capacity(13);
        body.push(MESSAGE_VERSION);
        body.extend_from_slice(&self.run_id.to_be_bytes());
        body.extend_from_slice(&std::process::id().to_be_bytes());
        debug_assert_eq!(body.len(), 13);
        write_frame(&mut self.stream, HELLO, &body).map_err(ControlError::Io)?;
        let (kind, body) = read_frame(&mut self.stream).map_err(map_read_err)?;
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
        self.max_inflight = u32::from_be_bytes(body[5..9].try_into().expect("4"));
        let echoed = u64::from_be_bytes(body[9..17].try_into().expect("8"));
        if echoed != self.run_id {
            return Err(ControlError::RunId);
        }
        Ok(())
    }

    fn try_decide(
        &mut self,
        resource: &Resource,
        port: u16,
        proto: Proto,
    ) -> Result<Decision, ControlError> {
        let text = resource.as_str();
        if text.is_empty() || text.len() > MAX_RESOURCE {
            return Err(ControlError::Malformed("resource length"));
        }
        if text.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(ControlError::Malformed(
                "resource has whitespace or a control byte",
            ));
        }
        if port == 0 {
            return Err(ControlError::Malformed("port is zero"));
        }
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let mut body = Vec::with_capacity(13 + text.len());
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&(text.len() as u16).to_be_bytes());
        body.extend_from_slice(text.as_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        body.push(proto.code());
        write_frame(&mut self.stream, DECIDE_REQ, &body).map_err(ControlError::Io)?;
        let (kind, body) = read_frame(&mut self.stream).map_err(map_read_err)?;
        if kind != DECIDE_RESP {
            return Err(ControlError::Malformed("expected DECIDE_RESP"));
        }
        if body.len() < 11 {
            return Err(ControlError::Malformed("wrong DECIDE_RESP size"));
        }
        let got = u64::from_be_bytes(body[0..8].try_into().expect("8"));
        if got != id {
            return Err(ControlError::Id { want: id, got });
        }
        let verdict = body[8];
        let reason_len = u16::from_be_bytes(body[9..11].try_into().expect("2")) as usize;
        if reason_len > MAX_REASON || body.len() != 11 + reason_len {
            return Err(ControlError::Malformed("DECIDE_RESP reason length"));
        }
        let reason = std::str::from_utf8(&body[11..]).map_err(|_| ControlError::Reason)?;
        match verdict {
            0 => Ok(Decision::Deny {
                reason: Reason::from_text(reason),
                text: reason.to_string(),
            }),
            1 => Ok(Decision::Allow),
            v => Err(ControlError::Verdict(v)),
        }
    }
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

    const RUN: RunId = 0x0102_0304_0506_0708;

    #[test]
    fn hello_and_decisions_match_the_plugin_bytes() {
        let (path, handle) = fake(|s| {
            let (kind, body) = read(s);
            assert_eq!(kind, HELLO);
            // type | version | run id | pid
            assert_eq!(body[0], 1);
            assert_eq!(u64::from_be_bytes(body[1..9].try_into().unwrap()), RUN);
            assert_eq!(
                u32::from_be_bytes(body[9..13].try_into().unwrap()),
                std::process::id()
            );
            ack(s, RUN);
            let (kind, body) = read(s);
            assert_eq!(kind, DECIDE_REQ);
            let id = u64::from_be_bytes(body[0..8].try_into().unwrap());
            let len = u16::from_be_bytes([body[8], body[9]]) as usize;
            assert_eq!(&body[10..10 + len], b"allowed.example");
            assert_eq!(
                u16::from_be_bytes([body[10 + len], body[10 + len + 1]]),
                443
            );
            assert_eq!(body[10 + len + 2], 1);
            respond(s, id, 1, "allowed");
            let (kind, body) = read(s);
            assert_eq!(kind, DECIDE_REQ);
            let id = u64::from_be_bytes(body[0..8].try_into().unwrap());
            respond(s, id, 0, "permission denied");
        });
        let mut control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
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
    fn wrong_id_denies_and_kills_channel() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let _ = read(s);
            respond(s, 999, 1, "allowed");
        });
        let mut control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let first = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(first.reason(), Some(Reason::Malformed));
        assert!(control.is_dead());
        let second = control.decide(&Resource::Domain("b.example".into()), 443, Proto::Tcp);
        assert_eq!(second.reason(), Some(Reason::Malformed));
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
        let mut control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let decision = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(decision.reason(), Some(Reason::Malformed));
        handle.join().unwrap();
    }

    #[test]
    fn eof_denies() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let _ = read(s);
            let _ = s.shutdown(std::net::Shutdown::Both);
        });
        let mut control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let decision = control.decide(&Resource::Domain("a.example".into()), 443, Proto::Tcp);
        assert_eq!(decision.reason(), Some(Reason::Malformed));
        handle.join().unwrap();
    }

    #[test]
    fn reason_is_classified_and_bounded() {
        let (path, handle) = fake(|s| {
            let _ = read(s);
            ack(s, RUN);
            let _ = read(s);
            let id = 1;
            respond(s, id, 0, "decision timeout");
        });
        let mut control = Control::connect(&path, RUN, Duration::from_secs(2)).unwrap();
        let decision = control.decide(&Resource::Domain("a.example".into()), 53, Proto::Udp);
        assert_eq!(decision.reason(), Some(Reason::Timeout));
        handle.join().unwrap();
    }
}
