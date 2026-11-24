//! A minimal DNS wire parser for the relay's local answers.
//!
//! Only one question is accepted, which is what every resolver stub sends.
//! Compression pointers in a question are refused (a query has none), names
//! are bounded to 255 bytes and labels to 63, and the response is built from
//! the query's own question bytes: no name is ever re-encoded.
//!
//! A denied QNAME gets `REFUSED` (RCODE 5), visibly, instead of a timeout.
//! A parse failure or a second question is not a policy event: the caller
//! drops the datagram (UDP) or closes (TCP), so the client can retry another
//! server.

/// The header length of a DNS message.
pub const HEADER: usize = 12;
/// The largest DNS message the relay accepts over UDP.
pub const MAX_UDP: usize = 1232;
/// The largest DNS message over TCP (the two-byte length prefix allows 65535;
/// the relay bounds what it buffers).
pub const MAX_TCP: usize = 4096;

/// One parsed query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The query id.
    pub id: u16,
    /// The flags word.
    pub flags: u16,
    /// The canonical lower-case QNAME, without a trailing dot.
    pub name: String,
    /// The query type.
    pub qtype: u16,
    /// The query class.
    pub qclass: u16,
    /// The question section, including the trailing zero label, as it
    /// appeared.
    pub question: Vec<u8>,
}

/// Why bytes are not a query the relay can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// Fewer than a header.
    Short,
    /// The header's counts are not one question and no records.
    Counts,
    /// A name is malformed or uses compression.
    Name,
    /// A label or the whole name is too long.
    Long,
    /// The question is truncated.
    Truncated,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DnsError::Short => "short DNS message",
            DnsError::Counts => "not one DNS question",
            DnsError::Name => "malformed or compressed DNS question name",
            DnsError::Long => "DNS name too long",
            DnsError::Truncated => "truncated DNS question",
        })
    }
}

impl std::error::Error for DnsError {}

/// Parses a DNS query. Only requests (`QR=0`) with exactly one question and
/// no answer, authority or additional records are accepted.
pub fn parse_query(message: &[u8]) -> Result<Query, DnsError> {
    if message.len() < HEADER {
        return Err(DnsError::Short);
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 != 0 {
        return Err(DnsError::Counts);
    }
    let qd = u16::from_be_bytes([message[4], message[5]]);
    let an = u16::from_be_bytes([message[6], message[7]]);
    let ns = u16::from_be_bytes([message[8], message[9]]);
    let ar = u16::from_be_bytes([message[10], message[11]]);
    if qd != 1 || an != 0 || ns != 0 || ar != 0 {
        return Err(DnsError::Counts);
    }
    let mut at = HEADER;
    let mut labels = Vec::new();
    let mut wire = Vec::new();
    loop {
        let len = *message.get(at).ok_or(DnsError::Truncated)? as usize;
        wire.push(len as u8);
        at += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return Err(DnsError::Name);
        }
        if len > 63 || at + len > message.len() {
            return if len > 63 {
                Err(DnsError::Long)
            } else {
                Err(DnsError::Truncated)
            };
        }
        let label = &message[at..at + len];
        if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
            return Err(DnsError::Name);
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        wire.extend_from_slice(label);
        at += len;
        if wire.len() > 255 {
            return Err(DnsError::Long);
        }
    }
    if at + 4 > message.len() {
        return Err(DnsError::Truncated);
    }
    let qtype = u16::from_be_bytes([message[at], message[at + 1]]);
    let qclass = u16::from_be_bytes([message[at + 2], message[at + 3]]);
    wire.extend_from_slice(&message[at..at + 4]);
    Ok(Query {
        id,
        flags,
        name: labels.join("."),
        qtype,
        qclass,
        question: wire,
    })
}

/// A response with `rcode` (5 REFUSED, 2 SERVFAIL, 0 NOERROR) and no
/// records. The question is copied verbatim and the query id is kept.
pub fn answer(query: &Query, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + query.question.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, OPCODE copied, RD copied, RA=0, RCODE.
    let flags = 0x8000 | (query.flags & 0x7800) | (query.flags & 0x0100) | u16::from(rcode & 0x0f);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.question);
    out
}

/// `REFUSED`: the QNAME is not allowed.
pub fn refused(query: &Query) -> Vec<u8> {
    answer(query, 5)
}

/// `SERVFAIL`: allowed, but no upstream could be reached.
pub fn servfail(query: &Query) -> Vec<u8> {
    answer(query, 2)
}

/// A TCP-framed DNS message: two-byte length prefix and the message.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + message.len());
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// Parses one length-prefixed TCP DNS message, returning it and the bytes
/// consumed.
pub fn unframe(data: &[u8]) -> Option<(&[u8], usize)> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if len == 0 || len > MAX_TCP || data.len() < 2 + len {
        return None;
    }
    Some((&data[2..2 + len], 2 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&1u16.to_be_bytes()); // A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        out
    }

    #[test]
    fn parses_one_question() {
        let q = parse_query(&query("Evil.C2.Example")).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "evil.c2.example");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);
    }

    #[test]
    fn refuses_compression_and_two_questions() {
        let mut q = query("a.example");
        q[HEADER] = 0xc0;
        assert_eq!(parse_query(&q), Err(DnsError::Name));
        let mut two = query("a.example");
        two[5] = 2;
        assert_eq!(parse_query(&two), Err(DnsError::Counts));
    }

    #[test]
    fn refused_keeps_id_and_question() {
        let raw = query("denied.example");
        let q = parse_query(&raw).unwrap();
        let reply = refused(&q);
        assert_eq!(&reply[0..2], &[0x12, 0x34]);
        assert_eq!(reply[3] & 0x0f, 5);
        assert_eq!(&reply[12..], &raw[12..]);
        assert_eq!(u16::from_be_bytes([reply[4], reply[5]]), 1);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0);
    }

    #[test]
    fn tcp_framing_round_trips() {
        let raw = query("allowed.example");
        let framed = frame(&raw);
        let (message, used) = unframe(&framed).unwrap();
        assert_eq!(message, raw.as_slice());
        assert_eq!(used, framed.len());
        assert_eq!(unframe(&framed[..framed.len() - 1]), None);
    }
}
