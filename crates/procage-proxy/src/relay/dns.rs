//! A minimal DNS wire parser for the relay's local answers.
//!
//! Only one question is accepted, which is what every resolver stub sends.
//! Compression pointers in a question are refused (a query has none), names
//! are bounded to 255 bytes and labels to 63, and the response is built from
//! the query's own question bytes: no name is ever re-encoded.
//!
//! One EDNS0 `OPT` record (type 41) in the additional section is accepted and
//! echoed, bounded, in a `REFUSED`/`SERVFAIL` answer; a second OPT, another
//! additional type or a malformed OPT is refused.
//!
//! A denied QNAME gets `REFUSED` (RCODE 5), visibly, instead of a timeout.
//! A parse failure or a second question is not a policy event: the caller
//! drops the datagram (UDP) or closes (TCP), so the client can retry another
//! server.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The header length of a DNS message.
pub const HEADER: usize = 12;
/// The largest DNS message the relay accepts over UDP.
pub const MAX_UDP: usize = 1232;
/// The largest DNS message over TCP (the two-byte length prefix allows 65535;
/// the relay bounds what it buffers).
pub const MAX_TCP: usize = 4096;
/// The most answer records the relay's mapping parser examines.
pub const MAX_ANSWERS: usize = 64;
/// The most CNAME links followed from one QNAME.
pub const MAX_CNAME: usize = 8;
/// The largest OPT record echoed in a local answer.
pub const MAX_OPT: usize = 512;

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
    /// The raw EDNS0 OPT record, when the query carried one.
    pub opt: Option<Vec<u8>>,
}

/// One address from a DNS answer, with the TTL that bounds the mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// The address record's value.
    pub ip: IpAddr,
    /// The smallest TTL along the QNAME→CNAME→address chain.
    pub ttl: u32,
}

/// Why bytes are not a query the relay can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// Fewer than a header.
    Short,
    /// The header's counts are not one question and no records (or one OPT).
    Counts,
    /// A name is malformed or uses compression.
    Name,
    /// A label or the whole name is too long.
    Long,
    /// The question is truncated.
    Truncated,
    /// More records than a bounded parser visits.
    TooMany,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DnsError::Short => "short DNS message",
            DnsError::Counts => "not one DNS question",
            DnsError::Name => "malformed or compressed DNS question name",
            DnsError::Long => "DNS name too long",
            DnsError::Truncated => "truncated DNS question",
            DnsError::TooMany => "too many DNS answer records",
        })
    }
}

impl std::error::Error for DnsError {}

/// Parses a DNS query. Only requests (`QR=0`) with exactly one question and
/// no answer or authority records are accepted; the additional section may
/// hold one OPT record.
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
    if qd != 1 || an != 0 || ns != 0 || ar > 1 {
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
    at += 4;
    let mut opt = None;
    if ar == 1 {
        let start = at;
        let owner = read_name(message, &mut at)?;
        if !owner.is_empty() {
            return Err(DnsError::Counts);
        }
        if at + 10 > message.len() {
            return Err(DnsError::Truncated);
        }
        let kind = u16::from_be_bytes([message[at], message[at + 1]]);
        let rdlen = u16::from_be_bytes([message[at + 8], message[at + 9]]) as usize;
        at += 10;
        if kind != 41 {
            return Err(DnsError::Counts);
        }
        if at + rdlen > message.len() {
            return Err(DnsError::Truncated);
        }
        at += rdlen;
        let record = message[start..at].to_vec();
        if record.len() > MAX_OPT {
            return Err(DnsError::Long);
        }
        opt = Some(record);
    }
    if at != message.len() {
        return Err(DnsError::Truncated);
    }
    Ok(Query {
        id,
        flags,
        name: labels.join("."),
        qtype,
        qclass,
        question: wire,
        opt,
    })
}

/// Parses the address records of a `NOERROR` response whose question is
/// `qname`, following a bounded CNAME chain. An error or no addresses is
/// empty: a mapping is only ever a shortcut, never an authorization on its
/// own.
pub fn parse_answers(message: &[u8], qname: &str) -> Result<Vec<Answer>, DnsError> {
    if message.len() < HEADER {
        return Err(DnsError::Short);
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 || flags & 0x0f != 0 {
        return Ok(Vec::new());
    }
    let qd = u16::from_be_bytes([message[4], message[5]]);
    let an = u16::from_be_bytes([message[6], message[7]]) as usize;
    if qd != 1 || an > MAX_ANSWERS {
        return Err(if an > MAX_ANSWERS {
            DnsError::TooMany
        } else {
            DnsError::Counts
        });
    }
    let mut at = HEADER;
    let question = read_name(message, &mut at)?;
    if !question.eq_ignore_ascii_case(qname.trim_end_matches('.')) {
        return Err(DnsError::Counts);
    }
    if at + 4 > message.len() {
        return Err(DnsError::Truncated);
    }
    at += 4;
    let mut cnames: Vec<(String, String, u32)> = Vec::new();
    let mut addresses: Vec<(String, Answer)> = Vec::new();
    for _ in 0..an {
        let owner = read_name(message, &mut at)?;
        if at + 10 > message.len() {
            return Err(DnsError::Truncated);
        }
        let kind = u16::from_be_bytes([message[at], message[at + 1]]);
        let ttl = u32::from_be_bytes([
            message[at + 4],
            message[at + 5],
            message[at + 6],
            message[at + 7],
        ]);
        let rdlen = u16::from_be_bytes([message[at + 8], message[at + 9]]) as usize;
        at += 10;
        if at + rdlen > message.len() {
            return Err(DnsError::Truncated);
        }
        let end = at + rdlen;
        match (kind, rdlen) {
            (5, _) => {
                let mut name_at = at;
                let target = read_name(message, &mut name_at)?;
                if name_at > end {
                    return Err(DnsError::Truncated);
                }
                cnames.push((owner, target, ttl));
            }
            (1, 4) => addresses.push((
                owner,
                Answer {
                    ip: IpAddr::V4(Ipv4Addr::new(
                        message[at],
                        message[at + 1],
                        message[at + 2],
                        message[at + 3],
                    )),
                    ttl,
                },
            )),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&message[at..at + 16]);
                addresses.push((
                    owner,
                    Answer {
                        ip: IpAddr::V6(Ipv6Addr::from(octets)),
                        ttl,
                    },
                ));
            }
            _ => {}
        }
        at = end;
    }
    let mut current = qname.trim_end_matches('.').to_ascii_lowercase();
    let mut ttl = u32::MAX;
    for _ in 0..MAX_CNAME {
        let found: Vec<&Answer> = addresses
            .iter()
            .filter(|(owner, _)| owner.eq_ignore_ascii_case(&current))
            .map(|(_, answer)| answer)
            .collect();
        if !found.is_empty() {
            return Ok(found
                .into_iter()
                .map(|answer| Answer {
                    ip: answer.ip,
                    ttl: ttl.min(answer.ttl),
                })
                .collect());
        }
        let Some((_, next, link_ttl)) = cnames
            .iter()
            .find(|(owner, _, _)| owner.eq_ignore_ascii_case(&current))
        else {
            break;
        };
        ttl = ttl.min(*link_ttl);
        current = next.clone();
    }
    Ok(Vec::new())
}

/// Reads a possibly-compressed name at `at`, advancing `at` past its encoding
/// in the original position. Pointers must point backwards and are bounded.
fn read_name(message: &[u8], at: &mut usize) -> Result<String, DnsError> {
    fn walk(
        message: &[u8],
        at: &mut usize,
        jumps: &mut usize,
        labels: &mut Vec<String>,
        length: &mut usize,
    ) -> Result<(), DnsError> {
        loop {
            let byte = *message.get(*at).ok_or(DnsError::Truncated)?;
            match byte & 0xc0 {
                0x00 => {
                    *at += 1;
                    if byte == 0 {
                        return Ok(());
                    }
                    let len = byte as usize;
                    if len > 63 || *at + len > message.len() {
                        return if len > 63 {
                            Err(DnsError::Long)
                        } else {
                            Err(DnsError::Truncated)
                        };
                    }
                    let label = &message[*at..*at + len];
                    if !label.iter().all(|b| b.is_ascii_graphic() && *b != b'.') {
                        return Err(DnsError::Name);
                    }
                    labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                    *length += len + 1;
                    if *length > 255 {
                        return Err(DnsError::Long);
                    }
                    *at += len;
                }
                0xc0 => {
                    if *at + 2 > message.len() {
                        return Err(DnsError::Truncated);
                    }
                    let pointer = (((byte & 0x3f) as usize) << 8) | message[*at + 1] as usize;
                    *at += 2;
                    if pointer >= message.len() || *jumps >= 16 {
                        return Err(DnsError::Name);
                    }
                    *jumps += 1;
                    let mut pointed = pointer;
                    walk(message, &mut pointed, jumps, labels, length)?;
                    return Ok(());
                }
                _ => return Err(DnsError::Name),
            }
        }
    }
    let mut jumps = 0usize;
    let mut labels = Vec::new();
    let mut length = 0usize;
    walk(message, at, &mut jumps, &mut labels, &mut length)?;
    Ok(labels.join("."))
}

/// A response with `rcode` (5 REFUSED, 2 SERVFAIL, 0 NOERROR) and no
/// records. The question is copied verbatim, the query id is kept, and a
/// bounded EDNS OPT is echoed so an EDNS client sees a valid answer.
pub fn answer(query: &Query, rcode: u8) -> Vec<u8> {
    let opt = query.opt.as_ref().filter(|record| record.len() <= MAX_OPT);
    let mut out = Vec::with_capacity(HEADER + query.question.len() + opt.map_or(0, Vec::len));
    out.extend_from_slice(&query.id.to_be_bytes());
    // QR=1, OPCODE copied, RD copied, RA=0, RCODE.
    let flags = 0x8000 | (query.flags & 0x7800) | (query.flags & 0x0100) | u16::from(rcode & 0x0f);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&u16::from(opt.is_some()).to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&query.question);
    if let Some(opt) = opt {
        out.extend_from_slice(opt);
    }
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

    fn edns_query(name: &str) -> Vec<u8> {
        let mut out = query(name);
        out[10..12].copy_from_slice(&1u16.to_be_bytes()); // ARCOUNT
        out.push(0); // root name
        out.extend_from_slice(&41u16.to_be_bytes()); // OPT
        out.extend_from_slice(&1232u16.to_be_bytes()); // UDP size
        out.extend_from_slice(&0u32.to_be_bytes()); // ext rcode/flags
        out.extend_from_slice(&0u16.to_be_bytes()); // no options
        out
    }

    fn name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn response(qname: &str, answers: &[(Option<&str>, u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // NS
        out.extend_from_slice(&0u16.to_be_bytes()); // AR
        out.extend_from_slice(&name(qname));
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        for (owner, kind, ttl, rdata) in answers {
            match owner {
                None => out.extend_from_slice(&[0xc0, 0x0c]), // the question
                Some(owner) => out.extend_from_slice(&name(owner)),
            }
            out.extend_from_slice(&kind.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(rdata);
        }
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

    #[test]
    fn edns_opt_is_accepted_and_echoed() {
        let raw = edns_query("allowed.example");
        let q = parse_query(&raw).unwrap();
        assert_eq!(q.name, "allowed.example");
        assert!(q.opt.is_some());
        let reply = refused(&q);
        assert_eq!(reply[3] & 0x0f, 5);
        assert_eq!(u16::from_be_bytes([reply[10], reply[11]]), 1);
        assert_eq!(
            &reply[reply.len() - q.opt.as_ref().unwrap().len()..],
            q.opt.as_ref().unwrap()
        );
    }

    #[test]
    fn malformed_or_extra_additional_records_are_refused() {
        let mut two_opt = edns_query("a.example");
        two_opt[10..12].copy_from_slice(&2u16.to_be_bytes());
        two_opt.extend_from_slice(&[0, 0, 41, 0, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_query(&two_opt), Err(DnsError::Counts));
        let mut other = edns_query("a.example");
        let opt = other.len() - 11;
        other[opt + 1] = 0;
        other[opt + 2] = 1; // type A, not OPT
        assert_eq!(parse_query(&other), Err(DnsError::Counts));
        let mut short = edns_query("a.example");
        short.pop();
        short.pop();
        assert!(parse_query(&short).is_err());
    }

    #[test]
    fn answers_follow_cname_and_keep_the_smallest_ttl() {
        let message = response(
            "www.example",
            &[
                (None, 5, 30, name("edge.example")),
                (Some("edge.example"), 1, 10, vec![192, 0, 2, 7]),
            ],
        );
        let answers = parse_answers(&message, "www.example").unwrap();
        assert_eq!(
            answers,
            vec![Answer {
                ip: "192.0.2.7".parse().unwrap(),
                ttl: 10
            }]
        );
        let mut six = vec![0u8; 16];
        six[15] = 1;
        let aaaa = response("www.example", &[(None, 28, 60, six)]);
        assert_eq!(
            parse_answers(&aaaa, "www.example").unwrap(),
            vec![Answer {
                ip: "::1".parse().unwrap(),
                ttl: 60
            }]
        );
    }

    #[test]
    fn answers_reject_a_mismatched_question_and_rcode() {
        let message = response("other.example", &[(None, 1, 10, vec![192, 0, 2, 7])]);
        assert_eq!(
            parse_answers(&message, "www.example"),
            Err(DnsError::Counts)
        );
        let mut servfail = response("www.example", &[(None, 1, 10, vec![192, 0, 2, 7])]);
        servfail[3] = 0x82;
        assert_eq!(parse_answers(&servfail, "www.example").unwrap(), Vec::new());
    }
}
