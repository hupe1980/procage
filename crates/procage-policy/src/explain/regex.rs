//! The SBPL regular expressions procage emits, matched over bytes.
//!
//! The subset is what the lowering writes: `^`, `$`, literals and `\`
//! escapes, `.`, bracket classes with ranges and negation, groups with `|`,
//! and `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}`. Anything else is a parse error,
//! which the evaluator answers as not modelled. Matching simulates the
//! compiled automaton (a Pike VM), so it takes time linear in the path
//! length times the pattern size.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

/// The largest count in `{m,n}`; larger counts are refused.
const MAX_COUNT: u32 = 64;

/// A compiled pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Regex {
    program: Vec<Inst>,
    /// Starts with `^`: only an attempt at the start can match.
    anchored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Empty,
    Class(Box<[bool; 256]>),
    Start,
    End,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(Box<Node>, u32, Option<u32>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Inst {
    Class(Box<[bool; 256]>),
    Split(usize, usize),
    Jump(usize),
    Start,
    End,
    Match,
}

struct Parser<'a> {
    src: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.at).copied()
    }

    fn alt(&mut self) -> Option<Node> {
        let mut branches = vec![self.concat()?];
        while self.peek() == Some(b'|') {
            self.at += 1;
            branches.push(self.concat()?);
        }
        Some(if branches.len() == 1 {
            branches.pop()?
        } else {
            Node::Alt(branches)
        })
    }

    fn concat(&mut self) -> Option<Node> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            let atom = self.atom()?;
            items.push(self.repeat(atom)?);
        }
        Some(match items.len() {
            0 => Node::Empty,
            1 => items.pop()?,
            _ => Node::Concat(items),
        })
    }

    fn atom(&mut self) -> Option<Node> {
        let c = self.peek()?;
        self.at += 1;
        Some(match c {
            b'^' => Node::Start,
            b'$' => Node::End,
            b'.' => Node::Class(Box::new([true; 256])),
            b'(' => {
                let inner = self.alt()?;
                if self.peek() != Some(b')') {
                    return None;
                }
                self.at += 1;
                inner
            }
            b'[' => self.class()?,
            b'\\' => {
                let e = self.peek()?;
                self.at += 1;
                if e.is_ascii_alphanumeric() {
                    // `\d`, `\w` and the like are not in the subset.
                    return None;
                }
                literal(e)
            }
            b'*' | b'+' | b'?' | b'{' | b')' | b']' | b'}' => return None,
            _ => literal(c),
        })
    }

    fn class(&mut self) -> Option<Node> {
        let mut set = [false; 256];
        let negate = self.peek() == Some(b'^');
        if negate {
            self.at += 1;
        }
        let mut first = true;
        loop {
            let c = self.peek()?;
            self.at += 1;
            if c == b']' && !first {
                break;
            }
            first = false;
            let lo = if c == b'\\' {
                let e = self.peek()?;
                self.at += 1;
                e
            } else if c == b'[' {
                // `[:alpha:]` and the like are not in the subset.
                return None;
            } else {
                c
            };
            if self.peek() == Some(b'-') && self.src.get(self.at + 1).is_some_and(|&n| n != b']') {
                self.at += 1;
                let hi = self.peek()?;
                self.at += 1;
                if hi < lo {
                    return None;
                }
                for b in lo..=hi {
                    set[b as usize] = true;
                }
            } else {
                set[lo as usize] = true;
            }
        }
        if negate {
            for b in &mut set {
                *b = !*b;
            }
        }
        Some(Node::Class(Box::new(set)))
    }

    fn repeat(&mut self, atom: Node) -> Option<Node> {
        let mut node = atom;
        loop {
            let (min, max) = match self.peek() {
                Some(b'*') => (0, None),
                Some(b'+') => (1, None),
                Some(b'?') => (0, Some(1)),
                Some(b'{') => {
                    self.at += 1;
                    let min = self.number()?;
                    let max = if self.peek() == Some(b',') {
                        self.at += 1;
                        if self.peek() == Some(b'}') {
                            None
                        } else {
                            Some(self.number()?)
                        }
                    } else {
                        Some(min)
                    };
                    if self.peek() != Some(b'}') || max.is_some_and(|m| m < min) {
                        return None;
                    }
                    (min, max)
                }
                _ => return Some(node),
            };
            self.at += 1;
            if matches!(node, Node::Start | Node::End | Node::Repeat(..)) {
                return None;
            }
            node = Node::Repeat(Box::new(node), min, max);
        }
    }

    fn number(&mut self) -> Option<u32> {
        let start = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.at += 1;
        }
        let n: u32 = core::str::from_utf8(&self.src[start..self.at])
            .ok()?
            .parse()
            .ok()?;
        (n <= MAX_COUNT).then_some(n)
    }
}

fn literal(c: u8) -> Node {
    let mut set = [false; 256];
    set[c as usize] = true;
    Node::Class(Box::new(set))
}

fn compile(node: &Node, out: &mut Vec<Inst>) {
    match node {
        Node::Empty => {}
        Node::Class(set) => out.push(Inst::Class(set.clone())),
        Node::Start => out.push(Inst::Start),
        Node::End => out.push(Inst::End),
        Node::Concat(items) => items.iter().for_each(|n| compile(n, out)),
        Node::Alt(branches) => {
            let mut jumps = Vec::new();
            for (i, branch) in branches.iter().enumerate() {
                if i + 1 < branches.len() {
                    let split = out.len();
                    out.push(Inst::Split(split + 1, 0));
                    compile(branch, out);
                    jumps.push(out.len());
                    out.push(Inst::Jump(0));
                    let next = out.len();
                    out[split] = Inst::Split(split + 1, next);
                } else {
                    compile(branch, out);
                }
            }
            let end = out.len();
            for j in jumps {
                out[j] = Inst::Jump(end);
            }
        }
        Node::Repeat(inner, min, max) => {
            for _ in 0..*min {
                compile(inner, out);
            }
            match max {
                None => {
                    let split = out.len();
                    out.push(Inst::Split(split + 1, 0));
                    compile(inner, out);
                    out.push(Inst::Jump(split));
                    let end = out.len();
                    out[split] = Inst::Split(split + 1, end);
                }
                Some(max) => {
                    let mut splits = Vec::new();
                    for _ in *min..*max {
                        splits.push(out.len());
                        out.push(Inst::Split(0, 0));
                        compile(inner, out);
                    }
                    let end = out.len();
                    for s in splits {
                        out[s] = Inst::Split(s + 1, end);
                    }
                }
            }
        }
    }
}

impl Regex {
    /// Parses `source`; `None` when it is outside the subset.
    pub(crate) fn new(source: &str) -> Option<Regex> {
        let mut parser = Parser {
            src: source.as_bytes(),
            at: 0,
        };
        let node = parser.alt()?;
        if parser.at != parser.src.len() {
            return None;
        }
        let mut program = Vec::new();
        compile(&node, &mut program);
        program.push(Inst::Match);
        let anchored = program.first() == Some(&Inst::Start);
        Some(Regex { program, anchored })
    }

    /// Whether the pattern matches anywhere in `text` (SBPL regexes are not
    /// anchored unless they say so).
    pub(crate) fn is_match(&self, text: &[u8]) -> bool {
        let n = self.program.len();
        let mut current: Vec<usize> = Vec::with_capacity(n);
        let mut next: Vec<usize> = Vec::with_capacity(n);
        let mut seen = vec![usize::MAX; n];
        let mut stack = Vec::with_capacity(n);
        for at in 0..=text.len() {
            // A new attempt starts at every position, unless anchored.
            if (at == 0 || !self.anchored)
                && self.add(&mut current, &mut seen, &mut stack, 0, at, text.len())
            {
                return true;
            }
            if self.anchored && current.is_empty() {
                return false;
            }
            let Some(&byte) = text.get(at) else { break };
            next.clear();
            for &pc in &current {
                if let Inst::Class(set) = &self.program[pc]
                    && set[byte as usize]
                    && self.add(&mut next, &mut seen, &mut stack, pc + 1, at + 1, text.len())
                {
                    return true;
                }
            }
            core::mem::swap(&mut current, &mut next);
        }
        false
    }

    /// Adds the closure of `pc` at position `at` to `list`; `true` if it
    /// reaches a match.
    fn add(
        &self,
        list: &mut Vec<usize>,
        seen: &mut [usize],
        stack: &mut Vec<usize>,
        pc: usize,
        at: usize,
        len: usize,
    ) -> bool {
        stack.clear();
        stack.push(pc);
        while let Some(pc) = stack.pop() {
            if seen[pc] == at {
                continue;
            }
            seen[pc] = at;
            match &self.program[pc] {
                Inst::Match => return true,
                Inst::Class(_) => list.push(pc),
                Inst::Jump(t) => stack.push(*t),
                Inst::Split(a, b) => {
                    stack.push(*b);
                    stack.push(*a);
                }
                Inst::Start => {
                    if at == 0 {
                        stack.push(pc + 1);
                    }
                }
                Inst::End => {
                    if at == len {
                        stack.push(pc + 1);
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(re: &str, text: &str) -> bool {
        Regex::new(re).unwrap().is_match(text.as_bytes())
    }

    #[test]
    fn the_emitted_forms_match() {
        assert!(m("^/dev/ttys[0-9]+$", "/dev/ttys004"));
        assert!(!m("^/dev/ttys[0-9]+$", "/dev/ttys"));
        assert!(m(
            crate::base::MACOS_V2_XCODE,
            "/Applications/Xcode-beta.app/Contents/x"
        ));
        assert!(!m(crate::base::MACOS_V2_XCODE, "/Applications/Xcode.app"));
        assert!(m(
            crate::base::MACOS_V2_OPENSSL,
            "/opt/homebrew/etc/openssl@3/cert.pem"
        ));
        assert!(m(
            crate::base::MACOS_V2_OPENSSL,
            "/usr/local/etc/openssl@1.1/certs/a/b"
        ));
        assert!(!m(
            crate::base::MACOS_V2_OPENSSL,
            "/opt/homebrew/etc/openssl@3/private/key"
        ));
        assert!(m(
            crate::base::MACOS_V2_FOLDERS,
            "/private/var/folders/ab/cd/T"
        ));
        assert!(!m(
            crate::base::MACOS_V2_FOLDERS,
            "/private/var/folders/ab/cd/T/x"
        ));
        let g = crate::Glob::new("/Users/*/.ssh/**").unwrap();
        let folded = g.to_sbpl_regex_folded();
        assert!(m(&folded, "/Users/me/.SSH"));
        assert!(m(&folded, "/Users/me/.ssh/id_ed25519"));
        assert!(!m(&folded, "/Users/me/x/.ssh"));
        let any = crate::Glob::new("/**/.git/hooks/**")
            .unwrap()
            .to_sbpl_regex();
        assert!(m(&any, "/w/.git/hooks/pre-commit"));
        assert!(m(&any, "/.git/hooks"));
        assert!(!m(&any, "/w/.git/hooksx"));
        assert!(m(
            &crate::Glob::new("/a/b\\*c").unwrap().to_sbpl_regex(),
            "/a/b*c"
        ));
        assert!(!m(
            &crate::Glob::new("/a/b\\*c").unwrap().to_sbpl_regex(),
            "/a/bxc"
        ));
    }

    #[test]
    fn unanchored_and_alternatives() {
        assert!(m("b(c|d)", "abd"));
        assert!(!m("^b", "ab"));
        assert!(m("^a{2,3}$", "aaa"));
        assert!(!m("^a{2,3}$", "aaaa"));
        assert!(m("^a{2,}$", "aaaaa"));
        assert!(m("^[^/]?x$", "x"));
        assert!(m("^[a-]$", "-"));
    }

    #[test]
    fn outside_the_subset() {
        for re in [
            "\\d",
            "a**",
            "[[:alpha:]]",
            "(a",
            "a)",
            "a{65}",
            "a{3,2}",
            "[z-a]",
            "^*",
        ] {
            assert!(Regex::new(re).is_none(), "{re}");
        }
    }

    #[test]
    fn linear_on_long_paths() {
        let re = Regex::new("^(.*/)?(.*/)?(.*/)?\\.[gG][iI][tT]/(.*/)?x$").unwrap();
        let path: alloc::string::String = "/a".repeat(2000);
        assert!(!re.is_match(path.as_bytes()));
    }
}
