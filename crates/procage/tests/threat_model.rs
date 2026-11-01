//! The threat-model gate.
//!
//! Checks `THREAT_MODEL.md` and the files that link to it:
//!
//! - the required sections, in order, and the release status;
//! - the escape-class catalog: its strict table format, the allowed values,
//!   the published ids (append-only), and the evidence and kernel-fact rules;
//! - the links from the README and the crate docs.
//!
//! - the escape suite: every class has a canary (a test function named
//!   `rNN_…`) in the escape-suite file of every platform it lists.
//!
//! A class may be `mitigated` or `detected` only with evidence: canaries of
//! the escape suite that are not ignored, one in the file of every platform
//! the class lists, and no open (ignored) canary for the class. A `partial`
//! class needs at least one such canary and a note under `### Open
//! variants`. Every check is a function over the file contents. The unit
//! tests at the end apply one defect to the real files and assert that
//! exactly the expected rule fires.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

/// Every escape-class id ever published. Append-only: an id is never removed,
/// renumbered or reused; a class that no longer applies becomes `retired`.
const PUBLISHED: [&str; 23] = [
    "R-02", "R-03", "R-04", "R-05", "R-06", "R-07", "R-08", "R-09", "R-10", "R-11", "R-12", "R-21",
    "R-22", "R-23", "R-24", "R-25", "R-26", "R-28", "R-29", "R-30", "R-31", "R-32", "R-34",
];

/// The `## ` headings the threat model must contain, in this order.
const HEADINGS: [&str; 10] = [
    "Release status",
    "Adversary",
    "Assets",
    "Trusted",
    "In scope",
    "Out of scope",
    "Strength",
    "Dependencies on undocumented interfaces",
    "Non-goals",
    "Escape classes",
];

const HEADER: [&str; 8] = [
    "Id",
    "Class",
    "Description",
    "Platforms",
    "Disposition",
    "Status",
    "Evidence",
    "Observed on",
];

const EMPTY: &str = "—";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    RowFormat,
    Value,
    DispositionStatus,
    BaselineMissing,
    BaselineUnknown,
    DuplicateId,
    EvidenceRequired,
    EvidenceLocation,
    EvidenceMissing,
    EvidenceIgnored,
    EvidencePlatform,
    CanaryMissing,
    OpenCanary,
    OpenVariantNote,
    KernelFact,
    Heading,
    ReleaseStatus,
    HarnessNote,
    Link,
}

impl Rule {
    fn name(self) -> &'static str {
        match self {
            Rule::RowFormat => "row-format",
            Rule::Value => "value",
            Rule::DispositionStatus => "disposition-status",
            Rule::BaselineMissing => "baseline-missing",
            Rule::BaselineUnknown => "baseline-unknown",
            Rule::DuplicateId => "duplicate-id",
            Rule::EvidenceRequired => "evidence-required",
            Rule::EvidenceLocation => "evidence-location",
            Rule::EvidenceMissing => "evidence-missing",
            Rule::EvidenceIgnored => "evidence-ignored",
            Rule::EvidencePlatform => "evidence-platform",
            Rule::CanaryMissing => "canary-missing",
            Rule::OpenCanary => "open-canary",
            Rule::OpenVariantNote => "open-variant-note",
            Rule::KernelFact => "kernel-fact",
            Rule::Heading => "heading",
            Rule::ReleaseStatus => "release-status",
            Rule::HarnessNote => "harness-note",
            Rule::Link => "link",
        }
    }
}

#[derive(Debug)]
struct Violation {
    rule: Rule,
    subject: String,
    detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "threat-model gate: {}: {}: {}",
            self.rule.name(),
            self.subject,
            self.detail
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Platforms {
    Macos,
    Linux,
    Both,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    Mitigate,
    Detect,
    Harness,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Planned,
    Partial,
    Mitigated,
    Detected,
    Documented,
    Retired,
}

impl Disposition {
    fn allows(self, status: Status) -> bool {
        use Status::*;
        match self {
            Disposition::Mitigate => matches!(status, Planned | Partial | Mitigated | Retired),
            Disposition::Detect => matches!(status, Planned | Partial | Detected | Retired),
            Disposition::Harness => matches!(status, Documented | Retired),
        }
    }
}

/// `<path>::<fn>`, a canary that is evidence for a class.
#[derive(Debug)]
struct EvidenceRef {
    path: String,
    func: String,
}

#[derive(Debug)]
struct EscapeClass {
    id: String,
    platforms: Platforms,
    disposition: Disposition,
    status: Status,
    evidence: Vec<EvidenceRef>,
    observed_on: Vec<String>,
}

impl Platforms {
    fn covers(self, platform: Platforms) -> bool {
        self == Platforms::Both || self == platform
    }

    fn listed(self) -> &'static [Platforms] {
        match self {
            Platforms::Macos => &[Platforms::Macos],
            Platforms::Linux => &[Platforms::Linux],
            Platforms::Both => &[Platforms::Macos, Platforms::Linux],
        }
    }
}

/// The escape-suite file of each platform.
const SUITES: [(Platforms, &str); 2] = [
    (Platforms::Macos, "tests/escape_macos.rs"),
    (Platforms::Linux, "tests/escape_linux.rs"),
];

/// The canaries of one escape-suite file: function name → ignored.
type Canaries = std::collections::BTreeMap<String, bool>;

/// Everything the gate reads, so the tests can substitute any part.
struct Inputs<'a> {
    doc: &'a str,
    readme: &'a str,
    lib_rs: &'a str,
    kernel_facts: &'a BTreeSet<String>,
    version: &'a str,
    /// Per platform, the canaries of its escape-suite file.
    canaries: &'a [(Platforms, Canaries)],
}

/// The `rNN_` prefix of the canaries for class `id`.
fn canary_prefix(id: &str) -> String {
    format!("r{}_", &id[2..])
}

/// The canary functions of an escape-suite file: every `fn rNN_…(`, and
/// whether an `#[ignore` attribute sits in the attribute lines above it.
fn canaries(src: &str) -> Canaries {
    let lines: Vec<&str> = src.lines().map(str::trim).collect();
    let mut out = Canaries::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(rest) = line.strip_prefix("fn ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once('(') else {
            continue;
        };
        let b = name.as_bytes();
        let canary = b.len() > 4
            && b[0] == b'r'
            && b[1].is_ascii_digit()
            && b[2].is_ascii_digit()
            && b[3] == b'_';
        if !canary {
            continue;
        }
        let ignored = lines[..i]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#[") || l.starts_with("///"))
            .any(|l| l.starts_with("#[ignore"));
        out.insert(name.to_owned(), ignored);
    }
    out
}

fn violation(rule: Rule, subject: impl Into<String>, detail: impl Into<String>) -> Violation {
    Violation {
        rule,
        subject: subject.into(),
        detail: detail.into(),
    }
}

/// The body of the `## <title>` section: the lines up to the next `## ` heading.
fn section<'a>(doc: &'a str, title: &str) -> Option<Vec<(usize, &'a str)>> {
    let heading = format!("## {title}");
    let mut lines = doc.lines().enumerate();
    lines.find(|(_, l)| l.trim_end() == heading)?;
    Some(
        lines
            .take_while(|(_, l)| !l.starts_with("## "))
            .map(|(i, l)| (i + 1, l))
            .collect(),
    )
}

fn check_headings(doc: &str, version: &str, out: &mut Vec<Violation>) {
    let found: Vec<&str> = doc.lines().filter_map(|l| l.strip_prefix("## ")).collect();
    let mut at = 0;
    for required in HEADINGS {
        match found[at..].iter().position(|h| h.trim_end() == required) {
            Some(i) => at += i + 1,
            None => out.push(violation(
                Rule::Heading,
                required,
                "required heading missing or out of order",
            )),
        }
    }
    if let Some(body) = section(doc, "Release status") {
        let expected = format!("procage {version}");
        if !body.iter().any(|(_, l)| l.contains(&expected)) {
            out.push(violation(
                Rule::ReleaseStatus,
                expected,
                "the release status does not name the current crate version",
            ));
        }
    }
}

fn cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
    inner.split('|').map(|c| c.trim().to_owned()).collect()
}

fn is_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 4 && s.starts_with("R-") && b[2].is_ascii_digit() && b[3].is_ascii_digit()
}

fn is_kernel_fact(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 6
        && (s.starts_with("KF-M") || s.starts_with("KF-L"))
        && b[4].is_ascii_digit()
        && b[5].is_ascii_digit()
}

fn list(cell: &str) -> Vec<&str> {
    if cell == EMPTY {
        Vec::new()
    } else {
        cell.split(", ").collect()
    }
}

fn parse_evidence(s: &str) -> Option<EvidenceRef> {
    let (path, func) = s.split_once("::")?;
    let ident = !func.is_empty() && func.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    (!path.is_empty() && ident).then(|| EvidenceRef {
        path: path.to_owned(),
        func: func.to_owned(),
    })
}

/// Parses one row. Field errors are reported against the id; the row is
/// kept only when every field is valid.
fn parse_row(c: &[String], id: &str, out: &mut Vec<Violation>) -> Option<EscapeClass> {
    let mut ok = true;
    let mut bad = |field: &str, value: &str, allowed: &str| {
        out.push(violation(
            Rule::Value,
            format!("{id} {field}"),
            format!("`{value}` is not one of: {allowed}"),
        ));
        ok = false;
    };
    for (i, field) in [(1, "class"), (2, "description")] {
        if c[i].is_empty() || c[i] == EMPTY {
            bad(field, &c[i], "non-empty text");
        }
    }
    let platforms = match c[3].as_str() {
        "macOS" => Some(Platforms::Macos),
        "Linux" => Some(Platforms::Linux),
        "macOS, Linux" => Some(Platforms::Both),
        v => {
            bad("platforms", v, "macOS | Linux | macOS, Linux");
            None
        }
    };
    let disposition = match c[4].as_str() {
        "mitigate" => Some(Disposition::Mitigate),
        "detect" => Some(Disposition::Detect),
        "harness" => Some(Disposition::Harness),
        v => {
            bad("disposition", v, "mitigate | detect | harness");
            None
        }
    };
    let status = match c[5].as_str() {
        "planned" => Some(Status::Planned),
        "partial" => Some(Status::Partial),
        "mitigated" => Some(Status::Mitigated),
        "detected" => Some(Status::Detected),
        "documented" => Some(Status::Documented),
        "retired" => Some(Status::Retired),
        v => {
            bad(
                "status",
                v,
                "planned | partial | mitigated | detected | documented | retired",
            );
            None
        }
    };
    let mut evidence = Vec::new();
    for e in list(&c[6]) {
        match parse_evidence(e) {
            Some(r) => evidence.push(r),
            None => bad("evidence", e, "`—` or `<path>::<fn>`, comma-separated"),
        }
    }
    let mut observed_on = Vec::new();
    for k in list(&c[7]) {
        if is_kernel_fact(k) {
            observed_on.push(k.to_owned());
        } else {
            bad(
                "observed on",
                k,
                "`—` or `KF-Mnn` / `KF-Lnn`, comma-separated",
            );
        }
    }
    ok.then_some(EscapeClass {
        id: id.to_owned(),
        platforms: platforms?,
        disposition: disposition?,
        status: status?,
        evidence,
        observed_on,
    })
}

/// Parses the catalog strictly: a malformed row is a violation, never skipped.
/// Returns the valid rows and every id seen (valid or not), in order.
fn parse_catalog(doc: &str, out: &mut Vec<Violation>) -> (Vec<EscapeClass>, Vec<String>) {
    let mut rows = Vec::new();
    let mut ids = Vec::new();
    let Some(body) = section(doc, "Escape classes") else {
        return (rows, ids);
    };
    let Some(start) = body.iter().position(|(_, l)| l.starts_with('|')) else {
        out.push(violation(
            Rule::RowFormat,
            "Escape classes",
            "no catalog table",
        ));
        return (rows, ids);
    };
    let (header_line, header) = body[start];
    if cells(header) != HEADER {
        out.push(violation(
            Rule::RowFormat,
            format!("line {header_line}"),
            format!("the header must be `| {} |`", HEADER.join(" | ")),
        ));
        return (rows, ids);
    }
    let table_end = body[start..]
        .iter()
        .position(|(_, l)| !l.starts_with('|'))
        .map_or(body.len(), |i| start + i);
    for &(line_no, line) in &body[start + 1..table_end] {
        let c = cells(line);
        if line_no == header_line + 1 {
            let separator = c.len() == HEADER.len()
                && c.iter()
                    .all(|s| !s.is_empty() && s.chars().all(|ch| matches!(ch, '-' | ':')));
            if !separator {
                out.push(violation(
                    Rule::RowFormat,
                    format!("line {line_no}"),
                    "the header must be followed by a separator row",
                ));
            }
            continue;
        }
        let id = c[0].clone();
        if is_id(&id) {
            ids.push(id.clone());
        }
        if c.len() != HEADER.len() {
            out.push(violation(
                Rule::RowFormat,
                format!("line {line_no}"),
                format!("{} cells, expected {}", c.len(), HEADER.len()),
            ));
            continue;
        }
        if !is_id(&id) {
            out.push(violation(
                Rule::Value,
                format!("line {line_no} id"),
                format!("`{id}` is not `R-NN`"),
            ));
            continue;
        }
        if let Some(row) = parse_row(&c, &id, out) {
            rows.push(row);
        }
    }
    for &(line_no, line) in &body[table_end..] {
        if line.starts_with('|') {
            out.push(violation(
                Rule::RowFormat,
                format!("line {line_no}"),
                "table row outside the catalog table",
            ));
        }
    }
    (rows, ids)
}

fn check_baseline(ids: &[String], out: &mut Vec<Violation>) {
    let mut seen = BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            out.push(violation(Rule::DuplicateId, id, "listed more than once"));
        }
        if !PUBLISHED.contains(&id.as_str()) {
            out.push(violation(
                Rule::BaselineUnknown,
                id,
                "not in the published-id baseline; add it to PUBLISHED in the same change",
            ));
        }
    }
    for id in PUBLISHED {
        if !seen.contains(id) {
            out.push(violation(
                Rule::BaselineMissing,
                id,
                "published id absent; ids are retired, never removed",
            ));
        }
    }
}

fn check_row(row: &EscapeClass, inputs: &Inputs<'_>, out: &mut Vec<Violation>) {
    let id = &row.id;
    if !row.disposition.allows(row.status) {
        out.push(violation(
            Rule::DispositionStatus,
            id,
            format!(
                "status {:?} is not allowed for disposition {:?}",
                row.status, row.disposition
            ),
        ));
    }
    let claims = matches!(row.status, Status::Mitigated | Status::Detected);
    if (claims || row.status == Status::Partial) && row.evidence.is_empty() {
        out.push(violation(
            Rule::EvidenceRequired,
            id,
            "mitigated, detected or partial needs a canary of the escape suite as evidence",
        ));
    }
    let prefix = canary_prefix(id);
    let mut proven = Vec::new();
    for e in &row.evidence {
        let reference = format!("{}::{}", e.path, e.func);
        let suite = SUITES.iter().find(|(_, path)| *path == e.path);
        let Some(&(platform, _)) = suite.filter(|_| e.func.starts_with(&prefix)) else {
            out.push(violation(
                Rule::EvidenceLocation,
                format!("{id} {reference}"),
                format!(
                    "evidence must be a canary `{prefix}…` in {} or {}",
                    SUITES[0].1, SUITES[1].1
                ),
            ));
            continue;
        };
        let found = inputs
            .canaries
            .iter()
            .find(|(p, _)| *p == platform)
            .and_then(|(_, c)| c.get(&e.func));
        match found {
            None => out.push(violation(
                Rule::EvidenceMissing,
                format!("{id} {reference}"),
                "no such canary",
            )),
            Some(true) => out.push(violation(
                Rule::EvidenceIgnored,
                format!("{id} {reference}"),
                "an ignored (open) canary is never evidence",
            )),
            Some(false) if !row.platforms.covers(platform) => out.push(violation(
                Rule::EvidencePlatform,
                format!("{id} {reference}"),
                "evidence for a platform the class does not list",
            )),
            Some(false) => proven.push(platform),
        }
    }
    if claims && !row.evidence.is_empty() {
        for &platform in row.platforms.listed() {
            if !proven.contains(&platform) {
                out.push(violation(
                    Rule::EvidencePlatform,
                    format!("{id} {platform:?}"),
                    "mitigated or detected needs a passing canary on every listed platform",
                ));
            }
        }
    }
    if row.status == Status::Retired {
        return;
    }
    for (platform, canaries) in inputs.canaries {
        let mine = || {
            canaries
                .iter()
                .filter(|(name, _)| name.starts_with(&prefix))
        };
        if row.platforms.covers(*platform) && mine().next().is_none() {
            out.push(violation(
                Rule::CanaryMissing,
                format!("{id} {platform:?}"),
                format!("no canary `{prefix}…` for a listed platform"),
            ));
        }
        if claims {
            for (name, _) in mine().filter(|(_, ignored)| **ignored) {
                out.push(violation(
                    Rule::OpenCanary,
                    format!("{id} {name}"),
                    "a mitigated or detected class has an open canary",
                ));
            }
        }
    }
    for k in &row.observed_on {
        if !inputs.kernel_facts.contains(k) {
            out.push(violation(
                Rule::KernelFact,
                format!("{id} {k}"),
                "not in the kernel-facts catalog",
            ));
        }
    }
}

/// The ids with an entry `- **R-NN** …` under `### <title>`.
fn notes(doc: &str, title: &str) -> BTreeSet<String> {
    let body = section(doc, "Escape classes").unwrap_or_default();
    let heading = format!("### {title}");
    let mut in_notes = false;
    let mut noted = BTreeSet::new();
    for (_, line) in body {
        if line.starts_with("### ") {
            in_notes = line.trim_end() == heading;
        } else if in_notes
            && let Some(rest) = line.strip_prefix("- **")
            && let Some((id, _)) = rest.split_once("**")
        {
            noted.insert(id.to_owned());
        }
    }
    noted
}

fn check_notes(doc: &str, rows: &[EscapeClass], out: &mut Vec<Violation>) {
    let harness = notes(doc, "Harness responsibilities");
    let open = notes(doc, "Open variants");
    for row in rows {
        if row.disposition == Disposition::Harness && !harness.contains(&row.id) {
            out.push(violation(
                Rule::HarnessNote,
                &row.id,
                "a harness class needs an entry under `### Harness responsibilities`",
            ));
        }
        if row.status == Status::Partial && !open.contains(&row.id) {
            out.push(violation(
                Rule::OpenVariantNote,
                &row.id,
                "a partial class needs an entry under `### Open variants`",
            ));
        }
    }
}

fn check_links(readme: &str, lib_rs: &str, out: &mut Vec<Violation>) {
    if !readme.contains("](crates/procage/THREAT_MODEL.md)") {
        out.push(violation(
            Rule::Link,
            "README.md",
            "no link to THREAT_MODEL.md",
        ));
    }
    if !lib_rs.contains("pub mod threat_model;") || !lib_rs.contains("](threat_model)") {
        out.push(violation(
            Rule::Link,
            "src/lib.rs",
            "needs `pub mod threat_model;` and a doc link to it",
        ));
    }
}

fn check(inputs: &Inputs<'_>) -> (Vec<EscapeClass>, Vec<Violation>) {
    let mut out = Vec::new();
    check_headings(inputs.doc, inputs.version, &mut out);
    let (rows, ids) = parse_catalog(inputs.doc, &mut out);
    check_baseline(&ids, &mut out);
    for row in &rows {
        check_row(row, inputs, &mut out);
    }
    check_notes(inputs.doc, &rows, &mut out);
    check_links(inputs.readme, inputs.lib_rs, &mut out);
    (rows, out)
}

/// The `id: "KF-…"` literals of the kernel-facts catalog.
fn kernel_fact_ids(src: &str) -> BTreeSet<String> {
    src.split("id: \"")
        .skip(1)
        .filter_map(|s| s.split_once('"').map(|(id, _)| id))
        .filter(|id| is_kernel_fact(id))
        .map(str::to_owned)
        .collect()
}

struct Files {
    doc: String,
    readme: String,
    lib_rs: String,
    kernel_facts: BTreeSet<String>,
    /// The escape-suite files, in the order of `SUITES`.
    suites: [String; 2],
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn load() -> Files {
    let read = |p: &str| {
        fs::read_to_string(root().join(p)).unwrap_or_else(|e| panic!("cannot read {p}: {e}"))
    };
    Files {
        doc: read("THREAT_MODEL.md"),
        readme: read("../../README.md"),
        lib_rs: read("src/lib.rs"),
        kernel_facts: kernel_fact_ids(&read("../procage-kernel-facts/tests/kernel_facts.rs")),
        suites: SUITES.map(|(_, path)| read(path)),
    }
}

fn run(files: &Files) -> (Vec<EscapeClass>, Vec<Violation>) {
    let canaries: Vec<(Platforms, Canaries)> = SUITES
        .iter()
        .zip(&files.suites)
        .map(|((platform, _), src)| (*platform, canaries(src)))
        .collect();
    check(&Inputs {
        doc: &files.doc,
        readme: &files.readme,
        lib_rs: &files.lib_rs,
        kernel_facts: &files.kernel_facts,
        version: env!("CARGO_PKG_VERSION"),
        canaries: &canaries,
    })
}

#[test]
fn gate() {
    let files = load();
    assert!(
        files.kernel_facts.len() >= 40,
        "kernel-facts catalog not found"
    );
    let (rows, violations) = run(&files);
    for v in &violations {
        eprintln!("{v}");
    }
    assert!(
        violations.is_empty(),
        "{} threat-model violation(s)",
        violations.len()
    );
    assert_eq!(rows.len(), PUBLISHED.len());
}

/// Applies `edit` to the cells of the row with `id` and rebuilds the line.
fn edit_row(doc: &str, id: &str, edit: impl Fn(&mut Vec<String>)) -> String {
    let prefix = format!("| {id} |");
    let mut found = false;
    let lines: Vec<String> = doc
        .lines()
        .map(|l| {
            if l.starts_with(&prefix) {
                found = true;
                let mut c = cells(l);
                edit(&mut c);
                format!("| {} |", c.join(" | "))
            } else {
                l.to_owned()
            }
        })
        .collect();
    assert!(found, "row {id} not found");
    lines.join("\n") + "\n"
}

fn row_line(doc: &str, id: &str) -> String {
    let prefix = format!("| {id} |");
    doc.lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("row {id} not found"))
        .to_owned()
}

fn set(field: usize, value: &'static str) -> impl Fn(&mut Vec<String>) {
    move |c| c[field] = value.to_owned()
}

/// Runs the gate with a mutated copy and asserts that only `rule` fires and
/// that some violation names `subject`.
fn assert_caught(mutate: impl FnOnce(&mut Files), rule: Rule, subject: &str) {
    let mut files = load();
    mutate(&mut files);
    let (_, violations) = run(&files);
    assert!(!violations.is_empty(), "{} was not caught", rule.name());
    for v in &violations {
        assert_eq!(v.rule, rule, "unexpected extra violation: {v}");
    }
    assert!(
        violations.iter().any(|v| v.subject.contains(subject)),
        "no {} violation names {subject}: {violations:?}",
        rule.name()
    );
}

#[test]
fn removed_id_is_caught() {
    assert_caught(
        |f| {
            let line = row_line(&f.doc, "R-22");
            f.doc = f.doc.replace(&format!("{line}\n"), "");
        },
        Rule::BaselineMissing,
        "R-22",
    );
}

#[test]
fn duplicate_id_is_caught() {
    assert_caught(
        |f| {
            let line = row_line(&f.doc, "R-10");
            f.doc = f.doc.replace(&line, &format!("{line}\n{line}"));
        },
        Rule::DuplicateId,
        "R-10",
    );
}

#[test]
fn unknown_id_is_caught() {
    assert_caught(
        |f| {
            let line = row_line(&f.doc, "R-10");
            let extra = line.replacen("R-10", "R-99", 1);
            f.doc = f.doc.replace(&line, &format!("{line}\n{extra}"));
            f.doc = edit_row(&f.doc, "R-99", |c| {
                c[5] = "retired".into();
                c[6] = EMPTY.into();
            });
        },
        Rule::BaselineUnknown,
        "R-99",
    );
}

#[test]
fn missing_cell_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(&f.doc, "R-10", |c| {
                c.pop();
            })
        },
        Rule::RowFormat,
        "line",
    );
}

#[test]
fn unknown_status_is_caught() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-10", set(5, "done")),
        Rule::Value,
        "R-10 status",
    );
}

#[test]
fn harness_class_cannot_be_planned() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-07", set(5, "planned")),
        Rule::DispositionStatus,
        "R-07",
    );
}

/// Appends `extra` to the evidence of `id`.
fn add_evidence(extra: &'static str) -> impl Fn(&mut Vec<String>) {
    move |c| c[6] = format!("{}, {extra}", c[6])
}

#[test]
fn mitigated_without_evidence_is_caught() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-10", set(6, EMPTY)),
        Rule::EvidenceRequired,
        "R-10",
    );
}

#[test]
fn partial_without_evidence_is_caught() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-23", set(6, EMPTY)),
        Rule::EvidenceRequired,
        "R-23",
    );
}

#[test]
fn evidence_in_library_source_is_caught() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-10", add_evidence("src/lib.rs::caged")),
        Rule::EvidenceLocation,
        "R-10 src/lib.rs::caged",
    );
}

#[test]
fn evidence_in_another_test_file_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(
                &f.doc,
                "R-10",
                add_evidence("tests/spawn_macos.rs::each_run_gets_its_own_private_tmpdir"),
            )
        },
        Rule::EvidenceLocation,
        "R-10 tests/spawn_macos.rs",
    );
}

#[test]
fn kernel_fact_as_evidence_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(
                &f.doc,
                "R-10",
                add_evidence("tests/kernel_facts/tests/kernel_facts.rs::main"),
            )
        },
        Rule::EvidenceLocation,
        "R-10 tests/kernel_facts",
    );
}

#[test]
fn another_class_canary_as_evidence_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(
                &f.doc,
                "R-10",
                add_evidence(
                    "tests/escape_linux.rs::r21_an_inherited_descriptor_does_not_reach_the_child",
                ),
            )
        },
        Rule::EvidenceLocation,
        "R-10 tests/escape_linux.rs::r21",
    );
}

#[test]
fn nonexistent_evidence_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(
                &f.doc,
                "R-10",
                add_evidence("tests/escape_linux.rs::r10_absent"),
            )
        },
        Rule::EvidenceMissing,
        "R-10 tests/escape_linux.rs::r10_absent",
    );
}

#[test]
fn ignored_canary_as_evidence_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(
                &f.doc,
                "R-26",
                set(
                    6,
                    "tests/escape_macos.rs::r26_the_helper_cannot_be_replaced, \
                     tests/escape_linux.rs::r26_the_helper_cannot_be_replaced",
                ),
            )
        },
        Rule::EvidenceIgnored,
        "R-26",
    );
}

#[test]
fn mitigated_on_one_platform_only_is_caught() {
    assert_caught(
        |f| {
            f.doc = edit_row(
                &f.doc,
                "R-10",
                set(
                    6,
                    "tests/escape_macos.rs::r10_runs_do_not_share_temporary_files",
                ),
            )
        },
        Rule::EvidencePlatform,
        "R-10 Linux",
    );
}

#[test]
fn missing_canary_is_caught() {
    assert_caught(
        |f| f.suites[1] = f.suites[1].replace("fn r26_", "fn helper_"),
        Rule::CanaryMissing,
        "R-26 Linux",
    );
}

#[test]
fn mitigated_with_an_open_canary_is_caught() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-25", set(5, "mitigated")),
        Rule::OpenCanary,
        "R-25 r25_other_processes_arguments_are_unreadable",
    );
}

#[test]
fn partial_without_a_note_is_caught() {
    assert_caught(
        |f| f.doc = f.doc.replace("- **R-25**", "- R-25"),
        Rule::OpenVariantNote,
        "R-25",
    );
}

#[test]
fn unknown_kernel_fact_is_caught() {
    assert_caught(
        |f| f.doc = edit_row(&f.doc, "R-21", set(7, "KF-M99")),
        Rule::KernelFact,
        "R-21 KF-M99",
    );
}

#[test]
fn missing_heading_is_caught() {
    assert_caught(
        |f| f.doc = f.doc.replace("## Out of scope\n", "Out of scope:\n"),
        Rule::Heading,
        "Out of scope",
    );
}

#[test]
fn wrong_release_is_caught() {
    assert_caught(
        |f| {
            let current = format!("procage {}", env!("CARGO_PKG_VERSION"));
            f.doc = f.doc.replace(&current, "procage 0.0.0");
        },
        Rule::ReleaseStatus,
        env!("CARGO_PKG_VERSION"),
    );
}

#[test]
fn missing_harness_note_is_caught() {
    assert_caught(
        |f| f.doc = f.doc.replace("- **R-07**", "- R-07"),
        Rule::HarnessNote,
        "R-07",
    );
}

#[test]
fn missing_readme_link_is_caught() {
    assert_caught(
        |f| {
            f.readme = f
                .readme
                .replace("](crates/procage/THREAT_MODEL.md)", "](docs.md)")
        },
        Rule::Link,
        "README.md",
    );
}

#[test]
fn missing_crate_docs_link_is_caught() {
    assert_caught(
        |f| f.lib_rs = f.lib_rs.replace("](threat_model)", "]"),
        Rule::Link,
        "src/lib.rs",
    );
}

/// The real catalog parses with the statuses the escape suite supports.
#[test]
fn statuses_are_parsed() {
    let (rows, violations) = run(&load());
    assert!(violations.is_empty(), "{violations:?}");
    let status = |id: &str| rows.iter().find(|r| r.id == id).map(|r| r.status);
    assert_eq!(status("R-10"), Some(Status::Mitigated));
    assert_eq!(status("R-23"), Some(Status::Mitigated));
    assert_eq!(status("R-25"), Some(Status::Partial));
    assert_eq!(status("R-26"), Some(Status::Planned));
}
