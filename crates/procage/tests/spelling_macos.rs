//! The spelling matrix on macOS: a rule enforces on the file under every
//! spelling the volume treats as the same name, or the cage is refused.
//!
//! Seatbelt matches every path filter case- and normalization-insensitively,
//! on every volume (measured on macOS 26.6.2). On the default,
//! case-insensitive volume that is exactly the volume's own rule, so any
//! spelling of a rule enforces. On a case-sensitive volume a deny also
//! covers the case variants (it only denies more), but an allow would allow
//! other files, so allow rules and grants there are refused with
//! [`SpawnError::CaseSensitive`]. Linux case-folding directories are not
//! covered by a lane.

#![cfg(target_os = "macos")]

#[path = "support/scratch.rs"]
mod scratch_support;
use scratch_support::Scratch;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use procage::macos::{Cage, Grants, SpawnError};
use procage::policy::{AbsPath, Access, Base, FsRule, FsTarget, Grant, GrantName, Policy};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh directory, resolved (the temp dir is reached through a link).
fn scratch(tag: &str) -> Scratch {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    Scratch::at(std::env::temp_dir().join(format!("procage-sp-{}-{tag}-{n}", std::process::id())))
        .canonical()
}

fn abs(p: impl AsRef<Path>) -> AbsPath {
    AbsPath::new(p.as_ref().as_os_str().as_encoded_bytes()).unwrap()
}

fn rule(access: Access, p: impl AsRef<Path>) -> FsRule {
    FsRule::new(access, FsTarget::Subpath(abs(p)))
}

fn literal(access: Access, p: impl AsRef<Path>) -> FsRule {
    FsRule::new(access, FsTarget::Literal(abs(p)))
}

/// Base profile V3 (ordinary programs start), exec of the system's
/// programs and read of `/` itself.
fn base() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V3;
    for dir in ["/usr/lib", "/System", "/bin", "/usr/bin"] {
        p.fs.push(rule(Access::Exec, dir));
    }
    p.fs.push(literal(Access::Read, "/"));
    p
}

/// Whether `script` succeeds under `/bin/sh` in a child caged by `cage`.
fn runs(cage: &Cage, script: &str, grants: &Grants) -> bool {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cage
        .spawn(&mut cmd, grants)
        .unwrap_or_else(|e| panic!("spawn: {e}"));
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    let ok = child.wait().unwrap().success();
    if std::env::var_os("PROCAGE_SPELLING_DEBUG").is_some() {
        eprintln!("{script}: {ok} {err}");
    }
    ok
}

fn nfc() -> String {
    "caf\u{e9}".to_string()
}

fn nfd() -> String {
    "cafe\u{301}".to_string()
}

/// On the default volume a deny or an allow enforces under every case and
/// Unicode form of its name, through nested links, for a leaf created after
/// the cage, and through the data-volume firmlink.
#[test]
fn every_spelling_enforces_on_the_default_volume() {
    let d = scratch("default");
    let dir = d.join("dir");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("secret"), "s").unwrap();
    std::fs::write(dir.join("other"), "o").unwrap();
    std::fs::write(dir.join(nfd()), "u").unwrap();
    let show = |p: &Path| p.display().to_string();

    // A deny in another case, and in the other Unicode form.
    let mut p = base();
    p.fs.push(rule(Access::Read, &d));
    p.fs.push(literal(Access::Hide, dir.join("SECRET")));
    p.fs.push(literal(Access::Hide, dir.join(nfc())));
    let cage = Cage::new(&p).unwrap();
    let none = Grants::new();
    assert!(
        runs(&cage, &format!("cat '{}'", show(&dir.join("other"))), &none),
        "control"
    );
    assert!(
        !runs(
            &cage,
            &format!("cat '{}'", show(&dir.join("secret"))),
            &none
        ),
        "case"
    );
    assert!(
        !runs(&cage, &format!("cat '{}'", show(&dir.join(nfd()))), &none),
        "NFD on disk"
    );

    // An allow in another case reaches the file, and is not refused.
    let mut p = base();
    p.fs.push(rule(Access::Read, d.join("DIR")));
    let cage = Cage::new(&p).unwrap();
    assert!(
        runs(&cage, &format!("cat '{}'", show(&dir.join("other"))), &none),
        "allow in case"
    );

    // A deny on a leaf that does not exist yet covers it in any case.
    let mut p = base();
    p.fs.push(rule(Access::Write, &d));
    p.fs.push(literal(Access::Hide, dir.join("Missing")));
    let cage = Cage::new(&p).unwrap();
    let missing = show(&dir.join("missing"));
    assert!(
        !runs(
            &cage,
            &format!("echo y > '{missing}' && cat '{missing}'"),
            &none
        ),
        "leaf"
    );

    // Through two links, and through the data-volume firmlink.
    let l2 = d.join("l2");
    let l1 = d.join("l1");
    std::os::unix::fs::symlink(&dir, &l2).unwrap();
    std::os::unix::fs::symlink(&l2, &l1).unwrap();
    let data = PathBuf::from(format!("/System/Volumes/Data{}", show(&dir)));
    for hidden in [l1.join("secret"), data.join("secret")] {
        let mut p = base();
        p.fs.push(rule(Access::Read, &d));
        p.fs.push(literal(Access::Hide, &hidden));
        let cage = Cage::new(&p).unwrap();
        assert!(
            !runs(
                &cage,
                &format!("cat '{}'", show(&dir.join("secret"))),
                &none
            ),
            "{hidden:?}"
        );
        assert!(
            runs(&cage, &format!("cat '{}'", show(&dir.join("other"))), &none),
            "{hidden:?}"
        );
    }
}

/// A case-sensitive APFS image, attached without root, detached on drop.
struct Image {
    mount: PathBuf,
}

impl Image {
    fn new(d: &Path) -> Image {
        let image = d.join("cs.dmg");
        let mount = d.join("cs");
        let ok = |c: &mut Command| c.status().is_ok_and(|s| s.success());
        // A lane that cannot make the image fails here: the matrix is never
        // skipped.
        assert!(
            ok(Command::new("/usr/bin/hdiutil")
                .args(["create", "-quiet", "-size", "20m", "-fs"])
                .arg("Case-sensitive APFS")
                .args(["-volname", "procage-cs"])
                .arg(&image)),
            "hdiutil create"
        );
        assert!(
            ok(Command::new("/usr/bin/hdiutil")
                .args(["attach", "-quiet", "-nobrowse", "-mountpoint"])
                .arg(&mount)
                .arg(&image)),
            "hdiutil attach"
        );
        Image { mount }
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&self.mount)
            .status();
    }
}

/// On a case-sensitive volume an allow rule, an allowed socket and a grant
/// are refused; a deny is kept and also denies the case variants.
#[test]
fn a_case_sensitive_volume_refuses_allows_and_keeps_denies() {
    let d = scratch("cs");
    let image = Image::new(&d);
    let cs = image.mount.clone();
    std::fs::write(cs.join("a"), "a").unwrap();
    std::fs::write(cs.join("A"), "A").unwrap();
    std::fs::write(cs.join("b"), "b").unwrap();
    let refused = |p: &Policy| match Cage::new(p) {
        Err(SpawnError::CaseSensitive { path }) => path,
        other => panic!("not refused as case-sensitive: {:?}", other.map(|_| ())),
    };

    for access in [Access::Read, Access::Write, Access::Exec] {
        let mut p = base();
        p.fs.push(literal(access, cs.join("a")));
        assert_eq!(
            refused(&p),
            cs.join("a").display().to_string(),
            "{access:?}"
        );
    }
    let mut p = base();
    p.ipc.unix_sockets.push(abs(cs.join("s.sock")));
    assert_eq!(
        refused(&p),
        cs.join("s.sock").display().to_string(),
        "socket"
    );

    // A grant bound to a path on the image.
    let mut p = base();
    p.grants.push(Grant {
        name: GrantName::new("out").unwrap(),
        access: Access::Write,
    });
    let cage = Cage::new(&p).unwrap();
    let mut cmd = Command::new("/usr/bin/true");
    match cage.spawn(&mut cmd, &Grants::new().bind("out", cs.join("a"))) {
        Err(SpawnError::CaseSensitive { path }) => {
            assert_eq!(path, cs.join("a").display().to_string());
        }
        other => panic!("grant not refused: {:?}", other.map(|_| ())),
    }

    // A deny is kept: read through the parent's tree, `a` hidden, `A` too.
    let mut p = base();
    p.fs.push(rule(Access::Read, &d));
    p.fs.push(literal(Access::Hide, cs.join("a")));
    let cage = Cage::new(&p).unwrap();
    let none = Grants::new();
    assert!(
        runs(&cage, &format!("cat '{}'", cs.join("b").display()), &none),
        "control"
    );
    assert!(
        !runs(&cage, &format!("cat '{}'", cs.join("a").display()), &none),
        "a"
    );
    assert!(
        !runs(&cage, &format!("cat '{}'", cs.join("A").display()), &none),
        "A"
    );
}
