//! The portable surface: this file uses only `procage::native` and the
//! subset both backends share, and builds and runs on macOS and Linux
//! without `cfg` in the test bodies.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use procage::native::{Cage, CageOptions, Child, Grants};
use procage::policy::{Access, Base, Grant, GrantName, LowerOptions, Policy, Tty};

fn policy() -> Policy {
    let mut p = Policy::default();
    p.base = Base::V1;
    p.grants.push(Grant {
        name: GrantName::new("data").unwrap(),
        access: Access::Read,
    });
    p
}

fn cage(p: &Policy) -> Cage {
    let options =
        CageOptions::default().with_lower(LowerOptions::default().accept_spawn_snapshot());
    Cage::with_options(p, &options).unwrap_or_else(|e| panic!("{e}"))
}

fn data_dir() -> std::path::PathBuf {
    let dir = std::fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("procage-native-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("f"), "granted").unwrap();
    dir
}

fn quiet(program: &str, arg: &str) -> Command {
    let mut c = Command::new(program);
    c.arg(arg).stdin(Stdio::null()).stderr(Stdio::null());
    c
}

fn alive(pid: u32) -> bool {
    Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn gone_within(child: &mut Child, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if child.try_wait().unwrap().is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn a_granted_file_is_read_through_the_common_subset() {
    let dir = data_dir();
    let cage = cage(&policy());
    let mut cmd = quiet("/bin/cat", dir.join("f").to_str().unwrap());
    cmd.stdout(Stdio::piped());
    let child = cage
        .spawn_with_fds(&mut cmd, &Grants::new().bind("data", &dir), &[])
        .unwrap();
    assert!(child.dropped_env().is_empty());
    assert!(child.tmpdir().is_none());
    let out = child.detach().wait_with_output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "granted");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn kill_all_and_detach_have_the_same_meaning() {
    let cage = cage(&policy());
    let mut child = cage
        .spawn(&mut quiet("/bin/sleep", "30"), &Grants::new())
        .unwrap();
    child.kill_all().unwrap();
    assert!(gone_within(&mut child, Duration::from_secs(2)));
    let child = cage
        .spawn(&mut quiet("/bin/sleep", "30"), &Grants::new())
        .unwrap();
    let mut detached = child.detach();
    assert!(alive(detached.id()));
    detached.kill().unwrap();
    detached.wait().unwrap();
}

#[test]
fn errors_explain_themselves() {
    let mut p = policy();
    p.tty = Tty::NewPty;
    let err = Cage::new(&p).map(drop).unwrap_err();
    assert!(err.to_string().contains("Tty::NewPty"), "{err}");
}
