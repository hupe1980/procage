//! The data format: versioned, strict, round-tripping (feature `serde`).

#![cfg(feature = "serde")]

mod common;

use common::*;
use procage_policy::*;
use serde_json::{Value, json};

fn round_trip(policy: &Policy) -> Policy {
    let text = serde_json::to_string(policy).unwrap();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

fn read(value: Value) -> Result<Policy, String> {
    serde_json::from_value(value).map_err(|e| e.to_string())
}

#[test]
fn reference_policies_round_trip() {
    for (name, policy) in reference_policies() {
        assert_eq!(round_trip(&policy), policy, "{name}");
    }
}

#[test]
fn non_utf8_paths_round_trip_as_bytes() {
    let mut p = Policy::default();
    p.fs.push(FsRule::new(
        Access::Read,
        FsTarget::Literal(AbsPath::new(&b"/\xff"[..]).unwrap()),
    ));
    let value = serde_json::to_value(&p).unwrap();
    assert_eq!(value["fs"][0]["target"], json!({"literal": [47, 255]}));
    assert_eq!(round_trip(&p), p);
    let text = serde_json::to_value(read_only()).unwrap();
    assert_eq!(text["fs"][0]["target"], json!({"subpath": "/work"}));
}

#[test]
fn the_documented_example_parses() {
    let doc = json!({
      "version": 1,
      "fs": [{"access": "write", "target": {"subpath": "/work"}},
             {"access": "protect", "target": {"subpath": "/work/.git"}}],
      "net": {"proxy": {"http": 3128, "socks": null}},
      "process": {"exec": "granted", "fork": true, "signals": "self-and-children"},
      "ipc": {"posix_shm": false, "sysv": false},
      "env": {"allowlist": ["PATH", "HOME"]},
      "limits": {"nproc": null, "cpu_seconds": null, "fsize_bytes": null, "nofile": 1024, "core_bytes": 0},
      "tty": "none",
      "waive": [],
      "grants": [{"name": "scratch", "access": "write"}],
      "seatbelt": null,
      "linux": null
    });
    let p = read(doc).unwrap();
    assert_eq!(p.fs.len(), 2);
    assert_eq!(p.grants[0].name.as_str(), "scratch");
    // Written before `lifetime` existed: the default applies.
    assert_eq!(p.process.lifetime, Lifetime::Run);
    assert_eq!(p.limits.nofile, Some(1024));
    // Missing sections take the deny-everything defaults.
    assert_eq!(read(json!({"version": 1})).unwrap(), Policy::default());
}

#[test]
fn unknown_fields_are_refused() {
    let err = read(json!({"version": 1, "allow_everything": true})).unwrap_err();
    assert!(err.contains("allow_everything"), "{err}");
    let err = read(json!({"version": 1, "fs": [{"access": "read", "target": {"subpath": "/w"}, "except": []}]})).unwrap_err();
    assert!(err.contains("except"), "{err}");
    let err = read(json!({"version": 1, "net": {"proxy": {"http": 1, "socks": null, "dns": 53}}}))
        .unwrap_err();
    assert!(err.contains("dns"), "{err}");
}

#[test]
fn versions_other_than_one_are_refused() {
    assert!(
        read(json!({"version": 2}))
            .unwrap_err()
            .contains("unsupported policy version 2")
    );
    assert!(read(json!({})).unwrap_err().contains("version"));
}

#[test]
fn invalid_values_are_refused_with_the_constructor_message() {
    let cases = [
        (
            json!({"version": 1, "fs": [{"access": "read", "target": {"subpath": "work"}}]}),
            "not absolute",
        ),
        (
            json!({"version": 1, "fs": [{"access": "read", "target": {"subpath": "/a/../b"}}]}),
            "'..'",
        ),
        (
            json!({"version": 1, "fs": [{"access": "read", "target": {"glob": "/a/[b]"}}]}),
            "unsupported syntax",
        ),
        (
            json!({"version": 1, "waive": ["no-such-class"]}),
            "unknown hard-deny class",
        ),
        (
            json!({"version": 1, "grants": [{"name": "a b", "access": "read"}]}),
            "invalid grant name",
        ),
        (
            json!({"version": 1, "net": {"loopback": {"list": [0]}}}),
            "invalid port",
        ),
        (
            json!({"version": 1, "seatbelt": {"rules": [{"effect": "allow", "ops": ["default"], "filters": []}]}}),
            "unknown Seatbelt operation",
        ),
        (
            json!({"version": 1, "seatbelt": {"rules": [{"effect": "allow", "ops": ["x) (with no-sandbox"], "filters": []}]}}),
            "unknown Seatbelt operation",
        ),
    ];
    for (doc, needle) in cases {
        let err = read(doc.clone()).unwrap_err();
        assert!(err.contains(needle), "{doc}: {err}");
    }
}

/// Changes one random leaf or key of a JSON document.
fn mutate(value: &mut Value, rng: &mut Rng) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let key = rng.pick(&keys).clone();
            if rng.chance(10) {
                let v = map.remove(&key).unwrap();
                map.insert(format!("{key}x"), v);
            } else {
                mutate(map.get_mut(&key).unwrap(), rng);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            let i = rng.below(items.len());
            mutate(&mut items[i], rng);
        }
        other => {
            *other = match rng.below(7) {
                0 => json!(null),
                1 => json!(rng.next_u64() % 70_000),
                2 => json!(String::from_utf8_lossy(&rng.nasty_bytes(8))),
                3 => json!(rng.nasty_text(8)),
                4 => json!([1, "x"]),
                5 => json!({"literal": "/x"}),
                _ => json!(true),
            }
        }
    }
}

#[test]
fn mutated_documents_never_panic_and_accepted_ones_round_trip() {
    let mut rng = Rng::new(1234);
    let docs: Vec<Value> = reference_policies()
        .into_iter()
        .map(|(_, p)| serde_json::to_value(p).unwrap())
        .collect();
    let mut accepted = 0;
    for _ in 0..CASES {
        let mut doc = rng.pick(&docs).clone();
        for _ in 0..1 + rng.below(3) {
            mutate(&mut doc, &mut rng);
        }
        if let Ok(policy) = serde_json::from_value::<Policy>(doc) {
            accepted += 1;
            assert_eq!(round_trip(&policy), policy);
            for target in [
                Target::MacOs,
                Target::Linux {
                    tier: Tier::T2,
                    landlock_abi: 6,
                },
            ] {
                let _ = lower(&policy, target, &LowerOptions::default());
            }
        }
    }
    assert!(
        accepted > 100,
        "only {accepted} mutated documents were accepted"
    );
}

#[test]
fn lifetime_is_kebab_case() {
    let mut p = Policy::default();
    p.process.fork = true;
    p.process.lifetime = Lifetime::Tree;
    let value = serde_json::to_value(&p).unwrap();
    assert_eq!(value["process"]["lifetime"], json!("tree"));
    assert_eq!(round_trip(&p), p);
    let mut doc = value;
    doc["process"]["lifetime"] = json!("forever");
    assert!(read(doc).is_err());
}
