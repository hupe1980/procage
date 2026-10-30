//! `unsafe` code exists only in `src/macos/sys.rs` and `src/linux/sys.rs`, and every use there has a
//! `// SAFETY:` comment in the comment block directly above it.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Lines that use `unsafe` as a keyword (not in comments or lint names).
fn unsafe_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or("");
            code.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|word| word == "unsafe")
                && !code.contains("unsafe_code")
        })
        .map(|(i, _)| i)
        .collect()
}

#[test]
fn unsafe_is_confined_to_the_sys_modules_with_safety_comments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sys = [root.join("src/macos/sys.rs"), root.join("src/linux/sys.rs")];
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut problems = Vec::new();
    let mut in_sys = 0;
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for i in unsafe_lines(&text) {
            let shown = format!("{}:{}", file.strip_prefix(root).unwrap().display(), i + 1);
            if !sys.contains(file) {
                problems.push(format!("{shown}: unsafe outside the sys modules"));
                continue;
            }
            in_sys += 1;
            let block = lines[..i]
                .iter()
                .rev()
                .take_while(|l| l.trim_start().starts_with("//"));
            let commented =
                lines[i].contains("// SAFETY:") || block.into_iter().any(|l| l.contains("SAFETY:"));
            // Foreign function pointer types are declarations, not unsafe
            // operations.
            let declaration = lines[i].contains("unsafe extern \"C\" fn");
            if !commented && !declaration {
                problems.push(format!("{shown}: unsafe without a SAFETY comment"));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        in_sys > 20,
        "found only {in_sys} unsafe uses in the sys modules"
    );
}

#[test]
fn the_scanner_finds_what_it_must() {
    assert_eq!(unsafe_lines("let x = unsafe { f() };"), [0]);
    assert!(unsafe_lines("#![allow(unsafe_code)]\n// unsafe in a comment").is_empty());
}
