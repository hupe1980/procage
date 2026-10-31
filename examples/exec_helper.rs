//! A helper that becomes a caged command, for code that starts and kills
//! processes itself (an MCP client, a terminal emulator):
//!
//! ```text
//! exec_helper <workspace> <program> [args…]
//! ```
//!
//! The program runs on procage's base profile, may write only inside
//! `<workspace>`, and starts there. The helper's pid, standard streams,
//! process group and exit status become the program's. On Linux tier T2 the
//! write rule reaches git hook and shell startup names, which only tier T1
//! can protect inside a writable tree, so the policy is refused there with
//! an error that names the class.

use std::process::Command;

use procage::native::{Cage, CageOptions, Grants};
use procage::policy::{AbsPath, Access, Base, Exec, FsRule, FsTarget, LowerOptions, Policy};

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [workspace, program, args @ ..] = args.as_slice() else {
        eprintln!("usage: exec_helper <workspace> <program> [args…]");
        std::process::exit(2);
    };
    let workspace = std::fs::canonicalize(workspace).unwrap_or_else(|e| fail(&e));
    let workspace_path =
        AbsPath::new(workspace.as_os_str().as_encoded_bytes()).unwrap_or_else(|e| fail(&e));

    let mut policy = Policy::default();
    policy.base = Base::V1;
    policy.process.fork = true;
    policy.process.exec = Exec::Any;
    policy.fs.push(FsRule::new(
        Access::Write,
        FsTarget::Subpath(workspace_path),
    ));
    let options =
        CageOptions::default().with_lower(LowerOptions::default().accept_spawn_snapshot());
    let cage = Cage::with_options(&policy, &options).unwrap_or_else(|e| fail(&e));

    let mut command = Command::new(program);
    command.args(args).current_dir(&workspace);
    // Returns only if the program could not be started in the cage.
    fail(&cage.exec(&mut command, &Grants::new()))
}

fn fail(error: &dyn std::fmt::Display) -> ! {
    eprintln!("exec_helper: {error}");
    std::process::exit(126)
}
