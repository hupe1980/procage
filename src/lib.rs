//! # procage
//!
//! Process sandboxing for Rust, in development. procage is designed to run a
//! child process in a cage on macOS (Seatbelt, applied through libsandbox
//! rather than the deprecated `/usr/bin/sandbox-exec`) and on Linux (Landlock,
//! seccomp and namespaces), without helper binaries.
//!
//! **Status: version 0.0.1 only reserves the name. It contains no sandboxing
//! API and enforces nothing.**
//!
//! Read the [threat model](threat_model) for the adversary, the scope, the
//! limits of an OS sandbox and the status of every known escape class.

pub mod threat_model;
