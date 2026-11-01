//! Raw system interfaces: the only module in the workspace allowed to use
//! `unsafe`. Every unsafe block states why it is sound in a `SAFETY:` comment.
//!
//! Everything here is a thin, typed wrapper; policy and assertions live in the
//! probe and the runner.

#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

/// The calling thread's `errno`.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
