//! Name resolution, behind a trait so tests can count and script queries.

use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::panic::{RefUnwindSafe, UnwindSafe};

/// Resolves a host name to its addresses. Unwind safe, so that a proxy (and
/// what holds one) is.
pub trait Resolve: Send + Sync + RefUnwindSafe + UnwindSafe + 'static {
    /// The addresses of `name`, in the order the resolver gives them.
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>>;
}

/// The system resolver (`getaddrinfo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        Ok((name, 0).to_socket_addrs()?.map(|a| a.ip()).collect())
    }
}
