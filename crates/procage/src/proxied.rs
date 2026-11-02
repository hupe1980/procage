//! A cage's own proxy (feature `proxy`): which protocols a run serves, its
//! listeners, the proxy variables, and its refusals in the run's record.

use std::net::{SocketAddr, TcpListener};
use std::process::Command;

use procage_policy::Network;
use procage_proxy::{Protocol, Proxy, Run};

use crate::violation::{Sink, Violation, lock};

/// The proxy and the protocols the policy names.
#[derive(Debug, Clone)]
pub(crate) struct Proxied {
    proxy: Proxy,
    /// Each protocol with the port the policy gives it.
    protocols: Vec<(Protocol, u16)>,
}

impl Proxied {
    /// `None` unless the policy's network is `Network::Proxy`.
    pub(crate) fn new(proxy: &Proxy, net: &Network) -> Option<Proxied> {
        let Network::Proxy { http, socks } = net else {
            return None;
        };
        let protocols = [(Protocol::Http, http), (Protocol::Socks5, socks)]
            .into_iter()
            .filter_map(|(p, port)| port.map(|port| (p, port.get())))
            .collect();
        Some(Proxied {
            proxy: proxy.clone(),
            protocols,
        })
    }

    /// Each protocol with the port the policy gives it.
    #[cfg(target_os = "linux")]
    pub(crate) fn protocols(&self) -> &[(Protocol, u16)] {
        &self.protocols
    }

    /// One listener per protocol on a fresh loopback port.
    #[cfg(target_os = "macos")]
    pub(crate) fn bind(&self) -> std::io::Result<Vec<(Protocol, TcpListener)>> {
        self.protocols
            .iter()
            .map(|&(p, _)| Ok((p, TcpListener::bind("127.0.0.1:0")?)))
            .collect()
    }

    /// Serves the run's listeners; refusals go into `record` when the run
    /// reports violations.
    pub(crate) fn serve(
        &self,
        listeners: Vec<(Protocol, TcpListener)>,
        record: Option<Sink>,
    ) -> Option<Run> {
        self.proxy
            .serve(listeners, move |refusal| {
                if let Some(record) = &record {
                    lock(record).push(Violation::refused(&refusal));
                }
            })
            .ok()
    }
}

/// Points the usual proxy variables at the run's addresses (the child sees
/// these, whatever the environment policy passes) and removes the
/// exceptions, which could only make a client try a route that fails.
pub(crate) fn set_env(command: &mut Command, addrs: &[(Protocol, SocketAddr)]) {
    let url = |p: Protocol| {
        addrs.iter().find(|(q, _)| *q == p).map(|(_, a)| match p {
            Protocol::Http => format!("http://{a}"),
            Protocol::Socks5 => format!("socks5h://{a}"),
        })
    };
    let http = url(Protocol::Http);
    let all = url(Protocol::Socks5).or_else(|| http.clone());
    for (names, value) in [
        (["HTTP_PROXY", "http_proxy"], &http),
        (["HTTPS_PROXY", "https_proxy"], &http),
        (["ALL_PROXY", "all_proxy"], &all),
    ] {
        if let Some(v) = value {
            for name in names {
                command.env(name, v);
            }
        }
    }
    for name in ["NO_PROXY", "no_proxy"] {
        command.env_remove(name);
    }
}
