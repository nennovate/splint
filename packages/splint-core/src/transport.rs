//! Which scheme a host, Signet or verifier may use to reach another machine.
//!
//! HTTPS, unless a test setup asks for plain HTTP twice over, and even then only to names that can't
//! reach the public internet. So a stray `SPLINT_SCHEME=http` on a real server stops it starting,
//! rather than sending host keys and first contacts where anyone on the path can swap them.
//!
//! A release build goes further: plain HTTP stays on this machine, whatever is set, because a name on
//! a shared network is still a network. Only a build made for a test network, with the
//! `test-network` feature, can use a container's name.

use std::env;
use std::fmt;
use std::net::IpAddr;

/// Whether this build may use plain HTTP on a network, rather than only on this machine.
const CAN_USE_TEST_NETWORKS: bool = cfg!(any(debug_assertions, feature = "test-network"));

/// `https` unless set. Anything but `https` or `http` is refused.
pub const SCHEME_SETTING: &str = "SPLINT_SCHEME";
/// Only `yes` opts in, so a setting meant to turn it off can't open the guard.
pub const PLAIN_HTTP_OPT_IN: &str = "SPLINT_TEST_ONLY_PLAIN_HTTP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Https,
    PlainHttpForTests,
}

#[derive(PartialEq, Eq, thiserror::Error)]
pub enum TransportRefused {
    #[error("{SCHEME_SETTING} must be https or http")]
    UnknownScheme,
    #[error("plain HTTP is for test setups only, and needs {PLAIN_HTTP_OPT_IN}=yes")]
    PlainHttpNotOptedIn,
    #[error("plain HTTP can't reach {0}, because that name can leave this machine")]
    PlainHttpToPublicName(String),
    #[error("listening on {0} without TLS would accept traffic from other machines")]
    ListensBeyondThisMachine(String),
}

/// A `main` that returns an error prints it this way, and the person reading needs the sentence.
impl fmt::Debug for TransportRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Scheme {
    pub fn from_env() -> Result<Self, TransportRefused> {
        Self::choose(
            env::var(SCHEME_SETTING).ok().as_deref(),
            env::var(PLAIN_HTTP_OPT_IN).ok().as_deref(),
        )
    }

    fn choose(scheme: Option<&str>, opt_in: Option<&str>) -> Result<Self, TransportRefused> {
        match (scheme, opt_in) {
            (None | Some("https"), _) => Ok(Self::Https),
            (Some("http"), Some("yes")) => Ok(Self::PlainHttpForTests),
            (Some("http"), _) => Err(TransportRefused::PlainHttpNotOptedIn),
            (Some(_), _) => Err(TransportRefused::UnknownScheme),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::PlainHttpForTests => "http",
        }
    }

    pub const fn is_https(self) -> bool {
        matches!(self, Self::Https)
    }

    /// Whether this scheme may be used to call this domain. HTTPS may go anywhere.
    pub fn check_destination(self, domain: &str) -> Result<(), TransportRefused> {
        if self.is_https() || is_local_name(domain, CAN_USE_TEST_NETWORKS) {
            Ok(())
        } else {
            Err(TransportRefused::PlainHttpToPublicName(domain.to_owned()))
        }
    }

    /// This software doesn't terminate TLS itself: a proxy on the same machine does. So outside a
    /// test setup, a plain listener has to be one only this machine can reach.
    pub fn check_listen_address(self, listen: &str) -> Result<(), TransportRefused> {
        if (!self.is_https() && CAN_USE_TEST_NETWORKS) || is_loopback(host_part(listen)) {
            Ok(())
        } else {
            Err(TransportRefused::ListensBeyondThisMachine(
                listen.to_owned(),
            ))
        }
    }
}

/// `name`, `name:port` or `[v6]:port`, without the port or brackets.
fn host_part(domain: &str) -> &str {
    if let Some(rest) = domain.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match domain.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.parse::<u16>().is_ok() => name,
        _ => domain,
    }
}

/// Whether a host's domain, such as `127.0.0.1:7000`, is on this machine itself.
pub fn stays_on_this_machine(domain: &str) -> bool {
    is_loopback(host_part(domain))
}

/// Whether a local API's URL keeps its bearer token off the network: either TLS, or this machine.
pub fn keeps_token_local(url: &str) -> bool {
    match url.split_once("://") {
        Some(("https", _)) => true,
        Some(("http", rest)) => {
            let authority = rest.split('/').next().unwrap_or(rest);
            !authority.contains('@') && is_loopback(host_part(authority))
        }
        _ => false,
    }
}

/// The name `localhost`, or an IP address that stays on this machine. `0.0.0.0` isn't one, because
/// listening there accepts traffic from every network.
pub fn is_loopback(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// A name that can't be looked up on the public internet: loopback, the names reserved for testing,
/// or a single label such as a container's name. A numeric address that isn't loopback is public as
/// far as this goes, because nothing here can tell which networks it crosses.
fn is_local_name(domain: &str, test_networks: bool) -> bool {
    let host = host_part(domain);
    if !test_networks || host.parse::<IpAddr>().is_ok() {
        return is_loopback(host);
    }
    let lower = host.trim_end_matches('.').to_ascii_lowercase();
    !lower.contains('.') || lower.ends_with(".localhost") || lower.ends_with(".test")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_the_default_and_plain_http_needs_the_opt_in() {
        assert_eq!(Scheme::choose(None, None), Ok(Scheme::Https));
        assert_eq!(Scheme::choose(Some("https"), None), Ok(Scheme::Https));
        assert_eq!(
            Scheme::choose(Some("http"), Some("yes")),
            Ok(Scheme::PlainHttpForTests)
        );
        for opt_in in [None, Some(""), Some("no"), Some("YES"), Some("1")] {
            assert_eq!(
                Scheme::choose(Some("http"), opt_in),
                Err(TransportRefused::PlainHttpNotOptedIn),
                "{opt_in:?}"
            );
        }
        for other in ["", "ftp", "HTTP", "http "] {
            assert_eq!(
                Scheme::choose(Some(other), Some("yes")),
                Err(TransportRefused::UnknownScheme),
                "{other:?}"
            );
        }
    }

    #[test]
    fn what_ships_keeps_plain_http_on_this_machine_and_a_test_network_build_stays_off_the_internet()
    {
        for here in [
            "127.0.0.1:7001",
            "127.9.9.9",
            "[::1]:7001",
            "localhost:7001",
            "LOCALHOST",
        ] {
            assert!(is_local_name(here, true), "{here}");
            assert!(is_local_name(here, false), "{here}");
        }
        for test_network in [
            "splint-test-load-small:8080",
            "a.localhost:7001",
            "host-a.test",
            "host-a.test.",
        ] {
            assert!(is_local_name(test_network, true), "{test_network}");
            assert!(!is_local_name(test_network, false), "{test_network}");
        }
    }

    /// `make e2e` runs this in a release build, which is the build that ships.
    #[cfg(not(any(debug_assertions, feature = "test-network")))]
    #[test]
    fn a_release_build_has_no_plain_http_beyond_this_machine() {
        let plain = Scheme::PlainHttpForTests;
        assert_eq!(plain.check_destination("127.0.0.1:7001"), Ok(()));
        assert_eq!(plain.check_listen_address("127.0.0.1:7001"), Ok(()));
        for name in ["host-a", "host-a.test", "a.localhost:7001"] {
            assert!(plain.check_destination(name).is_err(), "{name}");
        }
        for wide in ["0.0.0.0:8080", "[::]:8080", "host-a:8080"] {
            assert!(plain.check_listen_address(wide).is_err(), "{wide}");
        }
    }

    #[test]
    fn the_opt_in_only_reaches_names_that_stay_off_the_internet() {
        let plain = Scheme::PlainHttpForTests;
        assert_eq!(plain.check_destination("127.0.0.1:7001"), Ok(()));
        for public in [
            "host.example",
            "host.example:7001",
            "203-0-113-5.sslip.io",
            "203.0.113.5:443",
            "10.0.0.1:7001",
            "localhost.nowhere.example",
            "test.example",
            "[2001:db8::1]:443",
        ] {
            assert!(plain.check_destination(public).is_err(), "{public}");
            assert_eq!(Scheme::Https.check_destination(public), Ok(()), "{public}");
        }
    }

    #[test]
    fn only_loopback_counts_as_this_machine() {
        for here in [
            "127.0.0.1:7000",
            "127.9.9.9",
            "localhost:7000",
            "[::1]:7000",
        ] {
            assert!(stays_on_this_machine(here), "{here}");
        }
        for there in [
            "example.com:7000",
            "10.0.0.2:7000",
            "localhost.example.com",
            "127.0.0.1.example.com:7000",
            "0.0.0.0:7000",
            "169.254.169.254",
            "a-name",
        ] {
            assert!(!stays_on_this_machine(there), "{there}");
        }
    }

    #[test]
    fn a_token_only_travels_over_tls_or_stays_on_this_machine() {
        for fine in [
            "http://127.0.0.1:7100",
            "http://localhost:7100/",
            "http://[::1]:7100",
            "https://signet.example",
        ] {
            assert!(keeps_token_local(fine), "{fine}");
        }
        for refused in [
            "http://signet.example:7100",
            "http://10.0.0.5:7100",
            "http://user@127.0.0.1:7100",
            "http://127.0.0.1.example:7100",
            "ftp://127.0.0.1",
            "127.0.0.1:7100",
        ] {
            assert!(!keeps_token_local(refused), "{refused}");
        }
    }

    #[test]
    fn a_real_deployment_only_listens_where_this_machine_alone_can_reach() {
        for local in ["127.0.0.1:8080", "[::1]:8080", "localhost:8080"] {
            assert_eq!(Scheme::Https.check_listen_address(local), Ok(()), "{local}");
        }
        for open in ["0.0.0.0:8080", "[::]:8080", "203.0.113.5:80", "host:80"] {
            assert!(Scheme::Https.check_listen_address(open).is_err(), "{open}");
            let plain = Scheme::PlainHttpForTests.check_listen_address(open);
            assert_eq!(plain.is_ok(), CAN_USE_TEST_NETWORKS, "{open}");
        }
    }
}
