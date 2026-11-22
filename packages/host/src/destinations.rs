//! Where this host may call another host: for a delivery, a host key, a lookup, or a retirement or
//! recovery passed on.
//!
//! Hosts are open to each other, so anyone can make this host call a name of their choosing: by
//! naming it as a delivery's sending host, as an agent's recipient host or in an address to look up.
//! A name alone must not reach a service on this host's own network, or have it scan ports. So a host
//! its operator names with `peer` may be anywhere, on any port, and any other host has to be on port
//! 443 at public addresses only. Both are judged from the URL as the HTTP client reads it, so a
//! numeric name such as `2130706433` is judged as the address it is. A name is resolved by a resolver
//! that drops every address that isn't public, and the connection goes only to what it returned, so
//! a second lookup can't answer differently.
//!
//! No call to another host goes through a proxy, which would resolve names itself and pass the check
//! by. A call to this host's own name, which only its operator chooses, still goes the way the
//! machine's settings say, as every call did before: a host behind a proxy reaches itself through it.

use std::error::Error as StdError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{Client, RequestBuilder, Url};
use splint_core::canonical_domain;
use splint_core::transport::{Scheme, TransportRefused};

use crate::{Host, PEER_TIMEOUT, release};

/// Only `yes` turns it on. Off, a host this one hasn't named must be on public addresses, on port 443.
pub const INTERNAL_SETTING: &str = "SPLINT_ALLOW_INTERNAL_HOSTS";
const INTERNAL_YES: &str = "yes";
/// The one port a host this one hasn't named may be called on, under HTTPS.
const OPEN_PORT: u16 = 443;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CallRefused {
    #[error("that isn't a host's domain")]
    NotADomain,
    #[error("this host doesn't exchange with that host")]
    NotExchanged,
    #[error(transparent)]
    Transport(#[from] TransportRefused),
    #[error("a host this one doesn't name has to be on a public address")]
    NotPublic,
    #[error("a host this one doesn't name has to be on port 443")]
    NotTheOpenPort,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{INTERNAL_SETTING} must be yes, or not set")]
pub struct InternalSettingError;

/// Whether hosts this one doesn't name may be on internal addresses and other ports, as for an open
/// network on a local network. Off unless set to `yes`, and anything else stops the host.
pub fn internal_allowed_from(setting: Option<&str>) -> Result<bool, InternalSettingError> {
    match setting {
        None | Some("") => Ok(false),
        Some(INTERNAL_YES) => Ok(true),
        Some(_) => Err(InternalSettingError),
    }
}

/// The ways out: to this host's own name, as the machine's settings say; to hosts the operator named,
/// wherever they are; and to every other host, whose names resolve to public addresses only.
pub struct Callers {
    own: Client,
    anywhere: Client,
    public_only: Client,
    internal_allowed: bool,
}

impl Callers {
    pub fn new(scheme: Scheme, internal_allowed: bool) -> Result<Self, reqwest::Error> {
        // A redirect would send a call somewhere nothing here judged.
        let builder = || {
            Client::builder()
                .timeout(PEER_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .https_only(scheme.is_https())
                .default_headers(release::caller_headers())
        };
        // Plain HTTP is only for this machine, so it never goes to a proxy either.
        let own = if scheme.is_https() {
            builder()
        } else {
            builder().no_proxy()
        };
        Ok(Self {
            own: own.build()?,
            anywhere: builder().no_proxy().build()?,
            public_only: builder()
                .no_proxy()
                .dns_resolver(Arc::new(PublicOnly))
                .build()?,
            internal_allowed,
        })
    }
}

/// A call this host may make, with the client that may make it.
pub struct Call<'a> {
    client: &'a Client,
    url: Url,
}

impl Call<'_> {
    pub fn get(self) -> RequestBuilder {
        self.client.get(self.url)
    }

    pub fn post(self) -> RequestBuilder {
        self.client.post(self.url)
    }
}

impl Host {
    /// A call to `path` at another host, if this host may make it now. Every call to another host goes
    /// through this, under the peers file as it is at that moment.
    pub fn call(&self, domain: &str, path: &str) -> Result<Call<'_>, CallRefused> {
        if canonical_domain(domain).ok().as_deref() != Some(domain) {
            return Err(CallRefused::NotADomain);
        }
        let list = self.peers.current();
        if !list.exchanges_with(domain) {
            return Err(CallRefused::NotExchanged);
        }
        // Under the plain-HTTP test scheme this keeps every call on this machine.
        self.scheme.check_destination(domain)?;
        let url = Url::parse(&format!("{}://{domain}{path}", self.scheme.as_str()))
            .map_err(|_| CallRefused::NotADomain)?;
        if domain == self.domain {
            return Ok(Call {
                client: &self.calls.own,
                url,
            });
        }
        let anywhere = list.names(domain) || !self.scheme.is_https() || self.calls.internal_allowed;
        if anywhere {
            return Ok(Call {
                client: &self.calls.anywhere,
                url,
            });
        }
        check_public(&url)?;
        Ok(Call {
            client: &self.calls.public_only,
            url,
        })
    }
}

/// What a host this one doesn't name must be: a name, which the resolver judges, or a public address,
/// on port 443. The URL's own reading of the host is what's judged, because that's what's called.
fn check_public(url: &Url) -> Result<(), CallRefused> {
    let host = url.host_str().ok_or(CallRefused::NotADomain)?;
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>()
        && !is_public(ip)
    {
        return Err(CallRefused::NotPublic);
    }
    if url.port_or_known_default() != Some(OPEN_PORT) {
        return Err(CallRefused::NotTheOpenPort);
    }
    Ok(())
}

/// What hosts likely in one party's hands have in common, as far as a name can say: the last two labels
/// of a name, so every `sN.evil.example` under one wildcard is one family, and one network for an IPv6
/// address, of which a server has plenty. An IPv4 address is its own. There's no list of public
/// suffixes here, so hosts under `co.uk` count as one family too, which only ever costs them a wait.
pub fn family_of(domain: &str) -> String {
    let Ok(url) = Url::parse(&format!("https://{domain}")) else {
        return domain.to_owned();
    };
    let Some(host) = url.host_str() else {
        return domain.to_owned();
    };
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    match unbracketed.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => domain.to_owned(),
        Ok(IpAddr::V6(ip)) => {
            let [a, b, c, d, ..] = ip.segments();
            format!("{a:x}:{b:x}:{c:x}:{d:x}")
        }
        Err(_) => {
            let mut labels = host.rsplit('.');
            match (labels.next(), labels.next()) {
                (Some(last), Some(before)) => format!("{before}.{last}"),
                _ => host.to_owned(),
            }
        }
    }
}

/// Resolves a name to its public addresses only, and fails if it has none.
struct PublicOnly;

#[derive(Debug, thiserror::Error)]
#[error("that name has no public address")]
struct NoPublicAddress;

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        let name = name.as_str().to_owned();
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let public: Vec<SocketAddr> = found.filter(|found| is_public(found.ip())).collect();
            if public.is_empty() {
                return Err(Box::new(NoPublicAddress) as Box<dyn StdError + Send + Sync>);
            }
            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

/// Whether an address is one the public internet routes to. Std has no stable test for this, so it's
/// written out here, erring on the side of refusing: a real host is never on any of these.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        // `::ffff:a.b.c.d` reaches the IPv4 address it carries, so that's what's judged.
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| is_public_v6(ip), is_public_v4),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0 // this network, and unspecified
        || a == 10 // private
        || a == 127 // loopback
        || (a == 100 && (64..128).contains(&b)) // shared, as carrier-grade NAT uses
        || (a == 169 && b == 254) // link-local, where cloud metadata services sit
        || (a == 172 && (16..32).contains(&b)) // private
        || (a == 192 && b == 0 && c == 0) // protocol assignments
        || (a == 192 && b == 0 && c == 2) // documentation
        || (a == 192 && b == 88 && c == 99) // 6to4 relays
        || (a == 192 && b == 168) // private
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 198 && b == 51 && c == 100) // documentation
        || (a == 203 && b == 0 && c == 113) // documentation
        || a >= 224; // multicast, reserved and broadcast
    !reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let [first, second, ..] = ip.segments();
    // Only global unicast, 2000::/3, is public. That leaves out unspecified, loopback, IPv4-compatible,
    // NAT64, discard, unique-local, link-local and multicast addresses at once.
    let global_unicast = first & 0xe000 == 0x2000;
    // 2001::/23 holds protocol assignments, Teredo among them, and 2001:db8::/32 is documentation.
    let protocol = first == 0x2001 && (second < 0x0200 || second == 0x0db8);
    let reserved = protocol
        || first == 0x2002 // 6to4, which reaches an IPv4 address
        || (first == 0x3fff && second < 0x1000); // documentation
    global_unicast && !reserved
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::peering::{PeerList, Peers};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    /// Bug: a range left out lets anyone point this host at a service on its own network, such as a
    /// cloud metadata service, by naming that address as a host. Each range is tried at both ends and
    /// just outside them.
    #[test]
    fn only_addresses_the_internet_routes_to_are_public() {
        for refused in [
            "0.0.0.0",
            "0.255.255.255",
            "10.0.0.0",
            "10.255.255.255",
            "100.64.0.0",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.255",
            "169.254.0.0",
            "169.254.169.254",
            "169.254.255.255",
            "172.16.0.0",
            "172.31.255.255",
            "192.0.0.0",
            "192.0.0.255",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.0",
            "192.168.255.255",
            "198.18.0.0",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:1ff:ffff::1",
            "2001:db8::1",
            "2002:7f00:1::1",
            "3fff::1",
            "3fff:fff::1",
            "fc00::1",
            "fdff:ffff::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "4000::1",
        ] {
            assert!(!is_public(ip(refused)), "{refused}");
        }
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "9.255.255.255",
            "11.0.0.0",
            "100.63.255.255",
            "100.128.0.0",
            "126.255.255.255",
            "128.0.0.0",
            "169.253.255.255",
            "169.255.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "192.0.1.1",
            "192.167.255.255",
            "192.169.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "223.255.255.255",
            "::ffff:8.8.8.8",
            "2001:200::1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2a00:1450::1",
            "3ffe::1",
            "3fff:1000::1",
        ] {
            assert!(is_public(ip(public)), "{public}");
        }
    }

    async fn https_host(peers: &str) -> Host {
        let mut host = Host::with_closed_database("here.example").await.unwrap();
        host.scheme = Scheme::Https;
        host.calls = Callers::new(Scheme::Https, false).unwrap();
        host.peers = Peers::new(PeerList::parse(peers, "here.example", Scheme::Https).unwrap());
        host
    }

    /// Bug: a host is judged by the string it was named by, while the HTTP client reads `2130706433`,
    /// `127.1` or `0x7f.1` as 127.0.0.1, so any of them reaches this machine. Or `bad.example:443` gets
    /// past a block on `bad.example`, though it's the same place. Or a host nobody named is called on
    /// any port, which makes this host a scanner.
    #[tokio::test]
    async fn a_host_nobody_named_is_judged_as_the_client_reads_it() {
        let host = https_host("peer 10.0.0.5:8443\nblock Blocked.Example.:443\n").await;
        for refused in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "[::1]",
            "[fe80::1]",
            "[fd00::1]",
        ] {
            assert_eq!(
                host.call(refused, "/").err(),
                Some(CallRefused::NotPublic),
                "{refused}"
            );
            assert_eq!(
                host.call(&format!("{refused}:8443"), "/").err(),
                Some(CallRefused::NotPublic),
                "{refused}:8443"
            );
        }
        for other_port in ["host.example:8443", "8.8.8.8:22", "[2606:4700::1]:5432"] {
            assert_eq!(
                host.call(other_port, "/").err(),
                Some(CallRefused::NotTheOpenPort),
                "{other_port}"
            );
        }
        for not_a_domain in [
            "Host.Example",
            "host.example:443x",
            "",
            "a b",
            "1.2.3.4.5",
            "2130706433",
            "127.1",
            "0x7f.1",
            "0177.0.0.1",
            "10.1",
            "[::ffff:127.0.0.1]",
            "[::ffff:169.254.169.254]",
            "blocked.example:443",
            "BLOCKED.example.:443",
        ] {
            assert_eq!(
                host.call(not_a_domain, "/").err(),
                Some(CallRefused::NotADomain),
                "{not_a_domain}"
            );
        }
        assert_eq!(
            host.call("blocked.example", "/").err(),
            Some(CallRefused::NotExchanged)
        );
        // Controls: a public name or address on 443, and a named peer wherever it is.
        for allowed in ["host.example", "8.8.8.8", "[2606:4700::1]", "10.0.0.5:8443"] {
            assert!(host.call(allowed, "/").is_ok(), "{allowed}");
        }
    }

    /// Bug: a name that resolves to this machine or its network gets through, because only the name
    /// was judged.
    #[tokio::test]
    async fn a_name_resolves_to_public_addresses_only() {
        let resolve = |name: &str| PublicOnly.resolve(name.parse().unwrap());
        for internal in ["localhost", "127.0.0.1", "10.0.0.1"] {
            assert!(resolve(internal).await.is_err(), "{internal}");
        }
        // Control: an address that is public comes back, so the refusals aren't the resolver failing.
        let found: Vec<SocketAddr> = resolve("8.8.8.8").await.unwrap().collect();
        assert_eq!(found, [SocketAddr::from(([8, 8, 8, 8], 0))]);
    }

    /// Bug: subdomains of one wildcard, or a server's many IPv6 addresses, count as many parties, so one
    /// party takes every place meant to be shared. Or unrelated hosts count as one and wait for each other.
    #[test]
    fn one_partys_hosts_are_one_family() {
        for (one, other) in [
            ("s1.evil.example", "s2.evil.example"),
            ("a.b.evil.example", "evil.example"),
            ("evil.example:8443", "evil.example"),
            ("[2606:4700::1]", "[2606:4700::2]:8443"),
        ] {
            assert_eq!(family_of(one), family_of(other), "{one} and {other}");
        }
        for (one, other) in [
            ("evil.example", "good.example"),
            ("host.one", "host.two"),
            ("8.8.8.8", "8.8.4.4"),
            ("[2606:4700::1]", "[2606:4700:0:1::1]"),
        ] {
            assert_ne!(family_of(one), family_of(other), "{one} and {other}");
        }
    }

    #[test]
    fn only_yes_lets_unnamed_hosts_be_internal() {
        assert_eq!(internal_allowed_from(None), Ok(false));
        assert_eq!(internal_allowed_from(Some("")), Ok(false));
        assert_eq!(internal_allowed_from(Some("yes")), Ok(true));
        for refused in ["no", "YES", "1", "true"] {
            assert_eq!(
                internal_allowed_from(Some(refused)),
                Err(InternalSettingError),
                "{refused}"
            );
        }
    }
}
