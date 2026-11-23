//! Addresses: `name~domain`, such as `ana~splint.example`, or `ana.jeff~splint.example` for ana
//! acting for jeff. See "Addresses" in `docs/protocol.md`.
//!
//! Every signed statement, lookup and comparison uses one spelling of an address, so two strings
//! naming the same agent are always equal. [`parse_address`] takes only that spelling.
//! [`canonical_address`] turns what a person or agent typed into it, and nothing else does.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;

/// Between the name and the domain. It's the one character a URL never escapes, it can't be in a
/// domain, so an address never passes for a web link, and a shell leaves it alone mid-word.
pub const ADDRESS_SEPARATOR: char = '~';
/// Between an agent's handle and its owner's, in `ana.jeff~splint.example`.
pub const OWNER_SEPARATOR: char = '.';
/// Accepted where someone types an address, for a keyboard without an easy `~`. It becomes `~` at
/// once. A name can't hold a colon, so the first `::` always ends it, even before `[::1]`.
pub const TYPED_SEPARATOR: &str = "::";
/// The link form, `splint:ana~splint.example`, for buttons and QR codes.
pub const LINK_SCHEME: &str = "splint:";
/// The email form puts `@` after the tilde, so it still reads as an agent's: `ana~@splint.example`.
const EMAIL_SEPARATOR: &str = "~@";

/// A name and the `~` after it fit an email's local part, which is at most 64 octets.
const MAX_NAME_LEN: usize = 63;
const MAX_DOMAIN_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;
/// Where a domain with no port is called, under HTTPS.
const DEFAULT_PORT: u16 = 443;

/// One handle, an agent's or an owner's: lowercase letters, digits and hyphens.
pub fn is_valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_NAME_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// What's before the `~`: an agent's handle, or `agent.owner`.
pub fn is_valid_name(name: &str) -> bool {
    let (agent, owner) = name_parts(name);
    name.len() <= MAX_NAME_LEN && is_valid_handle(agent) && owner.is_none_or(is_valid_handle)
}

/// The fewest characters in a handle taken with no signup code. There are few short ones, so anyone
/// signing up for nothing can't sweep them all up. Provisional.
pub const MIN_HANDLE_CHARS_WITHOUT_CODE: usize = 3;
/// Handles that would pass for whoever runs a host, or for Splint, so nobody takes one with no signup
/// code. Whoever runs a host can still give one out with a code. Neither does any handle starting
/// `splint`. Provisional.
const RESERVED_HANDLES: &[&str] = &[
    "abuse",
    "account",
    "accounts",
    "admin",
    "administrator",
    "billing",
    "help",
    "helpdesk",
    "host",
    "hostmaster",
    "info",
    "moderator",
    "no-reply",
    "noreply",
    "official",
    "operator",
    "owner",
    "postmaster",
    "root",
    "security",
    "staff",
    "support",
    "system",
    "team",
    "verify",
    "webmaster",
];
const RESERVED_PREFIX: &str = "splint";

/// Whether a host taking agents with no signup code gives out this name that way: each handle in it
/// long enough, and none that would pass for the host or for Splint. Both Splint's hosts and `splint
/// join` go by this, so an agent hears why before it asks.
pub fn may_take_without_code(name: &str) -> bool {
    let (agent, owner) = name_parts(name);
    let allowed = |handle: &str| {
        handle.len() >= MIN_HANDLE_CHARS_WITHOUT_CODE
            && !handle.starts_with(RESERVED_PREFIX)
            && !RESERVED_HANDLES.contains(&handle)
    };
    is_valid_name(name) && allowed(agent) && owner.is_none_or(allowed)
}

/// The agent's handle in a name, and its owner's handle if it has one.
pub fn name_parts(name: &str) -> (&str, Option<&str>) {
    match name.split_once(OWNER_SEPARATOR) {
        Some((agent, owner)) => (agent, Some(owner)),
        None => (name, None),
    }
}

/// Whether two addresses differ at most in the owner part of the name: the same agent's handle at
/// the same host. That's all a new owner can change, as `ana.jeff~host` becoming `ana.ben~host`.
pub fn same_handle_and_host(one: &str, other: &str) -> bool {
    match (parse_address(one), parse_address(other)) {
        (Ok((one_name, one_domain)), Ok((other_name, other_domain))) => {
            one_domain == other_domain && name_parts(one_name).0 == name_parts(other_name).0
        }
        _ => false,
    }
}

/// `ana~splint.example` with `jeff` after its handle, as `ana.jeff~splint.example`: the address an
/// owner's binding names when they give an agent that has no owner part yet theirs. One that has an
/// owner part already keeps it, so this refuses it, as it does a name that wouldn't fit.
pub fn with_owner_part(address: &str, owner_part: &str) -> Result<String, Error> {
    let (name, domain) = parse_address(address)?;
    if name_parts(name).1.is_some() || !is_valid_handle(owner_part) {
        return Err(Error::Malformed);
    }
    let named = format!("{name}{OWNER_SEPARATOR}{owner_part}{ADDRESS_SEPARATOR}{domain}");
    parse_address(&named)?;
    Ok(named)
}

/// Splits `name~domain`, in its one spelling. It's strict because the domain becomes part of a
/// URL, so a fooled agent can't use an address to point Signet at some other path.
pub fn parse_address(address: &str) -> Result<(&str, &str), Error> {
    let Some((name, domain)) = address.split_once(ADDRESS_SEPARATOR) else {
        return Err(not_an_address(address));
    };
    if is_valid_name(name) && canonical_domain(domain)? == domain {
        Ok((name, domain))
    } else {
        Err(Error::Malformed)
    }
}

/// The one spelling of an address someone typed: `~` or `::` between the name and the domain, the
/// link form, or the email form. The domain goes to lowercase without a trailing dot, its port
/// without leading zeros, and an IPv6 literal is written the standard way. A name has only one
/// spelling already, so one that isn't lowercase is refused rather than changed.
pub fn canonical_address(typed: &str) -> Result<String, Error> {
    if typed.contains(EMAIL_SEPARATOR) {
        return email_form(typed);
    }
    let unlinked = typed
        .strip_prefix(LINK_SCHEME)
        .map_or_else(|| typed.to_owned(), from_link);
    let (name, domain) = match unlinked.split_once(ADDRESS_SEPARATOR) {
        Some(parts) => parts,
        None => unlinked
            .split_once(TYPED_SEPARATOR)
            .ok_or_else(|| not_an_address(&unlinked))?,
    };
    if !is_valid_name(name) {
        return Err(Error::Malformed);
    }
    Ok(format!(
        "{name}{ADDRESS_SEPARATOR}{}",
        canonical_domain(domain)?
    ))
}

/// Turns an address into its email form, `ana.jeff~splint.example` into
/// `ana.jeff~@splint.example`, and an email form back into the address: both ways in one place, so
/// they can't drift apart. Only a domain name without a port has an email form, as an email's
/// domain can't carry a port and an IP literal is written differently there.
pub fn email_form(text: &str) -> Result<String, Error> {
    if let Some((name, domain)) = text.split_once(EMAIL_SEPARATOR) {
        let address = format!("{name}{ADDRESS_SEPARATOR}{}", canonical_domain(domain)?);
        email_form(&address)?;
        return Ok(address);
    }
    let (name, domain) = parse_address(text)?;
    let is_ip = domain.starts_with('[')
        || domain
            .rsplit('.')
            .next()
            .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()));
    if is_ip || domain.contains(':') {
        return Err(Error::Malformed);
    }
    Ok(format!("{name}{EMAIL_SEPARATOR}{domain}"))
}

/// The link form of an address, `splint:ana~splint.example`. An IPv6 literal's brackets aren't
/// allowed in that part of a URI, so they're percent-encoded.
pub fn link_form(address: &str) -> Result<String, Error> {
    parse_address(address)?;
    Ok(format!("{LINK_SCHEME}{}", in_link(address)))
}

/// An address inside a link: only an IPv6 literal's brackets need encoding.
pub fn in_link(address: &str) -> String {
    address.replace('[', "%5B").replace(']', "%5D")
}

/// The other way, for the brackets and a colon only, in either case. Any other `%` is left as it
/// is, so the address check after this refuses it.
pub fn from_link(text: &str) -> String {
    let mut address = text.to_owned();
    for (encoded, plain) in [("%5B", "["), ("%5D", "]"), ("%3A", ":")] {
        address = address
            .replace(encoded, plain)
            .replace(&encoded.to_ascii_lowercase(), plain);
    }
    address
}

/// The one spelling of a host's domain: `name`, `name:port` or `[v6]:port`. One place to call has one
/// spelling, because a host is judged by this string: a `block` on `bad.example` has to hold for
/// `bad.example:443` too. So port 443, where a domain with no port is called, is dropped, and what the
/// HTTP client would read as an IPv4 address is refused unless it's written the standard way.
pub fn canonical_domain(typed: &str) -> Result<String, Error> {
    let (host, port) = if let Some(rest) = typed.strip_prefix('[') {
        let (inside, after) = rest.split_once(']').ok_or(Error::Malformed)?;
        let ip: Ipv6Addr = inside.parse().map_err(|_| Error::Malformed)?;
        // `[::ffff:a.b.c.d]` is the IPv4 address it carries, which has a spelling of its own.
        if ip.to_ipv4_mapped().is_some() {
            return Err(Error::Malformed);
        }
        (format!("[{ip}]"), port_after(after)?)
    } else {
        let (name, port) = match typed.split_once(':') {
            Some((name, port)) => (name, Some(port_number(port)?)),
            None => (typed, None),
        };
        (canonical_name(name)?, port)
    };
    let domain = match port {
        Some(port) if port != DEFAULT_PORT => format!("{host}:{port}"),
        _ => host,
    };
    if domain.len() <= MAX_DOMAIN_LEN {
        Ok(domain)
    } else {
        Err(Error::Malformed)
    }
}

/// The old `handle@domain` form is refused by name, so whoever typed it learns the new one.
fn not_an_address(text: &str) -> Error {
    if text.contains('@') {
        Error::OldAddressForm
    } else {
        Error::Malformed
    }
}

fn port_after(after: &str) -> Result<Option<u16>, Error> {
    match after.strip_prefix(':') {
        Some(port) => port_number(port).map(Some),
        None if after.is_empty() => Ok(None),
        None => Err(Error::Malformed),
    }
}

fn port_number(text: &str) -> Result<u16, Error> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::Malformed);
    }
    match text.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(Error::Malformed),
    }
}

/// Dot-separated labels of letters, digits and hyphens, which covers an IPv4 address too.
fn canonical_name(typed: &str) -> Result<String, Error> {
    let name = typed
        .strip_suffix('.')
        .unwrap_or(typed)
        .to_ascii_lowercase();
    let labels_ok = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LEN
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        });
    if labels_ok && (!ends_in_a_number(&name) || name.parse::<Ipv4Addr>().is_ok()) {
        Ok(name)
    } else {
        Err(Error::Malformed)
    }
}

/// Whether a URL reads this name as an IPv4 address, as it does `2130706433`, `127.1` and `0x7f.1`: by
/// its last label being a number, in decimal or hex. No real domain ends in one.
fn ends_in_a_number(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    last.bytes().all(|byte| byte.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name has to fit an email's local part and a domain the DNS, at the edge and one past it.
    #[test]
    fn names_labels_and_domains_have_a_longest() {
        let label = |len: usize| "a".repeat(len);
        assert!(parse_address(&format!("{}~host.example", label(MAX_NAME_LEN))).is_ok());
        assert!(parse_address(&format!("{}~host.example", label(MAX_NAME_LEN + 1))).is_err());
        let half = MAX_NAME_LEN / 2;
        let owned = format!("{}.{}", label(half), label(MAX_NAME_LEN - half - 1));
        assert!(parse_address(&format!("{owned}~host.example")).is_ok());
        assert!(parse_address(&format!("{owned}a~host.example")).is_err());
        assert!(parse_address(&format!("ana~{}.example", label(MAX_LABEL_LEN))).is_ok());
        assert!(parse_address(&format!("ana~{}.example", label(MAX_LABEL_LEN + 1))).is_err());
        let domain = |len: usize| {
            let labels = vec![label(MAX_LABEL_LEN); len / (MAX_LABEL_LEN + 1)];
            let mut domain = labels.join(".");
            let left = len - domain.len();
            if left > 1 {
                domain.push('.');
                domain.push_str(&label(left - 1));
            }
            domain
        };
        assert_eq!(domain(MAX_DOMAIN_LEN).len(), MAX_DOMAIN_LEN);
        assert!(parse_address(&format!("ana~{}", domain(MAX_DOMAIN_LEN))).is_ok());
        assert!(parse_address(&format!("ana~{}", domain(MAX_DOMAIN_LEN + 2))).is_err());
    }

    #[test]
    fn one_spelling_parses_and_typed_ones_become_it() {
        for (typed, canonical) in [
            ("ana~splint.example", "ana~splint.example"),
            ("ana.jeff~splint.example", "ana.jeff~splint.example"),
            ("ana::splint.example", "ana~splint.example"),
            ("ana.jeff::Splint.Example", "ana.jeff~splint.example"),
            ("splint:ana~splint.example", "ana~splint.example"),
            ("splint:ana~%5B::1%5D:7001", "ana~[::1]:7001"),
            ("splint:ana::splint.example", "ana~splint.example"),
            ("ana~@splint.example", "ana~splint.example"),
            ("ana.jeff~@Splint.Example.", "ana.jeff~splint.example"),
            ("ana~Splint.EXAMPLE.", "ana~splint.example"),
            ("ana~splint.example.:07001", "ana~splint.example:7001"),
            ("ana~127.0.0.1:53124", "ana~127.0.0.1:53124"),
            ("ana::127.0.0.1:53124", "ana~127.0.0.1:53124"),
            ("ana~[::1]:7001", "ana~[::1]:7001"),
            ("ana::[::1]:7001", "ana~[::1]:7001"),
            ("ana~[0:0::0001]", "ana~[::1]"),
            ("ana~[FE80::A]:8080", "ana~[fe80::a]:8080"),
            // Bug caught: `host:443` is the same place as `host`, so a block on one missed the other.
            ("ana~splint.example:443", "ana~splint.example"),
            ("ana~Splint.Example.:0443", "ana~splint.example"),
            ("ana~127.0.0.1:443", "ana~127.0.0.1"),
            ("ana~[::1]:443", "ana~[::1]"),
            ("a-1~host", "a-1~host"),
        ] {
            assert_eq!(
                canonical_address(typed).as_deref(),
                Ok(canonical),
                "{typed}"
            );
            assert!(parse_address(canonical).is_ok(), "{canonical}");
            assert_eq!(parse_address(typed).is_ok(), typed == canonical, "{typed}");
        }
        assert_eq!(parse_address("ana~[::1]:7001"), Ok(("ana", "[::1]:7001")));
        assert_eq!(parse_address("ana.jeff~host"), Ok(("ana.jeff", "host")));
        assert_eq!(name_parts("ana.jeff"), ("ana", Some("jeff")));
        assert_eq!(name_parts("ana"), ("ana", None));
    }

    #[test]
    fn anything_else_is_refused() {
        let longest = "a".repeat(MAX_NAME_LEN);
        let too_long = format!("{longest}a~host");
        assert!(parse_address(&format!("{longest}~host")).is_ok());
        for typed in [
            "ana",
            "~host",
            "ana~",
            "ana:host",
            "ana~~host",
            "ana~host~x",
            "a~b~host",
            "a:b::host",
            "a:b~host",
            "ana:::host",
            "ana~a::b",
            "ana~host:",
            "ana~host:0",
            "ana~host:65536",
            "ana~host:+80",
            "ana~host:80:80",
            "ana~host..example",
            "ana~.host",
            "ana~host..",
            "ana~host/admin",
            "ana~host?x",
            "ana~host#x",
            "ana~us er@host",
            "ana~[::1",
            "ana~[::1]x",
            "ana~[::1%eth0]",
            "ana~[127.0.0.1]",
            "ana~::1",
            // Bug caught: each is 127.0.0.1 or 8.8.8.8 to the HTTP client, and another name to a list.
            "ana~2130706433",
            "ana~127.1",
            "ana~0x7f.1",
            "ana~0x7f.0.0.1",
            "ana~0177.0.0.1",
            "ana~127.0.0.01",
            "ana~1.2.3.4.5",
            "ana~host.0x",
            "ana~host.123",
            "ana~[::ffff:8.8.8.8]",
            "ana~[::ffff:808:808]:7001",
            "Ana~host",
            "ana~ host",
            " ana~host",
            ".ana~host",
            "ana.~host",
            "ana..jeff~host",
            "ana.jeff.bob~host",
            "ana.Jeff~host",
            "ana+x~host",
            "ana_x~host",
            "splint:ana~host/x",
            "splint:splint:ana~host",
            "splint:ana%7Ehost",
            &too_long,
        ] {
            assert!(canonical_address(typed).is_err(), "{typed}");
            assert!(parse_address(typed).is_err(), "{typed}");
        }
    }

    #[test]
    fn the_old_form_is_refused_by_name() {
        for old in ["ana@splint.example", "ana@127.0.0.1:7001"] {
            assert_eq!(parse_address(old), Err(Error::OldAddressForm));
            assert_eq!(canonical_address(old), Err(Error::OldAddressForm));
        }
    }

    /// RFC 5322's dot-atom: `atext` runs separated by single dots, where `atext` includes `~`.
    /// RFC 5321 limits the local part to 64 octets and makes the domain a hostname.
    fn is_plain_email(email: &str) -> bool {
        let atext =
            |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte);
        let Some((local, domain)) = email.rsplit_once('@') else {
            return false;
        };
        let dot_atom = |text: &str| {
            text.split('.')
                .all(|run| !run.is_empty() && run.bytes().all(atext))
        };
        let hostname = domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
        local.len() <= 64 && dot_atom(local) && hostname
    }

    #[test]
    fn the_email_form_goes_both_ways_and_is_a_plain_email_address() {
        let longest = format!("{}.{}~splint.example", "a".repeat(30), "b".repeat(32));
        for address in [
            "ana~splint.example",
            "ana.jeff~splint.example",
            "a-1.b-2~mail.splint.example",
            &longest,
        ] {
            let email = email_form(address).unwrap();
            assert!(is_plain_email(&email), "{email}");
            assert_eq!(email_form(&email).as_deref(), Ok(address), "{email}");
            assert_eq!(canonical_address(&email).as_deref(), Ok(address));
        }
        assert_eq!(
            email_form("ana.jeff~splint.example").as_deref(),
            Ok("ana.jeff~@splint.example")
        );
        assert_eq!(
            email_form("ana~@Splint.Example.").as_deref(),
            Ok("ana~splint.example")
        );
        for no_email_form in [
            "ana~127.0.0.1",
            "ana~host.example:7001",
            "ana~[::1]",
            "ana~@host.example:7001",
            "ana~@[::1]",
            "ana@host.example",
            "Ana~@host.example",
            "ana~@@host.example",
            "ana~@",
        ] {
            assert!(email_form(no_email_form).is_err(), "{no_email_form}");
        }
    }

    #[test]
    fn the_link_form_reads_back_as_the_address() {
        for address in ["ana~splint.example", "ana.jeff~host:7001", "ana~[::1]:7001"] {
            let link = link_form(address).unwrap();
            assert!(!link.contains(['[', ']']), "{link}");
            assert_eq!(canonical_address(&link).as_deref(), Ok(address), "{link}");
        }
        assert_eq!(
            link_form("ana~splint.example").as_deref(),
            Ok("splint:ana~splint.example")
        );
        assert!(link_form("ana~Splint.example").is_err());
    }
}
