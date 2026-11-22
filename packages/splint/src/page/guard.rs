//! Who may talk to the page: this device's browser, on this page, holding this run's secret.
//!
//! The page listens on loopback, but any website the owner visits can make their browser call
//! loopback, and a name of an attacker's can be pointed at it. So every request must name this exact
//! address as its host, which stops a rebound name, and must come from this page's own origin. A call
//! also needs the secret in a header, which a browser won't let another site add without asking, and
//! this page never says yes to that.

use axum::http::header::{AUTHORIZATION, HOST, ORIGIN};
use axum::http::{HeaderMap, Method};
use splint_core::secrets_match;

const BEARER: &str = "Bearer ";
const SEC_FETCH_SITE: &str = "sec-fetch-site";
const SAME_ORIGIN: &str = "same-origin";
/// What a browser says when a person opened the link themselves.
const OPENED_BY_A_PERSON: &str = "none";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    WrongHost,
    OtherOrigin,
    NoSecret,
}

pub struct Guard {
    host: String,
    origin: String,
    secret: String,
}

impl Guard {
    pub fn new(host: String, secret: String) -> Self {
        Self {
            origin: format!("http://{host}"),
            host,
            secret,
        }
    }

    /// For anything at all, the page's own files included.
    pub fn check_request(&self, headers: &HeaderMap) -> Result<(), Refusal> {
        let mut hosts = headers.get_all(HOST).iter();
        match (hosts.next(), hosts.next()) {
            (Some(host), None) if host.as_bytes() == self.host.as_bytes() => {}
            _ => return Err(Refusal::WrongHost),
        }
        if let Some(origin) = headers.get(ORIGIN)
            && origin.as_bytes() != self.origin.as_bytes()
        {
            return Err(Refusal::OtherOrigin);
        }
        match headers.get(SEC_FETCH_SITE).map(|site| site.as_bytes()) {
            None => Ok(()),
            Some(site) if site == SAME_ORIGIN.as_bytes() => Ok(()),
            Some(site) if site == OPENED_BY_A_PERSON.as_bytes() => Ok(()),
            Some(_) => Err(Refusal::OtherOrigin),
        }
    }

    /// For the calls that read or do something. A change must also carry this page's own origin,
    /// which a browser adds to every one and a script can't change.
    pub fn check_call(&self, method: &Method, headers: &HeaderMap) -> Result<(), Refusal> {
        self.check_request(headers)?;
        let secret = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix(BEARER))
            .ok_or(Refusal::NoSecret)?;
        if !secrets_match(secret.as_bytes(), self.secret.as_bytes()) {
            return Err(Refusal::NoSecret);
        }
        if method != Method::GET && headers.get(ORIGIN).is_none() {
            return Err(Refusal::OtherOrigin);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    const HOST_HERE: &str = "127.0.0.1:4242";
    const ORIGIN_HERE: &str = "http://127.0.0.1:4242";
    const SECRET: &str = "a-secret-for-this-test";

    fn guard() -> Guard {
        Guard::new(HOST_HERE.to_owned(), SECRET.to_owned())
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    fn honest() -> Vec<(&'static str, &'static str)> {
        vec![
            ("host", HOST_HERE),
            ("origin", ORIGIN_HERE),
            ("sec-fetch-site", "same-origin"),
            ("authorization", "Bearer a-secret-for-this-test"),
        ]
    }

    fn with(name: &'static str, value: &'static str) -> Vec<(&'static str, &'static str)> {
        let mut pairs = honest();
        pairs.retain(|(found, _)| *found != name);
        pairs.push((name, value));
        pairs
    }

    #[test]
    fn this_page_calling_itself_gets_through() {
        assert_eq!(
            guard().check_call(&Method::POST, &headers(&honest())),
            Ok(())
        );
    }

    #[test]
    fn a_name_rebound_to_loopback_is_refused() {
        for host in ["evil.example", "evil.example:4242", "localhost:4242"] {
            let call = guard().check_call(&Method::GET, &headers(&with("host", host)));
            assert_eq!(call, Err(Refusal::WrongHost), "{host}");
        }
        let two = [("host", HOST_HERE), ("host", "evil.example")];
        assert_eq!(
            guard().check_request(&headers(&two)),
            Err(Refusal::WrongHost)
        );
        assert_eq!(
            guard().check_request(&HeaderMap::new()),
            Err(Refusal::WrongHost)
        );
    }

    #[test]
    fn another_site_is_refused_even_holding_the_secret() {
        for origin in [
            "https://evil.example",
            "null",
            "http://127.0.0.1:4243",
            "http://localhost:4242",
        ] {
            let call = guard().check_call(&Method::POST, &headers(&with("origin", origin)));
            assert_eq!(call, Err(Refusal::OtherOrigin), "{origin}");
        }
        for site in ["cross-site", "same-site"] {
            let call = guard().check_call(&Method::POST, &headers(&with("sec-fetch-site", site)));
            assert_eq!(call, Err(Refusal::OtherOrigin), "{site}");
        }
    }

    #[test]
    fn a_change_has_to_say_where_it_came_from() {
        let mut pairs = honest();
        pairs.retain(|(name, _)| *name != "origin");
        assert_eq!(guard().check_call(&Method::GET, &headers(&pairs)), Ok(()));
        assert_eq!(
            guard().check_call(&Method::POST, &headers(&pairs)),
            Err(Refusal::OtherOrigin)
        );
    }

    #[test]
    fn every_call_needs_the_secret() {
        for wrong in [
            "Bearer wrong",
            "Bearer ",
            SECRET,
            "Basic a-secret-for-this-test",
        ] {
            let call = guard().check_call(&Method::GET, &headers(&with("authorization", wrong)));
            assert_eq!(call, Err(Refusal::NoSecret), "{wrong}");
        }
        let mut pairs = honest();
        pairs.retain(|(name, _)| *name != "authorization");
        assert_eq!(
            guard().check_call(&Method::GET, &headers(&pairs)),
            Err(Refusal::NoSecret)
        );
    }

    #[test]
    fn the_page_itself_opens_with_no_secret_from_a_person_only() {
        let opened = [("host", HOST_HERE), ("sec-fetch-site", "none")];
        assert_eq!(guard().check_request(&headers(&opened)), Ok(()));
        let framed = [("host", HOST_HERE), ("sec-fetch-site", "cross-site")];
        assert_eq!(
            guard().check_request(&headers(&framed)),
            Err(Refusal::OtherOrigin)
        );
    }
}
