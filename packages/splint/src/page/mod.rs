//! `splint page`: a page on the owner's own device, for what an agent can't do itself. It shows
//! who's waiting, what changed and any exchange as readable dialogue, and signs what the owner says.
//!
//! A browser meets this program only over HTTP on loopback, with no shared code. Everything shown
//! is worked out here from what's signed, and the only code that opens the owner's key is
//! `owner-key`, run for each signature, so the key never reaches the browser, Signet or a host. No
//! host ever serves this page, because a host serving it could show one thing and sign another.

pub mod controls;
mod guard;
mod guest_links;
mod server;
pub mod state;
pub mod walk;

use std::io::{self, Write};
use std::sync::Arc;

use splint_core::Identity;
use tokio::sync::Mutex;

use crate::failure::Failure;
use crate::home::Home;
use crate::owner_key::OwnerKey;
use crate::owner_side::OwnerSide;
use crate::secrets::Token;

use self::guard::Guard;

pub struct Page {
    home: Home,
    /// The agent this page is for, if this device signs for one it had to be told.
    named: Option<String>,
    owner: Identity,
    guard: Guard,
    /// Rules are replaced whole, so each change here starts from the last one finished.
    changing_rules: Mutex<()>,
}

/// Stays running until it's stopped, so the link is written out as soon as it works.
pub async fn serve(home: Home, named: Option<&str>) -> Result<String, Failure> {
    OwnerSide::resolve(&home, named, "open the owner's page")?;
    let owner = Identity::from_encoded(&OwnerKey::new(&home).existing_identity()?)?;
    // Only ever loopback: there's no setting to change this, so nothing can leave it open by mistake.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let here = listener.local_addr()?;
    let secret = Token::generate()?;
    let guard = Guard::new(here.to_string(), secret.expose().to_owned());
    let page = Arc::new(Page {
        home,
        named: named.map(str::to_owned),
        owner,
        guard,
        changing_rules: Mutex::new(()),
    });
    // After the #, so it never leaves the browser and is in no request or log.
    let mut out = io::stdout();
    writeln!(
        out,
        "Open this on this device. Anyone holding the link can sign as you, until you stop this:\n\n  \
         http://{here}/#s={}",
        secret.expose()
    )?;
    out.flush()?;
    axum::serve(listener, server::routes(page)).await?;
    Ok("The page has stopped.".to_owned())
}
