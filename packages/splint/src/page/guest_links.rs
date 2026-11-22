//! One-use links this owner made, kept on their own device so one can be copied again until it ends.
//! Each holds a key that can only answer its own offer, so it's kept with the same care as a token.

use std::fs;
use std::io::ErrorKind;

use crate::failure::Failure;
use crate::home::Home;
use crate::secrets::write_private;

use super::state::SavedLink;

fn read(home: &Home) -> Result<Vec<SavedLink>, Failure> {
    match fs::read(home.guest_links_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| Failure::refused("the links kept on this device can't be read")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

/// What hasn't ended, newest first.
pub fn kept(home: &Home, now: u64) -> Result<Vec<SavedLink>, Failure> {
    let mut links = read(home)?;
    links.retain(|link| link.deadline > now);
    links.reverse();
    Ok(links)
}

/// Adds one, and lets go of what's ended.
pub fn keep(home: &Home, link: SavedLink, now: u64) -> Result<(), Failure> {
    let mut links = read(home)?;
    links.retain(|held| held.deadline > now);
    links.push(link);
    let bytes =
        serde_json::to_vec(&links).map_err(|_| Failure::refused("couldn't write down the link"))?;
    write_private(&home.guest_links_file(), &bytes)?;
    Ok(())
}
