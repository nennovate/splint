//! Names this host's operator keeps back, from the file `SPLINT_RESERVED_NAMES` names: words, such as
//! a brand, that nobody here has as a name of their own, alone or after an agent's handle as an owner's
//! name, though any agent can have one as its handle, as `word.ana`. One a line, and `#` starts a
//! comment. Splint names none itself, so what's kept back is the operator's choice, read at each start.
//! Provisional.

use std::collections::HashSet;
use std::sync::Arc;
use std::{env, fs};

use splint_core::is_valid_handle;

use crate::operator::SettingError;

pub const SETTING: &str = "SPLINT_RESERVED_NAMES";

#[derive(Debug, thiserror::Error)]
enum KeptNamesError {
    #[error("the file it names can't be read")]
    Unreadable,
    #[error("line {0} isn't one name of lowercase letters, digits and hyphens")]
    NotAName(usize),
}

#[derive(Clone, Default)]
pub struct KeptNames(Arc<HashSet<String>>);

impl KeptNames {
    /// What the operator named, or nothing where they named no file. A file that's named and can't be
    /// read, or holds a line that isn't a name, stops the start, so nothing is let through unseen.
    pub fn at_start() -> Result<Self, SettingError> {
        let Some(path) = env::var_os(SETTING) else {
            return Ok(Self::default());
        };
        let text = fs::read_to_string(path)
            .map_err(|_| SettingError::refused(SETTING, KeptNamesError::Unreadable))?;
        Self::from_text(&text).map_err(|why| SettingError::refused(SETTING, why))
    }

    fn from_text(text: &str) -> Result<Self, KeptNamesError> {
        let mut names = HashSet::new();
        for (index, line) in text.lines().enumerate() {
            let name = line.split('#').next().unwrap_or_default().trim();
            if name.is_empty() {
                continue;
            }
            if !is_valid_handle(name) {
                return Err(KeptNamesError::NotAName(index.saturating_add(1)));
            }
            names.insert(name.to_owned());
        }
        Ok(Self(Arc::new(names)))
    }

    pub fn holds(&self, name: &str) -> bool {
        self.0.contains(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug caught: a line with a capital or a stray character read as some other name, so the name the
    /// operator meant to keep back was given out.
    #[test]
    fn a_line_that_isnt_a_name_is_refused_rather_than_read_as_another() {
        let kept = KeptNames::from_text("# brands\nacme\n\n  widget-co  # theirs\n").unwrap();
        assert!(kept.holds("acme") && kept.holds("widget-co") && !kept.holds("ana"));
        assert!(KeptNames::from_text("Acme\n").is_err());
        assert!(KeptNames::from_text("acme corp\n").is_err());
    }
}
