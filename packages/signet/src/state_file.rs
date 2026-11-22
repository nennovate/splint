//! Small JSON files that Signet keeps across restarts.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use splint_core::private_files;

#[derive(Debug)]
pub struct StateError;

impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("couldn't read or write Signet's state files")
    }
}

impl std::error::Error for StateError {}

pub fn load<V: DeserializeOwned>(path: &Path) -> Result<HashMap<String, V>, StateError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| StateError),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(HashMap::new()),
        Err(_) => Err(StateError),
    }
}

/// Writes to a temporary file first, so a crash can't leave half a file behind. It holds signed steps,
/// rules and who an agent deals with, and an agent mustn't read them.
pub fn save<K: Serialize, V: Serialize>(
    path: &Path,
    values: &HashMap<K, V>,
) -> Result<(), StateError> {
    let bytes = serde_json::to_vec(values).map_err(|_| StateError)?;
    let temporary = path.with_extension("tmp");
    let write = || -> std::io::Result<()> {
        let mut file = private_files::open(
            OpenOptions::new().write(true).create(true).truncate(true),
            &temporary,
        )?;
        // One left behind by an earlier version keeps its mode when it's opened.
        private_files::restrict(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    };
    write().map_err(|_| StateError)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn state_is_readable_only_by_who_runs_signet_even_over_a_wider_file() {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!("signet-state-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("state.json");
        let wide = fs::Permissions::from_mode(0o644);
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, wide.clone()).unwrap();
        fs::write(path.with_extension("tmp"), "{}").unwrap();
        fs::set_permissions(path.with_extension("tmp"), wide).unwrap();

        save(&path, &HashMap::from([("a", 1)])).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        fs::remove_dir_all(&directory).unwrap();
    }
}
