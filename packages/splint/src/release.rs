//! `splint verify`: checks the programs installed beside this one against the release they came
//! from, and the protocol this program speaks to its host and Signet.
//!
//! It runs as the `splint` it checks, so a changed `splint` could say all is well. The release's own
//! `install.sh --verify` checks the same files without running anything installed. See "What a
//! release proves" in `docs/how-it-works.md`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::redirect;
use splint_core::release::{
    OtherProtocol, PROTOCOL, PROTOCOL_HEADER, PROTOCOLS_HEADER, REPOSITORY as REPO, SPOKEN,
    check_protocol, commit, release_version, sha256_of_file,
};

use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::services::beside_this_program;
use crate::signet_api::SignetApi;

const SUMS: &str = "SHA256SUMS";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
/// Far more than a release's list of checksums needs.
const MAX_SUMS_BYTES: usize = 64 * 1024;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
/// What a release installs into `~/.splint/bin`, under the same names.
#[cfg(unix)]
const PROGRAMS: [&str; 4] = ["splint", "splint-host", "splint-signet", "splint-owner-key"];
/// A host runs on Linux, so Windows's release has the rest.
#[cfg(windows)]
const PROGRAMS: [&str; 3] = ["splint", "splint-signet", "splint-owner-key"];

/// Every call this program makes says which protocol it speaks, so a host or Signet on another one
/// refuses it with that reason, rather than misread it.
pub fn speaking_ours() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(PROTOCOL_HEADER, HeaderValue::from(PROTOCOL));
    if let Ok(spoken) = HeaderValue::try_from(SPOKEN.header_value()) {
        headers.insert(PROTOCOLS_HEADER, spoken);
    }
    headers
}

/// Whether an answer says it's on a protocol this program doesn't read.
pub fn other_protocol(answer: &HeaderMap) -> Option<OtherProtocol> {
    check_protocol(
        answer.get(PROTOCOL_HEADER).map(HeaderValue::as_bytes),
        answer.get(PROTOCOLS_HEADER).map(HeaderValue::as_bytes),
    )
    .err()
}

/// The release's name for this machine, as `install.sh` picks it.
fn platform() -> Result<&'static str, Failure> {
    match (env::consts::OS, env::consts::ARCH) {
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("macos", "x86_64") => Ok("macos-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("windows", "x86_64") => Ok("windows-x86_64"),
        ("windows", "aarch64") => Ok("windows-arm64"),
        _ => Err(Failure::refused(
            "there's no release for this kind of machine",
        )),
    }
}

/// A folder only this user can open, for the release's files, removed when done.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Self, Failure> {
        let random = splint_core::random_nonce()?;
        let path = env::temp_dir().join(format!("splint-verify-{random}"));
        // Fails if anything is already there, so nothing planted can stand in for it.
        splint_core::private_files::new_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Fetches one of a release's files into `scratch`: from `SPLINT_FROM_DIR` as `install.sh` does, or
/// the release on GitHub, or with `gh` while the repository is private. Only the checksums and
/// signatures below decide whether it counts.
async fn fetch(version: &str, name: &str, scratch: &Path) -> Result<PathBuf, Failure> {
    let to = scratch.join(name);
    if let Some(dir) = env::var_os("SPLINT_FROM_DIR") {
        let bytes = fs::read(Path::new(&dir).join(name))
            .map_err(|_| Failure::refused(format!("there's no {name} in SPLINT_FROM_DIR")))?;
        fs::write(&to, capped(bytes, name)?)?;
        return Ok(to);
    }
    let url = format!("https://github.com/{REPO}/releases/download/{version}/{name}");
    let http = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .https_only(true)
        // GitHub sends each download on to where it keeps the file.
        .redirect(redirect::Policy::limited(3))
        .build()?;
    if let Ok(answer) = http.get(&url).send().await
        && answer.status().is_success()
    {
        let bytes = answer.bytes().await?.to_vec();
        fs::write(&to, capped(bytes, name)?)?;
        return Ok(to);
    }
    let fetched = Command::new("gh")
        .args(["release", "download", version, "--repo", REPO, "--clobber"])
        .args(["--pattern", name, "--dir"])
        .arg(scratch)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if fetched && to.is_file() {
        let bytes = fs::read(&to)?;
        capped(bytes, name)?;
        return Ok(to);
    }
    Err(Failure::refused(format!(
        "couldn't download {name} for {version} from github.com/{REPO}"
    )))
}

fn capped(bytes: Vec<u8>, name: &str) -> Result<Vec<u8>, Failure> {
    if bytes.len() > MAX_SUMS_BYTES {
        return Err(Failure::refused(format!(
            "{name} is far bigger than it should be"
        )));
    }
    Ok(bytes)
}

/// Whether there's a cosign that reads the bundle format a release is signed in.
fn cosign_can_check() -> bool {
    let Ok(said) = Command::new("cosign").arg("version").output() else {
        return false;
    };
    let said = String::from_utf8_lossy(&said.stdout);
    said.lines()
        .find_map(|line| line.strip_prefix("GitVersion:"))
        .and_then(|version| version.trim().trim_start_matches('v').split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 3)
}

/// Checks the release's list of checksums was signed by this repository's release workflow, for
/// this version and the commit this program says it was built from. Says what it checked.
async fn check_signature(version: &str, sums: &Path, scratch: &Path) -> Result<String, Failure> {
    if !cosign_can_check() {
        return Ok(format!(
            "There's no cosign 3 here, so {SUMS} was checked against nothing but this download"
        ));
    }
    let bundle = fetch(version, &format!("{SUMS}.sigstore.json"), scratch).await?;
    let signer =
        format!("https://github.com/{REPO}/.github/workflows/release.yml@refs/tags/{version}");
    let mut cosign = Command::new("cosign");
    cosign
        .arg("verify-blob")
        .arg("--bundle")
        .arg(&bundle)
        .args(["--certificate-identity", &signer])
        .args(["--certificate-oidc-issuer", ISSUER])
        .args(["--certificate-github-workflow-repository", REPO]);
    if let Some(commit) = commit() {
        cosign.args(["--certificate-github-workflow-sha", commit]);
    }
    let signed = cosign
        .arg(sums)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !signed {
        return Err(Failure::refused(format!(
            "{SUMS} for {version} isn't signed by {REPO}'s release workflow for that tag and commit"
        )));
    }
    Ok(format!(
        "{SUMS} is signed by {REPO}'s release workflow for {version}"
    ))
}

/// The SHA-256 a list gives for a name. `sha256sum` writes a line as the hash, two spaces, the name.
fn listed<'a>(sums: &'a str, name: &str) -> Option<&'a str> {
    sums.lines().find_map(|line| {
        let (hash, listed) = line.split_once("  ")?;
        (listed == name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then_some(hash)
    })
}

/// What a running Signet says about its build, against the file installed. A Signet started before
/// an update still runs the old one. A changed Signet could say anything, so this only helps an
/// honest owner notice a restart is due.
async fn running_signet(home: &Home, installed_build: Option<&str>) -> Option<String> {
    let installed = Installed::load(home).ok().flatten()?;
    let release = SignetApi::new(home, &installed)
        .ok()?
        .release()
        .await
        .ok()?;
    match (release.build.as_deref(), installed_build) {
        (Some(running), Some(file)) if running == file => {
            Some("The running Signet says it's that same build.".to_owned())
        }
        _ => Some(
            "The running Signet says it's another build, as when it started before an update, so \
             run splint stop, then splint start."
                .to_owned(),
        ),
    }
}

pub async fn verify(home: &Home) -> Result<String, Failure> {
    let Some(version) = release_version() else {
        return Err(Failure::refused(
            "this splint was built from source, so there's no release to check it against. \
             deploy/release/build.sh builds a release's commit the same way, to compare",
        ));
    };
    let platform = platform()?;
    let scratch = Scratch::new()?;
    let sums_file = fetch(version, SUMS, &scratch.0).await?;
    let signature = check_signature(version, &sums_file, &scratch.0).await?;
    let sums = fs::read_to_string(&sums_file)
        .map_err(|_| Failure::refused(format!("{SUMS} isn't text")))?;

    let mut lines = Vec::new();
    let mut differ = false;
    let mut signet_build = None;
    for program in PROGRAMS {
        let name = format!(
            "splint-{version}-{platform}/bin/{program}{}",
            env::consts::EXE_SUFFIX
        );
        let want = listed(&sums, &name).ok_or_else(|| {
            Failure::refused(format!(
                "{version}'s {SUMS} doesn't list {program} for {platform}"
            ))
        })?;
        let path = beside_this_program(program)?;
        let line = match sha256_of_file(&path) {
            Ok(got) if got == want => {
                if program == "splint-signet" {
                    signet_build = Some(got);
                }
                format!("{program}: the same as {version} for {platform}")
            }
            Ok(_) => {
                differ = true;
                format!("{program}: NOT the same as {version} for {platform}")
            }
            Err(_) => {
                differ = true;
                format!("{program}: couldn't be read at {}", path.display())
            }
        };
        lines.push(line);
    }
    lines.push(format!("{signature}."));
    if !differ && let Some(running) = running_signet(home, signet_build.as_deref()).await {
        lines.push(running);
    }
    let check_without = if cfg!(windows) {
        format!(
            "& ([scriptblock]::Create((irm https://github.com/{REPO}/releases/download/{version}/install.ps1))) --verify"
        )
    } else {
        format!(
            "curl -fsSL https://github.com/{REPO}/releases/download/{version}/install.sh | sh -s -- --verify"
        )
    };
    lines.push(format!(
        "This ran as the splint it checks. To check without it: {check_without}"
    ));
    let said = lines.join("\n");
    if differ {
        Err(Failure::refused(format!(
            "what's installed here isn't {version}.\n{said}\nReinstall from the release, and find \
             out what changed those files."
        )))
    } else {
        Ok(said)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn only_a_whole_line_for_that_name_counts() {
        let sums = format!(
            "{HASH}  splint-v0.1.0-macos-arm64/bin/splint-signet\n\
             {HASH}  splint-v0.1.0-macos-arm64/bin/splint\n\
             nothex{HASH}  splint-v0.1.0-macos-arm64/bin/splint-host\n"
        );
        assert_eq!(
            listed(&sums, "splint-v0.1.0-macos-arm64/bin/splint"),
            Some(HASH)
        );
        assert_eq!(
            listed(&sums, "splint-v0.1.0-macos-arm64/bin/splint-host"),
            None
        );
        assert_eq!(
            listed(&sums, "splint-v0.1.0-macos-arm64/bin/splint-owner-key"),
            None
        );
        assert_eq!(listed(&sums, "bin/splint"), None);
    }
}
