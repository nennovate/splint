//! Has a Mac's Touch ID prompt call this program Splint. For a program outside an app bundle, macOS
//! takes the name from an Info.plist linked into it, and failing that from its file name. The plist
//! names no bundle identifier, so the program's identity stays as it was, and the file keeps its name.

use std::env;
use std::io::{self, Write};

const INFO: &str = "src/chip/Info.plist";

fn main() -> io::Result<()> {
    let mut cargo = io::stdout().lock();
    writeln!(cargo, "cargo:rerun-if-changed=build.rs")?;
    writeln!(cargo, "cargo:rerun-if-changed={INFO}")?;
    // The target's system, not that of the machine running this script.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return Ok(());
    }
    let info = format!("{}/{INFO}", env!("CARGO_MANIFEST_DIR"));
    for argument in ["-sectcreate", "__TEXT", "__info_plist", info.as_str()] {
        writeln!(cargo, "cargo:rustc-link-arg-bin=owner-key=-Xlinker")?;
        writeln!(cargo, "cargo:rustc-link-arg-bin=owner-key={argument}")?;
    }
    Ok(())
}
