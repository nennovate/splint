#!/usr/bin/env python3
"""Run the repo rule check against a small repo with one rule broken at a time.

The check passes when it selects no files, so a wrong scope can't show up any other way.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CHECK = Path(__file__).with_name("check_repo_rules.py").resolve()

CLEAN = {
    "README.md": "Vendor names are fine out here: Anthropic.\n",
    "packages/Cargo.toml": '[workspace]\nmembers = ["host", "signet"]\n\n[workspace.package]\nlicense = "Apache-2.0"\n',
    "packages/deny.toml": "# Shared files beside the packages aren't package code: Anthropic.\n",
    "packages/host/Cargo.toml": (
        '[package]\nname = "host"\nlicense = "AGPL-3.0-only"\n\n[lints]\nworkspace = true\n\n'
        '[dependencies]\nserde = "1"\n'
    ),
    "packages/signet/Cargo.toml": (
        '[package]\nname = "signet"\nlicense.workspace = true\n\n[lints]\nworkspace = true\n\n'
        '[dependencies]\nserde = "1"\n'
    ),
    "packages/host/src/delivery/mod.rs": "pub fn deliver() {}\n",
    "tools/checks/allowed-dependencies.toml": '[dependencies]\nserde = "serialization"\n',
}


def run_check(changes: dict[str, str]) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
        for name, text in {**CLEAN, **changes}.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return subprocess.run(
            [sys.executable, str(CHECK)], cwd=root, capture_output=True, text=True
        )


class RepoRules(unittest.TestCase):
    def assert_refused(self, changes: dict[str, str], complaint: str) -> None:
        result = run_check(changes)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(complaint, result.stderr)

    def test_a_new_way_to_make_a_verified_envelope_is_refused(self) -> None:
        source = (
            "impl VerifiedEnvelope {\n"
            "    pub fn verify(c: &str) -> Result<Self, Error> { todo!() }\n"
            "    pub fn from_bytes(c: &str) -> Self { todo!() }\n"
            "}\n"
        )
        self.assert_refused({"packages/splint-core/src/envelope.rs": source}, "from_bytes makes a VerifiedEnvelope")

    def test_the_ways_to_verify_an_envelope_are_fine(self) -> None:
        source = (
            "impl VerifiedEnvelope {\n"
            "    pub fn verify(c: &str) -> Result<Self, Error> { todo!() }\n"
            "    pub fn verify_ignoring_clock(c: &str) -> Result<Self, Error> { todo!() }\n"
            "    pub fn id(&self) -> &MessageId { todo!() }\n"
            "}\n"
        )
        result = run_check({"packages/splint-core/src/envelope.rs": source})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_way_to_make_a_granted_is_refused(self) -> None:
        source = "impl Granted {\n    pub fn new() -> Granted { todo!() }\n}\n"
        self.assert_refused({"packages/splint-core/src/grants.rs": source}, "new makes a Granted")

    def test_crypto_in_an_adapter_is_refused(self) -> None:
        path = "adapters/mcp/src/main.ts"
        self.assert_refused({path: 'import { sign } from "node:crypto";\n'}, "use no crypto")

    def test_a_vendor_name_in_an_adapter_is_fine(self) -> None:
        result = run_check({"adapters/mcp/src/main.ts": "// For Anthropic's MCP.\n"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_unlisted_adapter_dependency_is_refused(self) -> None:
        manifest = '{"dependencies": {"left-pad": "1.3.0"}}'
        self.assert_refused({"adapters/mcp/package.json": manifest}, "dependency 'left-pad'")

    def test_an_unpinned_adapter_dependency_is_refused(self) -> None:
        listed = '[dependencies]\nserde = "serialization"\n[adapter-dependencies]\nleft-pad = "padding"\n'
        files = {
            "tools/checks/allowed-dependencies.toml": listed,
            "adapters/mcp/package.json": '{"dependencies": {"left-pad": "^1.3.0"}}',
            "adapters/mcp/package-lock.json": "{}",
        }
        self.assert_refused(files, "exact version")

    def test_an_adapter_dependency_with_no_lock_file_is_refused(self) -> None:
        listed = '[dependencies]\nserde = "serialization"\n[adapter-dependencies]\nleft-pad = "padding"\n'
        files = {
            "tools/checks/allowed-dependencies.toml": listed,
            "adapters/mcp/package.json": '{"dependencies": {"left-pad": "1.3.0"}}',
        }
        self.assert_refused(files, "package-lock.json")

    def test_a_clean_repo_passes(self) -> None:
        result = run_check({})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_workspace_member_outside_the_scope_is_refused(self) -> None:
        workspace = '[workspace]\nmembers = ["host", "signet", "owner-key"]\n'
        self.assert_refused({"packages/Cargo.toml": workspace}, "workspace member 'owner-key'")

    def test_a_vendor_name_in_package_source_is_refused(self) -> None:
        self.assert_refused({"packages/host/src/main.rs": "// Uses Anthropic.\n"}, "names runtime")

    def test_a_vendor_name_deep_in_a_package_is_refused(self) -> None:
        path = "packages/host/src/delivery/retry/backoff.rs"
        self.assert_refused({path: "// Uses Anthropic.\n"}, path)

    def test_a_vendor_name_in_a_package_outside_the_rust_workspace_is_refused(self) -> None:
        path = "packages/client/src/index.ts"
        self.assert_refused({path: "// Uses Anthropic.\n"}, path)

    def test_a_vendor_name_in_a_file_name_is_refused(self) -> None:
        self.assert_refused({"packages/host/src/anthropic.rs": ""}, "names runtime")

    def test_a_link_to_a_private_place_is_refused(self) -> None:
        # Bug this catches: links to the private tracker, a private doc or someone's machine reaching the
        # public repo. Each is joined here so this file doesn't match the rule itself.
        for place in [
            "https://github.com/nenye-a/" + "splint/issues/45",
            "https://github.com/nenye-a/" + "splint/pull/631",
            "https://claude.ai/" + "artifact/abc",
            "/Users/" + "ana/notes.md",
            "/private/tmp/" + "claude-1/x",
        ]:
            self.assert_refused({"docs/guide.md": f"See {place} for more.\n"}, "private place")

    def test_naming_another_repository_than_splints_own_is_refused(self) -> None:
        # Bug this catches: an installer or guide fetching from a repository other than the one that
        # signs the release, so every install fails its signature check or answers 404. Joined so this
        # file doesn't match the rule itself.
        for path, name in [
            ("deploy/release/install.ps1", "https://github.com/nenye-a/" + "splint/releases/latest/download/install.sh"),
            ("deploy/release/install.sh", "REPO=someone/" + "splint"),
            ("adapters/cursor/splint.mdc", "git@github.com:someone/" + "splint.git"),
            ("docs/guide.md", "gh release download --repo someone/" + "splint"),
            ("docs/guide.md", "https://raw.githubusercontent.com/someone/" + "splint/main/x"),
            ("docs/guide.md", "https://github.com/Nenye-A/" + "Splint"),
        ]:
            self.assert_refused({path: f"{name}\n"}, "nennovate/splint")
        release = "https://github.com/nennovate/splint/releases/latest/download/install.sh"
        result = run_check({"docs/guide.md": f"Install with {release}.\n"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_catch_all_module_is_refused(self) -> None:
        self.assert_refused({"packages/host/src/utils.rs": ""}, "catch-all")

    def test_switching_off_a_required_lint_is_refused(self) -> None:
        source = "#[allow(clippy::unwrap_used)]\nfn main() {}\n"
        self.assert_refused({"packages/host/src/main.rs": source}, "switches off")
        # Bug this catches: a `)` in a comment ended the pattern's look at the attribute early.
        hidden = "#[allow(dead_code /* ) */, clippy::unwrap_used)]\nfn main() {}\n"
        self.assert_refused({"packages/host/src/main.rs": hidden}, "unwrap_used")

    def test_opening_a_transaction_directly_is_allowed_only_where_no_caller_can_cancel_it(self) -> None:
        lifted = "#[expect(clippy::disallowed_methods, reason = \"x\")]\nfn f() {}\n"
        result = run_check({"packages/host/src/database.rs": lifted})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_refused({"packages/host/src/delivery.rs": lifted}, "disallowed_methods")
        # Bug this catches: a group switched the warn-level lint off with it, even in database.rs.
        for group in ["clippy::style", "clippy::all", "warnings"]:
            grouped = f"#[allow({group})]\nfn f() {{}}\n"
            self.assert_refused({"packages/host/src/database.rs": grouped}, group)

    def test_unsafe_is_allowed_in_the_approved_files_and_nowhere_else(self) -> None:
        allowed = "packages/splint-core/src/private_files/windows.rs"
        result = run_check({allowed: "#![allow(unsafe_code)]\n"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_refused({allowed: "#![allow(unsafe_code)]\n#[allow(clippy::unwrap_used)]\nfn f() {}\n"}, "unwrap_used")
        self.assert_refused({"packages/splint-core/src/private_files/other.rs": "#![allow(unsafe_code)]\n"}, "unsafe_code")
        result = run_check({allowed: "#![allow(unsafe_code)]\nfn f(p: *const u8) -> u8 { unsafe { *p } }\n"})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsafe_lifted_where_no_pattern_sees_it_is_refused(self) -> None:
        # Bug this catches: with the workspace denying `unsafe` rather than forbidding it, an `allow`
        # a macro builds let unsafe code in anywhere.
        built = (
            "macro_rules! lifted { ($lint:ident) => { #[allow($lint)] pub fn f(p: *const u8) -> u8 "
            "{ unsafe { *p } } } }\nlifted!(unsafe_code);\n"
        )
        self.assert_refused({"packages/host/src/delivery/mod.rs": built}, "uses unsafe")

    def test_unsafe_said_in_a_comment_or_text_is_fine(self) -> None:
        source = (
            '// Nothing unsafe here.\n/* nor /* here */ unsafe */\nconst SAID: &str = "unsafe";\n'
            'const RAW: &str = r#"un"safe"#;\nfn f<\'a>(x: &\'a str) -> char { let _ = x; \'u\' }\n'
        )
        result = run_check({"packages/host/src/delivery/mod.rs": source})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_hiding_source_with_include_is_refused(self) -> None:
        for source in ('include!("elsewhere.txt");\n', 'include !("elsewhere.txt");\n', "use std::include as inc;\n"):
            self.assert_refused({"packages/host/src/main.rs": source}, "include!")

    def test_a_module_loaded_from_a_file_these_checks_dont_read_is_refused(self) -> None:
        # Bug this catches: a module compiled from a .txt file, which only .rs files are scanned for,
        # could lift the workspace's `deny` and use unsafe code past both these checks and clippy.
        lifted = {"packages/host/src/lifted.txt": "#![allow(unsafe_code)]\npub fn f(b: &[u8]) -> u8 { unsafe { *b.as_ptr() } }\n"}
        for loading in (
            '#[path = "lifted.txt"]\nmod lifted;\n',
            '#[cfg_attr(all(), path = "lifted.txt")]\nmod lifted;\n',
            '#[path = "../src/lifted.rs"]\nmod lifted;\n',
            'macro_rules! from { ($a:meta) => { #[$a] mod lifted; } }\nfrom!(path = "lifted.txt");\n',
        ):
            self.assert_refused({**lifted, "packages/host/src/main.rs": loading}, "packages/host/src/main.rs: a")
        fine = {"packages/host/src/main.rs": '#[path = "delivery/mod.rs"] // read here\nmod delivery;\n'}
        result = run_check(fine)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_package_not_inheriting_workspace_lints_is_refused(self) -> None:
        manifest = '[package]\nname = "host"\n'
        self.assert_refused({"packages/host/Cargo.toml": manifest}, "must inherit workspace lints")

    def test_an_unlisted_dependency_is_refused(self) -> None:
        manifest = CLEAN["packages/host/Cargo.toml"] + 'unvetted = "1"\n'
        self.assert_refused({"packages/host/Cargo.toml": manifest}, "dependency 'unvetted'")

    def test_an_apache_crate_depending_on_the_host_is_refused(self) -> None:
        # Builders ship Signet, so this would quietly put their products under the AGPL.
        manifest = CLEAN["packages/signet/Cargo.toml"] + 'host = { path = "../host" }\n'
        self.assert_refused({"packages/signet/Cargo.toml": manifest}, "depends on the host")

    def test_a_crate_with_no_licence_is_refused(self) -> None:
        manifest = CLEAN["packages/signet/Cargo.toml"].replace("license.workspace = true\n", "")
        self.assert_refused({"packages/signet/Cargo.toml": manifest}, "licence must be Apache-2.0")

    def test_a_listed_dependency_without_a_reason_is_refused(self) -> None:
        listing = '[dependencies]\nserde = ""\n'
        self.assert_refused({"tools/checks/allowed-dependencies.toml": listing}, "needs a reason")


if __name__ == "__main__":
    unittest.main()
