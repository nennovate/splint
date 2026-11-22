#!/usr/bin/env python3
"""Enforce the repo rules that compilers and linters can't: see AGENTS.md."""

import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path

ALLOWED_DEPENDENCIES = Path("tools/checks/allowed-dependencies.toml")
RUST_WORKSPACE = Path("packages/Cargo.toml")
# See LICENSE: the host is AGPL, and every other crate is Apache.
HOST_CRATE = "host"
HOST_LICENCE = "AGPL-3.0-only"
LICENCE = "Apache-2.0"

RUNTIME_NAMES = re.compile(
    r"(?<![a-zA-Z])(?i:anthropic|chatgpt|claude|cloudflare|codex|gemini|gpt-?\d|langchain|langgraph"
    r"|llama|ollama|open[_-]?ai)"
    # Case-sensitive and bounded, because these three letters turn up in encoded data.
    r"|(?<![a-zA-Z0-9])(?:mcp|Mcp|MCP)(?![a-z0-9])"
)
CATCH_ALL_NAMES = {"common", "helpers", "misc", "models", "util", "utils"}
# Places only the project's own people can open, which the public repo can't point at: the private
# tracker's issues and PRs, private Claude docs, and someone's own machine. Each is spelt so that this
# file doesn't match itself.
PRIVATE_PLACES = re.compile(
    r"github\.com/nenye-a/(?:splint|accord)/(?:issues|pull)/\d"
    r"|claude\.ai/(?:code/)?artifact/"
    r"|/Users/[A-Za-z][\w.-]*/"
    r"|/private/tmp/claude\-"
)
# Splint's own repository, for everything that installs, verifies or links to it: a release signed in
# one repository and fetched from another fails its signature check, and a link to another 404s.
OTHER_REPOSITORY = re.compile(
    r"(?i:(?:github\.com[/:]|githubusercontent\.com/|api\.github\.com/repos/|--repo[ =]|\brepo\s*=\s*['\"]?)"
    r"(?!nennovate/)[\w.-]+/(?:splint|accord)(?![\w-])"
    r"|(?<![\w.-])nenye-a/(?:splint|accord)(?![\w-]))"
)
TEXT_SUFFIXES = {
    ".md", ".rs", ".py", ".ts", ".js", ".mjs", ".toml", ".json", ".yml", ".yaml", ".sh", ".mk",
    ".txt", ".html", ".css", ".service", ".timer", ".env", ".ps1", ".mdc",
}
# A group switches off what's in it, and `disallowed_methods` is warn-level, so it's in `warnings`,
# `clippy::all` and `clippy::style`.
LINT_ESCAPE = re.compile(
    r"\b(allow|expect)\s*\([^)]*\b(unsafe_code|warnings|clippy::(all|style|restriction|dbg_macro"
    r"|expect_used|indexing_slicing|panic|print_stderr|print_stdout|string_slice|todo|unimplemented"
    r"|unreachable|unwrap_used|disallowed_methods))\b"
)
# The one file that opens a database transaction directly, on a task no caller can cancel.
OPENS_TRANSACTIONS = Path("packages/host/src/database.rs")
# The two files allowed `unsafe`, each approved by Nenye as AGENTS.md requires: the Mac security
# chip's two calls into Apple's Objective-C types (2026-11-14), and the Windows calls the standard
# library lacks (PR 864, 2026-11-16).
# The workspace denies `unsafe` rather than forbidding it, so this list is what keeps it out elsewhere:
# a `deny` can be lifted by an attribute a macro builds, which no pattern can see, so the keyword
# itself is refused, as no unsafe code can be written without it.
UNSAFE_ALLOWED = {
    Path("packages/owner-key/src/chip/bridge.rs"),
    Path("packages/splint-core/src/private_files/windows.rs"),
}
UNSAFE_KEYWORD = re.compile(r"\bunsafe\b")
# Rust's literals, which `rust_code` blanks. Each starts where a token does, as words are taken whole.
RAW_STRING = re.compile(r'[bc]?r(#*)"')
STRING = re.compile(r'[bc]?"(?:\\.|[^"\\])*"', re.DOTALL)
CHARACTER = re.compile(r"b?'(?:\\u\{[0-9a-fA-F]{1,6}\}|\\.|[^\\'\n])'")
WORD = re.compile(r"[A-Za-z0-9_]+")
# `include!` however it's spelled or renamed, as it compiles a file these checks never read.
SOURCE_INCLUDE = re.compile(r"\binclude\s*!|::\s*include\b|\buse\b[^;]*\binclude\b")
# A `path` attribute can compile a module from any file, such as a .txt these checks never read, where
# an `allow` lifts the workspace's `deny`. One is fine only when it plainly names a .rs file read here.
ATTRIBUTE_START = re.compile(r"#\s*!?\s*\[")
PATH_KEY = re.compile(r"\bpath\s*=")
PLAIN_PATH = re.compile(r'#\s*\[\s*path\s*=\s*"(\d+)"\s*\]')
# A meta item a macro fills in, as in `#[$attribute]`, can be a `path` no pattern sees.
BUILT_META = re.compile(r"[\[(,]\s*\$")
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
# Adapters hold no key and sign nothing, so they have no reason to reach for any of these.
CRYPTO_IN_ADAPTER = re.compile(
    r"node:crypto|require\(\s*['\"]crypto|from\s+['\"]crypto|\bwebcrypto\b|crypto\.subtle|\bopenssl\b|\bcreate(Sign|Verify|Hmac)\b"
)
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+")
# AGENTS.md's first rule for wrong use: network bytes become one of these only by passing verification.
# A struct literal can't get round private fields, but a new `pub fn` could, and no test would see it.
VERIFIED_TYPES = {
    # `open` takes one already verified, and gives it back with its sealed body opened and checked.
    Path("packages/splint-core/src/envelope.rs"): ("VerifiedEnvelope", {"verify", "verify_kept", "verify_ignoring_clock", "open"}),
    Path("packages/splint-core/src/grants.rs"): ("Granted", {"check_call", "check"}),
}


def repo_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "-coz", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [path for path in map(Path, filter(None, listed.split("\0"))) if path.is_file()]


def check_runtime_references(path: Path, text: str) -> list[str]:
    match = RUNTIME_NAMES.search(text) or RUNTIME_NAMES.search(str(path))
    if match:
        return [f"{path}: names runtime or vendor '{match.group(0)}'; that belongs in adapters/"]
    return []


def check_private_places(path: Path, text: str) -> list[str]:
    match = PRIVATE_PLACES.search(text)
    if match:
        return [f"{path}: points at '{match.group(0)}', a private place the public repo can't link to"]
    return []


def check_repository_name(path: Path, text: str) -> list[str]:
    match = OTHER_REPOSITORY.search(text)
    if match:
        return [f"{path}: names '{match.group(0)}'; Splint's repository is nennovate/splint"]
    return []


def check_catch_all_names(path: Path) -> list[str]:
    found = CATCH_ALL_NAMES.intersection({path.stem, *path.parts})
    return [f"{path}: catch-all module name; group by feature instead"] if found else []


def rust_code(text: str, strings: list[str] | None = None) -> str:
    """Rust source with its comments and its string and character literals blanked, so a word in one
    isn't taken for code, and a comment inside an attribute can't hide what the attribute does.
    Given a list, each string literal's contents go in it, and the literal reads as its index there."""
    code = []

    def string(contents: str) -> str:
        if strings is None:
            return '""'
        strings.append(contents)
        return f'"{len(strings) - 1}"'

    at, end = 0, len(text)
    while at < end:
        if text.startswith("//", at):
            newline = text.find("\n", at)
            at = end if newline == -1 else newline
            code.append(" ")
        elif text.startswith("/*", at):
            depth = 0
            while at < end:
                if text.startswith("/*", at):
                    depth, at = depth + 1, at + 2
                elif text.startswith("*/", at):
                    depth, at = depth - 1, at + 2
                    if depth == 0:
                        break
                else:
                    at += 1
            code.append(" ")
        elif raw := RAW_STRING.match(text, at):
            closing = text.find('"' + raw.group(1), raw.end())
            stop = end if closing == -1 else closing
            at = end if closing == -1 else closing + 1 + len(raw.group(1))
            code.append(string(text[raw.end() : stop]))
        elif literal := STRING.match(text, at):
            at = literal.end()
            code.append(string(literal.group(0)[literal.group(0).index('"') + 1 : -1]))
        elif literal := CHARACTER.match(text, at):
            at = literal.end()
            code.append('""')
        elif word := WORD.match(text, at):
            at = word.end()
            code.append(word.group(0))
        else:
            code.append(text[at])
            at += 1
    return "".join(code)


def attributes(code: str) -> Iterator[str]:
    for start in ATTRIBUTE_START.finditer(code):
        depth = 0
        for at in range(start.end() - 1, len(code)):
            depth += {"[": 1, "]": -1}.get(code[at], 0)
            if depth == 0:
                yield code[start.start() : at + 1]
                break


def check_source_paths(path: Path, text: str, rust_files: set[Path]) -> list[str]:
    strings: list[str] = []
    problems = []
    for attribute in attributes(rust_code(text, strings)):
        if BUILT_META.search(attribute):
            problems.append(f"{path}: an attribute a macro fills in could load source these checks don't read")
        elif PATH_KEY.search(attribute):
            plain = PLAIN_PATH.fullmatch(attribute)
            target = Path(strings[int(plain.group(1))]) if plain else None
            if target is None or target.is_absolute() or ".." in target.parts or path.parent / target not in rust_files:
                problems.append(f"{path}: a path attribute may name only a .rs file beside it that these checks read")
    return problems


def check_unsafe(path: Path, code: str) -> list[str]:
    if path in UNSAFE_ALLOWED or not UNSAFE_KEYWORD.search(code):
        return []
    allowed = ", ".join(sorted(map(str, UNSAFE_ALLOWED)))
    return [f"{path}: uses unsafe, which only {allowed} may"]


def check_lint_escapes(path: Path, text: str) -> list[str]:
    problems = []
    for match in LINT_ESCAPE.finditer(rust_code(text)):
        if match.group(2) == "unsafe_code" and path in UNSAFE_ALLOWED:
            continue
        if match.group(2) == "clippy::disallowed_methods" and path == OPENS_TRANSACTIONS:
            continue
        problems.append(f"{path}: switches off a required lint: {match.group(0)}")
        break
    if SOURCE_INCLUDE.search(rust_code(text)):
        problems.append(f"{path}: include! hides source from these checks")
    return problems


def dependency_tables(manifest: dict) -> Iterator[dict]:
    for table in DEPENDENCY_TABLES:
        yield manifest.get(table, {})
    for target in manifest.get("target", {}).values():
        for table in DEPENDENCY_TABLES:
            yield target.get(table, {})


def dependency_name(key: str, spec: object) -> str:
    return spec.get("package", key) if isinstance(spec, dict) else key


def check_crate_manifest(path: Path, allowed: set[str], internal: set[str]) -> list[str]:
    manifest = tomllib.loads(path.read_text())
    problems = []
    if manifest.get("lints", {}).get("workspace") is not True:
        problems.append(f"{path}: must inherit workspace lints ([lints] workspace = true)")
    for table in dependency_tables(manifest):
        for key, spec in table.items():
            name = dependency_name(key, spec)
            if name not in allowed and name not in internal:
                problems.append(f"{path}: dependency '{name}' isn't in {ALLOWED_DEPENDENCIES}")
    return problems


def check_licence(path: Path, workspace_licence: object) -> list[str]:
    """Only the host is under the AGPL. A crate depending on it would carry the AGPL into what builders ship."""
    manifest = tomllib.loads(path.read_text())
    name = manifest["package"]["name"]
    licence = manifest["package"].get("license")
    if isinstance(licence, dict) and licence.get("workspace") is True:
        licence = workspace_licence
    expected = HOST_LICENCE if name == HOST_CRATE else LICENCE
    problems = [] if licence == expected else [f"{path}: licence must be {expected}, as LICENSE says"]
    if name != HOST_CRATE:
        for table in dependency_tables(manifest):
            if any(dependency_name(key, spec) == HOST_CRATE for key, spec in table.items()):
                problems.append(f"{path}: depends on the host, which would put this crate under the AGPL")
    return problems


def check_workspace_in_scope(manifests: list[Path]) -> list[str]:
    """A stale scope selects nothing and would pass, so what it must cover is read from the code."""
    members = tomllib.loads(RUST_WORKSPACE.read_text())["workspace"]["members"]
    return [
        f"{RUST_WORKSPACE}: these checks don't cover workspace member '{member}'"
        for member in members
        if Path("packages", member, "Cargo.toml") not in manifests
    ]


def check_adapter_manifest(path: Path, allowed: set[str], files: list[Path]) -> list[str]:
    manifest = json.loads(path.read_text())
    named = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
    problems = []
    for name, version in named.items():
        if name not in allowed:
            problems.append(f"{path}: dependency '{name}' isn't in {ALLOWED_DEPENDENCIES}")
        if not EXACT_VERSION.fullmatch(version):
            problems.append(f"{path}: dependency '{name}' must be pinned to an exact version")
    if named and path.with_name("package-lock.json") not in files:
        problems.append(f"{path}: needs a package-lock.json, or what's installed can change")
    return problems


def check_no_crypto_in_adapter(path: Path, text: str) -> list[str]:
    match = CRYPTO_IN_ADAPTER.search(text)
    return [f"{path}: adapters use no crypto, but this has '{match.group(0)}'"] if match else []


def check_verified_types(path: Path, text: str) -> list[str]:
    if path not in VERIFIED_TYPES:
        return []
    name, allowed = VERIFIED_TYPES[path]
    returning = r"pub(?:\([a-z]+\))?\s+fn\s+(\w+)[^{{;]*->\s*(?:Result<\s*)?{}\b"
    found = re.findall(returning.format(name), text)
    for block in re.findall(rf"^impl {name} \{{.*?^\}}", text, re.MULTILINE | re.DOTALL):
        found += re.findall(returning.format("Self"), block)
    return [
        f"{path}: {maker} makes a {name} without the check, so nothing about one can be relied on"
        for maker in found
        if maker not in allowed
    ]


def allowed_dependencies() -> tuple[set[str], set[str], list[str]]:
    tables = tomllib.loads(ALLOWED_DEPENDENCIES.read_text())
    listed, adapter = tables.get("dependencies", {}), tables.get("adapter-dependencies", {})
    problems = [
        f"{ALLOWED_DEPENDENCIES}: '{name}' needs a reason"
        for name, reason in {**listed, **adapter}.items()
        if not (isinstance(reason, str) and reason.strip())
    ]
    return set(listed), set(adapter), problems


def main() -> int:
    files = repo_files()
    # Inside a package, so not the shared Rust workspace files beside the packages.
    crate_files = [path for path in files if path.parts[0] == "packages" and len(path.parts) > 2]
    manifests = [path for path in crate_files if path.name == "Cargo.toml"]
    rust_files = {path for path in crate_files if path.suffix == ".rs"}

    allowed, allowed_in_adapters, problems = allowed_dependencies()
    problems += check_workspace_in_scope(manifests)
    internal = {tomllib.loads(path.read_text())["package"]["name"] for path in manifests}

    for path in crate_files:
        text = path.read_text(errors="replace")
        problems += check_runtime_references(path, text)
        problems += check_catch_all_names(path)
        if path.suffix == ".rs":
            problems += check_lint_escapes(path, text)
            problems += check_unsafe(path, rust_code(text))
            problems += check_source_paths(path, text, rust_files)
            problems += check_verified_types(path, text)
    workspace_licence = tomllib.loads(RUST_WORKSPACE.read_text()).get("workspace", {}).get("package", {}).get("license")
    for path in manifests:
        problems += check_crate_manifest(path, allowed, internal)
        problems += check_licence(path, workspace_licence)
    for path in files:
        if path.suffix in TEXT_SUFFIXES or path.name in {"Makefile", "Caddyfile"}:
            text = path.read_text(errors="replace")
            problems += check_private_places(path, text)
            problems += check_repository_name(path, text)
    for path in files:
        if path.parts[0] != "adapters" or path.name == "package-lock.json":
            continue
        problems += check_no_crypto_in_adapter(path, path.read_text(errors="replace"))
        if path.name == "package.json":
            problems += check_adapter_manifest(path, allowed_in_adapters, files)

    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
