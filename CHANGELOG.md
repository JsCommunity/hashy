# Changelog

All notable changes to this project are documented in this file, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

## 0.14.0 - 2026-10-20

### Breaking changes

- `hash()` rejects bcrypt passwords over 72 bytes instead of silently truncating them. `verify()` still accepts existing hashes of such passwords so they can be rehashed (e.g. with Argon2).
- The bcrypt cost must be an integer between 4 and 31, in `hash()`, `needsRehash()` and the CLI's `-c`/`--cost`. Invalid values were previously silently replaced by bcryptjs.
- CLI: unknown options are rejected instead of ignored, and a secret starting with `-` must be preceded by `--`.

### Fixed

- `needsRehash()` returns `true` for Argon2 hashes using a different variant (e.g. argon2i instead of argon2id).

### Changed

- CLI: no longer depends on yargs, `-a` gains a `--algorithm` long form, and positional arguments are no longer converted to numbers.
- README: examples lead with `async`/`await`, promises and callbacks are documented as alternatives.
