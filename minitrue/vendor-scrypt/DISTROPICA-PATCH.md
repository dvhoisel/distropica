# Distrópica scrypt fork

This directory is a narrowly patched copy of RustCrypto `scrypt` 0.12.0.

- Upstream crate: `scrypt` 0.12.0, published on crates.io
- Crate archive SHA-256: `d87af57419b594aa23fa95f09f0e06d80d84ba01c26148c43844cad6ff4485f0`
- Upstream repository commit recorded by the crate: `a795bf6f2dea6b9700fcc78f82a2ceaa19f36da7`
- License: MIT OR Apache-2.0 (unchanged; see `LICENSE-MIT` and `LICENSE-APACHE`)

The local patch adds `scrypt_fallible()`: all large work buffers are reserved
with `try_reserve_exact()` and wrapped in `zeroize::Zeroizing` before they hold
password-derived state. The original API and wire-compatible algorithm remain
available. `scrypt_work_bytes()` exposes only the checked memory calculation so
the accepted minisign boundary can be tested without allocating 1 GiB. The
small RFC 7914 vector also runs directly through the new fallible entry point.

No cryptographic primitive, parameter selection, or output format is changed.
