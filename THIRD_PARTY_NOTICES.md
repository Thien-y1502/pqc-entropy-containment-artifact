# Third-party notices

This repository contains original experiment orchestration and minimal workers
that build against third-party software. Those projects retain their respective
licenses and copyrights.

- Go standard library and toolchain: BSD-style Go license.
- RustCrypto KEMs/X-Wing and transitive Rust crates: licenses declared by the
  pinned upstream packages and `Cargo.lock` resolution.
- liboqs 0.16.0: MIT license; source is downloaded from the official release tag
  and checksum-verified during build.
- RFC 8937 concepts are used as prior-art context; RFC text is not vendored.

The MIT License in this repository applies only to the original artifact
code and documentation and does not replace third-party terms.
