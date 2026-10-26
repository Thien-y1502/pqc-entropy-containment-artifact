# Reproducibility and release boundary

## Pinned inputs

- Go toolchain/base: `golang:1.24.13-bookworm` at the digest in
  `docker/Dockerfile.go`.
- Rust toolchain/base: `rust:1.90.0-bookworm` at the digest in
  `docker/Dockerfile.rust`.
- RustCrypto KEMs commit:
  `19275cb6fd15ee64fc5ca93342c22e94dee65f38` with committed `Cargo.lock`.
- liboqs 0.16.0 source archive SHA-256:
  `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`.
- Runtime Python base digest is pinned in every Dockerfile.

The liboqs build runs official ML-KEM-768 and HQC-3 functional tests plus fixed
KAT digests before compiling the worker. Go and Rust unit tests run during the
image build.

## Integrity chain

Each run writes a schedule, canonical JSONL records, a summary, and an envelope
containing SHA-256 hashes of those files. Confirmation additionally compares
primary and replay semantic objects. Cost analysis verifies the schedule-record
identity set and the completeness of every randomized block before computing an
estimate.

## What is public

The release contains the minimal workers, orchestration, contracts, raw
digest-only evidence, analysis code, and result tables. Raw keys, entropy, and
shared secrets are absent.

Cloud deployment manifests, credentials, account identifiers, production
services, and unrelated source code are excluded because none is necessary for
the scientific reproduction. The clean Docker workflow is the public execution
path.

## Reproducibility level

The committed evidence represents an end-to-end executed study with complete
source, contracts, logs, and results. A successful public GitHub Actions run is
a clean-environment reproduction of the released implementation, but not an
independent reimplementation by another research team.
