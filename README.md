# Entropy-Containment Testing for PQ Hybrid and Dual-KEM Implementations

[![reproduce](https://github.com/Thien-y1502/pqc-entropy-containment-artifact/actions/workflows/reproduce.yml/badge.svg)](https://github.com/Thien-y1502/pqc-entropy-containment-artifact/actions/workflows/reproduce.yml)

This repository is the public, self-contained research artifact for a bounded
software-security study of entropy-state rollback in post-quantum hybrid and
dual-KEM key establishment. It contains only the code, contracts, results, and
documentation needed to inspect and reproduce the reported evidence. It is not
the source tree of a larger platform.

## What the artifact tests

The experiment asks whether an entropy-state rollback affecting an origin PQ
component also removes freshness from an otherwise independent peer component.
Five architectures are exercised under nominal execution, origin-state reuse,
and joint origin-state-plus-context reuse:

| ID | Architecture | Purpose |
|---|---|---|
| A0 | shared state | direct common-state baseline |
| A1 | label only | labeled derivation over one resettable root |
| A2 | unreachable global split | negative control for configuration that does not reach the real consumer |
| A3 | role-routed boundary | reached component-scoped entropy boundary |
| A4 | hedged boundary | RFC-8937-style prior-art control with an explicit context-reset boundary |

The same 5-by-3 decision surface is tested in:

- Go 1.24.13 `crypto/tls` X25519MLKEM768 ClientHello generation;
- RustCrypto X-Wing pinned to commit
  `19275cb6fd15ee64fc5ca93342c22e94dee65f38`;
- liboqs 0.16.0 ML-KEM-768 plus HQC-3.

## Executed evidence

- Confirmation: 360 primary plus 360 independent-schedule replay units.
- Cost characterization: 3,600 measured observations in 240 randomized
  complete blocks, with wall time, child CPU time, and peak RSS.
- All 720 confirmation units matched the pre-frozen qualitative expectations.
- Every primary/replay cryptographic artifact and qualitative outcome matched
  under the declared semantic comparator.
- All 36 prespecified nominal A3/A4-versus-A0 performance intervals included
  parity. The result does not prove zero overhead or equivalence; it rejects a
  speed- or memory-superiority claim at the resolution of this experiment.

See [RESULTS.md](RESULTS.md) for the exact bounded conclusions and
[results/claim_ledger.frozen.json](results/claim_ledger.frozen.json) for the
allowed and prohibited claims.

## One-command reproduction

Requirements: Docker with Linux containers, Python 3.13, Git, and approximately
8 GiB of free disk space. Network access is needed to fetch the pinned bases,
Rust crates, and the checksum-pinned liboqs 0.16.0 source archive.

Linux/macOS:

```bash
bash scripts/reproduce_all.sh
```

PowerShell:

```powershell
.\scripts\reproduce_all.ps1
```

The command builds three pinned containers, reruns both confirmation schedules,
reruns both cost phases, verifies evidence envelopes, analyzes the paired
blocks, and writes `reproduced-results/CHECKSUMS.sha256`. Existing output is
never overwritten.

The public GitHub Actions workflow executes the same Linux command from a clean
runner and publishes the exact reproduction evidence as a workflow artifact.

## Repository map

- `contracts/`: protocols frozen before confirmatory execution.
- `src/`: minimal pair workers for the three implementation realizations.
- `runners/`: schedule, execution, integrity, replay, and cost-analysis code.
- `docker/`: digest-pinned build definitions.
- `results/confirmation/`: canonical 720-unit evidence package.
- `results/performance/`: canonical 3,600-observation cost package.
- `results/performance-analysis/`: complete cell summaries and paired contrasts.
- `PUBLIC_RELEASE_MANIFEST.json`: machine-readable release scope and identities.
- `MANIFEST.sha256`: digest of every released file except the manifest itself.
- `NOVELTY_AND_WRITING_BOUNDARY.md`: conditional novelty, baseline rationale,
  and exact manuscript wording limits.
- `AI_HANDOFF.md`: evidence-oriented context for a manuscript-writing agent.
- `docs/`: method, reproduction boundary, and threats to validity.

## Security and claim boundary

The artifact records hashes and boolean agreement/freshness outcomes. Raw
entropy, private keys, and shared secrets are not written. The intervention is
a deterministic software-controlled rollback probe. The evidence does not
establish exploitability, physical-fault feasibility, secret recovery, a CVE,
IND-CCA failure, field prevalence, or production safety.

## Public-release boundary

The repository intentionally excludes cloud resource definitions, account
identifiers, credentials, production services, unrelated platform code, and
private research orchestration. Those objects are not needed to reproduce the
scientific result. The included Docker path is sufficient to rebuild the three
workers and repeat the complete experiment.

## License and citation

Original artifact code and documentation are licensed under the MIT License.
Third-party components retain their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Until a DOI record is minted with human-approved author metadata, cite the
versioned GitHub release. Authorship is deliberately not inferred by the
artifact automation.
