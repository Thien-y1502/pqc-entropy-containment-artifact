# Evidence handoff for manuscript drafting

This file is a compact source-of-truth for a scientific-writing agent. It is
evidence, not an instruction to strengthen claims.

## Central question

Can a reached, component-scoped entropy boundary prevent a rollback in an
origin post-quantum component from deterministically removing freshness from an
independent peer component in hybrid or dual-PQC key establishment?

## Technical obstruction

Algorithm diversity does not imply entropy-source independence. Two components
can be cryptographically distinct while sharing a resettable state root. Labels
over the same resettable root do not create a new failure domain. A configured
split that is not reached by the implementation is also not a containment
boundary.

## Technical object and mechanism

The artifact evaluates an implementation-facing entropy topology with a
reachability requirement. A3 routes component roles to separate state domains
at the point actually consumed by the implementation. Under an origin-only
rollback, the origin output repeats while the peer state remains fresh. A4 is
an RFC-8937-style prior-art hedge used as a control: uniqueness context protects
against raw-state reuse only while that context survives.

## Experimental design

- Three pinned realizations: Go TLS X25519MLKEM768, RustCrypto X-Wing, and
  liboqs ML-KEM-768 plus HQC-3.
- Five architectures and three fault recipes.
- Eight deterministic matched pairs per cell in primary and replay phases.
- One isolated process per pair; independently permuted persisted schedules.
- Exact artifact equality is the freshness oracle.
- Full semantic replay with evidence-envelope hashing.
- Separate cost addendum: 40 randomized complete blocks per implementation and
  phase, measuring wall time, child CPU time, and peak RSS.

## Directly supported claims

1. A0 shared state, A1 labels over one root, and A2 unreachable splitting fail
   to preserve peer and combined freshness under the frozen reuse recipes.
2. A reached A3 boundary preserves peer and combined freshness while the reset
   origin repeats.
3. A4 preserves freshness under raw-state reuse when unique context survives,
   and fails when state and context are reset together.
4. The qualitative 5-by-3 surface is identical across the three pinned
   implementation classes.
5. All 720 confirmation observations match frozen expectations and replay at
   the semantic cryptographic-artifact level.
6. The cost addendum does not establish a reproducible wall-time, CPU-time, or
   peak-RSS difference for nominal A3/A4 versus A0; all 36 prespecified ratio
   intervals include parity.

Use the exact scope and assumptions in
`results/claim_ledger.frozen.json`. C7 is deliberately deferred and prohibited
from manuscript use until the manuscript author completes a current,
independently auditable literature and overlap review.

## Claims that must not be written

- first discovery of shared-RNG risk or invention of hedged randomness;
- universal behavior across all PQC software;
- exploitability, secret recovery, a CVE, physical-fault feasibility,
  side-channel resistance, or IND-CCA failure;
- field failure prevalence or 720 iid security trials;
- raw bit-for-bit replay of every diagnostic trace;
- A3/A4 speed superiority, zero overhead, formal performance equivalence, or
  production readiness.

## Results that need explicit disclosure

- D01: four optional Go read-trace fields were excluded post-run from semantic
  replay; cryptographic artifacts and frozen outcomes remained exact.
- D02: a CRLF/LF digest-writing defect was corrected without changing comparison
  outcomes.
- The Go role router is call-order-pinned measurement instrumentation, not a
  proposed production API.
- The liboqs dual-PQC worker is an implementation realization, not a standardized
  network protocol.
- Process startup and cloud scheduling are included in the cost study.

## Suggested evidence-driven paper structure

1. Problem: algorithm diversity can retain a common entropy failure domain.
2. Closest work and standards: shared-RNG warning, hedging prior art, hybrid KEM
   security, implementation/fault testing, and common-cause software failures.
3. Model: component roles, entropy-state dependencies, reachability, rollback
   recipes, and freshness oracle.
4. Method: architecture ladder, sham control, three implementation mappings,
   frozen schedules, replay, and envelopes.
5. Results: 5-by-3 functional surface, cross-realization consistency, and exact
   bounded replay.
6. Cost addendum: complete-block estimates and the null practical conclusion.
7. Discussion: assurance implication is explicit component-scoped entropy
   interfaces plus reachability testing; no security-game or exploit claim.
8. Limitations and artifact availability.

The manuscript author remains responsible for literature refresh, overlap with
group prior work, venue format, authorship, disclosures, and final scientific
judgment.
