# Novelty and writing boundary

This document gives a manuscript-writing agent the strongest wording supported
by the released artifact. It separates the executed contribution from claims
that still require a current literature and group-overlap audit.

## Status at release v1.0.0

| Layer | Status | Meaning |
|---|---|---|
| Experimental contribution | complete for the frozen scope | code, contracts, 720 confirmation units, 3,600 cost observations, replay, analysis, and a clean public-CI reproduction are available |
| Mechanism claim | supported and bounded | a reached component-scoped entropy boundary preserves peer freshness under the declared origin-only software rollback intervention |
| Novelty positioning | conditional | the executable assurance specialization below survived the completed internal equivalence attack, but no absolute firstness claim is permitted |
| Final related-work claim | deferred | the manuscript author must refresh and document the literature and compare group prior work before submission |
| Venue or acceptance claim | not made | this artifact does not select a venue or predict acceptance |

## Problem-to-contribution chain

**Obstruction.** Algorithm diversity does not imply failure-domain diversity.
Cryptographically different components may consume entropy derived from one
resettable state root. Labels over that root, or a configured split that the
real consumer never reaches, do not create containment.

**Technical object.** The object under test is a reached, role-aware entropy
topology: component roles, the state roots they actually consume, and the
runtime reachability of the intended separation point.

**Mechanism.** A3 routes the origin and peer roles to separate state domains at
the consumed interface. A4 supplies a prior-art hedging control whose unique
context is explicitly included in the fault boundary.

**Algorithmic consequence.** The assurance method compares five architectures
under equal frozen rollback recipes, including label-only and unreachable-hook
negative controls, and checks the resulting real cryptographic artifacts.

**Falsifiable predictions.** Under origin-state reuse, A0--A2 should repeat the
origin, peer, and combined artifacts; A3 should repeat only the origin; A4
should remain fresh while unique context survives and should repeat when both
state and context are reset. Failure of those predictions in a pinned
realization rejects the corresponding mechanism claim.

## Conditional novelty that survived internal red-team review

The defensible candidate contribution is the combination of:

1. converting a standards-described shared-randomness concern into
   component-specific, executable freshness obligations;
2. distinguishing labels or configuration from separation of the state root
   actually reached by the implementation;
3. using an intentionally plausible but unreachable split as a false-assurance
   negative control;
4. comparing a reached role-routed boundary with a prior-art hedge under equal
   event budgets and an explicit context-reset boundary;
5. reproducing one frozen 5-by-3 qualitative decision surface in three pinned
   realization classes: Go TLS X25519MLKEM768, RustCrypto X-Wing, and liboqs
   ML-KEM-768 plus HQC-3;
6. publishing schedules, digest-only records, semantic replay comparators,
   evidence envelopes, matched cost measurements, and a clean CI execution.

This is an applied implementation-assurance contribution. The artifact does
not support describing it as a new KEM combiner, a new randomness hedge, a new
fault-injection paradigm, a new dependency-graph theorem, or a top-security
conceptual breakthrough.

## Why each baseline and ablation exists

| Element | Reviewer alternative it tests |
|---|---|
| A0 shared state | direct common-state propagation is sufficient to explain repetition |
| A1 label only | names or domain labels alone create independent failure domains |
| A2 unreachable split | configuring a second source is sufficient even if the measured path does not consume it |
| A3 reached role route | separation at the consumed component boundary preserves the unaffected peer |
| A4 hedge | established hedging explains freshness while unique context survives, and exposes the joint state/context boundary |
| nominal recipe | ordinary variation occurs without injected reuse |
| origin RNG-state reuse | isolates the declared origin-only rollback mechanism |
| origin RNG-state plus context reuse | tests the boundary at which the hedge control loses uniqueness |
| primary/replay phases | rules out dependence on one persisted schedule while preserving exact semantic units |
| three realization classes | tests transportability beyond one library lineage without claiming population representativeness |

The cost addendum is not evidence that one architecture is faster. Its purpose
is to detect a practically visible process-level cost difference under the
frozen harness. All 36 primary nominal A3/A4-versus-A0 ratio intervals included
parity in the canonical study; the clean public-CI reproduction did the same.
Neither result proves zero overhead or equivalence.

## Wording allowed for a manuscript draft

An agent may write a bounded statement such as:

> We operationalize component freshness under software entropy-state rollback
> as a reached-interface assurance test and evaluate shared, label-only,
> unreachable-split, role-routed, and hedged entropy topologies across three
> pinned hybrid or dual-PQC realization classes.

It may report the exact outcomes in `RESULTS.md` and the scopes in
`results/claim_ledger.frozen.json`. It must describe the novelty as conditional
until the separate literature audit is attached.

## Wording prohibited without new evidence

- first discovery of shared-RNG coupling or first PQC fault study;
- invention of hedged randomness or a new KEM combiner;
- proof of unpredictability, IND-CCA failure, exploitability, secret recovery,
  a CVE, physical-fault feasibility, or field prevalence;
- universal behavior across PQC implementations;
- production readiness or a production-safe Go API;
- bit-for-bit replay of every diagnostic field;
- zero overhead, performance equivalence, or speed/cost superiority;
- Q1/top-conference readiness, likely acceptance, or final novelty clearance.

## Required disclosures in any draft

- D01 excludes four non-semantic Go read-trace telemetry fields from semantic
  replay; cryptographic artifacts and frozen outcomes remain exact.
- D02 corrects a CRLF/LF report-digest defect without changing an outcome.
- The Go role router is call-order-pinned measurement instrumentation.
- The liboqs dual-PQC worker is a realization, not a standardized network
  protocol.
- Confirmation units are deterministic response-surface probes, not iid field
  samples.
- Process startup and scheduler variation are included in cost measurements.
- One clean GitHub-hosted execution is reproducibility evidence, not an
  independent reimplementation by another research team.

## Reading order for another agent

1. `README.md` -- scope and one-command reproduction.
2. This file -- conditional novelty and wording boundary.
3. `AI_HANDOFF.md` -- compact idea-to-evidence map.
4. `docs/METHOD.md` and the two frozen contracts -- estimands and protocol.
5. `RESULTS.md` -- exact canonical results.
6. `results/claim_ledger.frozen.json` -- allowed and prohibited claims.
7. `docs/THREATS_TO_VALIDITY.md` -- deviations, limits, and security boundary.
8. `PUBLIC_RELEASE_MANIFEST.json` and `MANIFEST.sha256` -- release identities
   and file integrity.

The writing agent owns citation refresh, comparison with the research group's
prior manuscripts, venue formatting, authorship, and final scientific judgment.
