# Method and measurement contract

## Fault model

The intervention resets deterministic software entropy state. The origin role
is ML-KEM-768. The peer role is X25519 in the hybrid realizations and HQC-3 in
the dual-PQC realization. The study compares an anchor trial with a matched
comparison trial under three recipes:

- `nominal`: no state reuse;
- `origin_rng_state_reuse`: origin raw state is reused while permitted
  independent state/context advances;
- `origin_rng_and_context_reuse`: origin raw state and uniqueness context are
  both reused.

The model does not estimate how often reset events occur in deployments.

## Property oracle

The oracle compares digests of public artifacts and combined outputs. Inequality
is recorded as freshness preservation for the matched pair. Honest agreement is
required for the RustCrypto and liboqs encapsulation/decapsulation paths. Go is
measured at ClientHello generation and therefore has no decapsulation claim.

Artifact inequality is not unpredictability and is not a cryptographic security
proof.

## Controls

- A0 identifies direct common-state propagation.
- A1 falsifies the idea that labels alone create failure-domain independence.
- A2 falsifies a configured split that does not reach the actual consumer.
- A3 tests a reached component-scoped boundary.
- A4 tests a declared prior-art hedge and its joint-state/context failure
  boundary.

## Confirmation unit

Each unit is one isolated child process that evaluates an anchor/comparison
pair. Eight disjoint pairs populate each architecture-by-recipe cell. The unit
is a deterministic implementation observation, not an independent draw from a
field-failure population.

## Cost unit and estimand

Each cost phase contains 40 complete randomized blocks. A block contains one
observation of every architecture-by-recipe cell and is the paired statistical
unit. Primary estimands are nominal A3-A0 and A4-A0 median paired differences
and ratios for wall time, child CPU time, and peak RSS. Uncertainty is a 95%
percentile bootstrap interval over blocks with 10,000 resamples. Every
prespecified contrast is retained; no null-hypothesis significance filter is
used.
