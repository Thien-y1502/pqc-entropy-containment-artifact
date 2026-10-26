# Executed results

## Scientific status

The functional confirmation and the process-level cost addendum are complete
for the frozen scope. The artifact supports manuscript development from the
executed evidence. It does not make a venue-readiness or manuscript-quality
decision.

## Functional confirmation

Every count is `freshness preserved / 8 matched pairs`; the table was identical
in Go TLS, RustCrypto X-Wing, and liboqs dual-PQC, in both primary and replay
execution.

| Architecture | Recipe | Origin | Peer | Combined |
|---|---|---:|---:|---:|
| A0 shared | nominal | 8/8 | 8/8 | 8/8 |
| A0 shared | RNG reuse | 0/8 | 0/8 | 0/8 |
| A0 shared | RNG + context reuse | 0/8 | 0/8 | 0/8 |
| A1 label only | nominal | 8/8 | 8/8 | 8/8 |
| A1 label only | RNG reuse | 0/8 | 0/8 | 0/8 |
| A1 label only | RNG + context reuse | 0/8 | 0/8 | 0/8 |
| A2 unreachable split | nominal | 8/8 | 8/8 | 8/8 |
| A2 unreachable split | RNG reuse | 0/8 | 0/8 | 0/8 |
| A2 unreachable split | RNG + context reuse | 0/8 | 0/8 | 0/8 |
| A3 role routed | nominal | 8/8 | 8/8 | 8/8 |
| A3 role routed | RNG reuse | 0/8 | 8/8 | 8/8 |
| A3 role routed | RNG + context reuse | 0/8 | 8/8 | 8/8 |
| A4 hedge | nominal | 8/8 | 8/8 | 8/8 |
| A4 hedge | RNG reuse | 8/8 | 8/8 | 8/8 |
| A4 hedge | RNG + context reuse | 0/8 | 0/8 | 0/8 |

Primary total: 360 units. Replay total: 360 units. All six evidence envelopes
validate. The replay comparator requires exact unit inputs, cryptographic
artifact hashes, and qualitative outcomes. Four non-semantic Go read-trace
fields and timing/schedule fields are excluded and must not be described as
raw bit-for-bit trace replay.

## Process-level cost addendum

The addendum used 40 randomized complete blocks per implementation and phase.
Each block contained all 15 architecture-by-recipe cells. Process startup is
included. Ratios below are paired medians for the nominal recipe; brackets are
95% percentile-bootstrap intervals over complete blocks.

### Wall-time ratio relative to A0

| Implementation | Phase | A3/A0 | A4/A0 |
|---|---|---:|---:|
| Go TLS | primary | 0.970 [0.932, 1.031] | 1.017 [0.972, 1.068] |
| Go TLS | replay | 0.966 [0.930, 1.014] | 1.022 [0.972, 1.051] |
| RustCrypto X-Wing | primary | 0.992 [0.928, 1.038] | 1.042 [0.951, 1.091] |
| RustCrypto X-Wing | replay | 0.989 [0.906, 1.028] | 0.953 [0.931, 1.010] |
| liboqs dual-PQC | primary | 0.998 [0.935, 1.036] | 0.995 [0.966, 1.006] |
| liboqs dual-PQC | replay | 1.001 [0.997, 1.027] | 0.997 [0.988, 1.007] |

### Child-CPU-time ratio relative to A0

| Implementation | Phase | A3/A0 | A4/A0 |
|---|---|---:|---:|
| Go TLS | primary | 0.993 [0.923, 1.037] | 1.043 [0.984, 1.098] |
| Go TLS | replay | 0.960 [0.940, 1.005] | 1.020 [0.975, 1.043] |
| RustCrypto X-Wing | primary | 0.994 [0.893, 1.054] | 1.043 [0.937, 1.101] |
| RustCrypto X-Wing | replay | 0.974 [0.893, 1.020] | 0.958 [0.916, 1.018] |
| liboqs dual-PQC | primary | 0.999 [0.990, 1.011] | 1.000 [0.989, 1.011] |
| liboqs dual-PQC | replay | 1.000 [0.993, 1.005] | 0.997 [0.988, 1.004] |

All prespecified nominal peak-RSS paired medians were exactly 1.000 relative to
A0, with ratio intervals [1.000, 1.000] at the process-accounting granularity.
Across wall time, CPU time, and RSS, all 36 nominal intervals included parity.

Absolute A0 nominal median wall times were 3.37/3.46 ms for Go,
4.99/5.25 ms for RustCrypto, and 99.65/95.23 ms for liboqs in
primary/replay phases. The implementations perform different operations, so
those absolute values are not an algorithm ranking.

## Bounded interpretation

The cost experiment does not detect a reproducible process-level speed, CPU, or
RSS difference between A3/A4 and A0 at the declared resolution. Point estimates
fluctuate around parity, and some signs change across phases. Therefore:

- a claim that A3 or A4 is faster, cheaper, or operationally superior is
  rejected;
- a claim of zero overhead or formal performance equivalence is also rejected;
- architecture selection should be argued from the tested containment boundary
  and separately evaluated integration/operational constraints, not from small
  timing point estimates in this harness.

Complete values are in `results/performance-analysis/cell_summary.csv` and
`results/performance-analysis/paired_contrasts.csv`.
