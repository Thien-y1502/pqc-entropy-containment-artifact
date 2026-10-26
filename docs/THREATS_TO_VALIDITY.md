# Threats to validity

## Construct validity

Freshness is defined by equality/non-equality of deterministic artifact digests.
The oracle does not measure unpredictability, secret recovery, or a security
game. A3 and A4 are intentional interventions, so part of the abstract response
is by construction; the empirical question is whether the boundary is reached
at the real implementation interface and reflected in real cryptographic
artifacts.

## Internal validity

The common runner aligns scheduling and outcome definitions across the three
workers and is a shared-method dependency. Independent implementation code,
artifact digests, negative controls, process isolation, replay permutations,
and envelope verification reduce but do not eliminate that concern.

D01 excludes four non-semantic Go read-trace fields from semantic replay after
those fields varied. The exclusion cannot hide a cryptographic artifact or
freshness mismatch, but the raw diagnostic trace is not bit-identical. D02 is a
line-ending correction to report serialization.

## External validity

Only three pinned realization classes are tested. The evidence does not cover
all libraries, protocol roles, versions, operating systems, compilers, hardware,
or physical fault mechanisms. The Go role router is measurement instrumentation
pinned to one call sequence.

## Statistical validity

Confirmation counts are exact deterministic response-surface observations and
must not be analyzed as iid Bernoulli trials. Cost estimates use complete blocks
and paired bootstrap intervals. Forty blocks bound precision; inclusion of
parity is not proof of equivalence or zero overhead. Cloud scheduling and
process startup contribute to timing variance.

## Security interpretation

The study supports an entropy-topology and freshness assurance claim only. No
claim is made about exploitability, CVE status, physical injection feasibility,
side channels, IND-CCA security, prevalence, or production deployment safety.
