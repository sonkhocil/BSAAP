# Gate 3C baseline classifiers

Gate 3C starts at `f9e5e64173af7c6864580b0a758dfb2652fe5387`.
The classifiers reside in `Bsaap.Baselines`, which references public simulation
contracts and the frozen forensic verifier. It has no dependency on the simulation
owner assembly, truth records, schedules or manifests.

## Trusted provisioning

The owner exports `ImmutableArray<TrustedPublicSigner>` from its original production
archive through `ExperimentOwner.ExportTrustedPublicKeys`. Provision a
`TrustedPublicKeyBootstrap` from these authenticated records before supplying evidence
to a signed classifier. Registrations contain public SPKI, signer identity, role and
explicit gateway, log and corridor grants. P-256 validation and role/scope checks use
the frozen registry. Public bootstrap records are immutable strings and immutable
arrays. The verification registry stays private to the baseline assembly.

Bootstrap keys must come from the trusted experiment owner or another authenticated
provisioning channel. Importing purported trust anchors from an arbitrary evidence
sender would defeat this boundary. Classifiers never discover or register keys from
collected evidence. Private keys and fault configuration are excluded.

Each signed classifier also receives an immutable `VerificationClock`. It maps
second-aligned logical timestamps to Gate 2 Unix seconds and supplies an explicit
retrospective verification time. No classifier reads the wall clock or measures
execution latency.

## Evidence capabilities and decisions

| Classifier | Processing and supported findings |
| --- | --- |
| B0 | Inspects ordinary unsigned records for presence, payload disagreement and conflicting leaf indexes. Observable inconsistencies yield inconclusive results with explanatory reasons. It cannot prove signed-log equivocation or a target-specific omission. |
| B1 | Authenticates the target gateway's acquired heads and complete snapshots using trusted gateway keys. Two authenticated conflicting heads at the same gateway/log/epoch/size support an equivocation accusation. Authenticated payload presence yields no finding. Absence alone is inconclusive. |
| B1-W | Retains B1 capability and independently verifies witness role, scopes, signature, observation time, checkpoint digest, root and exact gateway-signature binding. Missing or authentic unbound observations retain B1 capability. Invalid supplied attestations yield invalid-evidence outcomes. Witnessing does not establish a target logging obligation. |
| B2 | Authenticates candidate artifacts, correlates their signed references, and invokes the frozen Gate 2 audit engine for target-specific obligations, ACKs, challenged checkpoints, witnesses and snapshots. A verified omission proof yields an accusation. Verified presence yields no finding. Missing proof components remain inconclusive. |

B1-W and B2 retain independent signed-equivocation detection even when witness
assistance is absent or invalid. An authenticated conflict proves the log claim.
The separate omission query remains inconclusive when the acquired signed views
conflict. A genuine proof takes precedence over an invalid distractor for the same
equivocation query.

A `NoFinding` result records observed presence in the available view. Gate 2
`Compliant` records presence in the challenged snapshot. Neither establishes
publication by the obligation deadline. A signed payload mismatch is outside the
two scored claim kinds and remains inconclusive.

`Prediction` now includes an explanatory reason and optional frozen-engine verdict.
Owner scoring ignores these self-reported metadata when deciding whether an
accusation had admissible support.

## Evidence-supported scoring

Existing Gate 3B counts remain available. The report additionally exposes explicit
`RawFactuallyCorrectAccusations`, `EvidenceSupportedDetections`,
`EvidenceSupportedDetectionRate` and `EvidenceSupportedPrecision`.

- Raw factually correct accusations count accusations on independently established
  actual violations, regardless of acquired proof.
- Evidence-supported detections count accusations on actual positives for which
  the owner independently established baseline-admissible acquired proof.
- Evidence-supported detection rate divides supported detections by all actual
  positives. Evidence-supported precision divides supported detections by every
  accusation, including false and unsupported accusations.
- False accusations, unsupported accusations, inconclusive outputs, reported invalid
  evidence and missing predictions retain separate counts. Zero denominators are
  represented by nullable rates.

The always-accuse negative control demonstrates why raw detection is insufficient.
It cannot manufacture supported detections by adding claims without evidence.
For a complete omission proof, it can match B2's supported detection while producing
extra false accusations and lower supported precision. For a hidden fork, its raw
accusation can be factually correct while supported detection remains zero.

There is no aggregate ranking function or invented weighting between error types.
Review supported detection, false accusation and unsupported accusation counts
together. Raw detection alone is unsuitable for comparing these classifiers.

## Fairness and functional comparison

Each scenario constructs one synthetic payment workload, one production archive,
one observer collection plan and one trusted bootstrap. All classifiers use that
same acquired history and approved limits of four requests and six response
artifacts per request. Their typed evidence capabilities differ as approved in
Gate 3B. B0 receives one own-gateway unsigned view, B1 authenticates each acquired
gateway view, B1-W receives witnesses, and B2 receives obligations, ACKs and challenges.

This is a comparison of evidence capabilities under a common acquisition plan.
Equal request budgets do not imply equal evidence utility, byte counts,
cryptographic work or measurement cost. B1 does not infer obligations from peer
records. B2's stronger evidence prerequisites may make it inconclusive when B1
can already establish snapshot presence. B1-W may fall back to B1 when witnessing
is unavailable. These effects must be considered before interpreting detection
or inconclusive rates as algorithmic superiority.

The functional runner exercises nine small scenarios with seed 2027, one transaction
and four events. It invokes all four classifiers, records every query result and
owner score, and includes an always-accuse negative control. It contains no timing
measurement or performance benchmark loop.

```sh
dotnet run --project tools/Bsaap.FunctionalComparison -- \
  verification/gate3c/functional FULL_CLEAN_IMPLEMENTATION_COMMIT_SHA
```

The runner writes a verdict matrix, detailed results, and nine owner replay-input
files containing the manifest, public-key/signed-artifact archive and any transport
body overrides. It deserializes these inputs and confirms identical classifications
from all four classifiers. Cryptographic signatures and nonces use real randomness;
the saved owner archives support exact replay, while workload and verdict generation
are deterministic.

The owner method `WithDeliveredArtifactBodies` supports transport-corruption cases.
It changes delivered bodies while preserving original production truth, trusted
keys, routing and budgets. Classifiers see the resulting projections only.
Replay inputs are owner artifacts and must be kept outside classifier context.

## Remaining methodology limits

- Ground-truth physical and policy records remain independent of classifier
  predictions. The proof-eligibility oracle and signed classifiers share frozen
  Gate 2 verification primitives. This does not provide independent cryptographic
  implementation diversity.
- Owner isolation remains a trusted-process API boundary. Actively hostile
  classifiers require process isolation.
- The simulator currently audits gateway A in epoch 1, uses second-aligned signed
  fixtures, and requires target acceptance by the deadline. Real crash recovery,
  cross-epoch key lifecycle and production payment integration remain outside scope.
- Invalid-evidence counts record classifier outputs. Accuracy for identifying each
  corruption type is tested through regressions, while a general invalid-evidence
  confusion matrix remains a future methodology extension.
- Public queries cover every generated event, while the functional fixtures issue
  a signed obligation for the first event only. Detailed results preserve this
  distinction. The compact matrix reports that first event and the log-level
  equivocation query.
- The frozen engine prioritizes known equivocation over omission findings. Positive
  physical/policy truth can coexist with insufficient admissible omission proof.
  A late retry remains a deadline miss in owner truth even when all classifiers
  subsequently observe presence.
- No final benchmarks, statistical performance claims or branch merges are included.
