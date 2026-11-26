# Gate 3B evidence acquisition and scoring

This implementation extends Gate 3A commit
`28163bcea46b15489f85eb32d115c84d75d9b590` on `feature/gate3-simulation`.
The frozen Gate 2 source and test projects remain at
`ac1b997f3732483ae8d6df60774458111703f0eb`.

## Owner and classifier boundary

The owner retains `SimulationRun`, `ProtocolSchedule`, `ProtocolArchive`,
`AcquisitionPlan` and `ExperimentOwner`. Classifiers receive only one of
`B0Evidence`, `B1Evidence`, `B1WitnessEvidence` or `B2Evidence`.
The former global `EvidenceTrace` and label-derived evaluation API have been removed.

`PhysicalEventTruth` records actual writes and matching-payload writes separately
for each internal log view and observation horizon. An incorrect payload is tracked
separately from a physically absent write. `PolicyTruth` records target acceptance,
deadline presence, final presence and payload correctness. Its deadline-miss flag
survives successful later retries.

`ActualTruthFlags` derives omission-policy violations from accepted obligations
and actual write times. Signed-log equivocation derives from authenticated conflicting
checkpoint productions in the same log, epoch and tree size. The evaluator does not
read fault labels to assign expected verdicts. `EvidenceEligibility` is computed
independently for each observer, baseline and query from acquired artifacts.

Omission queries are per event and target log. Equivocation queries are per log and
epoch, so a fork is counted once. The public query stream covers the complete
synthetic workload regardless of injected faults. Internal fork names, fault schedules,
seed, complete artifact inventory and truth records never enter classifier bundles.

This is an API and dependency boundary within a trusted owner process. The internal
ledger is visible to the unit-test assembly through `InternalsVisibleTo`. Hostile
code requires process isolation. Do not pass owner objects, archives, manifests,
scoring reports or acquisition schedules to classifier code.

## Production and delivery

`ProtocolArchive.Create` generates real ECDSA P-256 signatures using the existing
Gate 2 signing contracts. The simulator retains public keys, signed artifacts and
owner routing metadata. Private signing keys are disposed and never exported.
The archive is an owner provenance artifact and must be pinned through its manifest,
rather than trusted as an externally supplied key authority.

Protocol schedules independently control obligation publication, target acceptance,
ACK availability, challenge issuance, checkpoint creation, witness observation and
attestation availability. ACK signatures bind the exact issuer artifact. A signature
can exist without the observer acquiring it.

The current policy requires target acceptance by the publication deadline. ACK
delivery may occur later. Retroactive target acceptance is rejected pending a
defined policy for that case. Self-issued obligations use their signed publication
as target acceptance. Challenges can reference accepted obligations only after the
acknowledgment is available to their issuing actor.

Checkpoint creation time is distinct from an optional signed timestamp claim.
A checkpoint response cannot be produced before its challenge. A backdated signed
timestamp can still be modeled as invalid freshness evidence. Witness observation
must follow actual checkpoint creation.

`EvidenceAcquisition` executes observer-specific requests and disclosure rules.
Direct requests retrieve only artifacts from the requested producer. Checkpoint
exchange forwards only heads already acquired by the sender at the forwarding
time. Artifact creation, delivery delay, request timeout and observer cutoff all
apply. Cutoffs and timeouts are inclusive. Simultaneous deliveries use disclosure
array order as the stable tie-breaker.

The artifact selection is owner-scheduled. There is no adaptive classifier querying
or final baseline algorithm. Observers may receive different views or no response.
A hidden fork remains outside every projection until a legitimate delivery occurs.

## Fair evidence projections

All four projections for an observer share an identical public query stream,
collection cutoff, request budget and response artifact budget. They derive from
the same acquired artifact history and identical payment workload.

| Projection | Acquired evidence supplied |
| --- | --- |
| B0 | Ordinary records from the most recently received own-gateway snapshot per log, with signatures and internal view labels removed |
| B1 | Bilateral signed checkpoints and complete snapshots, including signed heads legitimately conveyed inside snapshots |
| B1-W | B1 evidence plus acquired witness attestations |
| B2 | B1-W evidence plus acquired obligations, target ACKs and auditor challenges |

B0 receives one local view per log. B1 can acquire conflicting authenticated heads
and support an equivocation accusation without a witness or auditor challenge.
No baseline receives unpublished or undisclosed views by capability alone.

The shared request budget includes requests whose specialized response is unavailable
to a baseline. This implements paired evidence acquisition under a common collection
schedule. Adaptive request allocation and byte-normalized budgets are outside this
implementation.

Signed artifacts are held as immutable JSON strings. Reading an artifact produces a
fresh Gate 2 object graph, so mutable arrays and entry lists cannot alter other
projections or the owner archive. Malformed artifacts remain visible to the relevant
typed input, while the owner proof-eligibility check excludes unusable data.

## Scoring

Each classifier may submit one `Prediction` per public query with an outcome of
`NoFinding`, `Accusation`, `Inconclusive` or `InvalidEvidence`.
Missing outputs are counted separately. Unknown queries and duplicate outputs are
rejected. No output is hardcoded for any baseline.

For each claim kind, the report records the following independent quantities.

| Quantity | Definition |
| --- | --- |
| Actual positives | Independently established policy violations or signed-log equivocations |
| Actual negatives | Evaluated queries without that actual violation |
| Detections | Accusations on actual positives |
| False accusations | Accusations on actual negatives |
| Evidence-covered positives | Actual positives for which the observer and baseline acquired admissible proof |
| Evidence-conditional detections | Accusations on evidence-covered actual positives |
| Unsupported accusations | Accusations lacking baseline-admissible proof, regardless of factual truth |
| Inconclusive / invalid evidence | Counts of these distinct submitted outcomes |
| Missing / no finding | Counts retained independently |

The unconditional detection rate divides detections by actual positives. The false
accusation rate divides false accusations by actual negatives. Evidence coverage
divides evidence-covered positives by actual positives. Evidence-conditional detection
divides conditional detections by evidence-covered positives. A zero denominator
produces a nullable rate.

A truth-matching accusation can contribute to raw detection and also be unsupported.
This overlap is deliberate and is visible through the separate conditional metric.
Invalid-evidence counts describe the classifier's reported outcome. They do not
automatically establish the correctness of that outcome.

Admissible omission proof currently requires the complete frozen Gate 2 evidence
path. Signed ACK availability alone is insufficient. Eligibility authenticates
candidate proof bundles with the frozen engine, independently of classifier outputs.
B1, B1-W and B2 may establish equivocation from acquired authenticated conflicting
heads. B0 has no authenticated proof path.

Policy facts retain deadline misses after late writes. Gate 2 `Compliant` remains
presence in a challenged snapshot. It does not establish timely publication.
The frozen engine prioritizes known equivocation over omission findings. Independent
truth flags can therefore both be positive while only the equivocation proof is
admissible through that engine call.

Actual equivocation truth is bounded by the observer's collection cutoff. The owner
truth horizon must cover all cutoffs and obligation deadlines, and evaluated
obligations must already be due when collection closes. An undisclosed fork produced
after an early observer's cutoff does not retroactively change that observer's truth.

## Replay and timing

Logical milliseconds use `LogicalInstant`. Real execution durations use the distinct
`ElapsedDuration` type. No benchmark runner or measured latency computation is added.
The Gate 2 adapter requires exact second-aligned logical times and an explicit Unix
epoch mapping. It rejects conversions that would round timestamps or change strict
deadline boundaries.

Payment generation and scheduled delivery remain deterministic. Cryptographic keys,
signatures and challenge nonces use real randomness. Exact protocol replay retains
the owner archive, including signed bytes and public keys. `EvidenceManifest` records
the workload, protocol and acquisition schedules, versions, source SHA, runtime,
configuration digest and archive digest. `ExperimentOwner.Replay` verifies those
digests before reconstructing acquisition and scoring.

The source SHA is supplied by the owner. The future experiment launcher must validate
Git cleanliness and provenance. Neither the seed nor private signing keys are used
to reconstruct cryptographic credentials.

## Scope and remaining assumptions

- The current synthetic policy audits gateway A, epoch 1. Fault directionality,
  multiple witnesses, cross-epoch continuity and production payment schemas need
  additional methodology and adapters.
- Omission truth is evaluated per event across its modeled log views. Incorrect
  payloads are recorded separately and are outside the two scored claim kinds.
- The proof-eligibility oracle shares the frozen Gate 2 verifier with future B2
  integration. Physical and policy truth remain independent, but this does not
  constitute an independent cryptographic implementation.
- Evidence eligibility currently means positive accusation proof availability.
  It does not claim that absence of proof establishes innocence.
- Deadlines and query weighting are explicit inputs. Adaptive collectors, alternate
  scoring weights, classification of invalid-evidence correctness and negative
  compliance certificates remain methodology extensions.
- Crash behavior continues to simulate dropped writes and retries. Durable recovery
  integration, final baseline decision algorithms and performance experiments are
  outside Gate 3B.
