# Gate 3A simulation preparation

This document describes the historical Gate 3A API at commit
`28163bcea46b15489f85eb32d115c84d75d9b590`. The current acquisition contracts
and scoring semantics are documented in [Gate 3B](Gate3B-Evidence-And-Scoring.md).

The branch starts at frozen Gate 2 commit `ac1b997f3732483ae8d6df60774458111703f0eb`.
The existing forensic source and its tests retain their frozen contents.

## Workload and replay

`SyntheticGenerator.Generate` creates four logical events per transaction. The order is
pacs.008-like dispatch, transport acknowledgment, pacs.002-like acceptance for processing,
then settlement or rejection. One fifth of terminal statuses are rejected according to a
seeded byte. All messages are structured synthetic records, with synthetic party names,
integer amounts and ISO testing currency XTS. The records are ISO 20022-like research
fixtures. Schema validation and live payment systems are outside the scaffold.

SHA-256 counter derivation version `sha256-counter-v1` determines payment data and IDs.
Transactions are assigned round-robin to the configured corridors. Each event has a
distinct event ID and a transaction ID shared with its three related events. Sequence
numbers start at one and advance per logical event within a corridor. Leaf indexes
start at zero and advance independently for each gateway, log and view after fault
injection and delivery ordering. Retry and duplicate attempts preserve event ID and
corridor sequence. Attempt numbers distinguish writes of the same event.

All simulated timestamps use logical milliseconds. They must be converted explicitly
before any future adapter uses Gate 2 Unix-second contracts. Events with equal delivery
times retain deterministic insertion order. Fault rule array order is part of the
configuration and its digest. No wall clock, system random implementation, or random
cryptographic signatures determine the generated trace.

## Fault schedules

Event rules select a zero-based ordinal in the pristine event array, optionally restricted
to a corridor. Availability windows target gateway A and use inclusive start and exclusive
end. A and B represent the two gateway sides of each synthetic corridor.

| Fault | Provisional simulation behavior |
| --- | --- |
| Omission | Suppress every A write of the selected event, including retries. B retains evidence. |
| Equivocation | A presents two synthetic views with different amounts for the same event. |
| Duplicate | Add the configured number of writes at the original write time. |
| Delay | Add a positive interval to A delivery. Multiple delays accumulate. |
| Retry | Schedule extra attempts at positive multiples of the configured interval. |
| Crash | Drop attempts that arrive during the configured downtime. Later retry attempts can succeed. |
| Partition | Buffer an attempt until partition recovery. Overlapping windows extend recovery. |

A primary A view and an alternate A view are always generated. Their contents match
unless an equivocation rule applies. These are synthetic record views awaiting a future
cryptographic adapter, so the simulator does not claim to produce signed fork evidence.

Per-event delays apply first. Each attempt then advances through applicable partitions
and is dropped if its resulting delivery time falls within a crash. Retried writes are
scheduled relative to the delayed event time. Explicit omission suppresses all A
attempts. An event with no successful A write has an omission truth label. Otherwise
equivocation takes precedence over no finding. Delay, duplicate and recovered retry
events have no omission label at this stage. Timeliness policies and evaluation horizons
need methodology approval.

## Classifier and ground-truth boundaries

`Bsaap.Simulation.Contracts` is the classifier dependency. It exposes typed immutable
evidence records and four interfaces, `IB0Baseline`, `IB1Baseline`,
`IB1WitnessBaseline` and `IB2Baseline`. B1-W maps to `BaselineId.B1W`.
Each classifier receives only `EvidenceTrace` and returns event classifications.
Baseline-specific evidence projections and decision rules await methodology approval.

The owner creates `SimulationRun` and passes its `Evidence` property to the classifier.
The run retains a private immutable ledger of pristine events and expected labels.
The ledger is populated from pristine events and fault semantics, independent of
classifier outputs. Only the owner subsequently calls `Evaluate` with predictions.
Missing and unknown predictions are counted, and duplicate event predictions are
rejected. Aggregate correctness is a unit-test aid until metric definitions are approved.

The classifier contract has no dependency on the harness. Evidence excludes seed,
configuration, schedules and labels. Keep the run, evaluation results and manifest outside
the classifier context. This is an API and dependency boundary within a trusted host.
Executing an actively hostile classifier requires a separate process with restricted
filesystem and network access, since reflection and host-level privileges bypass
ordinary .NET private fields.

## Manifest usage

Create the manifest from the same immutable configuration used for the run, a full
clean source commit SHA supplied by the owner, and the captured runtime description.
Persist the JSON before a future experiment starts.

```csharp
var configuration = new SimulationConfiguration(
    Seed: 2027,
    Scenario: "synthetic-preparation",
    TransactionCount: 4,
    Corridors: ["SYN-A-B", "SYN-C-D"],
    StartTime: 100,
    TransactionSpacing: 40,
    EventSpacing: 10,
    Faults: [new FaultRule(FaultKind.Omission, EventOrdinal: 0)]);
var manifest = ExperimentManifest.Create(configuration, cleanSourceCommitSha);
File.WriteAllText("manifest.json", manifest.ToJson());
var run = SimulationRun.Create(configuration);
// Give only run.Evidence to a classifier. Evaluate predictions afterward in the owner.
```

The manifest records schema and generator versions, source SHA, frozen Gate 2 SHA,
seed, scenario, runtime/framework, OS, architecture, complete workload and ordered
fault configuration, and configuration SHA-256. JSON deserialization restores the
configuration for deterministic replay. The manifest API validates SHA syntax.
The future experiment launcher must verify Git cleanliness and actual checked-out
commit identity. Runtime details support provenance and do not affect replay.

## Methodology questions for approval

- What evidence and decision policies define B0, B1, B1-W and B2?
- Should an omission be judged at a publication deadline, an observation horizon, or
  final trace completion, and how should successful retries affect its label?
- Which faults target each gateway or witness, and what cross-corridor correlations
  and simultaneous-fault precedence should experiments model?
- Should crash recovery retain durable pending writes, and should partitions model
  each direction separately? The current model drops crash-time writes and buffers
  partition-time writes.
- Which metrics, scenario sizes, fault rates, repetitions and statistical procedures
  should final experiments use? Should classifiers run in isolated processes?

Only deterministic unit workloads run during this preparation. Baseline algorithms,
benchmark runners, final performance experiments and methodology claims remain pending.

The checked-in `Gate3A-ExampleManifest.json` was produced by the manifest factory
for a four-transaction synthetic configuration. Its source SHA identifies the clean
implementation commit immediately before the example artifact was added. Creating
this example only serializes configuration and runtime provenance.
