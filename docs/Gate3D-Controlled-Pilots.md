# Gate 3D controlled pilot protocol

The nine-condition four-way scope below records the preliminary protocol before
the extended assignment. The current five-way feasibility protocol is defined
in [the decision log](Gate3D-Engineering-Decisions.md), [data dictionary](Gate3D-Data-Dictionary.md)
and [validity report](Gate3D-Fairness-And-Validity.md).

Gate 3D starts at `2429f07c442b9aff1a237d99369f428e985f79df` on
`feature/gate3-simulation`. The frozen Gate 2 cryptographic source and tests
remain unchanged. All payment messages and identifiers are synthetic.

## Omission truth across views

The operational primary journal is subject to the target's accepted logging
obligation, independently of whether its operator publishes any checkpoints.
An authenticated gateway-committed alternative view issued by the observer's
collection cutoff is also subject to the same obligation. The owner verifies
a matching complete snapshot when establishing that an alternative is genuinely
gateway-committed.

An actual omission-policy violation exists when at least one of these obligated
views lacks the event at its accepted publication deadline. This is an ANY-view
policy. Compliance in another view does not cancel the violation. The operational
primary is a declared simulation role, invisible as a privileged view to classifiers.
An unsigned, unused internal alternative is excluded from the policy denominator.

Per-view physical writes and accepted deadlines determine truth. The injector's
fault labels and classifier outputs do not determine expected verdicts. A retry
after the deadline preserves the deadline miss even when both views eventually
contain the event. Wrong payloads remain separately recorded and are outside the
two scored claim kinds. An unaccepted counterparty demand does not establish
a policy violation.

This refines the earlier unconditional aggregation over every internal branch.
It also prevents checkpoint withholding from erasing the primary's accepted
logging duty. Tests cover compliance-state disagreement in both directions,
an uncommitted alternate branch, and total checkpoint withholding.

## Witness authentication and discovery

Authenticating a witness attestation verifies its signature, authorization and
binding to an acquired checkpoint. It does not reveal the gateway signature on an
otherwise unacquired checkpoint.

Discovery uses the new `WitnessCheckpointRetrieval` collection channel. A witness
must have observed the actual published checkpoint, explicitly retained its exact
gateway-signed bytes, made them available, and retained them through the scheduled
forwarding time. An explicit request and disclosure rule must then deliver the
checkpoint by the request timeout and collection cutoff. Retention uses an
inclusive availability time and exclusive expiry. Packets sent before expiry
may arrive afterward if their delivery deadline permits.

Attestation availability and checkpoint forwarding availability are independent.
The archive records the private observation and retention facts. A changed
attestation delivery does not synthesize checkpoint delivery. Existing observer
checkpoint exchange remains a separately requested channel.

All signed baselines can use a legitimately retrieved gateway checkpoint. No
discovery route is granted exclusively to B1-W. The pilot includes attestation-only,
explicit discovery with an attestation, and the same discovery without attestation
delivery. Tests require the acquired gateway evidence to match in the last pair.
The five equivocation-related conditions share identical production archives
for each seed and size, removing signature/nonce differences from this causal
comparison.

## Pilot scope and pairing

The runner executes two seeds, 2027 and 2028, and two workload sizes, two and four
transactions. Each transaction has four ISO 20022-like events. Nine conditions
produce 36 paired cases and 144 baseline results.

- Clean processing.
- Physical omission with a signed accepted obligation and complete obtainable proof.
- The same omission with target ACK delivery withheld.
- Signed equivocation with its alternate checkpoint hidden.
- Signed equivocation with its alternate checkpoint disclosed directly.
- An attestation about the hidden alternative, without checkpoint retrieval.
- Explicit witness-assisted checkpoint discovery.
- The same discovery with attestation delivery withheld.
- Different primary/alternate deadline states caused by a view-specific delay.

Every condition uses the same synthetic payment workload for a given seed and
transaction count. Faults change the write ledger, while public payment generation
remains identical. Each baseline receives its approved typed projection of one
common acquisition history, using the existing immutable trusted bootstrap.

Every case declares five requests and a maximum of six artifacts per request.
The fifth request is reserved for witness checkpoint retrieval in every condition.
A condition's disclosure rules govern whether any response is delivered.
The runner records actual delivery counts, common acquired gateway-root counts,
exposed witness counts and projected JSON input sizes.

There is one audited signed obligation, for event zero, per case. Public queries
still include every event and one log-level equivocation query. This preserves
the Gate 3C query design and keeps the pilot modest. It creates many unbound
negative/inconclusive omission queries, so their prevalence must be redesigned
before a representative full experiment. Equivocation is counted once per log
and epoch. The divergent-deadline case can have both actual truth flags positive.

## Measurement boundaries

Pilots run in Release configuration. Each classifier object, input projection and
trusted bootstrap is prepared before measurement. There is one unmeasured warmup
per classifier and case, followed by two measured invocations. Baseline order is
rotated deterministically across cases and repetitions. Warmup and measured
predictions must be identical.

`Stopwatch.GetTimestamp` brackets only a classifier delegate invocation, including
its artifact parsing, signature verification and immutable prediction construction.
It excludes workload generation, key generation, signing, acquisition, bootstrap
creation, input projection, owner truth, owner scoring, replay checks, serialization
and disk writes. Raw monotonic ticks, stopwatch frequency and a separate
`ElapsedDuration` are saved. Logical milliseconds control simulation deadlines
and never become measured execution latency.

The two timing samples are repeated observations of one case. Accuracy and
coverage counts are scored once per paired case, avoiding duplicate statistical
observations from repetitions. No confidence intervals or latency rankings are
derived from these samples.

The results capture framework, operating system, architecture, processor count,
server-GC mode, build configuration, stopwatch information, source SHA, frozen
Gate 2 SHA, workload, protocol schedule, acquisition policy and exact signed
artifact archive. The program writes replay inputs before executing each case.
It reconstructs inputs again and compares every prediction and owner score from
all four classifiers. Existing Gate 3C saved inputs retain compatible digests.

## Metrics and interpretation

Raw correct accusations, supported detections, false accusations, unsupported
accusations, positive-case evidence coverage, evidence-conditional detection,
inconclusive, reported invalid-evidence, no-finding and missing outputs are retained
separately. Undefined rates remain null. Repetition counts do not multiply their
denominators. Aggregate reports sum counts before computing pooled ratios.

A classifier's `NoFinding` represents presence in the available view. Frozen Gate 2
`Compliant` continues to mean presence in the challenged snapshot. Neither proves
deadline compliance across undisclosed obligated views. Physical truth can record
a deadline miss when later collected evidence cannot prove it.

Equal requests do not imply equal bytes, evidence utility or cryptographic work.
The signed baselines repeatedly authenticate snapshots per query, while B0 has
no corresponding cryptographic cost. B2 additionally requires complete
target-specific proof. These are declared capability and implementation differences.

## Execution and recommendation

```sh
dotnet build -c Release
dotnet test -c Release
dotnet run -c Release --no-build --project tools/Bsaap.ControlledPilot -- \
  verification/gate3d/pilot FULL_CLEAN_IMPLEMENTATION_COMMIT_SHA
```

The pilot validates classification, evidence causality, metric accounting,
measurement boundaries and replay. Its accuracy counts are useful as integration
checks under these exact scenarios. Its elapsed samples are instrumentation
sanity checks on the current shared environment.

Before final benchmarking, predeclare representative obligation prevalence and
fault rates, query weighting, collection strategies, byte/work accounting,
independent run counts, hardware isolation, warmup criteria and statistical
analysis. Establish an approved timing boundary for the eventual reported system.
The current single warmup, two repetitions and modest sizes cannot characterize
steady-state latency, tail latency, throughput or scaling. The owner and baseline
share frozen verification primitives, so proof eligibility is not an independent
cryptographic implementation. Owner-only records still require a trusted host
or separate classifier processes.

Actual crash recovery, cross-epoch behavior, production payment integration and
the final large-scale benchmark matrix remain outside this pilot. No
publication-level performance conclusion follows from these measurements.
