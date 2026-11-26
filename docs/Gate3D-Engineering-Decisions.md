# Gate 3D engineering decision log

## Milestone A

- The operational primary journal remains bound by an accepted target obligation
  even when checkpoints are withheld. An authenticated, issued alternative view
  adds another obligated view. A miss in any obligated view counts once for its
  event/log/epoch/deadline scope. An unused unsigned alternative is excluded.
- Scope is the target gateway A, corridor-specific log, epoch 1, event identity
  represented by transaction ID, corridor sequence, event type and expected payload,
  and the applicable obligation's deadline. Query results aggregate to one event
  claim, and log equivocation counts once per gateway/log/epoch.
- Wrong-payload records are tracked separately from physically absent entries.
  Late retries preserve deadline misses. Missing acceptance prevents a policy
  violation from being inferred from physical absence alone.
- Witness attestation authentication and checkpoint forwarding are separate.
  Forwarding requires actual observation, explicit retention, a retrieval request
  and delivery before request/cutoff limits. All authenticated configurations can
  use a legitimately forwarded gateway checkpoint.
- Methodology and replay regressions passed before pilot execution. No full pilot
  suite had run when the extended assignment arrived.
- Frozen Gate 2 source and tests are unchanged. The classifier assembly cannot
  reference owner truth. Trust bootstrap records carry public keys and grants only.

## Approved extension and conservative assumptions

- B1-R adds target-specific receipt obligations and ACKs to B1 while retaining
  independent checkpoint authentication and equivocation detection. It receives
  no witness attestations and cannot turn a gateway's timestamp into an independent
  omission proof.
- Existing numeric baseline identities remain stable for historical replay.
- Feasibility sizes will be bounded by the repeated full-snapshot verification
  and archival costs of the actual implementation. The suggested larger epochs
  will be reported as unexecuted if their cost is impractical.
- Public audit sampling will be declared independently of faults and paired across
  all configurations, so increasing full-log sizes does not silently create an
  unbounded number of repeated complete-snapshot verifications.

## Milestone B

- Added B1-R as a fifth configuration with immutable typed receipt/ACK input.
  Its numeric identity was appended, preserving historical B2 identity.
- B1-R validates receipt issuer and target ACK roles, gateways, logs, corridors,
  payload binding and delivery times. It can authenticate gateway forks without
  a witness. ACK acceptance alone never becomes a fresh omission proof.
- Shared receipt authentication was extracted from the B2 adapter. The frozen
  Gate 2 engine and its signing contracts were untouched.
- Twelve targeted B1-R tests passed before five-way functional validation.

## Milestone C

- Eighteen five-way functional scenario tests passed before feasibility execution.
  Expected outputs appear only in tests, never in classifier implementations.
- Added always-accuse and always-inconclusive controls. Proof eligibility and
  actual violation flags remain independent of these submitted outputs.
- One initial test invocation used an unsupported dotnet test --project switch.
  Its command error is retained. The corrected invocation passed all 18 tests.
- B1/B1-W/B1-R/B2 are capability configurations with R/W labels. B2 also validates
  challenged checkpoint freshness, so these observations cannot isolate a pure
  statistical witnessing effect independently of the full freshness mechanism.

## Milestone D

- Feasibility epochs are nominally 100 and 1,000 leaves, with two paired seeds.
  Only public event ordinals 0 and 1 and one log/epoch equivocation query are
  evaluated. Full acquired snapshots retain every leaf. This audit sample is
  fixed before fault schedules and is identical across all configurations.
- A single signed obligation covers event 0. Event 1 is a negative control.
  This prevalence is for feasibility validation and is not population-representative.
- Added exact source/assembly provenance checks, compressed hash-pinned archives,
  delivery-corruption digests, CSV and JSON exports and outcome-total validation.
- Managed allocations count synchronous current-thread allocations only.
  Native cryptographic allocations are not directly counted.
- Process memory includes pre/post working set and the OS-reported cumulative
  process-lifetime peak. It is not an isolated per-classifier peak.
- Dedicated full-snapshot authentication overlaps verification inside classifiers.
  These timings must not be added as disjoint components of end-to-end latency.
- Release build and one warmup/two measured repetitions are feasibility choices.
  No forced GC, CPU pinning or production network transport is used.

## Milestone E

- Executed 72 paired feasibility cases with seeds 2027/2028, nominal 100/1,000
  leaves, 18 conditions, five configurations and two measured repetitions.
  All 360 configuration results and 720 samples were saved.
- Release assembly source stamp and Git HEAD matched implementation commit
  e96bb0e89f310b610efadd11d835cf286bd3d26a. No debugger was attached according
  to the runtime guard. Final Debug and Release suites each passed 158 tests.
- The 10,000- and 50,000-leaf epochs were not executed. At 1,000 leaves the
  isolated snapshot diagnostic already had a 100.188 ms median and about
  3.41 MB of managed allocations. Repeated classification and archival costs
  made larger matrices inappropriate for this modest feasibility stage.
- Raw timing medians aggregate heterogeneous conditions and are diagnostic only.
  The two repetitions do not support steady-state or tail-latency claims.

## Milestone F

- Saved-input replay matched every prediction and score for all 72 cases.
  Separate process replays also matched at 100 and 1,000 leaves.
- Independent Python checks verified 72 archive digests, CSV/JSON row counts,
  finite rates, denominators, paired workloads, shared witness-family production
  bytes, source stamps and clock-unit conversions.
- No implemented configuration produced a false or unsupported accusation in
  these fixtures. The always-accuse control exposed 116 false omission accusations
  and 48 false equivocation accusations, despite raw detection of every positive.
- B1-R produced no supported omission accusation and received no witness inputs.
  Like B1 and B1-W, it produced 12 supported equivocation detections from 24 actual
  signed-equivocation cases. B2 additionally produced 4 supported omissions from
  28 actual omission-policy violations.
- Within-case timing max/min ratios had a median of 1.037, empirical 95th
  percentile 1.388 and maximum 21.255. Timing stability is insufficient for final
  benchmarking under this shared-host, one-warmup/two-sample protocol.
- Wrong source provenance was deliberately rejected before creating an output
  directory. Its expected nonzero exit and the earlier CLI invocation error are
  retained in verification logs, rather than represented as test results.
- Frozen Gate 2 source and tests remained byte-for-byte identical. No branches
  were merged. Recommendation is Not Ready for final benchmarking.
