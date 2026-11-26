# Independent pilot output checks

All count, digest, paired-workload, witness-causality, CSV/JSON and finite-rate checks passed.
Source commit `e96bb0e89f310b610efadd11d835cf286bd3d26a`. 72 paired cases, 360 configuration results, 720 classifier timing samples and 72 successful saved-input replays.

| Configuration | Omission raw / supported / actual | Equivocation raw / supported / actual | False | Unsupported | Inconclusive | Invalid |
| --- | --- | --- | --- | --- | --- | --- |
| B0 | 0/0/28 | 0/0/24 | 0 | 0 | 88 | 0 |
| B1 | 0/0/28 | 12/12/24 | 0 | 0 | 96 | 12 |
| B1W | 0/0/28 | 12/12/24 | 0 | 0 | 92 | 24 |
| B1R | 0/0/28 | 12/12/24 | 0 | 0 | 96 | 16 |
| B2 | 4/4/28 | 12/12/24 | 0 | 0 | 156 | 24 |

## Diagnostic costs

These are medians over heterogeneous feasibility conditions on this shared host, without statistical inference. Classifier rows include their different evidence-processing paths.

| Nominal leaves | Stage/configuration | Samples | Median elapsed ms | Median managed allocated bytes |
| --- | --- | --- | --- | --- |
| 100 | artifact_generation | 16 | 9.158 | 1433320 |
| 100 | evidence_collection | 36 | 0.065 | 13776 |
| 100 | full_snapshot_authentication | 36 | 10.081 | 343896 |
| 100 | owner_scoring_with_proof_eligibility | 180 | 1.347 | 523896 |
| 100 | classification B0 | 72 | 0.116 | 94808 |
| 100 | classification B1 | 72 | 33.075 | 1453960 |
| 100 | classification B1W | 72 | 33.004 | 1463056 |
| 100 | classification B1R | 72 | 33.597 | 1468556 |
| 100 | classification B2 | 72 | 35.940 | 1493680 |
| 1000 | artifact_generation | 16 | 85.216 | 13967000 |
| 1000 | evidence_collection | 36 | 0.075 | 14016 |
| 1000 | full_snapshot_authentication | 36 | 100.188 | 3411344 |
| 1000 | owner_scoring_with_proof_eligibility | 180 | 8.999 | 4729004 |
| 1000 | classification B0 | 72 | 0.566 | 887024 |
| 1000 | classification B1 | 72 | 304.396 | 13810120 |
| 1000 | classification B1W | 72 | 304.749 | 13818912 |
| 1000 | classification B1R | 72 | 303.881 | 13824508 |
| 1000 | classification B2 | 72 | 323.492 | 13849652 |

Within-case max/min repetition ratios across all configurations have median 1.037, empirical 95th percentile 1.388, and maximum 21.255. Only two repetitions were taken. These are diagnostic stability checks, not confidence intervals.

Maximum observed cumulative process peak working set was 396333056 bytes (378.0 MiB). This includes caches, setup, replay and previous cases.

## Serialized typed input bytes

| Nominal leaves | Configuration | Minimum bytes | Maximum bytes |
| --- | --- | --- | --- |
| 100 | B0 | 42467 | 43723 |
| 100 | B1 | 107831 | 109435 |
| 100 | B1W | 108481 | 110147 |
| 100 | B1R | 108793 | 111204 |
| 100 | B2 | 110101 | 112513 |
| 1000 | B0 | 422164 | 423459 |
| 1000 | B1 | 1045245 | 1047577 |
| 1000 | B1W | 1045796 | 1048301 |
| 1000 | B1R | 1046793 | 1049348 |
| 1000 | B2 | 1048094 | 1050685 |

## Negative controls

Always-accuse omission: raw correct 28, supported 4, false 116, unsupported 140.
Always-accuse equivocation: raw correct 24, supported 12, false 48, unsupported 60.
Always-inconclusive retained every actual positive in its unconditional denominator and issued zero accusations.

## Readiness

Not Ready for final benchmarking. Correctness and replay checks passed. Timing samples are too sparse and environment/GC/order effects remain uncontrolled. The 10,000- and 50,000-leaf matrices were not executed. Full-snapshot reauthentication and allocation costs already rise materially at 1,000 leaves. A representative query/obligation design, stronger isolation and a predeclared statistical protocol are still required.
