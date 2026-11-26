# Gate 3D execution and readiness assessment

Implementation source commit is `e96bb0e89f310b610efadd11d835cf286bd3d26a`.
The following artifact commit contains the saved experiments, without changing
the implementation that produced them.

Both final Debug and Release builds succeeded with zero warnings and errors.
Each full test run passed 158 tests, with zero failures and zero skips. The
42 frozen Gate 2 tests and all frozen cryptographic files are unchanged.

The runner executed 72 paired cases, 360 baseline evaluations and 720 timed
classifier calls. Its 18 conditions span clean processing, acknowledged omissions,
missing/delayed ACKs, witness absence, hidden/directly disclosed/witness-discovered
forks, corrupted signatures, partitions, duplicates, retries and delayed snapshots.
Every saved input replay reproduced all five configurations' verdicts and scores.
Separate-process replays passed at both feasibility sizes.

| Configuration | Supported omission / actual | Supported equivocation / actual | False | Unsupported |
| --- | --- | --- | --- | --- |
| B0 | 0/28 | 0/24 | 0 | 0 |
| B1 | 0/28 | 12/24 | 0 | 0 |
| B1-W | 0/28 | 12/24 | 0 | 0 |
| B1-R | 0/28 | 12/24 | 0 | 0 |
| B2 | 4/28 | 12/24 | 0 | 0 |

Raw correct accusations equaled supported detections for the implemented
configurations in these fixtures. Always-accuse raw correctness was 28 omission
and 24 equivocation cases, while only 4 and 12 respectively had acquired proof.
It generated 116 false omission accusations and 48 false equivocation accusations.
Always-inconclusive generated no accusations and retained all missed positives.

The operational primary remains obligated without published checkpoints.
An authenticated committed alternative adds a second policy view. Missing the
accepted deadline in any obligated view counts once. Per-view regressions ensure
that compliance elsewhere and later retries cannot erase that violation.
An unused unsigned alternate is excluded.

Witness availability never injects checkpoint evidence by itself. Explicit
observation, retention, request and delivery are required. B1, B1-W, B1-R and
B2 had identical equivocation outcomes in the witness-discovery conditions.
No B1-W detection advantage was manufactured.

## Measurement conditions and limitations

The environment was .NET 9.0.23, Debian 13 linux-x64, AMD EPYC 9V74, with a two-CPU
container quota and an 8 GiB memory limit. Workstation GC used Interactive latency
mode. Release execution refused an attached managed debugger. Samples used a
1 GHz monotonic Stopwatch frequency, one warmup and two repetitions, with
deterministically rotated configuration order and no forced GC.

At nominal 100 and 1,000 leaves, dedicated full-snapshot authentication medians
were 10.081 ms and 100.188 ms. Median current-thread managed allocations were
343,896 and 3,411,344 bytes. These diagnostics overlap verification performed inside
classification and must not be added to it as independent end-to-end components.

The cumulative observed process peak working set was 396,333,056 bytes, or 378.0
MiB, including setup, archive caches, previous cases and replay. It is not a
per-configuration peak. Native cryptographic allocations are outside the
managed-allocation counter.

Within-case repetition ratios had median 1.037, empirical 95th percentile 1.388
and maximum 21.255. Two samples are insufficient for a statistical stability
estimate, and these observations show material timing variability. No
publication-level performance or significance conclusion is supported.

The 10,000- and 50,000-leaf matrix was not executed. The feasibility runner used
100/1,000 leaves and a fixed public audit sample of two events plus a log claim.
Snapshots remained complete. This scope validates the pipeline while bounding
repeated snapshot-authentication and archive costs.

## Recommendation

**Not Ready for final benchmarking.** Functional behavior, replay and accounting
passed the controlled checks. Before a final experiment, approve representative
obligation/query prevalence, independent runs, warmup/stability criteria,
hardware/process isolation, memory attribution and a statistical protocol.
A full performance matrix would also need a deliberate strategy for repeated
snapshot verification, rather than treating the current repeated work as a
protocol-inherent cost.

Remaining assumptions include gateway A/epoch 1, target acceptance before the
deadline, a trusted owner host, common-verifier bias, capability-dependent evidence
utility despite equal request budgets, and single-obligation pilot prevalence.
General invalid-evidence classification accuracy and real durable crash recovery
remain outside these results.

The data dictionary, complete matrices, JSON/CSV exports, raw logs and independent
checks are retained under docs and verification/gate3d. No final paper, large-scale
benchmark matrix or branch merge was produced.
