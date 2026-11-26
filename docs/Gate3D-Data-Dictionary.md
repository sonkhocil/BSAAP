# Gate 3D data dictionary and replay

The extended runner emits schema `BSAAP-CONTROLLED-PILOT/2`. All owner artifacts
must remain outside classifier context.

| File | Meaning |
| --- | --- |
| results.json | Runtime/build/source metadata, actual epochs, unique artifact-generation measurements, pooled counts/rates, individual cases, all five predictions/scores, owner eligibility counts and both negative controls |
| scores.csv | One row per seed/epoch/condition/configuration/claim kind |
| timings.csv | Classification samples, scoring, setup and dedicated snapshot verification measurements |
| verdicts.csv | Every public query's outcome, frozen-engine verdict when applicable, and reason |
| verdict-matrix.md | Full three-query five-way matrix for the first seed and smallest epoch. All other matrices remain in CSV/JSON |
| input-NNN.json | Immutable scenario definition, acquisition plan, source manifest, compressed archive reference/digest and delivery-body overrides/digest |
| archives/HASH.json.gz | Deduplicated owner production archive containing public keys and exact signed artifacts, with no private signing keys |

## Scores

Counts are dimensionless. Rates are fractions in [0,1]; zero denominators yield
JSON null and an empty CSV field. No NaN or infinite rates are emitted.

- `actual_positive/negative` are independently derived owner facts.
- `admissible_evidence` counts acquired proof bundles under that configuration,
  independently of its submitted prediction.
- `raw_correct` is an accusation matching an actual violation.
- `supported` additionally requires admissible acquired evidence.
- `false_accusations` target actual negatives.
- `unsupported` counts accusations without admissible proof, including guesses
  that happen to match a hidden violation.
- `inconclusive`, `invalid_evidence`, `missing` and `no_finding` retain separate
  output counts. Invalid-evidence counts are reported classifier outcomes.
- `evidence_coverage` divides covered actual positives by all actual positives.
- `conditional_detection` divides supported detections by covered actual positives.
- `supported_precision` divides supported detections by all accusations.
- `serialized_input_bytes` is UTF-8 JSON byte length of the actual typed projection,
  including its public query context. It is not on-wire network bytes.

Counts are scored once per case, rather than once per timing repetition.
Pooled rates are computed from summed counts. Omission is scoped by event,
gateway, log, epoch and accepted deadline. Equivocation is once per log/epoch.

## Measurements

- `elapsed_ms` is actual monotonic wall elapsed milliseconds for the named
  synchronous operation. Logical timestamps never enter this field.
- `monotonic_ticks` uses the recorded Stopwatch frequency.
- `managed_allocated_bytes` uses GC.GetAllocatedBytesForCurrentThread.
- `working_set_before/after_bytes` sample process resident working set.
- `process_lifetime_peak_working_set_bytes` is the cumulative OS process high-water
  mark and includes setup, previous cases, archive caches and replay.
- `managed_heap_after_bytes` is GC.GetTotalMemory(false), without a forced collection.
- `gc_gen0/1/2` are changes in process collection counters over the operation.
- `repetition/order` are zero-based classification indices. -1 denotes a setup
  or scoring operation outside classification repetitions.

Stages are `artifact_generation`, `initial_workload_generation`,
`workload_replay_generation`, `archive_restore`, `evidence_collection`,
`owner_truth`, `public_key_bootstrap`, `full_snapshot_authentication`,
`classification` and `owner_scoring_with_proof_eligibility`.
Artifact generation includes actual P-256 key creation, signing and Merkle work.
It is recorded once per unique production archive. Replay load is separate.
Scoring includes owner proof eligibility checks. Dedicated snapshot authentication
is an overlapping diagnostic and must not be summed with classification.

Nominal leaf count is transactions times four. Faults can change actual signed
snapshot sizes, which are separately recorded as FullSnapshotLeaves. Duplicates
add leaves and omissions remove leaves.

## Provenance and commands

Run from the repository root at the implementation commit named in each input.
The final results commit can follow that implementation commit without changing
its source. Preserve the source SHA printed in the results.

```sh
pilot_source_sha=$(git rev-parse HEAD)
dotnet build -c Release --no-incremental \
  -p:SourceRevisionId="$pilot_source_sha" \
  -p:IncludeSourceRevisionInInformationalVersion=true
dotnet test -c Release --no-build
dotnet run -c Release --no-build --project tools/Bsaap.ControlledPilot -- \
  verification/gate3d/pilot "$pilot_source_sha"
dotnet run -c Release --no-build --project tools/Bsaap.ControlledPilot -- \
  --replay verification/gate3d/pilot/input-001.json
```

The runner checks that Git HEAD and assembly informational version match the
claimed source SHA and refuses tracked modifications or untracked implementation
files. It refuses an attached debugger and generation under Debug configuration.
The results include an assembly SHA-256 fingerprint and machine/runtime details.
Unit tests may execute measurement helpers without running the full suite.

An input manifest example is `verification/gate3d/pilot/input-001.json`.
Replaying verifies compressed bytes, exact signed-archive digest, workload,
protocol/acquisition configuration and delivery-override digest. Replay compares
all functional outcomes and scores. Elapsed samples are expected to differ.

For exact replay while keeping the artifact branch available, build a detached
worktree at the recorded implementation SHA and pass the artifact path from
the current checkout.

```sh
artifact_root="$(pwd)/verification/gate3d/pilot"
pilot_source_sha=e96bb0e89f310b610efadd11d835cf286bd3d26a
git worktree add --detach /tmp/bsaap-gate3d-source "$pilot_source_sha"
cd /tmp/bsaap-gate3d-source
dotnet build -c Release --no-incremental \
  -p:SourceRevisionId="$pilot_source_sha" \
  -p:IncludeSourceRevisionInInformationalVersion=true
dotnet test -c Release --no-build
dotnet run -c Release --no-build --project tools/Bsaap.ControlledPilot -- \
  --replay "$artifact_root/input-001.json"
```

Independent accounting checks run from the artifact checkout with
`python3 verification/gate3d/analyze_results.py`. A locally available pilot
binary's fingerprint is reported separately. Rebuilt binaries on other SDKs
or source paths can differ, so byte-identical binary reproduction is not
claimed. Functional signed-input replay and source provenance remain required.
