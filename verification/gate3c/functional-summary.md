# Gate 3C functional execution results

Implementation commit `aee9aca31d9737a9e11ea447eb6109f1c71cd4b2` was tested
with `dotnet build` and `dotnet test`. Build completed with zero warnings and
errors. Tests completed with 106 passed, zero failed and zero skipped, comprising
64 simulation/classifier/scoring tests and 42 frozen Gate 2 tests.

The functional runner completed nine scenarios, 36 baseline evaluations and
serialized-input replay checks for all four classifiers. Seed 2027, the generated
payment workload and approved collection budgets were common across baselines.
These are functional results from small synthetic fixtures.

| Baseline | Raw correct accusations | Supported detections | False accusations | Unsupported accusations |
| --- | --- | --- | --- | --- |
| B0 | 0 | 0 | 0 | 0 |
| B1 | 1 | 1 | 0 | 0 |
| B1-W | 1 | 1 | 0 | 0 |
| B2 | 2 | 2 | 0 | 0 |

In the proven-omission scenario, both B2 and the always-accuse negative control
had one raw correct accusation and one supported detection. B2 had zero false
and unsupported omission accusations and supported precision 1.0. The negative
control had three false and unsupported omission accusations and supported
precision 0.25. Its extra claims did not increase supported detection.

The full 18-row first-event/log verdict matrix is in
`functional/verdict-matrix.md`. All query predictions, scores and negative
controls are in `functional/results.json`. Nine owner replay inputs retain the
manifest, public keys, signed artifacts and any delivery-body corruption.
These owner artifacts must remain outside classifier context.

The implementation commit predates this artifact-only results commit so its
source SHA can be recorded accurately in every saved experiment manifest.
Frozen Gate 2 source and tests were compared against
`ac1b997f3732483ae8d6df60774458111703f0eb` with zero differences.
No statistical or performance inference is made from these functional fixtures.
