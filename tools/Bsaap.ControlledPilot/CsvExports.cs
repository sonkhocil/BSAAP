using System.Globalization;
using Bsaap.Simulation;

namespace Bsaap.ControlledPilot;

public sealed record ArtifactProductionCost(
    string ProductionKeySha256, string ArchiveSha256, ulong Seed, int Transactions,
    OperationMeasurement WorkloadGeneration, OperationMeasurement ArtifactGeneration);

public static class CsvExports
{
    public static void Write(string directory, IEnumerable<PilotCaseResult> runs,
        IEnumerable<ArtifactProductionCost> productions)
    {
        using var scores = new StreamWriter(Path.Combine(directory, "scores.csv"));
        using var timing = new StreamWriter(Path.Combine(directory, "timings.csv"));
        using var verdicts = new StreamWriter(Path.Combine(directory, "verdicts.csv"));
        scores.WriteLine("seed,nominal_leaves,condition,baseline,claim,actual_positive,actual_negative,admissible_evidence,raw_correct,supported,false_accusations,unsupported,inconclusive,invalid_evidence,missing,no_finding,evidence_coverage,conditional_detection,supported_precision,serialized_input_bytes");
        timing.WriteLine("seed,nominal_leaves,condition,baseline,stage,repetition,order,elapsed_ms,monotonic_ticks,managed_allocated_bytes,working_set_before_bytes,working_set_after_bytes,process_lifetime_peak_working_set_bytes,managed_heap_after_bytes,gc_gen0,gc_gen1,gc_gen2");
        verdicts.WriteLine("seed,nominal_leaves,condition,baseline,query_id,outcome,engine_verdict,reason");
        foreach (var run in runs)
        {
            foreach (var baseline in run.Baselines)
            {
                ScoreRow("omission", baseline.Score.Omission, baseline.EvidenceAvailability.AdmissibleOmissionCases);
                ScoreRow("equivocation", baseline.Score.Equivocation, baseline.EvidenceAvailability.AdmissibleEquivocationCases);
                foreach (var prediction in baseline.Predictions)
                    Row(verdicts, run.Seed, run.Transactions * 4, run.Condition, baseline.Baseline,
                        prediction.QueryId, prediction.Outcome, prediction.VerificationVerdict, prediction.Reason);
                foreach (var sample in baseline.Samples)
                    CostRow(run.Seed, run.Transactions, run.Condition.ToString(), baseline.Baseline.ToString(),
                        "classification", sample.Repetition, sample.Order, sample.Cost);
                CostRow(run.Seed, run.Transactions, run.Condition.ToString(), baseline.Baseline.ToString(),
                    "owner_scoring_with_proof_eligibility", -1, -1, baseline.ScoringCost);

                void ScoreRow(string claim, DetectionScore score, int admissible) =>
                    Row(scores, run.Seed, run.Transactions * 4, run.Condition, baseline.Baseline, claim,
                        score.ActualPositives, score.ActualNegatives, admissible, score.RawFactuallyCorrectAccusations,
                        score.EvidenceSupportedDetections, score.FalseAccusations, score.UnsupportedAccusations,
                        score.Inconclusive, score.InvalidEvidence, score.Missing, score.NoFinding,
                        score.EvidenceCoverage, score.EvidenceConditionalDetectionRate,
                        score.EvidenceSupportedPrecision, baseline.ProjectedInputBytes);
            }
            CostRow(run.Seed, run.Transactions, run.Condition.ToString(), "", "workload_replay_generation", -1, -1, run.Preparation.WorkloadGeneration);
            CostRow(run.Seed, run.Transactions, run.Condition.ToString(), "", "archive_restore", -1, -1, run.Preparation.ArchiveRestore);
            CostRow(run.Seed, run.Transactions, run.Condition.ToString(), "", "evidence_collection", -1, -1, run.Preparation.EvidenceCollection);
            CostRow(run.Seed, run.Transactions, run.Condition.ToString(), "", "owner_truth", -1, -1, run.Preparation.OwnerTruth);
            CostRow(run.Seed, run.Transactions, run.Condition.ToString(), "", "public_key_bootstrap", -1, -1, run.Preparation.PublicKeyBootstrap);
            CostRow(run.Seed, run.Transactions, run.Condition.ToString(), "", "full_snapshot_authentication", -1, -1, run.Preparation.FullSnapshotVerification);
        }
        foreach (var production in productions)
        {
            CostRow(production.Seed, production.Transactions, production.ProductionKeySha256, "", "initial_workload_generation",
                -1, -1, production.WorkloadGeneration);
            CostRow(production.Seed, production.Transactions, production.ProductionKeySha256, "", "artifact_generation",
                -1, -1, production.ArtifactGeneration);
        }

        void CostRow(ulong seed, int transactions, string condition, string baseline, string stage,
            int repetition, int order, OperationMeasurement cost) =>
            Row(timing, seed, transactions * 4, condition, baseline, stage, repetition, order,
                cost.Elapsed.Value.TotalMilliseconds, cost.MonotonicTicks, cost.ManagedAllocatedBytes,
                cost.WorkingSetBeforeBytes, cost.WorkingSetAfterBytes, cost.ProcessPeakWorkingSetBytes,
                cost.ManagedHeapAfterBytes, cost.Gen0Collections, cost.Gen1Collections, cost.Gen2Collections);
    }

    private static void Row(TextWriter writer, params object?[] values) =>
        writer.WriteLine(string.Join(",", values.Select(value =>
            "\"" + (value is IFormattable formatted ? formatted.ToString(null, CultureInfo.InvariantCulture) :
                value?.ToString() ?? "").Replace("\"", "\"\"") + "\"")));
}
