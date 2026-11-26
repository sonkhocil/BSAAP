using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bsaap.Baselines;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;

namespace Bsaap.ControlledPilot;

public sealed record PilotReplayInput(
    PilotDefinition Definition, EvidenceManifest Manifest, string ProductionArchive,
    ImmutableDictionary<string, string>? DeliveredBodyOverrides = null, string? OverridesSha256 = null);

public sealed record TimingSample(int Repetition, int Order, OperationMeasurement Cost)
{
    public long MonotonicTicks => Cost.MonotonicTicks;
    public ElapsedDuration Elapsed => Cost.Elapsed;
}
public sealed record PilotBaselineResult(
    BaselineId Baseline, int PublicQueries, int DeliveredArtifacts, int CommonAcquisitionGatewayRoots,
    int ExposedWitnessAttestations, int ProjectedInputBytes, ImmutableArray<Prediction> Predictions,
    ScoreReport Score, EvidenceAvailabilityCounts EvidenceAvailability,
    ImmutableArray<TimingSample> Samples, OperationMeasurement ScoringCost);
public sealed record PreparationCosts(
    OperationMeasurement WorkloadGeneration, OperationMeasurement ArchiveRestore,
    OperationMeasurement EvidenceCollection, OperationMeasurement OwnerTruth,
    OperationMeasurement PublicKeyBootstrap, OperationMeasurement FullSnapshotVerification,
    string FullSnapshotVerdict, ulong FullSnapshotLeaves);
public sealed record PilotCaseResult(
    ulong Seed, int Transactions, PilotCondition Condition, string WorkloadSha256,
    string ProtocolArchiveSha256, bool ReplayEquivalent, ImmutableArray<PilotBaselineResult> Baselines,
    PreparationCosts Preparation, ScoreReport AlwaysAccuse, ScoreReport AlwaysInconclusive);

public static class PilotExecution
{
    public const int WarmupInvocations = 1;
    public const int MeasuredRepetitions = 2;
    public static ImmutableArray<BaselineId> Configurations { get; } =
        [BaselineId.B0, BaselineId.B1, BaselineId.B1W, BaselineId.B1R, BaselineId.B2];

    public static PilotCaseResult Run(PilotReplayInput saved, PilotCondition condition, int orderOffset)
    {
        var definition = saved.Definition;
        if (orderOffset < 0 || orderOffset >= Configurations.Length || condition != definition.Condition ||
            JsonSerializer.Serialize(definition.Workload) != JsonSerializer.Serialize(saved.Manifest.Workload.Configuration) ||
            JsonSerializer.Serialize(definition.Protocol) != JsonSerializer.Serialize(saved.Manifest.Protocol) ||
            JsonSerializer.Serialize(definition.Acquisition) != JsonSerializer.Serialize(saved.Manifest.Acquisition))
            throw new ArgumentException("Pilot metadata differs from the pinned experiment manifest.");
        var overrides = saved.DeliveredBodyOverrides ?? ImmutableDictionary<string, string>.Empty;
        if (!overrides.IsEmpty && saved.OverridesSha256 != HashOverrides(overrides))
            throw new ArgumentException("Delivered override digest mismatch.");
        var generated = Measurement.Capture(() => SimulationRun.Create(definition.Workload));
        var restored = Measurement.Capture(() => ProtocolArchive.Restore(saved.ProductionArchive));
        saved.Manifest.VerifyArchive(restored.Value);
        var delivered = restored.Value.WithDeliveredBodies(overrides);
        var collected = Measurement.Capture(() => new EvidenceAcquisition(generated.Value, delivered, definition.Acquisition));
        var owned = Measurement.Capture(() => ExperimentOwner.FromProduction(generated.Value, definition.Protocol,
            restored.Value, collected.Value, definition.TruthHorizon));
        var owner = owned.Value;
        var bootstrapped = Measurement.Capture(() => new TrustedPublicKeyBootstrap(owner.ExportTrustedPublicKeys()));
        var trust = bootstrapped.Value;
        var clock = new VerificationClock(definition.Protocol.Clock.EpochSeconds,
            definition.Protocol.Clock.ToUnixSeconds(definition.VerificationTime));
        var b0 = owner.Acquisition.ProjectB0("reviewer");
        var b1 = owner.Acquisition.ProjectB1("reviewer");
        var b1w = owner.Acquisition.ProjectB1Witness("reviewer");
        var b1r = owner.Acquisition.ProjectB1Receipt("reviewer");
        var b2 = owner.Acquisition.ProjectB2("reviewer");
        var classifier0 = new B0Classifier();
        var classifier1 = new B1Classifier(trust, clock);
        var classifier1w = new B1WitnessClassifier(trust, clock);
        var classifier1r = new B1ReceiptClassifier(trust, clock);
        var classifier2 = new B2Classifier(trust, clock);
        Func<ImmutableArray<Prediction>>[] calls = [
            () => classifier0.Classify(b0), () => classifier1.Classify(b1), () => classifier1w.Classify(b1w),
            () => classifier1r.Classify(b1r), () => classifier2.Classify(b2)];
        object[] inputs = [b0, b1, b1w, b1r, b2];
        int gatewayRoots = b1.Checkpoints.Select(h => h.Artifact.Read()).Where(h => h.GatewayId == "A")
            .Select(h => Convert.ToHexString(h.RootHash)).Distinct(StringComparer.Ordinal).Count();
        var snapshot = b1.Snapshots.Select(s => s.Artifact.Read()).First(s => s.GatewayId == "A");
        var verificationKeys = restored.Value.CreateRegistry();
        var verified = Measurement.Capture(() => ForensicAuditEngine.AuthenticateSnapshot(snapshot,
            verificationKeys, snapshot.GatewayId, snapshot.LogId));
        var reference = new ImmutableArray<Prediction>[calls.Length];
        var samples = Enumerable.Range(0, calls.Length).Select(_ => ImmutableArray.CreateBuilder<TimingSample>()).ToArray();

        for (int warmup = 0; warmup < WarmupInvocations; warmup++)
        for (int order = 0; order < calls.Length; order++)
        {
            int position = (order + orderOffset) % calls.Length;
            reference[position] = calls[position]();
        }
        for (int repetition = 0; repetition < MeasuredRepetitions; repetition++)
        for (int order = 0; order < calls.Length; order++)
        {
            int position = (order + orderOffset + repetition) % calls.Length;
            var measured = Measurement.Capture(calls[position]);
            if (!reference[position].SequenceEqual(measured.Value))
                throw new InvalidOperationException("Classifier output changed between invocations.");
            samples[position].Add(new(repetition, order, measured.Cost));
        }

        var replay = ExperimentOwner.Replay(saved.Manifest, saved.ProductionArchive, definition.TruthHorizon)
            .WithDeliveredArtifactBodies(overrides);
        var replayTrust = new TrustedPublicKeyBootstrap(replay.ExportTrustedPublicKeys());
        ImmutableArray<Prediction>[] replayed = [
            new B0Classifier().Classify(replay.Acquisition.ProjectB0("reviewer")),
            new B1Classifier(replayTrust, clock).Classify(replay.Acquisition.ProjectB1("reviewer")),
            new B1WitnessClassifier(replayTrust, clock).Classify(replay.Acquisition.ProjectB1Witness("reviewer")),
            new B1ReceiptClassifier(replayTrust, clock).Classify(replay.Acquisition.ProjectB1Receipt("reviewer")),
            new B2Classifier(replayTrust, clock).Classify(replay.Acquisition.ProjectB2("reviewer"))];
        var results = ImmutableArray.CreateBuilder<PilotBaselineResult>();
        for (int position = 0; position < calls.Length; position++)
        {
            if (reference[position].Length != b0.Context.Targets.Length ||
                reference[position].Select(p => p.QueryId).Distinct().Count() != reference[position].Length)
                throw new InvalidOperationException("Missing or duplicate classification results.");
            var baseline = Configurations[position];
            var scored = Measurement.Capture(() => owner.Assess("reviewer", baseline,
                reference[position], definition.VerificationTime));
            ValidateScore(scored.Value.Score);
            var replayScore = replay.Assess("reviewer", baseline, replayed[position], definition.VerificationTime);
            if (!reference[position].SequenceEqual(replayed[position]) || scored.Value != replayScore)
                throw new InvalidOperationException("Saved-input replay changed predictions or scoring.");
            results.Add(new(baseline, b0.Context.Targets.Length, owner.Acquisition.DeliveredArtifactCount("reviewer"),
                gatewayRoots, baseline is BaselineId.B1W or BaselineId.B2 ? b1w.Witnesses.Length : 0,
                Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(inputs[position])), reference[position],
                scored.Value.Score, scored.Value.Availability, samples[position].ToImmutable(), scored.Cost));
        }
        var accusations = b0.Context.Targets.Select(q => new Prediction(q.QueryId, AssessmentOutcome.Accusation)).ToImmutableArray();
        var inconclusive = b0.Context.Targets.Select(q => new Prediction(q.QueryId, AssessmentOutcome.Inconclusive)).ToImmutableArray();
        var preparation = new PreparationCosts(generated.Cost, restored.Cost, collected.Cost, owned.Cost,
            bootstrapped.Cost, verified.Cost, verified.Value.Verdict.ToString(), snapshot.Checkpoint.TreeSize);
        return new(definition.Workload.Seed, definition.Workload.TransactionCount, condition,
            Hash(JsonSerializer.Serialize(SyntheticGenerator.Generate(definition.Workload))),
            saved.Manifest.ArchiveSha256, true, results.ToImmutable(), preparation,
            owner.Score("reviewer", BaselineId.B2, accusations, definition.VerificationTime),
            owner.Score("reviewer", BaselineId.B2, inconclusive, definition.VerificationTime));
    }

    public static ScoreReport Pool(IEnumerable<ScoreReport> reports)
    {
        var values = reports.ToArray();
        foreach (var report in values) ValidateScore(report);
        return new(Sum(values.Select(r => r.Omission)), Sum(values.Select(r => r.Equivocation)));
    }

    public static void ValidateScore(ScoreReport report)
    {
        foreach (var score in new[] { report.Omission, report.Equivocation })
        {
            int[] counts = [score.ActualPositives, score.ActualNegatives, score.Detections,
                score.FalseAccusations, score.EvidenceCoveredPositives, score.EvidenceConditionalDetections,
                score.UnsupportedAccusations, score.Inconclusive, score.InvalidEvidence,
                score.Missing, score.NoFinding, score.Accusations];
            if (counts.Any(count => count < 0) || score.Detections > score.ActualPositives ||
                score.FalseAccusations > score.ActualNegatives ||
                score.EvidenceCoveredPositives > score.ActualPositives ||
                score.EvidenceConditionalDetections > Math.Min(score.Detections, score.EvidenceCoveredPositives) ||
                score.UnsupportedAccusations > score.Accusations ||
                score.Accusations != score.Detections + score.FalseAccusations ||
                score.Accusations + score.Inconclusive + score.InvalidEvidence + score.Missing + score.NoFinding !=
                    score.ActualPositives + score.ActualNegatives)
                throw new InvalidOperationException("Invalid scoring counts or denominators.");
        }
    }

    private static DetectionScore Sum(IEnumerable<DetectionScore> scores)
    {
        var values = scores.ToArray();
        return new(values.Sum(s => s.ActualPositives), values.Sum(s => s.ActualNegatives),
            values.Sum(s => s.Detections), values.Sum(s => s.FalseAccusations),
            values.Sum(s => s.EvidenceCoveredPositives), values.Sum(s => s.EvidenceConditionalDetections),
            values.Sum(s => s.UnsupportedAccusations), values.Sum(s => s.Inconclusive),
            values.Sum(s => s.InvalidEvidence), values.Sum(s => s.Missing),
            values.Sum(s => s.NoFinding), values.Sum(s => s.Accusations));
    }

    public static string HashOverrides(ImmutableDictionary<string, string> overrides) =>
        Hash(JsonSerializer.Serialize(overrides.OrderBy(p => p.Key, StringComparer.Ordinal).ToArray()));

    public static string Hash(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
}
