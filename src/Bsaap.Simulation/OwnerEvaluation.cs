using System.Collections.Immutable;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// This owner-side module contains no classifier implementations.
internal static class OwnerEvaluation
{
    internal static ImmutableArray<ActualTruthFlags> ActualFacts(SimulationRun run,
        ProtocolSchedule schedule, ProtocolArchive productionArchive, AuditContext context, LogicalInstant horizon)
    {
        if (schedule.Obligations.Any(o => o.Deadline.Milliseconds > context.CollectionCutoff.Milliseconds))
            throw new ArgumentException("Collection must close after the obligations under evaluation are due.");
        var policies = run.PolicyTruth(schedule, horizon);
        var keys = productionArchive.CreateRegistry();
        var heads = productionArchive.Artifacts.Where(a => a.Kind == ArtifactKind.Checkpoint &&
            a.AvailableAt.Milliseconds <= Math.Min(horizon.Milliseconds, context.CollectionCutoff.Milliseconds))
            .Select(a => new SignedEvidence<SignedTreeHead>(a.Json).Read()).ToArray();

        return context.Targets.Select(query =>
        {
            bool omission = query.Kind == ClaimKind.OmissionPolicyViolation &&
                policies.Any(policy => policy.EventId == query.EventId && policy.DeadlineMiss);
            bool equivocation = query.Kind == ClaimKind.SignedLogEquivocation &&
                ForensicAuditEngine.CheckEquivocation(heads.Where(head => head.GatewayId == query.Gateway &&
                    head.LogId == query.LogId && head.EpochId == query.EpochId).ToArray(), keys).IsEquivocation;
            return new ActualTruthFlags(query.QueryId, query.Kind, omission, equivocation);
        }).ToImmutableArray();
    }

    internal static ImmutableArray<EvidenceEligibility> Eligibility(
        string observer, BaselineId baseline, EvidenceAcquisition acquisition,
        ProtocolArchive trustArchive, UnixTimeMapping clock, LogicalInstant verificationTime)
    {
        var full = acquisition.ProjectB2(observer);
        var bilateral = full.Witnessed.Bilateral;
        if (verificationTime.Milliseconds < bilateral.Context.CollectionCutoff.Milliseconds)
            throw new ArgumentException("Verification cannot precede the collection cutoff.");
        var keys = trustArchive.CreateRegistry();
        long now = clock.ToUnixSeconds(verificationTime);

        return bilateral.Context.Targets.Select(query =>
        {
            bool admissible = false;
            if (query.Kind == ClaimKind.SignedLogEquivocation && baseline != BaselineId.B0)
            {
                var heads = Read(bilateral.Checkpoints)
                    .Where(h => h.GatewayId == query.Gateway && h.LogId == query.LogId &&
                        h.EpochId == query.EpochId && h.Timestamp <= now).ToArray();
                admissible = ForensicAuditEngine.CheckEquivocation(heads, keys).IsEquivocation;
            }
            if (query.Kind == ClaimKind.OmissionPolicyViolation && baseline == BaselineId.B2)
            {
                var obligations = Read(full.Obligations.Concat(full.TargetAcks))
                    .Where(o => o.AuditedGatewayId == query.Gateway && o.LogId == query.LogId &&
                        o.EpochId == query.EpochId && o.TxId == query.TransactionId!.Value.Value &&
                        o.SeqNum == query.Sequence!.Value.Value && o.CorridorId == query.Corridor &&
                        o.Type == ProtocolArchive.Map(query.EventType!.Value) &&
                        o.PayloadHash is not null && Convert.ToHexString(o.PayloadHash) == query.PayloadSha256);
                // Eligibility is an evidence verification question. The frozen engine
                // authenticates candidate proof bundles, independent of injected labels
                // and independent of the classifier's submitted output.
                foreach (var obligation in obligations)
                foreach (var snapshot in Read(bilateral.Snapshots))
                foreach (var witness in Read(full.Witnessed.Witnesses))
                foreach (var challenge in Read(full.Challenges))
                {
                    var history = Read(bilateral.Checkpoints).Where(head => head.Timestamp <= now &&
                        ForensicAuditEngine.CheckEquivocation([head], keys).Verdict == AuditVerdict.Compliant).ToArray();
                    var verdict = ForensicAuditEngine.AuditLogSnapshot(obligation, witness, snapshot, history,
                        keys, now, query.Gateway, query.LogId, challenge);
                    if (verdict == AuditVerdict.ProvenLoggingPolicyViolation)
                        admissible = true;
                }
            }
            return new EvidenceEligibility(observer, baseline, query.QueryId, admissible);
        }).ToImmutableArray();
    }

    private static IEnumerable<T> Read<T>(IEnumerable<Acquired<T>> artifacts)
    {
        foreach (var acquired in artifacts)
            if (acquired.Artifact.TryRead(out var value))
                yield return value;
    }

    internal static ScoreReport Score(ImmutableArray<ActualTruthFlags> truth,
        ImmutableArray<EvidenceEligibility> eligibility, ImmutableArray<Prediction> predictions)
    {
        if (truth.IsDefault || eligibility.IsDefault || predictions.IsDefault ||
            truth.Select(t => t.QueryId).Distinct(StringComparer.Ordinal).Count() != truth.Length ||
            eligibility.Select(e => e.QueryId).Distinct(StringComparer.Ordinal).Count() != eligibility.Length ||
            !truth.Select(t => t.QueryId).Order().SequenceEqual(eligibility.Select(e => e.QueryId).Order()) ||
            eligibility.Select(e => (e.Observer, e.Baseline)).Distinct().Count() > 1 ||
            predictions.Any(p => p is null || !Enum.IsDefined(p.Outcome) ||
                !truth.Any(t => t.QueryId == p.QueryId)) ||
            predictions.Select(p => p.QueryId).Distinct(StringComparer.Ordinal).Count() != predictions.Length)
            throw new ArgumentException("Scoring requires one observer/baseline, unique known predictions and complete truth coverage.");
        var submitted = predictions.ToDictionary(p => p.QueryId, StringComparer.Ordinal);
        var available = eligibility.ToDictionary(e => e.QueryId, e => e.AdmissibleEvidence, StringComparer.Ordinal);
        return new(
            Metric(ClaimKind.OmissionPolicyViolation, truth, available, submitted),
            Metric(ClaimKind.SignedLogEquivocation, truth, available, submitted));
    }

    private static DetectionScore Metric(ClaimKind kind, ImmutableArray<ActualTruthFlags> truth,
        Dictionary<string, bool> eligibility, Dictionary<string, Prediction> predictions)
    {
        int positives = 0, negatives = 0, detected = 0, falseAccusations = 0;
        int covered = 0, conditionalDetected = 0, unsupported = 0;
        int inconclusive = 0, invalid = 0, missing = 0, noFinding = 0, accusations = 0;
        foreach (var fact in truth.Where(t => t.Kind == kind))
        {
            bool actual = kind == ClaimKind.OmissionPolicyViolation
                ? fact.ActualOmissionPolicyViolation : fact.ActualSignedLogEquivocation;
            if (actual) positives++; else negatives++;
            if (actual && eligibility[fact.QueryId]) covered++;
            if (!predictions.TryGetValue(fact.QueryId, out var prediction))
            {
                missing++;
                continue;
            }
            switch (prediction.Outcome)
            {
                case AssessmentOutcome.Accusation:
                    accusations++;
                    if (actual) detected++; else falseAccusations++;
                    if (actual && eligibility[fact.QueryId]) conditionalDetected++;
                    if (!eligibility[fact.QueryId]) unsupported++;
                    break;
                case AssessmentOutcome.Inconclusive: inconclusive++; break;
                case AssessmentOutcome.InvalidEvidence: invalid++; break;
                case AssessmentOutcome.NoFinding: noFinding++; break;
            }
        }
        return new(positives, negatives, detected, falseAccusations, covered, conditionalDetected,
            unsupported, inconclusive, invalid, missing, noFinding, accusations);
    }
}

public sealed record DetectionScore(
    int ActualPositives, int ActualNegatives, int Detections, int FalseAccusations,
    int EvidenceCoveredPositives, int EvidenceConditionalDetections,
    int UnsupportedAccusations, int Inconclusive, int InvalidEvidence, int Missing,
    int NoFinding, int Accusations)
{
    public int RawFactuallyCorrectAccusations => Detections;
    public int EvidenceSupportedDetections => EvidenceConditionalDetections;
    public double? EvidenceSupportedDetectionRate => Ratio(EvidenceSupportedDetections, ActualPositives);
    public double? EvidenceSupportedPrecision => Ratio(EvidenceSupportedDetections, Accusations);
    public double? UnconditionalDetectionRate => Ratio(Detections, ActualPositives);
    public double? FalseAccusationRate => Ratio(FalseAccusations, ActualNegatives);
    public double? EvidenceCoverage => Ratio(EvidenceCoveredPositives, ActualPositives);
    public double? EvidenceConditionalDetectionRate => Ratio(EvidenceConditionalDetections, EvidenceCoveredPositives);
    private static double? Ratio(int numerator, int denominator) =>
        denominator == 0 ? null : (double)numerator / denominator;
}
public sealed record ScoreReport(DetectionScore Omission, DetectionScore Equivocation);
