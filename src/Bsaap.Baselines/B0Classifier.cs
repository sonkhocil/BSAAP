using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

public sealed class B0Classifier : IB0Baseline
{
    public ImmutableArray<Prediction> Classify(B0Evidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (evidence.Context.Targets.IsDefault) throw new ArgumentException("Public queries are required.");
        return evidence.Context.Targets.Select(query => Assess(evidence, query)).ToImmutableArray();
    }

    private static Prediction Assess(B0Evidence evidence, AuditQuery query)
    {
        if (!EvidenceValidation.QueryValid(query) || evidence.Records.IsDefault)
            return new(query.QueryId, AssessmentOutcome.InvalidEvidence, "Malformed public query or unsigned records.");
        if (query.Kind == ClaimKind.SignedLogEquivocation)
            return new(query.QueryId, AssessmentOutcome.Inconclusive, "Unsigned records cannot establish signed-log equivocation.");
        var records = evidence.Records.Where(r => r is not null &&
            r.Gateway == query.Gateway && r.LogId == query.LogId).ToArray();
        if (records.Any(r => r.Event is null || r.LoggedAt.Milliseconds < r.Event.OccurredAt ||
            r.LoggedAt.Milliseconds > evidence.Context.CollectionCutoff.Milliseconds))
            return new(query.QueryId, AssessmentOutcome.InvalidEvidence, "Malformed unsigned record.");
        if (records.GroupBy(r => r.LeafIndex).Any(group => group.Select(r => r.Event).Distinct().Count() > 1))
            return new(query.QueryId, AssessmentOutcome.Inconclusive, "Unsigned records conflict at a leaf index.");
        var matching = records.Where(r => r.Event.EventId == query.EventId &&
            r.Event.TransactionId == query.TransactionId && r.Event.Sequence == query.Sequence &&
            r.Event.Corridor == query.Corridor && r.Event.Type == query.EventType).ToArray();
        if (matching.Length == 0)
            return new(query.QueryId, AssessmentOutcome.Inconclusive, "Expected event is absent from the acquired unsigned view.");
        if (matching.Any(r => !EvidenceValidation.PayloadMatches(
            SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(r.Event))), query)))
            return new(query.QueryId, AssessmentOutcome.Inconclusive, "Unsigned records disagree with the public event payload.");
        return new(query.QueryId, AssessmentOutcome.NoFinding, "Expected payload is observable in unsigned records.");
    }
}
