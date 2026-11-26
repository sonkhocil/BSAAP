using System.Collections.Immutable;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

public sealed class B1Classifier : IB1Baseline
{
    private readonly TrustedPublicKeyBootstrap _trust;
    private readonly VerificationClock _clock;
    public B1Classifier(TrustedPublicKeyBootstrap trust, VerificationClock clock)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(clock);
        _trust = trust;
        _clock = clock;
    }

    public ImmutableArray<Prediction> Classify(B1Evidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        _clock.Validate(evidence.Context);
        return evidence.Context.Targets.Select(query =>
        {
            if (!EvidenceValidation.QueryValid(query))
                return new Prediction(query.QueryId, AssessmentOutcome.InvalidEvidence, "Malformed public query.");
            var log = EvidenceValidation.Log(evidence, query, _trust.VerificationKeys, _clock);
            return Assess(query, log, log.Equivocates(_trust.VerificationKeys));
        }).ToImmutableArray();
    }

    internal static Prediction Assess(AuditQuery query, ValidatedLog log, bool equivocation)
    {
        if (equivocation)
            return query.Kind == ClaimKind.SignedLogEquivocation
                ? new(query.QueryId, AssessmentOutcome.Accusation, "Authenticated conflicting checkpoints acquired.",
                    AuditVerdict.EquivocationDetected)
                : new(query.QueryId, AssessmentOutcome.Inconclusive, "Conflicting signed views prevent an omission determination.");
        if (log.Invalid)
            return new(query.QueryId, AssessmentOutcome.InvalidEvidence, "Gateway evidence failed authentication or delivery validation.");
        if (query.Kind == ClaimKind.SignedLogEquivocation)
            return new(query.QueryId, AssessmentOutcome.Inconclusive, "No acquired authenticated checkpoint conflict.");
        var entries = log.Snapshots.SelectMany(s => s.Entries).Where(e => EvidenceValidation.Matches(e, query)).ToArray();
        if (entries.Length > 0 && entries.All(e => EvidenceValidation.PayloadMatches(e.PayloadHash, query)))
            return new(query.QueryId, AssessmentOutcome.NoFinding, "Expected payload is present in authenticated snapshot evidence.");
        return new(query.QueryId, AssessmentOutcome.Inconclusive,
            entries.Length == 0 ? "Absence lacks a target-specific obligation and fresh omission proof." :
            "Authenticated entries disagree with the expected payload.");
    }
}
