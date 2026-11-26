using System.Collections.Immutable;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

public sealed class B1ReceiptClassifier : IB1ReceiptBaseline
{
    private readonly TrustedPublicKeyBootstrap _trust;
    private readonly VerificationClock _clock;

    public B1ReceiptClassifier(TrustedPublicKeyBootstrap trust, VerificationClock clock)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(clock);
        _trust = trust;
        _clock = clock;
    }

    public ImmutableArray<Prediction> Classify(B1ReceiptEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        _clock.Validate(evidence.Authenticated.Context);
        return evidence.Authenticated.Context.Targets.Select(query => Assess(evidence, query)).ToImmutableArray();
    }

    private Prediction Assess(B1ReceiptEvidence evidence, AuditQuery query)
    {
        if (!EvidenceValidation.QueryValid(query))
            return new(query.QueryId, AssessmentOutcome.InvalidEvidence, "Malformed public query.");
        var keys = _trust.VerificationKeys;
        var log = EvidenceValidation.Log(evidence.Authenticated, query, keys, _clock);
        bool conflict = log.Equivocates(keys);
        var baseline = B1Classifier.Assess(query, log, conflict);
        if (query.Kind == ClaimKind.SignedLogEquivocation || conflict || log.Invalid)
            return baseline;

        bool invalid = evidence.Obligations.IsDefault || evidence.TargetAcks.IsDefault;
        bool accepted = false;
        foreach (var item in (evidence.Obligations.IsDefault ? [] : evidence.Obligations)
            .Concat(evidence.TargetAcks.IsDefault ? [] : evidence.TargetAcks))
        {
            if (item?.Artifact is null || !item.Artifact.TryRead(out var obligation))
            {
                invalid = true;
                continue;
            }
            if (!EvidenceValidation.Id(obligation.AuditedGatewayId) || !EvidenceValidation.Id(obligation.LogId))
            {
                invalid = true;
                continue;
            }
            if (obligation.AuditedGatewayId != query.Gateway || obligation.LogId != query.LogId ||
                obligation.EpochId != query.EpochId || obligation.CorridorId != query.Corridor ||
                obligation.TxId != query.TransactionId!.Value.Value || obligation.SeqNum != query.Sequence!.Value.Value ||
                obligation.Type != EvidenceValidation.EventType(query.EventType!.Value))
                continue;
            if (!EvidenceValidation.ReceiptValid(item, evidence.Authenticated.Context, _clock) ||
                obligation.Timestamp > _clock.UnixSeconds(item.ReceivedAt) ||
                !ReceiptValidation.Authenticate(obligation, query, keys))
                invalid = true;
            else if (EvidenceValidation.PayloadMatches(obligation.PayloadHash, query) && ReceiptValidation.Accepted(obligation))
                accepted = true;
        }
        if (invalid)
            return new(query.QueryId, AssessmentOutcome.InvalidEvidence, "Receipt signature, scope, ACK or delivery validation failed.");
        // Authenticated receipt acceptance establishes a target-specific promise.
        // It does not establish the freshness/completeness of an omission view.
        return baseline with { Reason = baseline.Reason + (accepted
            ? " Target-specific receipt acceptance verified; independent omission-proof timing remains unavailable."
            : " No authenticated target acceptance was acquired.") };
    }
}
