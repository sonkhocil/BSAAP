using System.Collections.Immutable;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

public sealed class B2Classifier : IB2Baseline
{
    private readonly TrustedPublicKeyBootstrap _trust;
    private readonly VerificationClock _clock;
    public B2Classifier(TrustedPublicKeyBootstrap trust, VerificationClock clock)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(clock);
        _trust = trust;
        _clock = clock;
    }

    public ImmutableArray<Prediction> Classify(B2Evidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        _clock.Validate(evidence.Witnessed.Bilateral.Context);
        return evidence.Witnessed.Bilateral.Context.Targets.Select(query => Assess(evidence, query)).ToImmutableArray();
    }

    private Prediction Assess(B2Evidence evidence, AuditQuery query)
    {
        if (!EvidenceValidation.QueryValid(query))
            return Invalid(query, "Malformed public query.");
        var keys = _trust.VerificationKeys;
        var bilateral = evidence.Witnessed.Bilateral;
        var log = EvidenceValidation.Log(bilateral, query, keys, _clock);
        bool conflict = log.Equivocates(keys);
        if (query.Kind == ClaimKind.SignedLogEquivocation || conflict)
            return B1Classifier.Assess(query, log, conflict);
        if (log.Invalid) return Invalid(query, "Gateway evidence failed authentication.");

        var observation = EvidenceValidation.Witnesses(evidence.Witnessed, query, log, keys, _clock);
        bool invalid = observation.Invalid;
        var obligations = Read(evidence.Obligations, bilateral.Context, ref invalid)
            .Concat(Read(evidence.TargetAcks, bilateral.Context, ref invalid))
            .Where(o => o.AuditedGatewayId == query.Gateway && o.LogId == query.LogId &&
                o.EpochId == query.EpochId && o.CorridorId == query.Corridor &&
                o.TxId == query.TransactionId!.Value.Value && o.SeqNum == query.Sequence!.Value.Value &&
                o.Type == EvidenceValidation.EventType(query.EventType!.Value)).ToArray();
        var validObligations = new List<SignedLoggingObligation>();
        foreach (var obligation in obligations)
        {
            if (!AuthenticateObligation(obligation, query))
                invalid = true;
            else if (EvidenceValidation.PayloadMatches(obligation.PayloadHash, query))
                validObligations.Add(obligation);
        }
        var challenges = Read(evidence.Challenges, bilateral.Context, ref invalid)
            .Where(c => c.GatewayId == query.Gateway && c.LogId == query.LogId && c.EpochId == query.EpochId).ToArray();
        var validChallenges = new List<SignedAuditChallenge>();
        foreach (var challenge in challenges)
        {
            if (!AuthenticateChallenge(challenge, query)) invalid = true;
            else validChallenges.Add(challenge);
        }
        var witnesses = Read(evidence.Witnessed.Witnesses, bilateral.Context, ref invalid)
            .Where(w => w.GatewayId == query.Gateway && w.LogId == query.LogId && w.EpochId == query.EpochId).ToArray();

        Prediction? verifiedPresence = null;
        AuditVerdict? lastVerdict = null;
        foreach (var obligation in validObligations)
        foreach (var snapshot in log.Snapshots)
        foreach (var witness in witnesses)
        foreach (var challenge in validChallenges)
        {
            // Correlate independently acquired artifacts using their signed
            // references. An authentic orphan artifact is insufficient evidence.
            if (witness.CheckpointDigest is null ||
                !witness.CheckpointDigest.AsSpan().SequenceEqual(snapshot.Checkpoint.GetCheckpointDigest()) ||
                snapshot.Checkpoint.ChallengeDigest is null ||
                !snapshot.Checkpoint.ChallengeDigest.AsSpan().SequenceEqual(challenge.GetChallengeDigest()) ||
                !challenge.ObligationDigest.AsSpan().SequenceEqual(obligation.GetEvidenceDigest()))
                continue;
            var verdict = ForensicAuditEngine.AuditLogSnapshot(obligation, witness, snapshot, log.Heads,
                keys, _clock.VerificationUnixSeconds, query.Gateway, query.LogId, challenge);
            if (verdict == AuditVerdict.ProvenLoggingPolicyViolation)
                return new(query.QueryId, AssessmentOutcome.Accusation, "Frozen Gate 2 verified the omission proof.", verdict);
            if (verdict == AuditVerdict.Compliant)
                verifiedPresence = new(query.QueryId, AssessmentOutcome.NoFinding,
                    "Frozen Gate 2 verified presence in the challenged snapshot. Publication timeliness remains unproven.", verdict);
            invalid |= InvalidVerdict(verdict);
            lastVerdict = verdict;
        }
        if (verifiedPresence is not null && !invalid) return verifiedPresence;
        if (invalid) return Invalid(query, "Supplied signed evidence failed authentication or binding.", lastVerdict);
        return new(query.QueryId, AssessmentOutcome.Inconclusive,
            "The acquired evidence does not establish a complete target-specific Gate 2 determination.", lastVerdict);
    }

    private bool AuthenticateObligation(SignedLoggingObligation obligation, AuditQuery query)
    {
        string issuer = obligation.IssuerGatewayId ?? obligation.IssuerSignerId;
        string targetSigner = obligation.TargetAckSignerId ?? obligation.AuditedGatewayId;
        if (obligation.Version != 2 || !EvidenceValidation.Id(issuer) ||
            !EvidenceValidation.Id(obligation.IssuerSignerId) || !EvidenceValidation.Id(targetSigner) ||
            !EvidenceValidation.Hash(obligation.PayloadHash) || !EvidenceValidation.Signature(obligation.IssuerSignature) ||
            obligation.Timestamp < 0 || obligation.PublicationDeadline < obligation.Timestamp ||
            !_trust.VerificationKeys.VerifySigner(obligation.IssuerSignerId, SignerRole.Gateway, issuer,
                query.LogId, query.Corridor, obligation.GetCanonicalBytes(), obligation.IssuerSignature, out _))
            return false;
        // An absent ACK is insufficient evidence. A supplied invalid ACK is invalid evidence.
        return obligation.TargetAckSignature is null ||
            (EvidenceValidation.Signature(obligation.TargetAckSignature) &&
             _trust.VerificationKeys.VerifySigner(targetSigner, SignerRole.Gateway, query.Gateway, query.LogId,
                 query.Corridor, obligation.GetTargetAckCanonicalBytes(), obligation.TargetAckSignature, out _));
    }

    private bool AuthenticateChallenge(SignedAuditChallenge challenge, AuditQuery query) =>
        EvidenceValidation.Id(challenge.AuditorId) && EvidenceValidation.Hash(challenge.Nonce) &&
        EvidenceValidation.Hash(challenge.ObligationDigest) && EvidenceValidation.Signature(challenge.Signature) &&
        challenge.IssuedAt >= 0 && challenge.IssuedAt <= _clock.VerificationUnixSeconds &&
        challenge.ExpiresAt >= challenge.IssuedAt &&
        _trust.VerificationKeys.VerifySigner(challenge.AuditorId, SignerRole.Auditor, query.Gateway,
            query.LogId, query.Corridor, challenge.GetCanonicalBytes(), challenge.Signature, out _);

    private List<T> Read<T>(ImmutableArray<Acquired<T>> supplied, AuditContext context, ref bool invalid)
    {
        var values = new List<T>();
        if (supplied.IsDefault) { invalid = true; return values; }
        foreach (var item in supplied)
        {
            if (item?.Artifact is null || !item.Artifact.TryRead(out var value) ||
                !EvidenceValidation.ReceiptValid(item, context, _clock))
                invalid = true;
            else
            {
                long receivedAt = _clock.UnixSeconds(item.ReceivedAt);
                bool plausible = value switch
                {
                    SignedLoggingObligation o => EvidenceValidation.Id(o.AuditedGatewayId) &&
                        EvidenceValidation.Id(o.LogId) && o.Timestamp <= receivedAt,
                    SignedAuditChallenge c => EvidenceValidation.Id(c.GatewayId) &&
                        EvidenceValidation.Id(c.LogId) && c.IssuedAt <= receivedAt,
                    WitnessAttestation w => EvidenceValidation.Id(w.GatewayId) &&
                        EvidenceValidation.Id(w.LogId) && w.WitnessObservedTime <= receivedAt,
                    _ => false
                };
                if (plausible) values.Add(value); else invalid = true;
            }
        }
        return values;
    }

    private static bool InvalidVerdict(AuditVerdict verdict) => verdict is
        AuditVerdict.InvalidCheckpointSignature or AuditVerdict.InvalidWitnessAttestation or
        AuditVerdict.WitnessAttestationMismatch or AuditVerdict.RoleViolation or
        AuditVerdict.UnauthenticatedGatewayKey or AuditVerdict.UnauthorizedSigner or
        AuditVerdict.ImpersonationDetected or AuditVerdict.InvalidAuditChallenge or AuditVerdict.IncompleteEvidence;

    private static Prediction Invalid(AuditQuery query, string reason, AuditVerdict? verdict = null) =>
        new(query.QueryId, AssessmentOutcome.InvalidEvidence, reason, verdict);
}
