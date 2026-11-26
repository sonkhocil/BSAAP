using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

internal static class ReceiptValidation
{
    internal static bool Authenticate(SignedLoggingObligation obligation, AuditQuery query, ITrustedKeyRegistry keys)
    {
        string issuer = obligation.IssuerGatewayId ?? obligation.IssuerSignerId;
        string targetSigner = obligation.TargetAckSignerId ?? obligation.AuditedGatewayId;
        if (obligation.Version != 2 || !EvidenceValidation.Id(issuer) ||
            !EvidenceValidation.Id(obligation.IssuerSignerId) || !EvidenceValidation.Id(targetSigner) ||
            !EvidenceValidation.Hash(obligation.PayloadHash) || !EvidenceValidation.Signature(obligation.IssuerSignature) ||
            obligation.Timestamp < 0 || obligation.PublicationDeadline < obligation.Timestamp ||
            !keys.VerifySigner(obligation.IssuerSignerId, SignerRole.Gateway, issuer,
                query.LogId, query.Corridor, obligation.GetCanonicalBytes(), obligation.IssuerSignature, out _))
            return false;
        return obligation.TargetAckSignature is null ||
            (EvidenceValidation.Signature(obligation.TargetAckSignature) &&
             keys.VerifySigner(targetSigner, SignerRole.Gateway, query.Gateway, query.LogId,
                 query.Corridor, obligation.GetTargetAckCanonicalBytes(), obligation.TargetAckSignature, out _));
    }

    internal static bool Accepted(SignedLoggingObligation obligation) =>
        (obligation.IssuerGatewayId ?? obligation.IssuerSignerId) == obligation.AuditedGatewayId ||
        obligation.TargetAckSignature is not null;
}
