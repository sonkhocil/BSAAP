using System.Collections.Immutable;
using System.Security.Cryptography;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

internal sealed record ValidatedLog(
    ImmutableArray<SignedTreeHead> Heads, ImmutableArray<LogSnapshot> Snapshots, bool Invalid)
{
    internal bool Equivocates(ITrustedKeyRegistry keys) =>
        ForensicAuditEngine.CheckEquivocation(Heads, keys).IsEquivocation;
}

internal static class EvidenceValidation
{
    internal static bool QueryValid(AuditQuery query) =>
        query is not null && Id(query.QueryId) && Enum.IsDefined(query.Kind) &&
        Id(query.Gateway) && Id(query.LogId) &&
        Id(query.Corridor) &&
        (query.Kind != ClaimKind.OmissionPolicyViolation ||
         (query.EventId is not null && query.TransactionId is not null && query.Sequence is not null &&
          query.EventType is { } type && Enum.IsDefined(type) &&
          query.PayloadSha256 is { Length: 64 } && query.PayloadSha256.All(Uri.IsHexDigit)));

    internal static bool ReceiptValid<T>(Acquired<T> item, AuditContext context, VerificationClock clock) =>
        item is not null && item.Artifact is not null && item.ReceiptNumber >= 0 &&
        item.ReceivedAt.Milliseconds >= 0 && item.ReceivedAt.Milliseconds % 1000 == 0 &&
        item.ReceivedAt.Milliseconds <= context.CollectionCutoff.Milliseconds &&
        clock.UnixSeconds(item.ReceivedAt) <= clock.VerificationUnixSeconds;

    internal static bool SameLog(SignedTreeHead head, AuditQuery query) =>
        head.GatewayId == query.Gateway && head.LogId == query.LogId && head.EpochId == query.EpochId;

    internal static ValidatedLog Log(B1Evidence evidence, AuditQuery query,
        ITrustedKeyRegistry keys, VerificationClock clock)
    {
        var heads = ImmutableArray.CreateBuilder<SignedTreeHead>();
        var snapshots = ImmutableArray.CreateBuilder<LogSnapshot>();
        bool invalid = evidence.Checkpoints.IsDefault || evidence.Snapshots.IsDefault;
        foreach (var item in evidence.Checkpoints.IsDefault ? [] : evidence.Checkpoints)
        {
            if (item?.Artifact is null || !item.Artifact.TryRead(out var head))
            {
                invalid = true;
                continue;
            }
            if (!Id(head.GatewayId) || !Id(head.LogId)) { invalid = true; continue; }
            if (!SameLog(head, query)) continue;
            if (!ReceiptValid(item, evidence.Context, clock) ||
                head.Timestamp > clock.UnixSeconds(item.ReceivedAt) ||
                ForensicAuditEngine.CheckEquivocation([head], keys).Verdict != AuditVerdict.Compliant)
                invalid = true;
            else
                heads.Add(head);
        }
        foreach (var item in evidence.Snapshots.IsDefault ? [] : evidence.Snapshots)
        {
            if (item?.Artifact is null || !item.Artifact.TryRead(out var snapshot))
            {
                invalid = true;
                continue;
            }
            if (!Id(snapshot.GatewayId) || !Id(snapshot.LogId)) { invalid = true; continue; }
            if (snapshot.GatewayId != query.Gateway || snapshot.LogId != query.LogId ||
                snapshot.EpochId != query.EpochId) continue;
            if (!ReceiptValid(item, evidence.Context, clock) || snapshot.Checkpoint is null ||
                snapshot.Checkpoint.Timestamp > clock.UnixSeconds(item.ReceivedAt) ||
                !ForensicAuditEngine.AuthenticateSnapshot(snapshot, keys, query.Gateway, query.LogId).IsValid)
                invalid = true;
            else
            {
                snapshots.Add(snapshot);
                heads.Add(snapshot.Checkpoint);
            }
        }
        return new(heads.ToImmutable(), snapshots.ToImmutable(), invalid);
    }

    internal static EventType EventType(SyntheticEventType type) => type switch
    {
        SyntheticEventType.Pacs008Dispatch => Bsaap.ForensicLog.Contracts.EventType.Pacs008Dispatch,
        SyntheticEventType.TransportAck => Bsaap.ForensicLog.Contracts.EventType.TransportAck,
        SyntheticEventType.Pacs002Actc => Bsaap.ForensicLog.Contracts.EventType.Pacs002Actc,
        SyntheticEventType.Pacs002Accc => Bsaap.ForensicLog.Contracts.EventType.Pacs002Accc,
        SyntheticEventType.Pacs002Rjct => Bsaap.ForensicLog.Contracts.EventType.Pacs002Rjct,
        _ => throw new ArgumentOutOfRangeException(nameof(type))
    };

    internal static bool Matches(LogEntry entry, AuditQuery query) =>
        entry.TxId == query.TransactionId!.Value.Value && entry.SeqNum == query.Sequence!.Value.Value &&
        entry.CorridorId == query.Corridor && entry.Type == EventType(query.EventType!.Value);

    internal static bool PayloadMatches(byte[] hash, AuditQuery query) =>
        string.Equals(Convert.ToHexString(hash), query.PayloadSha256, StringComparison.OrdinalIgnoreCase);

    internal static bool Id(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try { new System.Text.UTF8Encoding(false, true).GetByteCount(value); return true; }
        catch (System.Text.EncoderFallbackException) { return false; }
    }

    internal static bool Signature(byte[]? value) => value is { Length: 64 };
    internal static bool Hash(byte[]? value) => value is { Length: 32 };

    // Invalid means a supplied attestation fails authentication or its claimed
    // binding is contradictory. Unbound authentic observations remain insufficient.
    internal static (bool Invalid, bool Bound) Witnesses(B1WitnessEvidence evidence, AuditQuery query,
        ValidatedLog log, ITrustedKeyRegistry keys, VerificationClock clock)
    {
        bool invalid = evidence.Witnesses.IsDefault;
        bool bound = false;
        foreach (var item in evidence.Witnesses.IsDefault ? [] : evidence.Witnesses)
        {
            if (item?.Artifact is null || !item.Artifact.TryRead(out var witness))
            {
                invalid = true;
                continue;
            }
            if (!Id(witness.GatewayId) || !Id(witness.LogId)) { invalid = true; continue; }
            if (witness.GatewayId != query.Gateway || witness.LogId != query.LogId || witness.EpochId != query.EpochId)
                continue;
            if (!ReceiptValid(item, evidence.Bilateral.Context, clock) || !Id(witness.WitnessId) ||
                !Id(witness.GatewayId) || !Id(witness.LogId) || !Signature(witness.Signature) ||
                !Hash(witness.CheckpointRootHash) || !Hash(witness.CheckpointSignatureHash) ||
                !Hash(witness.CheckpointDigest) || witness.WitnessObservedTime < 0 ||
                witness.WitnessObservedTime > clock.UnixSeconds(item.ReceivedAt) ||
                !keys.VerifySigner(witness.WitnessId, SignerRole.Witness, witness.GatewayId, witness.LogId,
                    query.Corridor, witness.GetCanonicalBytes(), witness.Signature, out _))
            {
                invalid = true;
                continue;
            }
            foreach (var head in log.Heads.Where(h =>
                h.GetCheckpointDigest().AsSpan().SequenceEqual(witness.CheckpointDigest)))
            {
                bool matches = head.TreeSize == witness.TreeSize &&
                    head.RootHash.AsSpan().SequenceEqual(witness.CheckpointRootHash) &&
                    SHA256.HashData(head.Signature).AsSpan().SequenceEqual(witness.CheckpointSignatureHash) &&
                    witness.WitnessObservedTime >= head.Timestamp;
                if (matches) bound = true; else invalid = true;
            }
        }
        return (invalid, bound);
    }
}
