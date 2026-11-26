using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Bsaap.ForensicLog.Contracts
{
    public enum EventType
    {
        Pacs008Dispatch = 1,
        TransportAck = 2,
        Pacs002Actc = 3,
        Pacs002Accc = 4,
        Pacs002Rjct = 5,
        TimeoutRecord = 6
    }

    public enum SignerRole
    {
        Gateway = 1,
        Witness = 2,
        Auditor = 3
    }

    public enum AuditVerdict
    {
        Compliant,
        ProvenLoggingPolicyViolation,
        MismatchedPayload,
        IncompleteEvidence,
        GatewayNonCooperation,
        UnauthenticatedGatewayKey,
        ImpersonationDetected,
        InvalidCheckpointSignature,
        EquivocationDetected,
        UnprovenWithinWindow,
        UnprovenObligation,
        AppendOnlyViolation,
        InvalidWitnessAttestation,
        WitnessAttestationMismatch,
        RoleViolation,
        InvalidAuditChallenge,
        UnauthorizedSigner
    }

    public interface ITrustedKeyRegistry
    {
        bool TryGetPublicKey(string signerId, out byte[] publicKeyBytes);
        void RegisterSigner(string signerId, byte[] publicKeyBytes, SignerRole role, IEnumerable<string> authorizedGateways, IEnumerable<string>? authorizedLogs = null, IEnumerable<string>? authorizedCorridors = null);
        bool VerifySigner(string signerId, SignerRole requiredRole, string? claimedGatewayId, string? claimedLogId, string? corridorId, byte[] data, byte[] signature, out AuditVerdict errorReason);
    }

    // BinaryWriter encodes integers little-endian and UTF-8 strings with a
    // length prefix. Strict UTF-8 prevents aliases via replacement characters.
    internal static class Canonical
    {
        public static byte[] Encode(string domain, Action<System.IO.BinaryWriter> fields)
        {
            using var stream = new System.IO.MemoryStream();
            using var writer = new System.IO.BinaryWriter(stream, new UTF8Encoding(false, true));
            writer.Write("BSAAP/2/" + domain);
            fields(writer);
            writer.Flush();
            return stream.ToArray();
        }

        public static void WriteBytes(this System.IO.BinaryWriter writer, byte[] bytes)
        {
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }
    }

    public record LogEntry(
        ulong LeafIdx, string CorridorId, string LogId, ulong SeqNum, Guid TxId,
        EventType Type, byte[] PayloadHash, long Timestamp, string SignerId, byte[] Signature,
        ulong EpochId = 1)
    {
        public byte[] GetCanonicalBytes() => Canonical.Encode("entry", writer =>
        {
            writer.Write(LeafIdx);
            writer.Write(CorridorId);
            writer.Write(LogId);
            writer.Write(EpochId);
            writer.Write(SeqNum);
            writer.Write(TxId.ToByteArray());
            writer.Write((int)Type);
            writer.WriteBytes(PayloadHash);
            writer.Write(Timestamp);
            writer.Write(SignerId);
        });
    }

    public record SignedTreeHead(
        string GatewayId, string LogId, ulong EpochId, ulong TreeSize, byte[] RootHash,
        long Timestamp, string SignerId, byte[] Signature, byte[]? ChallengeDigest = null)
    {
        public byte[] GetCanonicalBytes() => Canonical.Encode("checkpoint", writer =>
        {
            writer.Write(GatewayId);
            writer.Write(LogId);
            writer.Write(EpochId);
            writer.Write(TreeSize);
            writer.WriteBytes(RootHash);
            writer.Write(Timestamp);
            writer.Write(SignerId);
            writer.WriteBytes(ChallengeDigest ?? Array.Empty<byte>());
        });

        public byte[] GetCheckpointDigest() => SHA256.HashData(GetCanonicalBytes());
    }

    public record LogSnapshot(
        string GatewayId, string LogId, ulong EpochId, List<LogEntry> Entries,
        SignedTreeHead Checkpoint);

    public record SignedLoggingObligation(
        uint Version, string AuditedGatewayId, string LogId, string CorridorId,
        ulong SeqNum, Guid TxId, EventType Type, byte[] PayloadHash, long Timestamp,
        long PublicationDeadline, string IssuerSignerId, byte[] IssuerSignature,
        byte[]? TargetAckSignature = null, ulong EpochId = 1,
        string? IssuerGatewayId = null, string? TargetAckSignerId = null)
    {
        public byte[] GetCanonicalBytes() => Canonical.Encode("obligation", writer =>
        {
            writer.Write(Version);
            writer.Write(AuditedGatewayId);
            writer.Write(LogId);
            writer.Write(EpochId);
            writer.Write(CorridorId);
            writer.Write(SeqNum);
            writer.Write(TxId.ToByteArray());
            writer.Write((int)Type);
            writer.WriteBytes(PayloadHash);
            writer.Write(Timestamp);
            writer.Write(PublicationDeadline);
            writer.Write(IssuerGatewayId ?? IssuerSignerId);
            writer.Write(IssuerSignerId);
            writer.Write(TargetAckSignerId ?? AuditedGatewayId);
        });

        public byte[] GetTargetAckCanonicalBytes() => Canonical.Encode("target-ack", writer =>
        {
            writer.Write(SHA256.HashData(GetCanonicalBytes()));
            writer.WriteBytes(IssuerSignature);
        });

        public byte[] GetEvidenceDigest() => SHA256.HashData(Canonical.Encode("signed-obligation", writer =>
        {
            writer.WriteBytes(GetCanonicalBytes());
            writer.WriteBytes(IssuerSignature);
            writer.WriteBytes(TargetAckSignature ?? Array.Empty<byte>());
        }));
    }

    public record WitnessAttestation(
        string WitnessId, string GatewayId, string LogId, ulong EpochId, ulong TreeSize,
        byte[] CheckpointRootHash, byte[] CheckpointSignatureHash,
        long WitnessObservedTime, byte[] Signature, byte[]? CheckpointDigest = null)
    {
        public byte[] GetCanonicalBytes() => Canonical.Encode("witness", writer =>
        {
            writer.Write(WitnessId);
            writer.Write(GatewayId);
            writer.Write(LogId);
            writer.Write(EpochId);
            writer.Write(TreeSize);
            writer.WriteBytes(CheckpointRootHash);
            writer.WriteBytes(CheckpointSignatureHash);
            writer.WriteBytes(CheckpointDigest ?? Array.Empty<byte>());
            writer.Write(WitnessObservedTime);
        });
    }

    public record SignedAuditChallenge(
        string AuditorId, string GatewayId, string LogId, ulong EpochId,
        byte[] ObligationDigest, byte[] Nonce, long IssuedAt, long ExpiresAt, byte[] Signature)
    {
        public byte[] GetCanonicalBytes() => Canonical.Encode("audit-challenge", writer =>
        {
            writer.Write(AuditorId);
            writer.Write(GatewayId);
            writer.Write(LogId);
            writer.Write(EpochId);
            writer.WriteBytes(ObligationDigest);
            writer.WriteBytes(Nonce);
            writer.Write(IssuedAt);
            writer.Write(ExpiresAt);
        });
        public byte[] GetChallengeDigest() => SHA256.HashData(Canonical.Encode("signed-challenge", writer =>
        {
            writer.WriteBytes(GetCanonicalBytes());
            writer.WriteBytes(Signature);
        }));
    }
}
