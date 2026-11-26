using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Bsaap.ForensicLog.Contracts;

namespace Bsaap.ForensicLog.Engine
{
    public static class Rfc9162MerkleTree
    {
        // RFC 9162 Section 2.1.3 Merkle Tree Hash (MTH)
        public static byte[] CalculateRfc9162MerkleRoot(IReadOnlyList<byte[]> leafDataEntries)
        {
            ArgumentNullException.ThrowIfNull(leafDataEntries);
            if (leafDataEntries.Count == 0)
            {
                return SHA256.HashData(Array.Empty<byte>());
            }

            return CalculateMthRecursive(leafDataEntries, 0, leafDataEntries.Count);
        }

        private static byte[] CalculateMthRecursive(IReadOnlyList<byte[]> entries, int start, int count)
        {
            if (count == 1)
            {
                byte[] leafData = entries[start];
                byte[] leafBuffer = new byte[1 + leafData.Length];
                leafBuffer[0] = 0x00;
                Buffer.BlockCopy(leafData, 0, leafBuffer, 1, leafData.Length);
                return SHA256.HashData(leafBuffer);
            }

            int k = 1;
            while (k <= (count - 1) / 2)
            {
                k *= 2;
            }

            byte[] leftRoot = CalculateMthRecursive(entries, start, k);
            byte[] rightRoot = CalculateMthRecursive(entries, start + k, count - k);

            byte[] nodeBuffer = new byte[1 + 32 + 32];
            nodeBuffer[0] = 0x01;
            Buffer.BlockCopy(leftRoot, 0, nodeBuffer, 1, 32);
            Buffer.BlockCopy(rightRoot, 0, nodeBuffer, 33, 32);
            return SHA256.HashData(nodeBuffer);
        }
    }

    public sealed class TrustedKeyRegistry : ITrustedKeyRegistry
    {
        private sealed record SignerInfo(
            byte[] PublicKey, SignerRole Role, HashSet<string> Gateways,
            HashSet<string> Logs, HashSet<string> Corridors);

        private readonly Dictionary<string, SignerInfo> _signers = new(StringComparer.Ordinal);
        private readonly object _registrationLock = new();

        public void RegisterSigner(
            string signerId, byte[] publicKeyBytes, SignerRole role,
            IEnumerable<string> authorizedGateways, IEnumerable<string>? authorizedLogs = null,
            IEnumerable<string>? authorizedCorridors = null)
        {
            if (!EvidenceFields.ValidId(signerId) || !Enum.IsDefined(role))
                throw new ArgumentException("Invalid signer identity or role.");

            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(publicKeyBytes, out int read);
            if (read != publicKeyBytes.Length ||
                key.ExportParameters(false).Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
                throw new ArgumentException("Expected a complete named P-256 public key.", nameof(publicKeyBytes));

            var info = new SignerInfo(key.ExportSubjectPublicKeyInfo(), role,
                Scope(authorizedGateways), Scope(authorizedLogs), Scope(authorizedCorridors));
            if (info.Gateways.Count == 0 || (role == SignerRole.Gateway && info.Gateways.Count != 1))
                throw new ArgumentException("A gateway key must identify one gateway. Other keys need a gateway scope.");

            lock (_registrationLock)
            {
                if (_signers.ContainsKey(signerId) ||
                    _signers.Values.Any(existing => existing.PublicKey.AsSpan().SequenceEqual(info.PublicKey)))
                    throw new ArgumentException("Signer IDs and public keys must be unique.");
                _signers.Add(signerId, info);
            }
        }

        private static HashSet<string> Scope(IEnumerable<string>? ids)
        {
            var scope = new HashSet<string>(ids ?? Array.Empty<string>(), StringComparer.Ordinal);
            if (scope.Any(id => !EvidenceFields.ValidId(id)))
                throw new ArgumentException("Invalid authorization scope.");
            return scope;
        }

        private SignerInfo? Find(string? id)
        {
            lock (_registrationLock)
                return id is null ? null : _signers.GetValueOrDefault(id);
        }

        public bool TryGetPublicKey(string signerId, out byte[] publicKeyBytes)
        {
            var info = Find(signerId);
            publicKeyBytes = info?.PublicKey.ToArray() ?? Array.Empty<byte>();
            return info is not null;
        }

        public bool VerifySigner(
            string signerId, SignerRole requiredRole, string? claimedGatewayId,
            string? claimedLogId, string? corridorId, byte[] data, byte[] signature,
            out AuditVerdict errorReason)
        {
            var info = Find(signerId);
            if (info is null)
                errorReason = AuditVerdict.UnauthenticatedGatewayKey;
            else if (info.Role != requiredRole)
                errorReason = AuditVerdict.RoleViolation;
            else if (claimedGatewayId is null || !info.Gateways.Contains(claimedGatewayId) ||
                     (claimedLogId is not null && !info.Logs.Contains(claimedLogId)))
                errorReason = AuditVerdict.UnauthorizedSigner;
            else if (corridorId is not null && !info.Corridors.Contains(corridorId))
                errorReason = AuditVerdict.UnprovenObligation;
            else if (data is null || !EvidenceFields.ValidSignature(signature))
                errorReason = AuditVerdict.IncompleteEvidence;
            else
            {
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(info.PublicKey, out _);
                errorReason = key.VerifyData(data, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                    ? AuditVerdict.Compliant : AuditVerdict.IncompleteEvidence;
            }
            return errorReason == AuditVerdict.Compliant;
        }
    }

    internal static class EvidenceFields
    {
        private static readonly System.Text.UTF8Encoding StrictUtf8 = new(false, true);

        public static bool ValidId(string? id)
        {
            if (string.IsNullOrWhiteSpace(id))
                return false;
            try
            {
                StrictUtf8.GetByteCount(id);
                return true;
            }
            catch (System.Text.EncoderFallbackException)
            {
                return false;
            }
        }

        public static bool ValidHash(byte[]? value) => value is { Length: 32 };
        public static bool ValidSignature(byte[]? value) => value is { Length: 64 };
        public static bool Equal(byte[] left, byte[] right) => left.AsSpan().SequenceEqual(right);
    }

    public static class ForensicAuditEngine
    {
        // Capture caller-owned buffers before authentication so later decisions use
        // the same evidence that was verified. Callers must allow capture to complete.
        private static byte[] Copy(byte[] value) => value is null ? null! : (byte[])value.Clone();

        private static SignedTreeHead Capture(SignedTreeHead head) => head is null ? null! : head with
        {
            RootHash = Copy(head.RootHash), Signature = Copy(head.Signature),
            ChallengeDigest = head.ChallengeDigest is null ? null : Copy(head.ChallengeDigest)
        };

        private static LogSnapshot Capture(LogSnapshot snapshot) => snapshot is null ? null! : snapshot with
        {
            Checkpoint = Capture(snapshot.Checkpoint),
            Entries = snapshot.Entries is null ? null! : snapshot.Entries.ToArray().Select(entry =>
                entry is null ? null! : entry with
                {
                    PayloadHash = Copy(entry.PayloadHash), Signature = Copy(entry.Signature)
                }).ToList()
        };

        private static bool SameLog(SignedTreeHead left, SignedTreeHead right) =>
            left.GatewayId == right.GatewayId && left.LogId == right.LogId && left.EpochId == right.EpochId;

        private static AuditVerdict VerifyCheckpoint(SignedTreeHead? head, ITrustedKeyRegistry keys)
        {
            if (head is null || !EvidenceFields.ValidId(head.GatewayId) ||
                !EvidenceFields.ValidId(head.LogId) || !EvidenceFields.ValidId(head.SignerId) ||
                !EvidenceFields.ValidHash(head.RootHash) || !EvidenceFields.ValidSignature(head.Signature) ||
                (head.ChallengeDigest is not null && !EvidenceFields.ValidHash(head.ChallengeDigest)) ||
                head.Timestamp < 0)
                return AuditVerdict.InvalidCheckpointSignature;

            if (!keys.VerifySigner(head.SignerId, SignerRole.Gateway, head.GatewayId, head.LogId,
                    null, head.GetCanonicalBytes(), head.Signature, out var error))
                return error == AuditVerdict.IncompleteEvidence ? AuditVerdict.InvalidCheckpointSignature : error;

            if (head.TreeSize == 0 && !EvidenceFields.Equal(head.RootHash, SHA256.HashData(Array.Empty<byte>())))
                return AuditVerdict.IncompleteEvidence;
            return AuditVerdict.Compliant;
        }

        public static (bool IsEquivocation, AuditVerdict Verdict) CheckEquivocation(
            IReadOnlyList<SignedTreeHead> allKnownSths, ITrustedKeyRegistry keyRegistry)
        {
            if (allKnownSths is null || allKnownSths.Count == 0)
                return (false, AuditVerdict.IncompleteEvidence);

            var roots = new Dictionary<(string, string, ulong, ulong), byte[]>();
            var verdict = AuditVerdict.Compliant;
            foreach (var original in allKnownSths)
            {
                var head = Capture(original);
                var result = VerifyCheckpoint(head, keyRegistry);
                if (result != AuditVerdict.Compliant)
                {
                    verdict = result;
                    continue;
                }

                var position = (head.GatewayId, head.LogId, head.EpochId, head.TreeSize);
                if (roots.TryGetValue(position, out var root) && !EvidenceFields.Equal(root, head.RootHash))
                    return (true, AuditVerdict.EquivocationDetected);
                roots.TryAdd(position, head.RootHash);
            }
            return (false, verdict);
        }

        public static (bool IsValid, AuditVerdict Verdict) AuthenticateSnapshot(
            LogSnapshot snapshot, ITrustedKeyRegistry keyRegistry, string auditedGatewayId, string auditedLogId) =>
            AuthenticateCapturedSnapshot(Capture(snapshot), keyRegistry, auditedGatewayId, auditedLogId);

        private static (bool IsValid, AuditVerdict Verdict) AuthenticateCapturedSnapshot(
            LogSnapshot snapshot, ITrustedKeyRegistry keyRegistry, string auditedGatewayId, string auditedLogId)
        {
            if (snapshot?.Checkpoint is not { } head || snapshot.Entries is null ||
                snapshot.GatewayId != auditedGatewayId || snapshot.LogId != auditedLogId ||
                snapshot.GatewayId != head.GatewayId || snapshot.LogId != head.LogId ||
                snapshot.EpochId != head.EpochId || (ulong)snapshot.Entries.Count != head.TreeSize)
                return (false, AuditVerdict.IncompleteEvidence);

            var result = VerifyCheckpoint(head, keyRegistry);
            if (result != AuditVerdict.Compliant)
                return (false, result);

            var leaves = new byte[snapshot.Entries.Count][];
            for (int i = 0; i < leaves.Length; i++)
            {
                var entry = snapshot.Entries[i];
                if (entry is null || entry.LeafIdx != (ulong)i || entry.LogId != auditedLogId ||
                    entry.EpochId != head.EpochId || !EvidenceFields.ValidId(entry.CorridorId) ||
                    !EvidenceFields.ValidId(entry.SignerId) || !EvidenceFields.ValidHash(entry.PayloadHash) ||
                    !EvidenceFields.ValidSignature(entry.Signature) || !Enum.IsDefined(entry.Type) ||
                    entry.Timestamp < 0 || entry.Timestamp > head.Timestamp)
                    return (false, AuditVerdict.IncompleteEvidence);

                var leaf = entry.GetCanonicalBytes();
                if (!keyRegistry.VerifySigner(entry.SignerId, SignerRole.Gateway, auditedGatewayId,
                        entry.LogId, entry.CorridorId, leaf, entry.Signature, out var entryError))
                    return (false, entryError);
                leaves[i] = leaf;
            }

            var root = Rfc9162MerkleTree.CalculateRfc9162MerkleRoot(leaves);
            return EvidenceFields.Equal(root, head.RootHash)
                ? (true, AuditVerdict.Compliant) : (false, AuditVerdict.IncompleteEvidence);
        }

        public static (bool IsConsistent, AuditVerdict Verdict) VerifyAppendOnlyConsistency(
            SignedTreeHead sthOld, LogSnapshot snapshotOld, SignedTreeHead sthNew, LogSnapshot snapshotNew,
            ITrustedKeyRegistry keyRegistry)
        {
            sthOld = Capture(sthOld);
            sthNew = Capture(sthNew);
            snapshotOld = Capture(snapshotOld);
            snapshotNew = Capture(snapshotNew);
            var oldResult = VerifyCheckpoint(sthOld, keyRegistry);
            if (oldResult != AuditVerdict.Compliant)
                return (false, oldResult);
            var newResult = VerifyCheckpoint(sthNew, keyRegistry);
            if (newResult != AuditVerdict.Compliant)
                return (false, newResult);

            if (!SameLog(sthOld, sthNew))
                return (false, AuditVerdict.IncompleteEvidence);

            var oldSnapshot = AuthenticateCapturedSnapshot(snapshotOld, keyRegistry, sthOld.GatewayId, sthOld.LogId);
            if (!oldSnapshot.IsValid)
                return (false, oldSnapshot.Verdict);
            var newSnapshot = AuthenticateCapturedSnapshot(snapshotNew, keyRegistry, sthNew.GatewayId, sthNew.LogId);
            if (!newSnapshot.IsValid)
                return (false, newSnapshot.Verdict);

            if (!EvidenceFields.Equal(sthOld.GetCanonicalBytes(), snapshotOld.Checkpoint.GetCanonicalBytes()) ||
                !EvidenceFields.Equal(sthNew.GetCanonicalBytes(), snapshotNew.Checkpoint.GetCanonicalBytes()))
                return (false, AuditVerdict.IncompleteEvidence);

            if (sthOld.TreeSize == sthNew.TreeSize)
                return EvidenceFields.Equal(sthOld.RootHash, sthNew.RootHash)
                    ? (true, AuditVerdict.Compliant) : (false, AuditVerdict.EquivocationDetected);

            // Signed gateway timestamps do not independently establish observation order.
            var shorter = sthOld.TreeSize < sthNew.TreeSize ? sthOld : sthNew;
            var longerSnapshot = sthOld.TreeSize < sthNew.TreeSize ? snapshotNew : snapshotOld;
            if (!MatchesPrefix(shorter, longerSnapshot))
                return (false, AuditVerdict.AppendOnlyViolation);
            if (sthOld.TreeSize > sthNew.TreeSize || sthNew.Timestamp < sthOld.Timestamp)
                return (false, AuditVerdict.UnprovenWithinWindow);
            return (true, AuditVerdict.Compliant);
        }

        private static bool MatchesPrefix(SignedTreeHead shorter, LogSnapshot longer)
        {
            var prefix = longer.Entries.Take((int)shorter.TreeSize).Select(e => e.GetCanonicalBytes()).ToArray();
            return EvidenceFields.Equal(shorter.RootHash, Rfc9162MerkleTree.CalculateRfc9162MerkleRoot(prefix));
        }

        private static bool VerifyObligation(SignedLoggingObligation obligation, LogSnapshot snapshot,
            ITrustedKeyRegistry keys, string gateway, string log)
        {
            if (obligation is null || obligation.Version != 2 || obligation.AuditedGatewayId != gateway ||
                obligation.LogId != log || obligation.EpochId != snapshot.EpochId ||
                !EvidenceFields.ValidId(obligation.CorridorId) ||
                !EvidenceFields.ValidId(obligation.IssuerSignerId) ||
                !EvidenceFields.ValidHash(obligation.PayloadHash) ||
                !EvidenceFields.ValidSignature(obligation.IssuerSignature) ||
                !Enum.IsDefined(obligation.Type) || obligation.Timestamp < 0 ||
                obligation.PublicationDeadline < obligation.Timestamp)
                return false;

            var issuer = obligation.IssuerGatewayId ?? obligation.IssuerSignerId;
            var ackSigner = obligation.TargetAckSignerId ?? gateway;
            if (!EvidenceFields.ValidId(issuer) || !EvidenceFields.ValidId(ackSigner))
                return false;

            if (!keys.VerifySigner(obligation.IssuerSignerId, SignerRole.Gateway, issuer, log,
                    obligation.CorridorId, obligation.GetCanonicalBytes(), obligation.IssuerSignature, out _))
                return false;

            return issuer == gateway ||
                (EvidenceFields.ValidSignature(obligation.TargetAckSignature) &&
                 keys.VerifySigner(ackSigner, SignerRole.Gateway, gateway, log, obligation.CorridorId,
                     obligation.GetTargetAckCanonicalBytes(), obligation.TargetAckSignature!, out _));
        }

        private static AuditVerdict VerifyObservation(WitnessAttestation witness, SignedTreeHead head,
            SignedLoggingObligation obligation, ITrustedKeyRegistry keys, long now)
        {
            if (witness is null)
                return AuditVerdict.IncompleteEvidence;
            if (!EvidenceFields.ValidId(witness.WitnessId) || !EvidenceFields.ValidId(witness.GatewayId) ||
                !EvidenceFields.ValidId(witness.LogId) || !EvidenceFields.ValidSignature(witness.Signature) ||
                !EvidenceFields.ValidHash(witness.CheckpointRootHash) ||
                !EvidenceFields.ValidHash(witness.CheckpointSignatureHash) ||
                !EvidenceFields.ValidHash(witness.CheckpointDigest) ||
                witness.WitnessObservedTime < head.Timestamp || witness.WitnessObservedTime > now)
                return AuditVerdict.InvalidWitnessAttestation;

            if (!keys.VerifySigner(witness.WitnessId, SignerRole.Witness, witness.GatewayId, witness.LogId,
                    obligation.CorridorId, witness.GetCanonicalBytes(), witness.Signature, out var error))
                return error == AuditVerdict.RoleViolation ? error : AuditVerdict.InvalidWitnessAttestation;

            if (witness.GatewayId != head.GatewayId || witness.LogId != head.LogId ||
                witness.EpochId != head.EpochId || witness.TreeSize != head.TreeSize ||
                !EvidenceFields.Equal(witness.CheckpointRootHash, head.RootHash) ||
                !EvidenceFields.Equal(witness.CheckpointSignatureHash, SHA256.HashData(head.Signature)) ||
                !EvidenceFields.Equal(witness.CheckpointDigest!, head.GetCheckpointDigest()))
                return AuditVerdict.WitnessAttestationMismatch;
            return AuditVerdict.Compliant;
        }

        private static AuditVerdict VerifyFreshness(SignedAuditChallenge? challenge, SignedTreeHead head,
            WitnessAttestation witness, SignedLoggingObligation obligation, ITrustedKeyRegistry keys, long now)
        {
            if (challenge is null || head.ChallengeDigest is null)
                return AuditVerdict.UnprovenWithinWindow;
            if (!EvidenceFields.ValidId(challenge.AuditorId) || challenge.GatewayId != head.GatewayId ||
                challenge.LogId != head.LogId || challenge.EpochId != head.EpochId ||
                !EvidenceFields.ValidHash(challenge.Nonce) || !EvidenceFields.ValidHash(challenge.ObligationDigest) ||
                !EvidenceFields.ValidSignature(challenge.Signature) ||
                !EvidenceFields.Equal(challenge.ObligationDigest, obligation.GetEvidenceDigest()) ||
                !keys.VerifySigner(challenge.AuditorId, SignerRole.Auditor, head.GatewayId, head.LogId,
                    obligation.CorridorId, challenge.GetCanonicalBytes(), challenge.Signature, out _) ||
                !EvidenceFields.Equal(challenge.GetChallengeDigest(), head.ChallengeDigest))
                return AuditVerdict.InvalidAuditChallenge;

            if (challenge.IssuedAt <= obligation.PublicationDeadline || head.Timestamp < challenge.IssuedAt ||
                witness.WitnessObservedTime > challenge.ExpiresAt || now > challenge.ExpiresAt)
                return AuditVerdict.UnprovenWithinWindow;
            return AuditVerdict.Compliant;
        }

        public static AuditVerdict AuditLogSnapshot(
            SignedLoggingObligation obligation, WitnessAttestation witnessAttestation, LogSnapshot snapshot,
            IReadOnlyList<SignedTreeHead> sthHistory, ITrustedKeyRegistry keyRegistry, long currentTimeSec,
            string auditedGatewayId, string auditedLogId, SignedAuditChallenge? challenge = null)
        {
            snapshot = Capture(snapshot);
            if (obligation is not null)
                obligation = obligation with
                {
                    PayloadHash = Copy(obligation.PayloadHash), IssuerSignature = Copy(obligation.IssuerSignature),
                    TargetAckSignature = obligation.TargetAckSignature is null ? null : Copy(obligation.TargetAckSignature)
                };
            if (witnessAttestation is not null)
                witnessAttestation = witnessAttestation with
                {
                    CheckpointRootHash = Copy(witnessAttestation.CheckpointRootHash),
                    CheckpointSignatureHash = Copy(witnessAttestation.CheckpointSignatureHash),
                    CheckpointDigest = witnessAttestation.CheckpointDigest is null ? null : Copy(witnessAttestation.CheckpointDigest),
                    Signature = Copy(witnessAttestation.Signature)
                };
            if (challenge is not null)
                challenge = challenge with
                {
                    ObligationDigest = Copy(challenge.ObligationDigest), Nonce = Copy(challenge.Nonce),
                    Signature = Copy(challenge.Signature)
                };

            var snapshotResult = AuthenticateCapturedSnapshot(snapshot, keyRegistry, auditedGatewayId, auditedLogId);
            if (!snapshotResult.IsValid)
                return snapshotResult.Verdict;

            var head = snapshot.Checkpoint;
            if (head.Timestamp > currentTimeSec || sthHistory is null || sthHistory.Any(previous => previous is null))
                return AuditVerdict.IncompleteEvidence;

            var history = sthHistory.Where(previous => SameLog(previous, head))
                .Select(Capture).ToArray();
            if (history.Any(previous => previous.Timestamp > currentTimeSec))
                return AuditVerdict.InvalidCheckpointSignature;
            var equivocation = CheckEquivocation(history.Append(head).ToArray(), keyRegistry);
            if (equivocation.Verdict != AuditVerdict.Compliant)
                return equivocation.Verdict;

            if (obligation is null || !VerifyObligation(obligation, snapshot, keyRegistry, auditedGatewayId, auditedLogId))
                return AuditVerdict.UnprovenObligation;

            if (witnessAttestation is null)
                return AuditVerdict.IncompleteEvidence;
            var observation = VerifyObservation(witnessAttestation, head, obligation, keyRegistry, currentTimeSec);
            if (observation != AuditVerdict.Compliant)
                return observation;

            var freshness = VerifyFreshness(challenge, head, witnessAttestation, obligation, keyRegistry, currentTimeSec);
            if (freshness != AuditVerdict.Compliant)
                return freshness;

            // A demonstrably incompatible prefix is evidence. A larger known head with
            // unavailable leaves makes this snapshot insufficient for an omission claim.
            foreach (var previous in history)
            {
                if (previous.TreeSize > head.TreeSize)
                    return AuditVerdict.UnprovenWithinWindow;
                if (!MatchesPrefix(previous, snapshot))
                    return AuditVerdict.AppendOnlyViolation;
                if (previous.Timestamp > head.Timestamp)
                    return AuditVerdict.UnprovenWithinWindow;
            }

            var matching = snapshot.Entries.Where(entry =>
                entry.CorridorId == obligation.CorridorId && entry.SeqNum == obligation.SeqNum &&
                entry.TxId == obligation.TxId && entry.Type == obligation.Type).ToArray();

            if (matching.Length == 0)
                return AuditVerdict.ProvenLoggingPolicyViolation;
            var matches = matching.Count(entry => EvidenceFields.Equal(entry.PayloadHash, obligation.PayloadHash));
            if (matches == matching.Length)
                return AuditVerdict.Compliant;
            return matches == 0 ? AuditVerdict.MismatchedPayload : AuditVerdict.IncompleteEvidence;
        }
    }
}
