using System.Security.Cryptography;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Xunit;

namespace Bsaap.ForensicLog.Tests;

public sealed class ForensicAuditEngineTests : IDisposable
{
    private const string Gateway = "gateway-A";
    private const string Peer = "gateway-B";
    private const string Log = "synthetic-payments";
    private const string Corridor = "A-to-B";
    private const string GatewayKey = "A-signing-key";
    private const string WitnessKey = "independent-witness";
    private const string AuditorKey = "independent-auditor";
    private const long Now = 1_000;
    private static readonly Guid TxId = Guid.Parse("00000000-0000-4000-8000-000000000001");
    private static readonly byte[] EmptyRoot = SHA256.HashData([]);
    private readonly TrustedKeyRegistry _keys = new();
    private readonly ECDsa _gateway = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _peer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _witness = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _auditor = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public ForensicAuditEngineTests()
    {
        Register(GatewayKey, _gateway, SignerRole.Gateway, Gateway);
        Register(Peer, _peer, SignerRole.Gateway, Peer);
        Register(WitnessKey, _witness, SignerRole.Witness, Gateway);
        Register(AuditorKey, _auditor, SignerRole.Auditor, Gateway);
    }

    public void Dispose()
    {
        _gateway.Dispose();
        _peer.Dispose();
        _witness.Dispose();
        _auditor.Dispose();
    }

    private void Register(string id, ECDsa key, SignerRole role, string gateway, string log = Log,
        string corridor = Corridor) =>
        _keys.RegisterSigner(id, key.ExportSubjectPublicKeyInfo(), role, [gateway], [log], [corridor]);

    private static byte[] Sign(ECDsa key, byte[] bytes) =>
        key.SignData(bytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    private static byte[] Hash(byte data) => SHA256.HashData([data]);

    private LogEntry Entry(ulong index = 0, byte payload = 1) =>
        SignEntry(new(index, Corridor, Log, 7, TxId, EventType.TransportAck, Hash(payload), 800, GatewayKey, []),
            _gateway);

    private static LogEntry SignEntry(LogEntry entry, ECDsa key) =>
        entry with { Signature = Sign(key, entry.GetCanonicalBytes()) };

    private SignedTreeHead Head(ulong size, byte[] root, SignedAuditChallenge? challenge = null, long time = 950) =>
        SignHead(new(Gateway, Log, 1, size, root, time, GatewayKey, [], challenge?.GetChallengeDigest()), _gateway);

    private static SignedTreeHead SignHead(SignedTreeHead head, ECDsa key) =>
        head with { Signature = Sign(key, head.GetCanonicalBytes()) };

    private LogSnapshot Snapshot(SignedAuditChallenge? challenge = null, params LogEntry[] entries)
    {
        var root = Rfc9162MerkleTree.CalculateRfc9162MerkleRoot(entries.Select(e => e.GetCanonicalBytes()).ToArray());
        return new(Gateway, Log, 1, entries.ToList(), Head((ulong)entries.Length, root, challenge));
    }

    private SignedLoggingObligation Obligation(bool bilateral = false, bool acknowledged = true)
    {
        var obligation = new SignedLoggingObligation(2, Gateway, Log, Corridor, 7, TxId, EventType.TransportAck,
            Hash(1), 800, 900, bilateral ? Peer : GatewayKey, [], IssuerGatewayId: bilateral ? Peer : Gateway,
            TargetAckSignerId: GatewayKey);
        obligation = obligation with
        {
            IssuerSignature = Sign(bilateral ? _peer : _gateway, obligation.GetCanonicalBytes())
        };
        return bilateral && acknowledged
            ? obligation with { TargetAckSignature = Sign(_gateway, obligation.GetTargetAckCanonicalBytes()) }
            : obligation;
    }

    private SignedAuditChallenge Challenge(SignedLoggingObligation obligation, long issued = 925, long expiry = 1_050)
    {
        var challenge = new SignedAuditChallenge(AuditorKey, Gateway, Log, 1, obligation.GetEvidenceDigest(),
            RandomNumberGenerator.GetBytes(32), issued, expiry, []);
        return challenge with { Signature = Sign(_auditor, challenge.GetCanonicalBytes()) };
    }

    private WitnessAttestation Observe(SignedTreeHead head, long time = 975) =>
        SignWitness(new(WitnessKey, head.GatewayId, head.LogId, head.EpochId, head.TreeSize, head.RootHash,
            SHA256.HashData(head.Signature), time, [], head.GetCheckpointDigest()), _witness);

    private static WitnessAttestation SignWitness(WitnessAttestation witness, ECDsa key) =>
        witness with { Signature = Sign(key, witness.GetCanonicalBytes()) };

    private AuditVerdict Audit(SignedLoggingObligation obligation, LogSnapshot snapshot,
        SignedAuditChallenge? challenge, WitnessAttestation? witness = null, params SignedTreeHead[] history) =>
        ForensicAuditEngine.AuditLogSnapshot(obligation, witness ?? Observe(snapshot.Checkpoint), snapshot,
            history, _keys, Now, Gateway, Log, challenge);

    [Fact]
    public void MatchingGatewayEntryAndAcknowledgedBilateralObligationAreVerified()
    {
        var obligation = Obligation(bilateral: true);
        var challenge = Challenge(obligation);
        var snapshot = Snapshot(challenge, Entry());
        Assert.Equal(AuditVerdict.Compliant, Audit(obligation, snapshot, challenge));
    }

    [Fact]
    public void FreshEmptySnapshotProvesOmission()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        Assert.Equal(AuditVerdict.ProvenLoggingPolicyViolation, Audit(obligation, Snapshot(challenge), challenge));
    }

    [Fact]
    public void WrongPayloadIsDistinguishedFromConflictingDuplicates()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        Assert.Equal(AuditVerdict.MismatchedPayload, Audit(obligation, Snapshot(challenge, Entry(payload: 2)), challenge));
        Assert.Equal(AuditVerdict.IncompleteEvidence,
            Audit(obligation, Snapshot(challenge, Entry(), Entry(1, 2)), challenge));
    }

    [Fact]
    public void ObservingAnUnchallengedCheckpointLateDoesNotProveOmission()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        foreach (long time in new long[] { 850, 950 })
        {
            var snapshot = Snapshot() with { Checkpoint = Head(0, EmptyRoot, time: time) };
            Assert.Equal(AuditVerdict.UnprovenWithinWindow, Audit(obligation, snapshot, challenge));
        }
    }

    [Theory]
    [InlineData(900, 1050, 950)]
    [InlineData(925, 999, 950)]
    [InlineData(925, 1050, 924)]
    public void RejectsCheckpointOutsideChallengeWindow(long issued, long expiry, long checkpoint)
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation, issued, expiry);
        var snapshot = Snapshot(challenge) with { Checkpoint = Head(0, EmptyRoot, challenge, checkpoint) };
        Assert.Equal(AuditVerdict.UnprovenWithinWindow, Audit(obligation, snapshot, challenge));
    }

    [Fact]
    public void ChallengeCannotBeSubstitutedOrUsedForAnotherObligation()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        Assert.Equal(AuditVerdict.InvalidAuditChallenge,
            Audit(obligation, Snapshot(challenge), Challenge(obligation)));
        var other = Obligation(bilateral: true);
        Assert.Equal(AuditVerdict.InvalidAuditChallenge, Audit(other, Snapshot(challenge), challenge));
    }

    [Fact]
    public void ARealGatewaySignatureCannotActAsAnAuditor()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation) with { AuditorId = GatewayKey };
        challenge = challenge with { Signature = Sign(_gateway, challenge.GetCanonicalBytes()) };
        Assert.Equal(AuditVerdict.InvalidAuditChallenge, Audit(obligation, Snapshot(challenge), challenge));
    }

    [Fact]
    public void AValidWrongScopeAuditorCannotIssueChallenge()
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Register("other-auditor", otherKey, SignerRole.Auditor, Gateway, corridor: "elsewhere");
        var obligation = Obligation();
        var challenge = Challenge(obligation) with { AuditorId = "other-auditor" };
        challenge = challenge with { Signature = Sign(otherKey, challenge.GetCanonicalBytes()) };
        Assert.Equal(AuditVerdict.InvalidAuditChallenge, Audit(obligation, Snapshot(challenge), challenge));
    }

    [Fact]
    public void ForgedChallengeIsRejectedEvenWhenGatewayAndWitnessSignTheirArtifacts()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        challenge = challenge with { Signature = Sign(_peer, challenge.GetCanonicalBytes()) };
        Assert.Equal(AuditVerdict.InvalidAuditChallenge, Audit(obligation, Snapshot(challenge), challenge));
    }

    [Fact]
    public void RejectsMissingAndForgedCounterpartyAcknowledgements()
    {
        var obligation = Obligation(bilateral: true, acknowledged: false);
        Assert.Equal(AuditVerdict.UnprovenObligation, Audit(obligation, Snapshot(), null));
        var badAck = obligation with { TargetAckSignature = Sign(_peer, obligation.GetTargetAckCanonicalBytes()) };
        Assert.Equal(AuditVerdict.UnprovenObligation, Audit(badAck, Snapshot(), null));
        var issuedAgain = obligation with { IssuerSignature = Sign(_peer, obligation.GetCanonicalBytes()) };
        issuedAgain = issuedAgain with { TargetAckSignature = Obligation(bilateral: true).TargetAckSignature };
        Assert.Equal(AuditVerdict.UnprovenObligation, Audit(issuedAgain, Snapshot(), null));
    }

    [Fact]
    public void RejectsForgedUnsupportedAndCrossEpochObligations()
    {
        var obligation = Obligation();
        Assert.Equal(AuditVerdict.UnprovenObligation, Audit(
            obligation with { IssuerSignature = Sign(_peer, obligation.GetCanonicalBytes()) }, Snapshot(), null));

        foreach (var malformed in new[] { obligation with { EpochId = 2 }, obligation with { Version = 1 },
                     obligation with { PublicationDeadline = 799 }, obligation with { PayloadHash = [] } })
        {
            var signed = malformed with { IssuerSignature = Sign(_gateway, malformed.GetCanonicalBytes()) };
            Assert.Equal(AuditVerdict.UnprovenObligation, Audit(signed, Snapshot(), null));
        }
    }

    [Fact]
    public void WitnessMustBeIndependentlyAuthorizedAndBindExactSignedCheckpoint()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        var snapshot = Snapshot(challenge);
        var head = snapshot.Checkpoint;
        var attestation = Observe(head);
        Assert.Equal(AuditVerdict.RoleViolation, Audit(obligation, snapshot, challenge,
            SignWitness(attestation with { WitnessId = GatewayKey }, _gateway)));
        Assert.Equal(AuditVerdict.InvalidWitnessAttestation, Audit(obligation, snapshot, challenge,
            SignWitness(attestation, _peer)));
        Assert.Equal(AuditVerdict.WitnessAttestationMismatch, Audit(obligation, snapshot, challenge,
            SignWitness(attestation with { CheckpointSignatureHash = Hash(5) }, _witness)));
        Assert.Equal(AuditVerdict.WitnessAttestationMismatch, Audit(obligation, snapshot, challenge,
            SignWitness(attestation with { CheckpointDigest = Hash(5) }, _witness)));
        Assert.Equal(AuditVerdict.WitnessAttestationMismatch, Audit(obligation, snapshot, challenge,
            Observe(SignHead(head with { Timestamp = 951 }, _gateway))));
        Assert.Equal(AuditVerdict.InvalidWitnessAttestation, Audit(obligation, snapshot, challenge, Observe(head, 949)));
        Assert.Equal(AuditVerdict.InvalidWitnessAttestation, Audit(obligation, snapshot, challenge, Observe(head, Now + 1)));
        Assert.Equal(AuditVerdict.IncompleteEvidence, ForensicAuditEngine.AuditLogSnapshot(obligation, null!,
            snapshot, [], _keys, Now, Gateway, Log, challenge));
    }

    [Fact]
    public void WitnessAndAuditorCannotSignGatewayCheckpoint()
    {
        var head = Snapshot().Checkpoint;
        foreach (var (id, key) in new[] { (WitnessKey, _witness), (AuditorKey, _auditor) })
        {
            var snapshot = Snapshot() with { Checkpoint = SignHead(head with { SignerId = id }, key) };
            Assert.Equal((false, AuditVerdict.RoleViolation), Authenticate(snapshot));
        }
    }

    [Fact]
    public void MissingReorderedMalformedOrForgedLeavesFailAuthentication()
    {
        var snapshot = Snapshot(null, Entry(), Entry(1));
        Assert.Equal((true, AuditVerdict.Compliant), Authenticate(snapshot));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Authenticate(snapshot with { Entries = [Entry()] }));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence),
            Authenticate(snapshot with { Entries = [snapshot.Entries[1], snapshot.Entries[0]] }));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Authenticate(Snapshot(null, Entry()) with { Entries = [Entry() with { PayloadHash = null! }] }));
    }

    [Fact]
    public void SnapshotRejectsCrossOwnerCrossEpochAndForgedLeavesWithValidCheckpoint()
    {
        var entry = Entry();
        var foreign = SignEntry(entry with { SignerId = Peer }, _peer);
        Assert.Equal((false, AuditVerdict.UnauthorizedSigner), Authenticate(Snapshot(null, foreign)));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence),
            Authenticate(Snapshot(null, SignEntry(entry with { EpochId = 2 }, _gateway))));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Authenticate(Snapshot(null, SignEntry(entry, _peer))));
    }

    [Fact]
    public void SnapshotRejectsForgedRootOversizedCountAndUnauthorizedLog()
    {
        var entry = Entry();
        var snapshot = Snapshot(null, entry);
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Authenticate(snapshot with { Checkpoint = Head(1, Hash(9)) }));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Authenticate(Snapshot() with { Checkpoint = Head(1UL << 32, Hash(9)) }));
        var unscoped = SignHead(snapshot.Checkpoint with { LogId = "other-log" }, _gateway);
        Assert.Equal((false, AuditVerdict.UnauthorizedSigner),
            ForensicAuditEngine.AuthenticateSnapshot(snapshot with { LogId = "other-log", Checkpoint = unscoped },
                _keys, Gateway, "other-log"));
        Assert.Equal((false, AuditVerdict.InvalidCheckpointSignature),
            Authenticate(snapshot with { Checkpoint = SignHead(snapshot.Checkpoint, _peer) }));
    }

    private (bool, AuditVerdict) Authenticate(LogSnapshot snapshot) =>
        ForensicAuditEngine.AuthenticateSnapshot(snapshot, _keys, Gateway, Log);

    private (bool, AuditVerdict) Consistency(LogSnapshot old, LogSnapshot newer) =>
        ForensicAuditEngine.VerifyAppendOnlyConsistency(old.Checkpoint, old, newer.Checkpoint, newer, _keys);

    [Fact]
    public void AppendOnlyVerifiesGrowthAndRejectsSignedRewriteOrUnauthenticatedArgument()
    {
        var old = Snapshot(null, Entry());
        var extension = Snapshot(null, old.Entries[0], Entry(1));
        Assert.Equal((true, AuditVerdict.Compliant), Consistency(old, extension));
        Assert.Equal((true, AuditVerdict.Compliant), Consistency(Snapshot(), extension));
        var rewrite = Snapshot(null, Entry(payload: 2), Entry(1));
        Assert.Equal((false, AuditVerdict.AppendOnlyViolation), Consistency(old, rewrite));
        Assert.Equal((false, AuditVerdict.UnprovenWithinWindow), Consistency(extension, old));
        Assert.Equal((false, AuditVerdict.InvalidCheckpointSignature),
            ForensicAuditEngine.VerifyAppendOnlyConsistency(SignHead(old.Checkpoint, _peer), old,
                extension.Checkpoint, extension, _keys));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Consistency(old, extension with { Entries = [] }));
        Assert.Equal((false, AuditVerdict.IncompleteEvidence),
            ForensicAuditEngine.VerifyAppendOnlyConsistency(SignHead(old.Checkpoint with { Timestamp = 940 }, _gateway),
                old, extension.Checkpoint, extension, _keys));
    }

    [Fact]
    public void EquivocationRequiresTwoAuthorizedConflictingHeadsAtSamePosition()
    {
        var first = Head(1, Hash(1));
        var fork = Head(1, Hash(2));
        Assert.Equal((true, AuditVerdict.EquivocationDetected),
            ForensicAuditEngine.CheckEquivocation([first, fork], _keys));
        Assert.Equal((false, AuditVerdict.InvalidCheckpointSignature),
            ForensicAuditEngine.CheckEquivocation([first, SignHead(fork, _peer)], _keys));
        Assert.Equal((false, AuditVerdict.UnauthorizedSigner),
            ForensicAuditEngine.CheckEquivocation([first, SignHead(fork with { SignerId = Peer }, _peer)], _keys));
        Assert.Equal((false, AuditVerdict.Compliant),
            ForensicAuditEngine.CheckEquivocation([first, SignHead(fork with { EpochId = 2 }, _gateway),
                SignHead(fork with { GatewayId = Peer, SignerId = Peer }, _peer),
                Head(2, Hash(2)), Head(1, Hash(1), time: 970)], _keys));
    }

    [Fact]
    public void AuditChecksCurrentHeadAgainstScopedHistoryAndBlocksStaleSnapshot()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        var snapshot = Snapshot(challenge, Entry());
        var fork = Head(1, Hash(9));
        Assert.Equal(AuditVerdict.EquivocationDetected, Audit(obligation, snapshot, challenge, null, fork));
        Assert.Equal(AuditVerdict.InvalidCheckpointSignature,
            Audit(obligation, snapshot, challenge, null, SignHead(fork, _peer)));
        var unrelated = SignHead(fork with { EpochId = 2 }, _gateway);
        Assert.Equal(AuditVerdict.Compliant, Audit(obligation, snapshot, challenge, null, unrelated));
        var longer = Snapshot(null, Entry(), Entry(1)).Checkpoint;
        Assert.Equal(AuditVerdict.UnprovenWithinWindow,
            Audit(obligation, Snapshot(challenge), challenge, null, longer));
        var rewritten = Snapshot(challenge, Entry(payload: 2), Entry(1));
        Assert.Equal(AuditVerdict.AppendOnlyViolation,
            Audit(obligation, rewritten, challenge, null, snapshot.Checkpoint));
    }

    [Fact]
    public void MissingHistoryInputAndFutureCheckpointDoNotSupportOmission()
    {
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        var snapshot = Snapshot(challenge);
        Assert.Equal(AuditVerdict.IncompleteEvidence, ForensicAuditEngine.AuditLogSnapshot(obligation,
            Observe(snapshot.Checkpoint), snapshot, null!, _keys, Now, Gateway, Log, challenge));
        Assert.Equal(AuditVerdict.IncompleteEvidence, Audit(obligation, snapshot, challenge, null, [null!]));
        var future = snapshot with { Checkpoint = Head(0, EmptyRoot, challenge, Now + 1) };
        Assert.Equal(AuditVerdict.IncompleteEvidence, Audit(obligation, future, challenge));
    }

    [Fact]
    public void WrongScopeWitnessCannotAuthorizeAnOmissionFinding()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        Register("other-witness", key, SignerRole.Witness, Gateway, corridor: "other-corridor");
        var obligation = Obligation();
        var challenge = Challenge(obligation);
        var snapshot = Snapshot(challenge);
        var observation = SignWitness(Observe(snapshot.Checkpoint) with { WitnessId = "other-witness" }, key);
        Assert.Equal(AuditVerdict.InvalidWitnessAttestation, Audit(obligation, snapshot, challenge, observation));
    }

    [Fact]
    public void EqualSizeForkIsReportedAndCrossEpochSnapshotsAreIncomparable()
    {
        var original = Snapshot(null, Entry());
        var fork = Snapshot(null, Entry(payload: 9));
        Assert.Equal((false, AuditVerdict.EquivocationDetected), Consistency(original, fork));
        var otherEpoch = fork with
        {
            EpochId = 2, Checkpoint = SignHead(fork.Checkpoint with { EpochId = 2 }, _gateway)
        };
        Assert.Equal((false, AuditVerdict.IncompleteEvidence), Consistency(original, otherEpoch));
    }

    [Fact]
    public void RegistryRejectsKeyReuseReplacementWrongCurveAndTrailingData()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.Throws<ArgumentException>(() => Register("wrong-curve", p384, SignerRole.Gateway, Gateway));
        Assert.Throws<ArgumentException>(() => Register("role-alias", _gateway, SignerRole.Witness, Gateway));
        Assert.Throws<ArgumentException>(() => Register(GatewayKey, _peer, SignerRole.Gateway, Gateway));
        Assert.Throws<ArgumentException>(() => _keys.RegisterSigner("trailing", [.. _gateway.ExportSubjectPublicKeyInfo(), 0],
            SignerRole.Auditor, [Gateway]));
    }

    [Fact]
    public void RegistryKeyBuffersAreIsolatedAndUnspecifiedScopesDenyAccess()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] exported = key.ExportSubjectPublicKeyInfo();
        _keys.RegisterSigner("unscoped", exported, SignerRole.Gateway, [Gateway]);
        Array.Clear(exported);
        Assert.True(_keys.TryGetPublicKey("unscoped", out var returned));
        Array.Clear(returned);
        Assert.True(_keys.TryGetPublicKey("unscoped", out var second));
        Assert.Equal(key.ExportSubjectPublicKeyInfo(), second);
        var head = SignHead(Snapshot().Checkpoint with { SignerId = "unscoped" }, key);
        Assert.Equal((false, AuditVerdict.UnauthorizedSigner), Authenticate(Snapshot() with { Checkpoint = head }));
    }

    [Fact]
    public void CanonicalEncodingSeparatesPreviouslyAmbiguousIdentifiersAndArtifactDomains()
    {
        var left = Head(1, Hash(1)) with { GatewayId = "a:b", LogId = "c" };
        var right = left with { GatewayId = "a", LogId = "b:c" };
        Assert.False(left.GetCanonicalBytes().AsSpan().SequenceEqual(right.GetCanonicalBytes()));
        var obligation = Obligation();
        Assert.False(obligation.GetCanonicalBytes().AsSpan().SequenceEqual(obligation.GetTargetAckCanonicalBytes()));
    }
}
