using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

internal sealed record PublicSigner(
    string Id, string PublicKey, SignerRole Role,
    ImmutableArray<string> Gateways, ImmutableArray<string> Logs, ImmutableArray<string> Corridors);
internal sealed record ArchiveData(
    ImmutableArray<PublishedArtifact> Artifacts, ImmutableArray<PublicSigner> Signers,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    ImmutableArray<RetainedCheckpoint> Retentions = default);

// Owner-side archive supports exact replay of randomized real signatures and nonces.
// Only public keys are retained. Acquisition never exposes the whole archive.
public sealed class ProtocolArchive
{
    internal ImmutableArray<PublishedArtifact> Artifacts { get; }
    private readonly ImmutableArray<PublicSigner> _signers;
    internal ImmutableArray<RetainedCheckpoint> Retentions { get; }

    internal ProtocolArchive(ImmutableArray<PublishedArtifact> artifacts, ImmutableArray<PublicSigner> signers,
        ImmutableArray<RetainedCheckpoint> retentions = default)
    {
        if (artifacts.IsDefault || signers.IsDefault || artifacts.Any(a => a is null ||
            string.IsNullOrWhiteSpace(a.Id) || a.AvailableAt.Milliseconds < 0) ||
            artifacts.Select(a => a.Id).Distinct(StringComparer.Ordinal).Count() != artifacts.Length)
            throw new ArgumentException("Invalid protocol archive.");
        Artifacts = artifacts;
        _signers = signers;
        Retentions = retentions.IsDefaultOrEmpty ? [] : retentions;
    }

    public string Serialize() => JsonSerializer.Serialize(new ArchiveData(Artifacts, _signers, Retentions.IsEmpty ? default : Retentions));
    public static ProtocolArchive Restore(string json)
    {
        var data = JsonSerializer.Deserialize<ArchiveData>(json)
            ?? throw new ArgumentException("Missing protocol archive.");
        return new(data.Artifacts, data.Signers, data.Retentions);
    }

    public ImmutableArray<TrustedPublicSigner> ExportTrustedPublicKeys() =>
        _signers.Select(s => new TrustedPublicSigner(s.Id, s.PublicKey, s.Role,
            s.Gateways, s.Logs, s.Corridors)).ToImmutableArray();

    public TrustedKeyRegistry CreateRegistry()
    {
        var registry = new TrustedKeyRegistry();
        foreach (var signer in _signers)
            registry.RegisterSigner(signer.Id, Convert.FromBase64String(signer.PublicKey), signer.Role,
                signer.Gateways, signer.Logs, signer.Corridors);
        return registry;
    }

    internal ProtocolArchive ReplaceArtifact(string id, string json) =>
        new(Artifacts.Select(a => a.Id == id ? a with { Json = json } : a).ToImmutableArray(), _signers, Retentions);

    public ProtocolArchive WithDeliveredBodies(ImmutableDictionary<string, string> bodies)
    {
        ArgumentNullException.ThrowIfNull(bodies);
        var delivered = this;
        foreach (var body in bodies)
        {
            if (!Artifacts.Any(artifact => artifact.Id == body.Key))
                throw new ArgumentException("Unknown delivered artifact ID.");
            delivered = delivered.ReplaceArtifact(body.Key, body.Value);
        }
        return delivered;
    }

    public static ProtocolArchive Create(SimulationRun run, ProtocolSchedule schedule)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(schedule);
        if (schedule.Obligations.IsDefault || schedule.Challenges.IsDefault ||
            schedule.Checkpoints.IsDefault || schedule.Witnesses.IsDefault)
            throw new ArgumentException("Protocol schedules must be explicit.");

        using var gatewayA = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var gatewayB = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var witness = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var auditor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var corridors = run.Pristine.Select(e => e.Corridor).Distinct(StringComparer.Ordinal).ToImmutableArray();
        var logs = corridors.SelectMany(c => new[] { c + "/A", c + "/B" }).ToImmutableArray();
        var signers = ImmutableArray.Create(
            Registration("A", gatewayA, SignerRole.Gateway, ["A"], corridors.Select(c => c + "/A").ToImmutableArray(), corridors),
            Registration("B", gatewayB, SignerRole.Gateway, ["B"], logs, corridors),
            Registration("W", witness, SignerRole.Witness, ["A", "B"], logs, corridors),
            Registration("AUDITOR", auditor, SignerRole.Auditor, ["A", "B"], logs, corridors));
        var artifacts = ImmutableArray.CreateBuilder<PublishedArtifact>();
        var retentions = ImmutableArray.CreateBuilder<RetainedCheckpoint>();
        var obligations = new Dictionary<string, SignedLoggingObligation>(StringComparer.Ordinal);
        var accepted = new Dictionary<string, (SignedLoggingObligation Obligation, LogicalInstant At)>(StringComparer.Ordinal);
        var challenges = new Dictionary<string, SignedAuditChallenge>(StringComparer.Ordinal);
        var heads = new Dictionary<string, SignedTreeHead>(StringComparer.Ordinal);
        var checkpointTimes = new Dictionary<string, LogicalInstant>(StringComparer.Ordinal);

        foreach (var publication in schedule.Obligations)
        {
            if (publication.EventOrdinal < 0 || publication.EventOrdinal >= run.Pristine.Length ||
                publication.IssuerGateway is not ("A" or "B") ||
                publication.PublishedAt.Milliseconds > publication.Deadline.Milliseconds ||
                (publication.TargetAckAt is null) != (publication.AckAvailableAt is null))
                throw new ArgumentException("Invalid obligation publication.");
            var original = run.Pristine[publication.EventOrdinal];
            long timestamp = schedule.Clock.ToUnixSeconds(publication.PublishedAt);
            long deadline = schedule.Clock.ToUnixSeconds(publication.Deadline);
            var obligation = new SignedLoggingObligation(2, "A", original.Corridor + "/A",
                original.Corridor, original.Sequence.Value, original.TransactionId.Value, Map(original.Type),
                PayloadHash(original), timestamp, deadline, publication.IssuerGateway, [],
                IssuerGatewayId: publication.IssuerGateway, TargetAckSignerId: "A");
            obligation = obligation with
            {
                IssuerSignature = Sign(publication.IssuerGateway == "A" ? gatewayA : gatewayB, obligation.GetCanonicalBytes())
            };
            obligations.Add(publication.Id, obligation);
            Add(artifacts, publication.Id, publication.IssuerGateway, ArtifactKind.Obligation,
                publication.PublishedAt, obligation);
            if (publication.IssuerGateway == "A")
                accepted.Add(publication.Id, (obligation, publication.PublishedAt));
            if (publication.TargetAckAt is { } ackAt && publication.AckAvailableAt is { } ackAvailable)
            {
                if (publication.IssuerGateway != "B" || ackAt.Milliseconds < publication.PublishedAt.Milliseconds ||
                    ackAt.Milliseconds > publication.Deadline.Milliseconds ||
                    ackAvailable.Milliseconds < ackAt.Milliseconds)
                    throw new ArgumentException("Invalid target ACK timeline.");
                schedule.Clock.ToUnixSeconds(ackAt);
                var acknowledged = obligation with
                {
                    TargetAckSignature = Sign(gatewayA, obligation.GetTargetAckCanonicalBytes())
                };
                accepted.Add(publication.Id, (acknowledged, ackAt));
                Add(artifacts, publication.Id + "/ack", "A", ArtifactKind.TargetAck, ackAvailable, acknowledged);
            }
        }

        foreach (var publication in schedule.Challenges)
        {
            var obligation = obligations[publication.ObligationId];
            LogicalInstant readyAt = schedule.Obligations.Single(o => o.Id == publication.ObligationId).PublishedAt;
            if (accepted.TryGetValue(publication.ObligationId, out var acceptance))
            {
                obligation = acceptance.Obligation;
                readyAt = schedule.Obligations.Single(o => o.Id == publication.ObligationId)
                    .AckAvailableAt ?? acceptance.At;
            }
            if (publication.IssuedAt.Milliseconds < readyAt.Milliseconds ||
                publication.ExpiresAt.Milliseconds < publication.IssuedAt.Milliseconds)
                throw new ArgumentException("Invalid challenge timeline.");
            var challenge = new SignedAuditChallenge("AUDITOR", obligation.AuditedGatewayId, obligation.LogId, 1,
                obligation.GetEvidenceDigest(), RandomNumberGenerator.GetBytes(32),
                schedule.Clock.ToUnixSeconds(publication.IssuedAt),
                schedule.Clock.ToUnixSeconds(publication.ExpiresAt), []);
            challenge = challenge with { Signature = Sign(auditor, challenge.GetCanonicalBytes()) };
            challenges.Add(publication.Id, challenge);
            Add(artifacts, publication.Id, "AUDITOR", ArtifactKind.Challenge, publication.IssuedAt, challenge);
        }

        foreach (var publication in schedule.Checkpoints)
        {
            if (publication.Gateway is not ("A" or "B") ||
                publication.InternalView is not ("primary" or "alternate") ||
                !corridors.Contains(publication.Corridor, StringComparer.Ordinal) ||
                (publication.Gateway == "B" && publication.InternalView != "primary"))
                throw new ArgumentException("Invalid checkpoint scope.");
            string log = publication.Corridor + "/" + publication.Gateway;
            var selected = run.Records.Where(r => r.Gateway == publication.Gateway &&
                r.LogId == log && r.ViewId == publication.InternalView &&
                r.LoggedAt <= publication.CreatedAt.Milliseconds).ToArray();
            var key = publication.Gateway == "A" ? gatewayA : gatewayB;
            var entries = selected.Select((record, index) =>
            {
                var entry = new LogEntry((ulong)index, record.Event.Corridor, log, record.Event.Sequence.Value,
                    record.Event.TransactionId.Value, Map(record.Event.Type), PayloadHash(record.Event),
                    schedule.Clock.ToUnixSeconds(new(record.LoggedAt)), publication.Gateway, []);
                return entry with { Signature = Sign(key, entry.GetCanonicalBytes()) };
            }).ToList();
            SignedAuditChallenge? challenge = publication.ChallengeId is null ? null : challenges[publication.ChallengeId];
            if (challenge is not null && (challenge.GatewayId != publication.Gateway || challenge.LogId != log ||
                schedule.Clock.ToUnixSeconds(publication.CreatedAt) < challenge.IssuedAt))
                throw new ArgumentException("Checkpoint challenge scope mismatch.");
            var head = new SignedTreeHead(publication.Gateway, log, 1, (ulong)entries.Count,
                Rfc9162MerkleTree.CalculateRfc9162MerkleRoot(entries.Select(e => e.GetCanonicalBytes()).ToArray()),
                schedule.Clock.ToUnixSeconds(publication.ClaimedTimestamp ?? publication.CreatedAt),
                publication.Gateway, [], challenge?.GetChallengeDigest());
            head = head with { Signature = Sign(key, head.GetCanonicalBytes()) };
            heads.Add(publication.Id, head);
            checkpointTimes.Add(publication.Id, publication.CreatedAt);
            Add(artifacts, publication.Id, publication.Gateway, ArtifactKind.Checkpoint, publication.CreatedAt, head);
            var local = selected.Select((record, index) => new PublicLogRecord(record.Gateway, record.LogId,
                new((ulong)index), record.Event, new(record.LoggedAt), record.Attempt)).ToImmutableArray();
            Add(artifacts, publication.Id + "/snapshot", publication.Gateway, ArtifactKind.Snapshot,
                publication.CreatedAt, new LogSnapshot(publication.Gateway, log, 1, entries, head), local);
        }

        foreach (var publication in schedule.Witnesses)
        {
            var head = heads[publication.CheckpointId];
            if (publication.ObservedAt.Milliseconds < checkpointTimes[publication.CheckpointId].Milliseconds ||
                publication.AvailableAt.Milliseconds < publication.ObservedAt.Milliseconds)
                throw new ArgumentException("Witness cannot observe unpublished checkpoints.");
            var attestation = new WitnessAttestation("W", head.GatewayId, head.LogId, head.EpochId, head.TreeSize,
                head.RootHash, SHA256.HashData(head.Signature), schedule.Clock.ToUnixSeconds(publication.ObservedAt),
                [], head.GetCheckpointDigest());
            attestation = attestation with { Signature = Sign(witness, attestation.GetCanonicalBytes()) };
            Add(artifacts, publication.Id, "W", ArtifactKind.Witness, publication.AvailableAt, attestation);
            if (publication.RetainCheckpoint)
            {
                var available = publication.CheckpointAvailableAt ?? publication.ObservedAt;
                if (publication.RetainedUntil is not { } until || available.Milliseconds < publication.ObservedAt.Milliseconds ||
                    until.Milliseconds <= available.Milliseconds)
                    throw new ArgumentException("Checkpoint retention needs an explicit valid interval.");
                retentions.Add(new(publication.CheckpointId, "W", publication.ObservedAt, available, until));
            }
            else if (publication.RetainedUntil is not null || publication.CheckpointAvailableAt is not null)
                throw new ArgumentException("Checkpoint forwarding requires explicit retention.");
        }
        return new(artifacts.ToImmutable(), signers, retentions.ToImmutable());
    }

    private static PublicSigner Registration(string id, ECDsa key, SignerRole role,
        ImmutableArray<string> gateways, ImmutableArray<string> logs, ImmutableArray<string> corridors) =>
        new(id, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()), role, gateways, logs, corridors);

    private static byte[] Sign(ECDsa key, byte[] bytes) => key.SignData(bytes, HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    private static void Add<T>(ImmutableArray<PublishedArtifact>.Builder artifacts, string id, string producer,
        ArtifactKind kind, LogicalInstant at, T value, ImmutableArray<PublicLogRecord> records = default) =>
        artifacts.Add(new(id, producer, kind, at, JsonSerializer.Serialize(value),
            records.IsDefault ? [] : records));

    internal static byte[] PayloadHash(SyntheticEvent value) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)));

    internal static EventType Map(SyntheticEventType type) => type switch
    {
        SyntheticEventType.Pacs008Dispatch => EventType.Pacs008Dispatch,
        SyntheticEventType.TransportAck => EventType.TransportAck,
        SyntheticEventType.Pacs002Actc => EventType.Pacs002Actc,
        SyntheticEventType.Pacs002Accc => EventType.Pacs002Accc,
        SyntheticEventType.Pacs002Rjct => EventType.Pacs002Rjct,
        _ => throw new ArgumentOutOfRangeException(nameof(type))
    };
}
