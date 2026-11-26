using System.Collections.Immutable;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

public sealed class EvidenceAcquisition
{
    private readonly ProtocolArchive _archive;
    private readonly AcquisitionPlan _plan;
    private readonly ImmutableArray<AuditQuery> _queries;
    internal ImmutableArray<ArtifactDelivery> Deliveries { get; }
    internal AcquisitionPlan Plan => _plan;
    internal ImmutableArray<string> ObserverIds => _plan.Observers.Select(o => o.Observer).ToImmutableArray();

    public EvidenceAcquisition(SimulationRun run, ProtocolArchive archive, AcquisitionPlan plan)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(plan);
        _archive = archive;
        _plan = plan;
        _queries = run.Pristine.Select(e => new AuditQuery("omission/" + e.EventId.Value.ToString("D"),
            ClaimKind.OmissionPolicyViolation, e.EventId, e.TransactionId, "A", e.Corridor + "/A",
            e.Corridor, e.Sequence, e.Type, Convert.ToHexString(ProtocolArchive.PayloadHash(e)))).Concat(run.Pristine.Select(e => e.Corridor).Distinct(StringComparer.Ordinal)
                .Select(c => new AuditQuery("equivocation/" + c + "/A/1", ClaimKind.SignedLogEquivocation,
                    null, null, "A", c + "/A", c, null))).ToImmutableArray();
        Deliveries = Collect(archive, plan);
    }

    private static ImmutableArray<ArtifactDelivery> Collect(ProtocolArchive archive, AcquisitionPlan plan)
    {
        if (plan.Budget is null || plan.Budget.MaximumRequests < 0 || plan.Budget.MaximumArtifactsPerRequest < 1 ||
            plan.Observers.IsDefaultOrEmpty || plan.Disclosure.IsDefault ||
            plan.Observers.Any(o => o is null || string.IsNullOrWhiteSpace(o.Observer) ||
                o.OwnGateway is not ("A" or "B") || o.Cutoff.Milliseconds < 0 || o.Requests.IsDefault ||
                o.Requests.Length > plan.Budget.MaximumRequests ||
                o.Requests.Any(r => r is null || string.IsNullOrWhiteSpace(r.Id) ||
                    string.IsNullOrWhiteSpace(r.Target) || !Enum.IsDefined(r.Channel) ||
                    r.SentAt.Milliseconds < 0 || r.TimeoutAt.Milliseconds < r.SentAt.Milliseconds ||
                    r.SentAt.Milliseconds > o.Cutoff.Milliseconds) ||
                o.Requests.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() != o.Requests.Length) ||
            plan.Observers.Select(o => o.Observer).Distinct(StringComparer.Ordinal).Count() != plan.Observers.Length)
            throw new ArgumentException("Invalid collection budget or observer plans.");

        var candidates = new List<(ObserverPlan Observer, CollectionRequest Request,
            PublishedArtifact Artifact, LogicalInstant SentAt, LogicalInstant ReceivedAt, int Ordinal)>();
        var counts = new Dictionary<(string, string), int>();
        var duplicates = new HashSet<(string, string, string)>();
        int ordinal = 0;
        foreach (var disclosure in plan.Disclosure)
        {
            if (disclosure is null || disclosure.DeliveryDelayMilliseconds < 0)
                throw new ArgumentException("Invalid disclosure delay.");
            var observer = plan.Observers.SingleOrDefault(o => o.Observer == disclosure.Observer)
                ?? throw new ArgumentException("Unknown observer.");
            var request = observer.Requests.SingleOrDefault(r => r.Id == disclosure.RequestId)
                ?? throw new ArgumentException("Unknown request.");
            var artifact = archive.Artifacts.SingleOrDefault(a => a.Id == disclosure.ArtifactId)
                ?? throw new ArgumentException("Unknown owner artifact.");
            var key = (observer.Observer, request.Id);
            counts[key] = counts.GetValueOrDefault(key) + 1;
            if (counts[key] > plan.Budget.MaximumArtifactsPerRequest ||
                !duplicates.Add((observer.Observer, request.Id, artifact.Id)))
                throw new ArgumentException("Disclosure exceeds the shared response budget.");
            if (request.Channel == CollectionChannel.Direct && request.Target != artifact.Producer)
                throw new ArgumentException("A direct endpoint cannot return another producer's artifact.");
            if (request.Channel == CollectionChannel.CheckpointExchange &&
                (!plan.Observers.Any(o => o.Observer == request.Target) ||
                 artifact.Kind != ArtifactKind.Checkpoint))
                throw new ArgumentException("Exchange supports collected checkpoints from named observers.");

            long sent = Math.Max(request.SentAt.Milliseconds, artifact.AvailableAt.Milliseconds);
            long received = checked(sent + disclosure.DeliveryDelayMilliseconds);
            candidates.Add((observer, request, artifact, new(sent), new(received), ordinal++));
        }

        var deliveries = ImmutableArray.CreateBuilder<ArtifactDelivery>();
        // Total ordering is part of the replay protocol. An exchange may forward only
        // evidence already received by its sender at its scheduled send time.
        foreach (var candidate in candidates.OrderBy(c => c.ReceivedAt.Milliseconds).ThenBy(c => c.Ordinal))
        {
            if (candidate.ReceivedAt.Milliseconds > candidate.Observer.Cutoff.Milliseconds ||
                candidate.ReceivedAt.Milliseconds > candidate.Request.TimeoutAt.Milliseconds)
                continue;
            if (candidate.Request.Channel == CollectionChannel.CheckpointExchange &&
                !deliveries.Any(d => d.Observer == candidate.Request.Target &&
                    d.ArtifactId == candidate.Artifact.Id && d.ReceivedAt.Milliseconds <= candidate.SentAt.Milliseconds))
                continue;
            int receipt = deliveries.Count(d => d.Observer == candidate.Observer.Observer);
            deliveries.Add(new(candidate.Observer.Observer, candidate.Request.Id, candidate.Artifact.Id,
                candidate.SentAt, candidate.ReceivedAt, receipt));
        }
        return deliveries.ToImmutable();
    }

    private ObserverPlan Observer(string observer) => _plan.Observers.Single(o => o.Observer == observer);
    private AuditContext Context(string observer)
    {
        var plan = Observer(observer);
        return new(_queries, plan.Cutoff, _plan.Budget.MaximumRequests, _plan.Budget.MaximumArtifactsPerRequest);
    }

    private ImmutableArray<Acquired<T>> Acquired<T>(string observer, ArtifactKind kind) =>
        Deliveries.Where(d => d.Observer == observer)
            .Select(d => (Delivery: d, Artifact: _archive.Artifacts.Single(a => a.Id == d.ArtifactId)))
            .Where(pair => pair.Artifact.Kind == kind)
            .Select(pair => new Acquired<T>(pair.Delivery.ReceiptNumber, pair.Delivery.ReceivedAt,
                new SignedEvidence<T>(pair.Artifact.Json))).ToImmutableArray();

    public B0Evidence ProjectB0(string observer)
    {
        var plan = Observer(observer);
        var records = Deliveries.Where(d => d.Observer == observer)
            .Select(d => (Delivery: d, Artifact: _archive.Artifacts.Single(a => a.Id == d.ArtifactId)))
            .Where(pair => pair.Artifact.Kind == ArtifactKind.Snapshot && pair.Artifact.Producer == plan.OwnGateway)
            .Where(pair => new SignedEvidence<LogSnapshot>(pair.Artifact.Json).TryRead(out _))
            .GroupBy(pair => new SignedEvidence<LogSnapshot>(pair.Artifact.Json).Read().LogId)
            .Select(group => group.OrderBy(pair => pair.Delivery.ReceiptNumber).Last())
            .SelectMany(pair => pair.Artifact.LocalRecords).ToImmutableArray();
        return new(Context(observer), records);
    }

    public B1Evidence ProjectB1(string observer)
    {
        var heads = Acquired<SignedTreeHead>(observer, ArtifactKind.Checkpoint);
        var snapshots = Acquired<LogSnapshot>(observer, ArtifactKind.Snapshot);
        // A collected full snapshot also legitimately conveys its signed head.
        heads = heads.AddRange(snapshots.Where(s => s.Artifact.TryRead(out var snapshot) && snapshot.Checkpoint is not null).Select(s =>
            new Acquired<SignedTreeHead>(s.ReceiptNumber, s.ReceivedAt,
                SignedEvidence<SignedTreeHead>.Capture(s.Artifact.Read().Checkpoint))));
        return new(Context(observer), heads, snapshots);
    }

    public B1WitnessEvidence ProjectB1Witness(string observer) =>
        new(ProjectB1(observer), Acquired<WitnessAttestation>(observer, ArtifactKind.Witness));
    public B2Evidence ProjectB2(string observer) =>
        new(ProjectB1Witness(observer),
            Acquired<SignedLoggingObligation>(observer, ArtifactKind.Obligation),
            Acquired<SignedLoggingObligation>(observer, ArtifactKind.TargetAck),
            Acquired<SignedAuditChallenge>(observer, ArtifactKind.Challenge));
}
