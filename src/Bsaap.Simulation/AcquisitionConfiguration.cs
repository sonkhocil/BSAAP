using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// All objects here belong to the experiment owner, never the classifier input.
public sealed record UnixTimeMapping(long EpochSeconds)
{
    public long ToUnixSeconds(LogicalInstant time)
    {
        if (EpochSeconds < 0 || time.Milliseconds < 0 || time.Milliseconds % 1000 != 0)
            throw new ArgumentException("Signed fixtures require exact second-aligned logical times.");
        return checked(EpochSeconds + time.Milliseconds / 1000);
    }
}

public sealed record ObligationPublication(
    string Id, int EventOrdinal, string IssuerGateway, LogicalInstant PublishedAt,
    LogicalInstant Deadline, LogicalInstant? TargetAckAt = null, LogicalInstant? AckAvailableAt = null);
public sealed record ChallengePublication(
    string Id, string ObligationId, LogicalInstant IssuedAt, LogicalInstant ExpiresAt);
public sealed record CheckpointPublication(
    string Id, string Gateway, string Corridor, string InternalView,
    LogicalInstant CreatedAt, string? ChallengeId = null, LogicalInstant? ClaimedTimestamp = null);
public sealed record WitnessPublication(
    string Id, string CheckpointId, LogicalInstant ObservedAt, LogicalInstant AvailableAt);
public sealed record ProtocolSchedule(
    UnixTimeMapping Clock,
    ImmutableArray<ObligationPublication> Obligations,
    ImmutableArray<ChallengePublication> Challenges,
    ImmutableArray<CheckpointPublication> Checkpoints,
    ImmutableArray<WitnessPublication> Witnesses);

public enum CollectionChannel { Direct, CheckpointExchange }
public sealed record CollectionBudget(int MaximumRequests, int MaximumArtifactsPerRequest);
public sealed record CollectionRequest(
    string Id, string Target, CollectionChannel Channel,
    LogicalInstant SentAt, LogicalInstant TimeoutAt);
public sealed record ObserverPlan(
    string Observer, string OwnGateway, LogicalInstant Cutoff,
    ImmutableArray<CollectionRequest> Requests);
// Artifact IDs and disclosure routing are owner-only. They never enter projections.
public sealed record DisclosureRule(
    string Observer, string RequestId, string ArtifactId, long DeliveryDelayMilliseconds = 0);
public sealed record AcquisitionPlan(
    CollectionBudget Budget, ImmutableArray<ObserverPlan> Observers,
    ImmutableArray<DisclosureRule> Disclosure);

internal enum ArtifactKind { Checkpoint, Snapshot, Obligation, TargetAck, Challenge, Witness }
internal sealed record PublishedArtifact(
    string Id, string Producer, ArtifactKind Kind, LogicalInstant AvailableAt, string Json,
    ImmutableArray<PublicLogRecord> LocalRecords);
internal sealed record ArtifactDelivery(
    string Observer, string RequestId, string ArtifactId,
    LogicalInstant SentAt, LogicalInstant ReceivedAt, int ReceiptNumber);
