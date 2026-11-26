using System.Collections.Immutable;

namespace Bsaap.Simulation.Contracts;

public readonly record struct TransactionId(Guid Value);
public readonly record struct EventId(Guid Value);
public readonly record struct CorridorSequence(ulong Value);
public readonly record struct LogLeafIndex(ulong Value);

public enum SyntheticEventType { Pacs008Dispatch, TransportAck, Pacs002Actc, Pacs002Accc, Pacs002Rjct }

// All amounts, parties and messages are synthetic. Time is logical milliseconds.
public sealed record SyntheticEvent(
    TransactionId TransactionId, EventId EventId, string Corridor,
    CorridorSequence Sequence, SyntheticEventType Type, long OccurredAt,
    long AmountMinorUnits, string Currency, string Debtor, string Creditor);

// Logical time never represents measured execution duration.
public readonly record struct LogicalInstant(long Milliseconds) : IComparable<LogicalInstant>
{
    public int CompareTo(LogicalInstant other) => Milliseconds.CompareTo(other.Milliseconds);
}
public readonly record struct ElapsedDuration(TimeSpan Value);

public sealed record PublicLogRecord(
    string Gateway, string LogId, LogLeafIndex LeafIndex, SyntheticEvent Event,
    LogicalInstant LoggedAt, int Attempt);

// JSON stores signed artifacts without exposing mutable Gate 2 byte arrays.
// Every Read returns a new object graph. No validity labels are supplied.
public sealed record SignedEvidence<T>(string Json)
{
    public T Read() => System.Text.Json.JsonSerializer.Deserialize<T>(Json)
        ?? throw new InvalidOperationException("Missing artifact.");
    public bool TryRead(out T artifact)
    {
        try
        {
            artifact = Read();
            return true;
        }
        catch (System.Text.Json.JsonException)
        {
            artifact = default!;
            return false;
        }
        catch (InvalidOperationException)
        {
            artifact = default!;
            return false;
        }
    }

    public static SignedEvidence<T> Capture(T artifact) =>
        new(System.Text.Json.JsonSerializer.Serialize(artifact));
}
public sealed record Acquired<T>(int ReceiptNumber, LogicalInstant ReceivedAt, SignedEvidence<T> Artifact);

public enum ClaimKind { OmissionPolicyViolation, SignedLogEquivocation }
public sealed record AuditQuery(
    string QueryId, ClaimKind Kind, EventId? EventId, TransactionId? TransactionId,
    string Gateway, string LogId, string Corridor, CorridorSequence? Sequence,
    SyntheticEventType? EventType = null, string? PayloadSha256 = null, ulong EpochId = 1);

public enum BaselineId { B0, B1, B1W, B2 }
public enum AssessmentOutcome { NoFinding, Accusation, Inconclusive, InvalidEvidence }
public sealed record Prediction(string QueryId, AssessmentOutcome Outcome);

// All projections share the same public query stream and acquisition budget.
public sealed record AuditContext(
    ImmutableArray<AuditQuery> Targets, LogicalInstant CollectionCutoff,
    int MaximumRequests, int MaximumArtifactsPerRequest);

public sealed record B0Evidence(AuditContext Context, ImmutableArray<PublicLogRecord> Records);
public sealed record B1Evidence(
    AuditContext Context,
    ImmutableArray<Acquired<Bsaap.ForensicLog.Contracts.SignedTreeHead>> Checkpoints,
    ImmutableArray<Acquired<Bsaap.ForensicLog.Contracts.LogSnapshot>> Snapshots);
public sealed record B1WitnessEvidence(
    B1Evidence Bilateral,
    ImmutableArray<Acquired<Bsaap.ForensicLog.Contracts.WitnessAttestation>> Witnesses);
public sealed record B2Evidence(
    B1WitnessEvidence Witnessed,
    ImmutableArray<Acquired<Bsaap.ForensicLog.Contracts.SignedLoggingObligation>> Obligations,
    ImmutableArray<Acquired<Bsaap.ForensicLog.Contracts.SignedLoggingObligation>> TargetAcks,
    ImmutableArray<Acquired<Bsaap.ForensicLog.Contracts.SignedAuditChallenge>> Challenges);

public interface IB0Baseline
{
    ImmutableArray<Prediction> Classify(B0Evidence evidence);
}
public interface IB1Baseline
{
    ImmutableArray<Prediction> Classify(B1Evidence evidence);
}
public interface IB1WitnessBaseline
{
    ImmutableArray<Prediction> Classify(B1WitnessEvidence evidence);
}
public interface IB2Baseline
{
    ImmutableArray<Prediction> Classify(B2Evidence evidence);
}
