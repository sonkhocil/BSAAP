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

public sealed record ObservedRecord(
    string Gateway, string LogId, string ViewId, LogLeafIndex LeafIndex,
    SyntheticEvent Event, long LoggedAt, int Attempt);

// This is the entire classifier input. Fault schedules, seed and truth are excluded.
public sealed record EvidenceTrace(ImmutableArray<ObservedRecord> Records);

public enum BaselineId { B0, B1, B1W, B2 }
public enum Classification { NoFinding, Omission, Equivocation, Inconclusive }
public sealed record Prediction(EventId EventId, Classification Classification);

public interface IForensicBaseline
{
    BaselineId Id { get; }
    ImmutableArray<Prediction> Classify(EvidenceTrace evidence);
}

public interface IB0Baseline : IForensicBaseline { }
public interface IB1Baseline : IForensicBaseline { }
public interface IB1WitnessBaseline : IForensicBaseline { }
public interface IB2Baseline : IForensicBaseline { }
