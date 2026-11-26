using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// These records are harness-only. They are absent from the classifier assembly.
internal sealed record ObservedRecord(
    string Gateway, string LogId, string ViewId, LogLeafIndex LeafIndex,
    SyntheticEvent Event, long LoggedAt, int Attempt);
internal sealed record PhysicalEventTruth(
    SyntheticEvent Original, string Gateway, string LogId, string InternalView,
    LogicalInstant Horizon, ImmutableArray<LogicalInstant> Writes, ImmutableArray<LogicalInstant> MatchingWrites)
{
    public bool PhysicallyAbsent => Writes.IsEmpty;
}
internal sealed record PolicyTruth(
    EventId EventId, string InternalView, bool AcceptedByDeadline,
    LogicalInstant Deadline, bool PresentByDeadline, bool PresentAtHorizon, bool CorrectPayloadByDeadline,
    string GatewayId, string LogId, ulong EpochId)
{
    public bool DeadlineMiss => AcceptedByDeadline && !PresentByDeadline;
}
internal sealed record EvidenceEligibility(
    string Observer, BaselineId Baseline, string QueryId, bool AdmissibleEvidence);
internal sealed record ActualTruthFlags(
    string QueryId, ClaimKind Kind, bool ActualOmissionPolicyViolation, bool ActualSignedLogEquivocation);

// Access is granted only to tests of the trusted owner harness.
