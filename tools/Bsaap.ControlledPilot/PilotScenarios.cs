using System.Collections.Immutable;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;

namespace Bsaap.ControlledPilot;

public enum PilotCondition
{
    Clean, Omission, MissingAck, HiddenFork, DisclosedFork,
    WitnessAttestationOnly, WitnessDiscovery, WitnessDiscoveryWithoutAttestation,
    DivergentDeadlineViews, DelayedAck, WitnessAbsence, ForgedCheckpoint, ForgedAck,
    InvalidWitness, TransportPartition, Duplicates, LateRetry, DelayedCheckpoint
}

public sealed record PilotDefinition(
    SimulationConfiguration Workload, ProtocolSchedule Protocol, AcquisitionPlan Acquisition,
    LogicalInstant TruthHorizon, LogicalInstant VerificationTime, PilotCondition Condition = PilotCondition.Clean);

public static class PilotScenarios
{
    public static PilotDefinition Create(ulong seed, int transactions, PilotCondition condition)
    {
        if (!Enum.IsDefined(condition) || transactions < 1) throw new ArgumentException("Invalid pilot case.");
        bool forkFamily = condition is PilotCondition.HiddenFork or PilotCondition.DisclosedFork or
            PilotCondition.WitnessAttestationOnly or PilotCondition.WitnessDiscovery or
            PilotCondition.WitnessDiscoveryWithoutAttestation;
        ImmutableArray<FaultRule> faults = condition switch
        {
            PilotCondition.Omission or PilotCondition.MissingAck or PilotCondition.DelayedAck or PilotCondition.DelayedCheckpoint => [new(FaultKind.Omission, 0)],
            PilotCondition.DivergentDeadlineViews => [new(FaultKind.Delay, 0, Delay: 60_000, InternalView: "alternate")],
            PilotCondition.TransportPartition => [new(FaultKind.Partition, Start: 100_000, End: 160_000)],
            PilotCondition.Duplicates => [new(FaultKind.Duplicate, 0, ExtraCopies: 2)],
            PilotCondition.LateRetry => [new(FaultKind.Crash, Start: 100_000, End: 110_000), new(FaultKind.Retry, 0, Delay: 60_000)],
            _ when forkFamily => [new(FaultKind.Equivocation, 0)],
            _ => []
        };
        var workload = new SimulationConfiguration(seed, "gate3d-controlled-pilot", transactions,
            ["SYN-A-B"], 100_000, 40_000, 10_000, faults);
        workload.Validate();
        long lastEvent = checked(100_000 + (transactions - 1L) * 40_000 + 30_000);
        long challenge = checked(Math.Max(lastEvent, 150_000) + 20_000);
        long checkpoint = challenge + 10_000;
        long observation = checkpoint + 10_000;
        long retrieval = observation + 10_000;
        long cutoff = retrieval + 20_000;
        long publication = condition == PilotCondition.DelayedCheckpoint ? cutoff + 20_000 : checkpoint;
        long witnessObservation = publication + 10_000;
        long collectionCutoff = condition == PilotCondition.DelayedCheckpoint ? witnessObservation + 20_000 : cutoff;
        var protocol = new ProtocolSchedule(new(1_800_000_000),
            [new("obligation", 0, "B", new(90_000), new(150_000), new(95_000), new(95_000))],
            [new("challenge", "obligation", new(challenge), new(cutoff + 10_000))],
            [new("head", "A", "SYN-A-B", "primary", new(publication), "challenge"),
             new("fork", "A", "SYN-A-B", "alternate", new(publication), "challenge"),
             new("peer", "B", "SYN-A-B", "primary", new(publication))],
            [new("witness", forkFamily ? "fork" : "head", new(witnessObservation), new(witnessObservation),
                RetainCheckpoint: forkFamily, RetainedUntil: forkFamily ? new(cutoff + 10_000) : null,
                CheckpointAvailableAt: forkFamily ? new(observation) : null)]);
        // The request budget and five scheduled requests are identical in every
        // condition. Disclosure changes model a response or its absence.
        var requests = ImmutableArray.Create(
            new CollectionRequest("a", "A", CollectionChannel.Direct, new(checkpoint), new(collectionCutoff)),
            new CollectionRequest("b", "B", CollectionChannel.Direct, new(checkpoint), new(collectionCutoff)),
            new CollectionRequest("w", "W", CollectionChannel.Direct, new(observation), new(collectionCutoff)),
            new CollectionRequest("aud", "AUDITOR", CollectionChannel.Direct, new(challenge), new(collectionCutoff)),
            new CollectionRequest("retained", "W", CollectionChannel.WitnessCheckpointRetrieval,
                new(retrieval), new(collectionCutoff)));
        ImmutableArray<DisclosureRule> disclosure = [
            new("reviewer", "a", "head"), new("reviewer", "a", "head/snapshot"),
            new("reviewer", "b", "peer"), new("reviewer", "b", "peer/snapshot"),
            new("reviewer", "b", "obligation"), new("reviewer", "aud", "challenge")];
        if (condition != PilotCondition.MissingAck)
            disclosure = disclosure.Add(new("reviewer", "a", "obligation/ack",
                condition == PilotCondition.DelayedAck ? collectionCutoff : 0));
        bool attestation = !forkFamily || condition is PilotCondition.WitnessAttestationOnly or PilotCondition.WitnessDiscovery;
        disclosure = disclosure.Add(new("reviewer", "w", "witness", attestation && condition != PilotCondition.WitnessAbsence ? 0 : collectionCutoff));
        if (condition == PilotCondition.DisclosedFork)
            disclosure = disclosure.Add(new("reviewer", "a", "fork"));
        if (condition is PilotCondition.WitnessDiscovery or PilotCondition.WitnessDiscoveryWithoutAttestation)
            disclosure = disclosure.Add(new("reviewer", "retained", "fork"));
        var acquisition = new AcquisitionPlan(new(5, 6),
            [new("reviewer", "A", new(collectionCutoff), requests)], disclosure, [0, 1]);
        return new(workload, protocol, acquisition, new(collectionCutoff + 10_000),
            new(collectionCutoff + 1_000_000), condition);
    }
}
