using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// The owner retains the complete write ledger. Classifier inputs are created
// only through EvidenceAcquisition projections, never from this internal trace.
public sealed class SimulationRun
{
    internal ImmutableArray<SyntheticEvent> Pristine { get; }
    internal ImmutableArray<ObservedRecord> Records { get; }

    private SimulationRun(ImmutableArray<ObservedRecord> records, ImmutableArray<SyntheticEvent> pristine)
    {
        Records = records;
        Pristine = pristine;
    }

    internal ImmutableArray<PhysicalEventTruth> PhysicalTruth(LogicalInstant horizon)
    {
        if (horizon.Milliseconds < 0)
            throw new ArgumentOutOfRangeException(nameof(horizon));
        return Pristine.SelectMany(original => new[] { "primary", "alternate" }.Select(view =>
            new PhysicalEventTruth(original, "A", original.Corridor + "/A", view, horizon,
                Records.Where(record => record.Gateway == "A" && record.ViewId == view &&
                    record.Event.EventId == original.EventId && record.LoggedAt <= horizon.Milliseconds)
                    .Select(record => new LogicalInstant(record.LoggedAt)).ToImmutableArray(),
                Records.Where(record => record.Gateway == "A" && record.ViewId == view &&
                    record.Event == original && record.LoggedAt <= horizon.Milliseconds)
                    .Select(record => new LogicalInstant(record.LoggedAt)).ToImmutableArray()))).ToImmutableArray();
    }

    internal ImmutableArray<PolicyTruth> PolicyTruth(
        ProtocolSchedule schedule, LogicalInstant horizon)
    {
        if (schedule.Obligations.Any(o => o.Deadline.Milliseconds > horizon.Milliseconds))
            throw new ArgumentException("Policy evaluation requires a horizon at or after every deadline.");
        var physical = PhysicalTruth(horizon);
        return schedule.Obligations.SelectMany(obligation =>
        {
            var original = Pristine[obligation.EventOrdinal];
            bool accepted = obligation.IssuerGateway == "A"
                ? obligation.PublishedAt.Milliseconds <= obligation.Deadline.Milliseconds
                : obligation.TargetAckAt is { } ack && ack.Milliseconds <= obligation.Deadline.Milliseconds;
            return physical.Where(fact => fact.Original.EventId == original.EventId).Select(fact =>
                new PolicyTruth(original.EventId, fact.InternalView, accepted, obligation.Deadline,
                    fact.Writes.Any(time => time.Milliseconds <= obligation.Deadline.Milliseconds),
                    !fact.PhysicallyAbsent,
                    fact.MatchingWrites.Any(time => time.Milliseconds <= obligation.Deadline.Milliseconds),
                    "A", original.Corridor + "/A", 1));
        }).ToImmutableArray();
    }

    public static SimulationRun Create(SimulationConfiguration configuration)
    {
        var pristine = SyntheticGenerator.Generate(configuration);
        var records = new List<ObservedRecord>();
        for (int ordinal = 0; ordinal < pristine.Length; ordinal++)
        {
            var paymentEvent = pristine[ordinal];
            AddRecord(records, paymentEvent, "B", "primary", paymentEvent.OccurredAt, 0);
            foreach (string view in new[] { "primary", "alternate" })
            {
                var rules = configuration.Faults.Where(rule => rule.EventOrdinal == ordinal &&
                    (rule.Corridor is null || rule.Corridor == paymentEvent.Corridor) &&
                    (rule.InternalView is null || rule.InternalView == view)).ToArray();
                bool omitted = rules.Any(rule => rule.Kind == FaultKind.Omission);
                bool equivocated = view == "alternate" && rules.Any(rule => rule.Kind == FaultKind.Equivocation);
                long loggedAt = paymentEvent.OccurredAt;
                foreach (var delay in rules.Where(rule => rule.Kind == FaultKind.Delay))
                    loggedAt = checked(loggedAt + delay.Delay);
                var attempts = new List<(long Time, int Attempt)> { (loggedAt, 0) };
                int attemptNumber = 0;
                foreach (var rule in rules.Where(rule => rule.Kind is FaultKind.Duplicate or FaultKind.Retry))
                {
                    for (int copy = 1; copy <= rule.ExtraCopies; copy++)
                    {
                        long time = rule.Kind == FaultKind.Retry ? checked(loggedAt + copy * rule.Delay) : loggedAt;
                        attempts.Add((time, ++attemptNumber));
                    }
                }

                var publishedEvent = equivocated
                    ? paymentEvent with { AmountMinorUnits = checked(paymentEvent.AmountMinorUnits + 1) }
                    : paymentEvent;
                foreach (var attempt in attempts)
                {
                    long time = RecoverFromPartitions(attempt.Time, paymentEvent.Corridor, view, configuration.Faults);
                    bool crashed = configuration.Faults.Any(rule => rule.Kind == FaultKind.Crash &&
                        InWindow(rule, time, paymentEvent.Corridor, view));
                    if (omitted || crashed) continue;
                    AddRecord(records, publishedEvent, "A", view, time, attempt.Attempt);
                }
            }
        }

        // Stable ordering resolves simultaneous writes by insertion order. Each log view
        // assigns independent, contiguous indices only after all delivery faults.
        var ordered = records.OrderBy(record => record.LoggedAt).ToArray();
        var nextIndex = new Dictionary<(string, string, string), ulong>();
        var evidence = ImmutableArray.CreateBuilder<ObservedRecord>();
        foreach (var record in ordered)
        {
            var scope = (record.Gateway, record.LogId, record.ViewId);
            ulong index = nextIndex.GetValueOrDefault(scope);
            evidence.Add(record with { LeafIndex = new LogLeafIndex(index) });
            nextIndex[scope] = checked(index + 1);
        }
        return new(evidence.ToImmutable(), pristine);
    }

    private static bool InWindow(FaultRule rule, long time, string corridor, string view) =>
        (rule.Corridor is null || rule.Corridor == corridor) &&
        (rule.InternalView is null || rule.InternalView == view) && time >= rule.Start && time < rule.End;

    private static long RecoverFromPartitions(long time, string corridor, string view, ImmutableArray<FaultRule> rules)
    {
        // Advancing strictly to an interval end also handles overlapping windows.
        bool advanced;
        do
        {
            advanced = false;
            foreach (var rule in rules.Where(rule => rule.Kind == FaultKind.Partition))
            {
                if (!InWindow(rule, time, corridor, view))
                    continue;
                time = rule.End;
                advanced = true;
            }
        } while (advanced);
        return time;
    }

    private static void AddRecord(List<ObservedRecord> records, SyntheticEvent paymentEvent,
        string gateway, string view, long time, int attempt) =>
        records.Add(new(gateway, paymentEvent.Corridor + "/" + gateway, view, default, paymentEvent, time, attempt));
}
