using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// Counts are returned to the experiment owner after classification. The classifier
// is never passed this run, its schedule, manifest or the private ground-truth ledger.
public sealed record Evaluation(int Events, int Correct, int Incorrect, int Missing, int Unknown);

public sealed class SimulationRun
{
    private sealed record GroundTruthEvent(SyntheticEvent Original, Classification Expected);
    private readonly ImmutableDictionary<EventId, GroundTruthEvent> _groundTruth;
    public EvidenceTrace Evidence { get; }

    private SimulationRun(EvidenceTrace evidence, ImmutableDictionary<EventId, GroundTruthEvent> groundTruth)
    {
        Evidence = evidence;
        _groundTruth = groundTruth;
    }

    public Evaluation Evaluate(ImmutableArray<Prediction> predictions)
    {
        if (predictions.IsDefault || predictions.Any(p => p is null || !Enum.IsDefined(p.Classification)) ||
            predictions.Select(p => p.EventId).Distinct().Count() != predictions.Length)
            throw new ArgumentException("Predictions must contain unique event IDs and valid classifications.");

        int correct = 0;
        int incorrect = 0;
        int unknown = 0;
        foreach (var prediction in predictions)
        {
            if (!_groundTruth.TryGetValue(prediction.EventId, out var expected))
                unknown++;
            else if (prediction.Classification == expected.Expected)
                correct++;
            else
                incorrect++;
        }
        return new(_groundTruth.Count, correct, incorrect, _groundTruth.Count - correct - incorrect, unknown);
    }

    public static SimulationRun Create(SimulationConfiguration configuration)
    {
        var pristine = SyntheticGenerator.Generate(configuration);
        var records = new List<ObservedRecord>();
        var truth = ImmutableDictionary.CreateBuilder<EventId, GroundTruthEvent>();
        for (int ordinal = 0; ordinal < pristine.Length; ordinal++)
        {
            var paymentEvent = pristine[ordinal];
            var rules = configuration.Faults.Where(rule =>
                rule.EventOrdinal == ordinal &&
                (rule.Corridor is null || rule.Corridor == paymentEvent.Corridor)).ToArray();
            bool omitted = rules.Any(rule => rule.Kind == FaultKind.Omission);
            bool equivocated = rules.Any(rule => rule.Kind == FaultKind.Equivocation);
            long loggedAt = paymentEvent.OccurredAt;
            foreach (var delay in rules.Where(rule => rule.Kind == FaultKind.Delay))
                loggedAt = checked(loggedAt + delay.Delay);
            // Peer evidence survives faults targeting gateway A.
            AddRecord(records, paymentEvent, "B", "primary", paymentEvent.OccurredAt, 0);
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

            var alternate = equivocated
                ? paymentEvent with { AmountMinorUnits = checked(paymentEvent.AmountMinorUnits + 1) }
                : paymentEvent;
            bool delivered = false;
            foreach (var attempt in attempts)
            {
                long time = RecoverFromPartitions(attempt.Time, paymentEvent.Corridor, configuration.Faults);
                bool crashed = configuration.Faults.Any(rule => rule.Kind == FaultKind.Crash &&
                    InWindow(rule, time, paymentEvent.Corridor));
                if (omitted || crashed)
                    continue;
                delivered = true;
                AddRecord(records, paymentEvent, "A", "primary", time, attempt.Attempt);
                AddRecord(records, alternate, "A", "alternate", time, attempt.Attempt);
            }
            truth.Add(paymentEvent.EventId, new(paymentEvent, !delivered ? Classification.Omission :
                equivocated ? Classification.Equivocation : Classification.NoFinding));
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
        return new(new EvidenceTrace(evidence.ToImmutable()), truth.ToImmutable());
    }

    private static bool InWindow(FaultRule rule, long time, string corridor) =>
        (rule.Corridor is null || rule.Corridor == corridor) && time >= rule.Start && time < rule.End;

    private static long RecoverFromPartitions(long time, string corridor, ImmutableArray<FaultRule> rules)
    {
        // Advancing strictly to an interval end also handles overlapping windows.
        bool advanced;
        do
        {
            advanced = false;
            foreach (var rule in rules.Where(rule => rule.Kind == FaultKind.Partition))
            {
                if (!InWindow(rule, time, corridor))
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
