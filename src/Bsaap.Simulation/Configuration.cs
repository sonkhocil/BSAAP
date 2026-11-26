using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace Bsaap.Simulation;

public enum FaultKind { Omission, Equivocation, Duplicate, Delay, Retry, Crash, Partition }

// EventOrdinal is zero-based in the pristine generated trace.
// Windows are [Start, End) in logical milliseconds and target corridor gateway A.
public sealed record FaultRule(
    FaultKind Kind, int? EventOrdinal = null, string? Corridor = null,
    long Start = 0, long End = 0, long Delay = 0, int ExtraCopies = 1,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? InternalView = null);

public sealed record SimulationConfiguration(
    ulong Seed, string Scenario, int TransactionCount, ImmutableArray<string> Corridors,
    long StartTime, long TransactionSpacing, long EventSpacing,
    ImmutableArray<FaultRule> Faults)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Scenario) || TransactionCount < 1 ||
            Corridors.IsDefaultOrEmpty || Corridors.Any(string.IsNullOrWhiteSpace) ||
            Corridors.Distinct(StringComparer.Ordinal).Count() != Corridors.Length ||
            StartTime < 0 || EventSpacing < 1 || TransactionSpacing < checked(4 * EventSpacing) ||
            Faults.IsDefault)
            throw new ArgumentException("Invalid synthetic workload configuration.");

        int eventCount = checked(TransactionCount * 4);
        _ = checked(StartTime + (TransactionCount - 1L) * TransactionSpacing + 3 * EventSpacing);
        foreach (var rule in Faults)
        {
            if (rule is null || !Enum.IsDefined(rule.Kind) ||
                (rule.Corridor is not null && !Corridors.Contains(rule.Corridor, StringComparer.Ordinal)) ||
                (rule.InternalView is not null && rule.InternalView is not ("primary" or "alternate")) ||
                (rule.Kind == FaultKind.Equivocation && rule.InternalView == "primary"))
                throw new ArgumentException("Invalid fault scope.");
            if (rule.Kind is FaultKind.Crash or FaultKind.Partition)
            {
                if (rule.EventOrdinal is not null || rule.Start < 0 || rule.End <= rule.Start ||
                    rule.Delay != 0 || rule.ExtraCopies != 1)
                    throw new ArgumentException("Availability faults require a nonempty time window.");
            }
            else if (rule.EventOrdinal is null || rule.EventOrdinal < 0 || rule.EventOrdinal >= eventCount ||
                     rule.Start != 0 || rule.End != 0 ||
                     (rule.Kind is FaultKind.Delay or FaultKind.Retry ? rule.Delay < 1 : rule.Delay != 0) ||
                     (rule.Kind is FaultKind.Duplicate or FaultKind.Retry
                         ? rule.ExtraCopies < 1 || rule.ExtraCopies > 100 : rule.ExtraCopies != 1))
                throw new ArgumentException("Invalid event fault parameters.");
        }
    }
}
