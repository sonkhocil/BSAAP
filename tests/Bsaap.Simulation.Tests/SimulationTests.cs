using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class SimulationTests
{
    internal static SimulationConfiguration Configuration(params FaultRule[] faults) =>
        new(2027, "synthetic-preparation", 4, ["SYN-A-B", "SYN-C-D"], 100_000, 40_000, 10_000, [.. faults]);

    [Fact]
    public void ReplayPreservesWorkloadAndWriteOrder()
    {
        var configuration = Configuration(new(FaultKind.Delay, 0, Delay: 150_000),
            new(FaultKind.Duplicate, 2, ExtraCopies: 2), new(FaultKind.Equivocation, 5),
            new(FaultKind.Omission, 7), new(FaultKind.Partition, Start: 130_000, End: 170_000));
        Assert.Equal(JsonSerializer.Serialize(SimulationRun.Create(configuration).Records),
            JsonSerializer.Serialize(SimulationRun.Create(configuration).Records));
        Assert.Equal(SyntheticGenerator.Generate(configuration).ToArray(),
            SyntheticGenerator.Generate(configuration with { Faults = [] }).ToArray());
        Assert.NotEqual(SyntheticGenerator.Generate(configuration)[0].TransactionId,
            SyntheticGenerator.Generate(configuration with { Seed = 2028 })[0].TransactionId);
    }

    [Fact]
    public void PinnedIdsAndConsistentSyntheticWorkloadRemainCompatible()
    {
        var events = SyntheticGenerator.Generate(Configuration());
        Assert.Equal(Guid.Parse("940c9696-eb7e-21e4-ca27-4dfb47cb0ffa"), events[0].TransactionId.Value);
        Assert.Equal(Guid.Parse("468cfeca-f11f-98a9-e25a-d1c05cf9150f"), events[0].EventId.Value);
        Assert.Equal(16, events.Length);
        Assert.Equal(16, events.Select(e => e.EventId).Distinct().Count());
        foreach (var transaction in events.GroupBy(e => e.TransactionId))
        {
            Assert.Equal(4, transaction.Count());
            Assert.Single(transaction.Select(e => e.AmountMinorUnits).Distinct());
            Assert.Single(transaction.Select(e => e.Corridor).Distinct());
            Assert.All(transaction, e =>
            {
                Assert.NotEqual(e.TransactionId.Value, e.EventId.Value);
                Assert.Equal("XTS", e.Currency);
                Assert.StartsWith("SYNTHETIC-", e.Debtor);
                Assert.StartsWith("SYNTHETIC-", e.Creditor);
            });
            Assert.Equal(SyntheticEventType.Pacs008Dispatch, transaction.First().Type);
            Assert.Contains(transaction.Last().Type,
                new[] { SyntheticEventType.Pacs002Accc, SyntheticEventType.Pacs002Rjct });
        }
        foreach (var corridor in events.GroupBy(e => e.Corridor))
            Assert.Equal(Enumerable.Range(1, corridor.Count()).Select(n => (ulong)n),
                corridor.Select(e => e.Sequence.Value));
    }

    [Fact]
    public void LeafIndicesFollowDeliveryAndRetriesKeepIdentity()
    {
        var run = SimulationRun.Create(Configuration(new(FaultKind.Omission, 0),
            new(FaultKind.Delay, 1, Delay: 200_000), new(FaultKind.Retry, 2, Delay: 15_000, ExtraCopies: 2)));
        foreach (var log in run.Records.GroupBy(r => (r.Gateway, r.LogId, r.ViewId)))
        {
            Assert.Equal(Enumerable.Range(0, log.Count()).Select(n => (ulong)n), log.Select(r => r.LeafIndex.Value));
            Assert.Equal(log.OrderBy(r => r.LoggedAt).ToArray(), log.ToArray());
        }
        var eventId = run.Pristine[2].EventId;
        var retries = run.Records.Where(r =>
            r.Gateway == "A" && r.ViewId == "primary" && r.Event.EventId == eventId).ToArray();
        Assert.Equal(new[] { 0, 1, 2 }, retries.Select(r => r.Attempt));
        Assert.Single(retries.Select(r => r.Event.TransactionId).Distinct());
        Assert.Single(retries.Select(r => r.Event.Sequence).Distinct());
        Assert.Equal(new long[] { 120_000, 135_000, 150_000 }, retries.Select(r => r.LoggedAt));
    }

    [Fact]
    public void CrashRetryAndPartitionSemanticsRemainDeterministic()
    {
        var run = SimulationRun.Create(Configuration(new(FaultKind.Crash, Start: 100_000, End: 110_000),
            new(FaultKind.Retry, 0, Delay: 15_000),
            new(FaultKind.Partition, Start: 110_000, End: 120_000)));
        var original = run.Pristine[0];
        var delivered = Assert.Single(run.Records.Where(r =>
            r.Gateway == "A" && r.ViewId == "primary" && r.Event.EventId == original.EventId));
        Assert.Equal(120_000, delivered.LoggedAt);
        Assert.Equal(1, delivered.Attempt);
        Assert.Equal(original, delivered.Event);
    }

    [Fact]
    public void InvalidSchedulesAndTimeConversionsAreRejected()
    {
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Omission, -1))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Delay, 0, Delay: -1))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Crash, Start: 100, End: 100))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration() with { Corridors = ["same", "same"] }));
        Assert.Throws<OverflowException>(() => SimulationRun.Create(Configuration() with { StartTime = long.MaxValue }));
        var clock = new UnixTimeMapping(1_800_000_000);
        Assert.Equal(1_800_000_100, clock.ToUnixSeconds(new(100_000)));
        Assert.Throws<ArgumentException>(() => clock.ToUnixSeconds(new(100_001)));
        Assert.NotEqual(typeof(LogicalInstant), typeof(ElapsedDuration));
    }
}
