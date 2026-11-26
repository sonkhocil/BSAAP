using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class SimulationTests
{
    private static SimulationConfiguration Configuration(params FaultRule[] faults) =>
        new(2027, "synthetic-preparation", 4, ["SYN-A-B", "SYN-C-D"], 100, 40, 10, [.. faults]);

    [Fact]
    public void ReplayIsIdenticalIncludingFaultsAndDeliveryOrder()
    {
        var configuration = Configuration(new FaultRule(FaultKind.Delay, 0, Delay: 150),
            new FaultRule(FaultKind.Duplicate, 2, ExtraCopies: 2), new FaultRule(FaultKind.Equivocation, 5),
            new FaultRule(FaultKind.Omission, 7), new FaultRule(FaultKind.Partition, Start: 130, End: 170));
        Assert.Equal(JsonSerializer.Serialize(SimulationRun.Create(configuration).Evidence),
            JsonSerializer.Serialize(SimulationRun.Create(configuration).Evidence));
        Assert.Equal(SyntheticGenerator.Generate(configuration).ToArray(),
            SyntheticGenerator.Generate(configuration with { Faults = [] }).ToArray());
        Assert.NotEqual(SyntheticGenerator.Generate(configuration)[0].TransactionId,
            SyntheticGenerator.Generate(configuration with { Seed = 2028 })[0].TransactionId);
    }

    [Fact]
    public void VersionOneIdentifierDerivationMatchesPinnedReferenceValues()
    {
        var first = SyntheticGenerator.Generate(Configuration())[0];
        Assert.Equal(Guid.Parse("940c9696-eb7e-21e4-ca27-4dfb47cb0ffa"), first.TransactionId.Value);
        Assert.Equal(Guid.Parse("468cfeca-f11f-98a9-e25a-d1c05cf9150f"), first.EventId.Value);
    }

    [Fact]
    public void EvidenceCopiesCannotChangeThePrivateLedger()
    {
        var run = SimulationRun.Create(Configuration());
        var record = run.Evidence.Records[0];
        var replaced = run.Evidence with
        {
            Records = run.Evidence.Records.SetItem(0,
                record with { Event = record.Event with { AmountMinorUnits = 999_999 } })
        };
        Assert.NotEqual(replaced.Records[0], run.Evidence.Records[0]);
        Assert.Equal(new Evaluation(16, 1, 0, 15, 0),
            run.Evaluate([new(record.Event.EventId, Classification.NoFinding)]));
    }

    [Fact]
    public void TransactionsHaveConsistentPaymentFieldsAndIndependentIdentifiers()
    {
        var events = SyntheticGenerator.Generate(Configuration());
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
                Assert.InRange(e.AmountMinorUnits, 1, 100_000);
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
    public void LeafIndicesFollowDeliveryWithinEachLogViewAndRetriesKeepEventIdentity()
    {
        var run = SimulationRun.Create(Configuration(new FaultRule(FaultKind.Omission, 0),
            new FaultRule(FaultKind.Delay, 1, Delay: 200), new FaultRule(FaultKind.Retry, 2, Delay: 15, ExtraCopies: 2)));
        foreach (var log in run.Evidence.Records.GroupBy(r => (r.Gateway, r.LogId, r.ViewId)))
        {
            Assert.Equal(Enumerable.Range(0, log.Count()).Select(n => (ulong)n),
                log.Select(r => r.LeafIndex.Value));
            Assert.Equal(log.OrderBy(r => r.LoggedAt).ToArray(), log.ToArray());
        }
        var eventId = SyntheticGenerator.Generate(Configuration())[2].EventId;
        var retries = run.Evidence.Records.Where(r =>
            r.Gateway == "A" && r.ViewId == "primary" && r.Event.EventId == eventId).ToArray();
        Assert.Equal(new[] { 0, 1, 2 }, retries.Select(r => r.Attempt));
        Assert.Single(retries.Select(r => r.Event.TransactionId).Distinct());
        Assert.Single(retries.Select(r => r.Event.Sequence).Distinct());
        Assert.Equal(new long[] { 120, 135, 150 }, retries.Select(r => r.LoggedAt));
    }

    [Theory]
    [InlineData(FaultKind.Omission, Classification.Omission)]
    [InlineData(FaultKind.Equivocation, Classification.Equivocation)]
    [InlineData(FaultKind.Duplicate, Classification.NoFinding)]
    [InlineData(FaultKind.Delay, Classification.NoFinding)]
    [InlineData(FaultKind.Retry, Classification.NoFinding)]
    public void ScheduledEventFaultsHaveExplicitSemantics(FaultKind kind, Classification expected)
    {
        var configuration = Configuration(new FaultRule(kind, 0, Delay: kind is FaultKind.Delay or FaultKind.Retry ? 5 : 0));
        var original = SyntheticGenerator.Generate(configuration)[0];
        var run = SimulationRun.Create(configuration);
        var primary = run.Evidence.Records.Where(r =>
            r.Gateway == "A" && r.ViewId == "primary" && r.Event.EventId == original.EventId).ToArray();
        Assert.Equal(kind == FaultKind.Omission ? 0 : kind is FaultKind.Duplicate or FaultKind.Retry ? 2 : 1,
            primary.Length);
        if (kind == FaultKind.Delay)
            Assert.Equal(105, primary[0].LoggedAt);
        var alternate = run.Evidence.Records.FirstOrDefault(r =>
            r.Gateway == "A" && r.ViewId == "alternate" && r.Event.EventId == original.EventId);
        if (kind == FaultKind.Equivocation)
            Assert.NotEqual(primary[0].Event.AmountMinorUnits, alternate!.Event.AmountMinorUnits);
        Assert.Equal(new Evaluation(16, 1, 0, 15, 0),
            run.Evaluate([new(original.EventId, expected)]));
    }

    [Fact]
    public void CrashesDropWritesAndPartitionsBufferUntilRecoveryWithExclusiveEnd()
    {
        var configuration = Configuration(new FaultRule(FaultKind.Crash, Corridor: "SYN-A-B", Start: 100, End: 110),
            new FaultRule(FaultKind.Partition, Corridor: "SYN-A-B", Start: 110, End: 125),
            new FaultRule(FaultKind.Partition, Corridor: "SYN-A-B", Start: 120, End: 130));
        var run = SimulationRun.Create(configuration);
        var pristine = SyntheticGenerator.Generate(configuration);
        Assert.DoesNotContain(run.Evidence.Records, r => r.Gateway == "A" && r.Event.EventId == pristine[0].EventId);
        Assert.Equal(130, run.Evidence.Records.First(r =>
            r.Gateway == "A" && r.Event.EventId == pristine[1].EventId).LoggedAt);
        Assert.Equal(130, run.Evidence.Records.First(r =>
            r.Gateway == "A" && r.Event.EventId == pristine[3].EventId).LoggedAt);
        Assert.Equal(new Evaluation(16, 1, 0, 15, 0),
            run.Evaluate([new(pristine[0].EventId, Classification.Omission)]));
    }

    [Fact]
    public void RetryAfterCrashRecoveryKeepsTheOriginalEvent()
    {
        var configuration = Configuration(new FaultRule(FaultKind.Crash, Start: 100, End: 110),
            new FaultRule(FaultKind.Retry, 0, Delay: 15));
        var run = SimulationRun.Create(configuration);
        var original = SyntheticGenerator.Generate(configuration)[0];
        var delivered = Assert.Single(run.Evidence.Records.Where(r =>
            r.Gateway == "A" && r.ViewId == "primary" && r.Event.EventId == original.EventId));
        Assert.Equal(115, delivered.LoggedAt);
        Assert.Equal(1, delivered.Attempt);
        Assert.Equal(original, delivered.Event);
        Assert.Equal(new Evaluation(16, 1, 0, 15, 0),
            run.Evaluate([new(original.EventId, Classification.NoFinding)]));
    }

    [Fact]
    public void ClassifierContractsHaveNoReferenceToTruthHarnessOrConfiguration()
    {
        var assembly = typeof(IForensicBaseline).Assembly;
        Assert.DoesNotContain(assembly.GetReferencedAssemblies(), a => a.Name == "Bsaap.Simulation");
        Assert.Equal(new[] { typeof(EvidenceTrace) },
            typeof(IForensicBaseline).GetMethod("Classify")!.GetParameters().Select(p => p.ParameterType));
        Assert.DoesNotContain(typeof(SimulationRun).GetProperties(), p =>
            p.PropertyType.Name.Contains("Dictionary", StringComparison.Ordinal));
        var run = SimulationRun.Create(Configuration(new FaultRule(FaultKind.Omission, 0)));
        var classifier = new EvidenceOnlyClassifier();
        var predictions = classifier.Classify(run.Evidence);
        Assert.Equal(new Evaluation(16, 15, 1, 0, 0), run.Evaluate(predictions));
        string input = JsonSerializer.Serialize(run.Evidence);
        Assert.DoesNotContain("Faults", input);
        Assert.DoesNotContain("Seed", input);
        Assert.DoesNotContain("GroundTruth", input);
    }

    private sealed class EvidenceOnlyClassifier : IB0Baseline
    {
        public BaselineId Id => BaselineId.B0;
        public ImmutableArray<Prediction> Classify(EvidenceTrace evidence) =>
            evidence.Records.Select(r => r.Event.EventId).Distinct()
                .Select(id => new Prediction(id, Classification.NoFinding)).ToImmutableArray();
    }

    [Fact]
    public void EvaluationRejectsDuplicatePredictionsAndCountsUnknownEvents()
    {
        var run = SimulationRun.Create(Configuration());
        var id = run.Evidence.Records[0].Event.EventId;
        Assert.Throws<ArgumentException>(() =>
            run.Evaluate([new(id, Classification.NoFinding), new(id, Classification.Omission)]));
        Assert.Equal(new Evaluation(16, 0, 0, 16, 1),
            run.Evaluate([new(new EventId(Guid.Empty), Classification.NoFinding)]));
    }

    [Fact]
    public void ManifestRoundTripsForReplayAndRecordsSourceRuntimeAndConfiguration()
    {
        var configuration = Configuration(new FaultRule(FaultKind.Delay, 0, Delay: 10));
        var runtime = new RuntimeDescription(".NET 9 test", "synthetic-platform", "X64");
        var manifest = ExperimentManifest.Create(configuration, ExperimentManifest.FrozenGate2, runtime);
        var replay = JsonSerializer.Deserialize<ExperimentManifest>(manifest.ToJson())!;
        Assert.Equal(manifest.ToJson(), replay.ToJson());
        Assert.Equal(manifest.ConfigurationSha256,
            ExperimentManifest.Create(replay.Configuration, replay.SourceCommitSha, runtime).ConfigurationSha256);
        Assert.Equal(JsonSerializer.Serialize(SimulationRun.Create(configuration).Evidence),
            JsonSerializer.Serialize(SimulationRun.Create(replay.Configuration).Evidence));
        Assert.Equal(configuration.Seed, replay.Seed);
        Assert.Equal(configuration.Scenario, replay.Scenario);
        Assert.Equal(runtime, replay.Runtime);
        Assert.Equal(ExperimentManifest.FrozenGate2, replay.SourceCommitSha);
        Assert.NotEqual(manifest.ConfigurationSha256, ExperimentManifest.Create(
            configuration with { Seed = 0 }, ExperimentManifest.FrozenGate2, runtime).ConfigurationSha256);
        Assert.Throws<ArgumentException>(() => ExperimentManifest.Create(configuration, "unknown"));
    }

    [Fact]
    public void InvalidSchedulesAndOverflowAreRejected()
    {
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Omission, -1))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Delay, 0, Delay: -1))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Crash, Start: 100, End: 100))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration(new FaultRule(FaultKind.Duplicate, 0, ExtraCopies: 0))));
        Assert.Throws<ArgumentException>(() => SimulationRun.Create(Configuration() with { Corridors = ["same", "same"] }));
        Assert.Throws<OverflowException>(() => SimulationRun.Create(Configuration() with { StartTime = long.MaxValue }));
    }
}
