using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bsaap.ControlledPilot;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class PilotExecutionTests
{
    [Fact]
    public void EveryConditionUsesPairedPaymentsAndIdenticalDeclaredCollectionBudgets()
    {
        var definitions = Enum.GetValues<PilotCondition>().Select(c => PilotScenarios.Create(2027, 2, c)).ToArray();
        string payments = JsonSerializer.Serialize(SyntheticGenerator.Generate(definitions[0].Workload));
        foreach (var definition in definitions)
        {
            Assert.Equal(payments, JsonSerializer.Serialize(SyntheticGenerator.Generate(definition.Workload)));
            Assert.Equal(new CollectionBudget(5, 6), definition.Acquisition.Budget);
            Assert.Equal(5, definition.Acquisition.Observers[0].Requests.Length);
            Assert.Single(definition.Protocol.Obligations);
            Assert.Equal(0, definition.Protocol.Obligations[0].EventOrdinal);
        }
    }

    [Fact]
    public void WitnessSiblingConditionsShareProductionAndDifferOnlyThroughAcquisition()
    {
        PilotCondition[] family = [PilotCondition.HiddenFork, PilotCondition.DisclosedFork,
            PilotCondition.WitnessAttestationOnly, PilotCondition.WitnessDiscovery,
            PilotCondition.WitnessDiscoveryWithoutAttestation];
        var definitions = family.Select(c => PilotScenarios.Create(2027, 2, c)).ToArray();
        Assert.All(definitions, d =>
        {
            Assert.Equal(JsonSerializer.Serialize(definitions[0].Protocol), JsonSerializer.Serialize(d.Protocol));
            Assert.Equal(JsonSerializer.Serialize(definitions[0].Workload), JsonSerializer.Serialize(d.Workload));
        });
        var run = SimulationRun.Create(definitions[0].Workload);
        var archive = ProtocolArchive.Create(run, definitions[0].Protocol);
        var withAttestation = new EvidenceAcquisition(run, archive, definitions[3].Acquisition);
        var withoutAttestation = new EvidenceAcquisition(run, archive, definitions[4].Acquisition);
        Assert.Equal(withAttestation.ProjectB1("reviewer").Checkpoints.Select(h => h.Artifact.Json),
            withoutAttestation.ProjectB1("reviewer").Checkpoints.Select(h => h.Artifact.Json));
        Assert.Single(withAttestation.ProjectB1Witness("reviewer").Witnesses);
        Assert.Empty(withoutAttestation.ProjectB1Witness("reviewer").Witnesses);
    }

    [Fact]
    public void MeasurementUsesMonotonicElapsedTimeAndScoresOncePerPairedCase()
    {
        var definition = PilotScenarios.Create(2027, 2, PilotCondition.Clean);
        var owner = ExperimentOwner.Create(definition.Workload, definition.Protocol,
            definition.Acquisition, definition.TruthHorizon);
        var archive = ProtocolArchive.Restore(owner.CaptureArchive());
        var manifest = EvidenceManifest.Create(definition.Workload, definition.Protocol,
            definition.Acquisition, archive, ExperimentManifest.FrozenGate2);
        var input = new PilotReplayInput(definition, manifest, archive.Serialize());
        var options = new JsonSerializerOptions();
        options.Converters.Add(new JsonStringEnumConverter());
        var restored = JsonSerializer.Deserialize<PilotReplayInput>(JsonSerializer.Serialize(input, options), options)!;
        var result = PilotExecution.Run(restored, PilotCondition.Clean, 0);
        Assert.True(result.ReplayEquivalent);
        Assert.Equal(5, result.Baselines.Length);
        Assert.Equal(10, result.Baselines.Sum(b => b.Samples.Length));
        foreach (var baseline in result.Baselines)
        {
            Assert.Equal(3, baseline.Predictions.Length);
            Assert.Equal(0, baseline.Score.Omission.ActualPositives);
            Assert.Equal(2, baseline.Score.Omission.ActualNegatives);
            Assert.Equal(1, baseline.Score.Equivocation.ActualNegatives);
            Assert.Equal(2, baseline.Samples.Length);
            Assert.All(baseline.Samples, sample =>
            {
                Assert.True(sample.MonotonicTicks >= 0);
                Assert.Equal(Stopwatch.GetElapsedTime(0, sample.MonotonicTicks), sample.Elapsed.Value);
                Assert.InRange(sample.Order, 0, 4);
            });
        }
        var corrupt = restored with { Definition = restored.Definition with
            { Workload = restored.Definition.Workload with { Seed = 0 } } };
        Assert.Throws<ArgumentException>(() => PilotExecution.Run(corrupt, PilotCondition.Clean, 0));
    }
    [Fact]
    public void PooledRatesUseSummedCountsInsteadOfMeanRunRates()
    {
        var first = new DetectionScore(1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1);
        var second = new DetectionScore(3, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0);
        var pooled = PilotExecution.Pool([new(first, first), new(second, second)]);
        Assert.Equal(4, pooled.Omission.ActualPositives);
        Assert.Equal(0.25, pooled.Omission.UnconditionalDetectionRate);
        Assert.Equal(0.25, pooled.Omission.EvidenceCoverage);
        Assert.Equal(1.0, pooled.Omission.EvidenceConditionalDetectionRate);
    }

}
