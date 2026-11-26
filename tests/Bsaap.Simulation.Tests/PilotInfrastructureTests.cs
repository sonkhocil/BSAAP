using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.ControlledPilot;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class PilotInfrastructureTests
{
    [Fact]
    public void CompressedSavedInputsPreserveProofsAndRejectArtifactTampering()
    {
        string directory = Path.Combine(Path.GetTempPath(), "bsaap-replay-" + Guid.NewGuid().ToString("N"));
        try
        {
            var definition = PilotScenarios.Create(2027, 2, PilotCondition.ForgedAck);
            var owner = ExperimentOwner.Create(definition.Workload, definition.Protocol,
                definition.Acquisition, definition.TruthHorizon);
            var archive = ProtocolArchive.Restore(owner.CaptureArchive());
            var manifest = EvidenceManifest.Create(definition.Workload, definition.Protocol,
                definition.Acquisition, archive, ExperimentManifest.FrozenGate2);
            var overrides = DeliveredCorruption.Create(PilotCondition.ForgedAck, archive);
            var input = new PilotReplayInput(definition, manifest, archive.Serialize(),
                overrides, PilotExecution.HashOverrides(overrides));
            string path = PilotStorage.Save(directory, 1, input);
            var loaded = PilotStorage.Load(path);
            Assert.Equal(input.ProductionArchive, loaded.ProductionArchive);
            Assert.Equal(input.OverridesSha256, loaded.OverridesSha256);
            var saved = JsonSerializer.Deserialize<SavedPilotCase>(File.ReadAllText(path), PilotStorage.JsonOptions())!;
            string archived = Path.Combine(directory, saved.ArchiveRelativePath);
            var bytes = File.ReadAllBytes(archived);
            bytes[^1] ^= 0xff;
            File.WriteAllBytes(archived, bytes);
            Assert.Throws<ArgumentException>(() => PilotStorage.Load(path));
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    [Fact]
    public void AuditSampleIsDeclaredAndIndependentOfFaultsAndKeepsFullLog()
    {
        var definition = PilotScenarios.Create(2027, 25, PilotCondition.Clean);
        var owner = ExperimentOwner.Create(definition.Workload, definition.Protocol,
            definition.Acquisition, definition.TruthHorizon);
        var projection = owner.Acquisition.ProjectB1("reviewer");
        Assert.Equal(3, projection.Context.Targets.Length);
        Assert.Equal(100UL, projection.Snapshots.Select(s => s.Artifact.Read())
            .First(s => s.GatewayId == "A").Checkpoint.TreeSize);
        var invalid = definition.Acquisition with { AuditedEventOrdinals = [0, 0] };
        Assert.Throws<ArgumentException>(() => ExperimentOwner.Create(definition.Workload, definition.Protocol,
            invalid, definition.TruthHorizon));
        invalid = definition.Acquisition with { AuditedEventOrdinals = [100] };
        Assert.Throws<ArgumentException>(() => ExperimentOwner.Create(definition.Workload, definition.Protocol,
            invalid, definition.TruthHorizon));
    }

    [Fact]
    public void InvalidDenominatorsAndOutcomeTotalsAreRejected()
    {
        var valid = new DetectionScore(1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1);
        PilotExecution.ValidateScore(new(valid, valid));
        Assert.Throws<InvalidOperationException>(() => PilotExecution.ValidateScore(new(valid with { ActualPositives = -1 }, valid)));
        Assert.Throws<InvalidOperationException>(() => PilotExecution.ValidateScore(new(valid with { EvidenceCoveredPositives = 2 }, valid)));
        Assert.Throws<InvalidOperationException>(() => PilotExecution.ValidateScore(new(valid with { Missing = 1 }, valid)));
    }

    [Fact]
    public void OwnerEligibilityCountsAreIndependentOfSubmittedAccusations()
    {
        var definition = PilotScenarios.Create(2027, 2, PilotCondition.Omission);
        var owner = ExperimentOwner.Create(definition.Workload, definition.Protocol,
            definition.Acquisition, definition.TruthHorizon);
        var targets = owner.Acquisition.ProjectB1("reviewer").Context.Targets;
        var accuse = targets.Select(t => new Prediction(t.QueryId, AssessmentOutcome.Accusation)).ToImmutableArray();
        var abstain = targets.Select(t => new Prediction(t.QueryId, AssessmentOutcome.Inconclusive)).ToImmutableArray();
        var first = owner.Assess("reviewer", BaselineId.B2, accuse, definition.VerificationTime);
        var second = owner.Assess("reviewer", BaselineId.B2, abstain, definition.VerificationTime);
        Assert.Equal(first.Availability, second.Availability);
        Assert.Equal(1, first.Availability.AdmissibleOmissionCases);
        Assert.Equal(0, owner.Assess("reviewer", BaselineId.B1R, accuse,
            definition.VerificationTime).Availability.AdmissibleOmissionCases);
    }
}
