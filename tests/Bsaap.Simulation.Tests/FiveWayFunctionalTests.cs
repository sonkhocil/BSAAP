using System.Collections.Immutable;
using Bsaap.Baselines;
using Bsaap.ControlledPilot;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class FiveWayFunctionalTests
{
    [Theory]
    [InlineData(PilotCondition.Clean, "NNNNN", "IIIII")]
    [InlineData(PilotCondition.Omission, "IIIIA", "IIIII")]
    [InlineData(PilotCondition.MissingAck, "IIIII", "IIIII")]
    [InlineData(PilotCondition.HiddenFork, "NNNNI", "IIIII")]
    [InlineData(PilotCondition.DisclosedFork, "NIIII", "IAAAA")]
    [InlineData(PilotCondition.WitnessAttestationOnly, "NNNNI", "IIIII")]
    [InlineData(PilotCondition.WitnessDiscovery, "NIIII", "IAAAA")]
    [InlineData(PilotCondition.WitnessDiscoveryWithoutAttestation, "NIIII", "IAAAA")]
    [InlineData(PilotCondition.DivergentDeadlineViews, "NNNNN", "IIIII")]
    [InlineData(PilotCondition.DelayedAck, "IIIII", "IIIII")]
    [InlineData(PilotCondition.WitnessAbsence, "NNNNI", "IIIII")]
    [InlineData(PilotCondition.ForgedCheckpoint, "NXXXX", "IXXXX")]
    [InlineData(PilotCondition.ForgedAck, "NNNXX", "IIIII")]
    [InlineData(PilotCondition.InvalidWitness, "NNXNX", "IIXII")]
    [InlineData(PilotCondition.TransportPartition, "NNNNN", "IIIII")]
    [InlineData(PilotCondition.Duplicates, "NNNNN", "IIIII")]
    [InlineData(PilotCondition.LateRetry, "NNNNN", "IIIII")]
    [InlineData(PilotCondition.DelayedCheckpoint, "IIIII", "IIIII")]
    public void AllFiveConfigurationsRespectTheirAcquiredCapabilities(
        PilotCondition condition, string omissionExpected, string equivocationExpected)
    {
        var definition = PilotScenarios.Create(2027, 2, condition);
        var owner = ExperimentOwner.Create(definition.Workload, definition.Protocol,
            definition.Acquisition, definition.TruthHorizon);
        var archive = ProtocolArchive.Restore(owner.CaptureArchive());
        owner = owner.WithDeliveredArtifactBodies(DeliveredCorruption.Create(condition, archive));
        var trust = new TrustedPublicKeyBootstrap(owner.ExportTrustedPublicKeys());
        var clock = new VerificationClock(definition.Protocol.Clock.EpochSeconds,
            definition.Protocol.Clock.ToUnixSeconds(definition.VerificationTime));
        ImmutableArray<Prediction>[] predictions = [
            new B0Classifier().Classify(owner.Acquisition.ProjectB0("reviewer")),
            new B1Classifier(trust, clock).Classify(owner.Acquisition.ProjectB1("reviewer")),
            new B1WitnessClassifier(trust, clock).Classify(owner.Acquisition.ProjectB1Witness("reviewer")),
            new B1ReceiptClassifier(trust, clock).Classify(owner.Acquisition.ProjectB1Receipt("reviewer")),
            new B2Classifier(trust, clock).Classify(owner.Acquisition.ProjectB2("reviewer"))];
        var queries = owner.Acquisition.ProjectB1("reviewer").Context.Targets;
        string omission = queries.First(q => q.Kind == ClaimKind.OmissionPolicyViolation).QueryId;
        string equivocation = queries.Single(q => q.Kind == ClaimKind.SignedLogEquivocation).QueryId;
        Assert.Equal(omissionExpected, string.Concat(predictions.Select(p => Symbol(p.Single(r => r.QueryId == omission).Outcome))));
        Assert.Equal(equivocationExpected, string.Concat(predictions.Select(p => Symbol(p.Single(r => r.QueryId == equivocation).Outcome))));
        for (int index = 0; index < predictions.Length; index++)
        {
            Assert.Equal(queries.Length, predictions[index].Length);
            var score = owner.Score("reviewer", PilotExecution.Configurations[index], predictions[index], definition.VerificationTime);
            Assert.Equal(0, score.Omission.FalseAccusations + score.Equivocation.FalseAccusations);
            Assert.Equal(0, score.Omission.UnsupportedAccusations + score.Equivocation.UnsupportedAccusations);
        }
        var always = queries.Select(q => new Prediction(q.QueryId, AssessmentOutcome.Accusation)).ToImmutableArray();
        var abstain = queries.Select(q => new Prediction(q.QueryId, AssessmentOutcome.Inconclusive)).ToImmutableArray();
        var control = owner.Score("reviewer", BaselineId.B2, always, definition.VerificationTime);
        var conservative = owner.Score("reviewer", BaselineId.B2, abstain, definition.VerificationTime);
        Assert.Equal(queries.Length, control.Omission.Accusations + control.Equivocation.Accusations);
        Assert.Equal(queries.Length, conservative.Omission.Inconclusive + conservative.Equivocation.Inconclusive);
        Assert.Equal(0, conservative.Omission.Accusations + conservative.Equivocation.Accusations);
    }

    private static char Symbol(AssessmentOutcome outcome) => outcome switch
    {
        AssessmentOutcome.NoFinding => 'N', AssessmentOutcome.Accusation => 'A',
        AssessmentOutcome.InvalidEvidence => 'X', _ => 'I'
    };
}
