using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.Baselines;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class ReceiptBaselineTests
{
    private static readonly VerificationClock Clock = new(1_800_000_000, 1_800_001_000);

    private static (ExperimentOwner Owner, B1ReceiptEvidence Evidence, TrustedPublicKeyBootstrap Trust)
        Create(SimulationConfiguration? workload = null, AcquisitionPlan? plan = null, ProtocolSchedule? schedule = null)
    {
        var owner = ExperimentOwner.Create(workload ?? EvidenceAcquisitionTests.Workload(),
            schedule ?? EvidenceAcquisitionTests.Schedule(), plan ?? EvidenceAcquisitionTests.Plan(), new(300_000));
        return (owner, owner.Acquisition.ProjectB1Receipt("reviewer"),
            new TrustedPublicKeyBootstrap(owner.ExportTrustedPublicKeys()));
    }

    private static Prediction Omission(B1ReceiptEvidence evidence, TrustedPublicKeyBootstrap trust) =>
        new B1ReceiptClassifier(trust, Clock).Classify(evidence)
            .First(p => p.QueryId == evidence.Authenticated.Context.Targets
                .First(q => q.Kind == ClaimKind.OmissionPolicyViolation).QueryId);

    [Fact]
    public void AcceptedReceiptAndCompliantSnapshotEstablishPresence()
    {
        var fixture = Create();
        Assert.Equal(AssessmentOutcome.NoFinding, Omission(fixture.Evidence, fixture.Trust).Outcome);
        Assert.Contains("acceptance verified", Omission(fixture.Evidence, fixture.Trust).Reason);
        Assert.DoesNotContain(typeof(B1ReceiptEvidence).GetProperties(), p => p.Name is "Witnesses" or "Challenges");
    }

    [Fact]
    public void AckAndPostDeadlineSnapshotDoNotInventIndependentOmissionProof()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)),
            schedule: EvidenceAcquisitionTests.Schedule(witnessed: false, challenge: false),
            plan: EvidenceAcquisitionTests.Plan(witnessed: false, challenge: false));
        var prediction = Omission(fixture.Evidence, fixture.Trust);
        Assert.Equal(AssessmentOutcome.Inconclusive, prediction.Outcome);
        Assert.Contains("acceptance verified", prediction.Reason);
        Assert.Null(prediction.VerificationVerdict);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingOrDelayedAckLeavesOmittedEntryInconclusive(bool delayed)
    {
        var plan = EvidenceAcquisitionTests.Plan(ack: delayed);
        if (delayed)
            plan = plan with { Disclosure = plan.Disclosure.Select(d => d.ArtifactId == "obligation/ack"
                ? d with { DeliveryDelayMilliseconds = 100_000 } : d).ToImmutableArray() };
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)), plan);
        Assert.Empty(fixture.Evidence.TargetAcks);
        Assert.Equal(AssessmentOutcome.Inconclusive, Omission(fixture.Evidence, fixture.Trust).Outcome);
    }

    [Fact]
    public void ForgedAckIsInvalidWithoutChangingOwnerTruth()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)));
        var ack = fixture.Evidence.TargetAcks[0].Artifact.Read();
        var corrupt = fixture.Owner.WithDeliveredArtifactBodies(
            ImmutableDictionary<string, string>.Empty.Add("obligation/ack",
                JsonSerializer.Serialize(ack with { TargetAckSignature = new byte[64] })));
        var prediction = Omission(corrupt.Acquisition.ProjectB1Receipt("reviewer"), fixture.Trust);
        Assert.Equal(AssessmentOutcome.InvalidEvidence, prediction.Outcome);
        var score = corrupt.Score("reviewer", BaselineId.B1R, [prediction], new(1_000_000));
        Assert.Equal(1, score.Omission.ActualPositives);
        Assert.Equal(0, score.Omission.EvidenceSupportedDetections);
        Assert.Equal(1, score.Omission.InvalidEvidence);
    }

    [Fact]
    public void ReceiptSignerRoleAndCorridorScopesAreEnforced()
    {
        var fixture = Create();
        foreach (bool wrongRole in new[] { false, true })
        {
            var keys = fixture.Owner.ExportTrustedPublicKeys();
            int issuer = Enumerable.Range(0, keys.Length).Single(i => keys[i].Id == "B");
            keys = keys.SetItem(issuer, wrongRole ? keys[issuer] with { Role = SignerRole.Witness } :
                keys[issuer] with { Corridors = ["unauthorized-corridor"] });
            Assert.Equal(AssessmentOutcome.InvalidEvidence,
                Omission(fixture.Evidence, new TrustedPublicKeyBootstrap(keys)).Outcome);
        }
    }

    [Theory]
    [InlineData(false, AssessmentOutcome.Inconclusive)]
    [InlineData(true, AssessmentOutcome.Accusation)]
    public void ReceiptBaselineDetectsOnlyAcquiredAuthenticatedForks(bool disclose, AssessmentOutcome expected)
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)),
            EvidenceAcquisitionTests.Plan(fork: disclose));
        var query = fixture.Evidence.Authenticated.Context.Targets.Single(q => q.Kind == ClaimKind.SignedLogEquivocation);
        var prediction = new B1ReceiptClassifier(fixture.Trust, Clock).Classify(fixture.Evidence)
            .Single(p => p.QueryId == query.QueryId);
        Assert.Equal(expected, prediction.Outcome);
        var score = fixture.Owner.Score("reviewer", BaselineId.B1R, [prediction], new(1_000_000));
        Assert.Equal(disclose ? 1 : 0, score.Equivocation.EvidenceSupportedDetections);
    }

    [Theory]
    [InlineData(FaultKind.Partition)]
    [InlineData(FaultKind.Duplicate)]
    [InlineData(FaultKind.Retry)]
    public void LateWritesDuplicatesAndRetriesDoNotBecomeReceiptOnlyPolicyProof(FaultKind kind)
    {
        ImmutableArray<FaultRule> rules = kind switch
        {
            FaultKind.Partition => [new(FaultKind.Partition, Start: 100_000, End: 160_000)],
            FaultKind.Duplicate => [new(FaultKind.Duplicate, 0, ExtraCopies: 2)],
            _ => [new(FaultKind.Crash, Start: 100_000, End: 110_000), new(FaultKind.Retry, 0, Delay: 60_000)]
        };
        var fixture = Create(EvidenceAcquisitionTests.Workload(rules.ToArray()));
        Assert.Equal(AssessmentOutcome.NoFinding, Omission(fixture.Evidence, fixture.Trust).Outcome);
    }

    [Fact]
    public void DelayedSnapshotRemainsInconclusiveForAnOmittedAcceptedEvent()
    {
        var schedule = EvidenceAcquisitionTests.Schedule(witnessed: false);
        schedule = schedule with { Checkpoints = schedule.Checkpoints.Select(c => c with { CreatedAt = new(205_000) }).ToImmutableArray() };
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)),
            EvidenceAcquisitionTests.Plan(witnessed: false), schedule);
        Assert.Equal(AssessmentOutcome.Inconclusive, Omission(fixture.Evidence, fixture.Trust).Outcome);
    }
}
