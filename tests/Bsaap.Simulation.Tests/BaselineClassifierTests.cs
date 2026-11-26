using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.Baselines;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class BaselineClassifierTests
{
    private static readonly VerificationClock Clock = new(1_800_000_000, 1_800_001_000);
    private sealed record Fixture(ProtocolArchive Trust, EvidenceAcquisition Acquisition, ExperimentOwner Owner)
    {
        internal TrustedPublicKeyBootstrap Bootstrap() => new(Trust.ExportTrustedPublicKeys());
        internal ImmutableArray<Prediction>[] Classify() =>
        [
            new B0Classifier().Classify(Acquisition.ProjectB0("reviewer")),
            new B1Classifier(Bootstrap(), Clock).Classify(Acquisition.ProjectB1("reviewer")),
            new B1WitnessClassifier(Bootstrap(), Clock).Classify(Acquisition.ProjectB1Witness("reviewer")),
            new B2Classifier(Bootstrap(), Clock).Classify(Acquisition.ProjectB2("reviewer"))
        ];
        internal AuditQuery Omission => Acquisition.ProjectB1("reviewer").Context.Targets
            .First(q => q.Kind == ClaimKind.OmissionPolicyViolation);
        internal AuditQuery Equivocation => Acquisition.ProjectB1("reviewer").Context.Targets
            .Single(q => q.Kind == ClaimKind.SignedLogEquivocation);
    }

    private static Fixture Create(SimulationConfiguration? workload = null,
        ProtocolSchedule? schedule = null, AcquisitionPlan? plan = null,
        Func<ProtocolArchive, ProtocolArchive>? corrupt = null)
    {
        var run = SimulationRun.Create(workload ?? EvidenceAcquisitionTests.Workload());
        schedule ??= EvidenceAcquisitionTests.Schedule();
        var trust = ProtocolArchive.Create(run, schedule);
        var acquisition = new EvidenceAcquisition(run, corrupt?.Invoke(trust) ?? trust,
            plan ?? EvidenceAcquisitionTests.Plan());
        return new(trust, acquisition, new ExperimentOwner(run, schedule, trust, acquisition, new(300_000)));
    }

    [Fact]
    public void AllBaselinesObserveCompliantEventWithoutClaimingTimeliness()
    {
        var fixture = Create();
        foreach (var results in fixture.Classify())
        {
            Assert.Equal(AssessmentOutcome.NoFinding, results.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
            Assert.Equal(AssessmentOutcome.Inconclusive, results.Single(p => p.QueryId == fixture.Equivocation.QueryId).Outcome);
        }
        var b2 = fixture.Classify()[3].Single(p => p.QueryId == fixture.Omission.QueryId);
        Assert.Equal(AuditVerdict.Compliant, b2.VerificationVerdict);
        Assert.Contains("timeliness remains unproven", b2.Reason);
    }

    [Fact]
    public void OnlyCompleteGate2EvidenceSupportsOmissionAccusation()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)));
        var results = fixture.Classify();
        Assert.All(results.Take(3), predictions => Assert.Equal(AssessmentOutcome.Inconclusive,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
        Assert.Equal(AssessmentOutcome.Accusation, results[3].Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
        Assert.Equal(AuditVerdict.ProvenLoggingPolicyViolation,
            results[3].Single(p => p.QueryId == fixture.Omission.QueryId).VerificationVerdict);
        var score = fixture.Owner.Score("reviewer", BaselineId.B2, results[3], new(1_000_000));
        Assert.Equal(1, score.Omission.EvidenceSupportedDetections);
        Assert.Equal(0, score.Omission.FalseAccusations);
        Assert.Equal(0, score.Omission.UnsupportedAccusations);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingAckPreventsB2PolicyAccusationEvenWithWitness(bool targetAccepted)
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)),
            EvidenceAcquisitionTests.Schedule(ack: targetAccepted), EvidenceAcquisitionTests.Plan(ack: false));
        var results = fixture.Classify();
        Assert.All(results, predictions => Assert.Equal(AssessmentOutcome.Inconclusive,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
        Assert.DoesNotContain(results.SelectMany(r => r), p => p.Outcome == AssessmentOutcome.Accusation);
    }

    [Fact]
    public void HiddenForkCannotBeAccusedByAnyBaseline()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)));
        Assert.All(fixture.Classify(), results => Assert.Equal(AssessmentOutcome.Inconclusive,
            results.Single(p => p.QueryId == fixture.Equivocation.QueryId).Outcome));
        Assert.DoesNotContain(fixture.Classify().SelectMany(r => r), p => p.Outcome == AssessmentOutcome.Accusation);
    }

    [Fact]
    public void SignedBaselinesDetectDisclosedForkWithoutWitnessOrAuditor()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)),
            EvidenceAcquisitionTests.Schedule(witnessed: false, challenge: false),
            EvidenceAcquisitionTests.Plan(witnessed: false, challenge: false, fork: true));
        var results = fixture.Classify();
        Assert.Equal(AssessmentOutcome.Inconclusive, results[0].Single(p => p.QueryId == fixture.Equivocation.QueryId).Outcome);
        for (int index = 1; index < results.Length; index++)
        {
            Assert.Equal(AssessmentOutcome.Accusation, results[index].Single(p => p.QueryId == fixture.Equivocation.QueryId).Outcome);
            var report = fixture.Owner.Score("reviewer", (BaselineId)index, results[index], new(1_000_000));
            Assert.Equal(1, report.Equivocation.EvidenceSupportedDetections);
            Assert.Equal(0, report.Equivocation.UnsupportedAccusations);
        }
    }

    [Fact]
    public void ForgedCheckpointIsInvalidAndCannotProveEquivocation()
    {
        var fixture = Create(corrupt: archive =>
        {
            var artifact = archive.Artifacts.Single(a => a.Id == "head");
            var head = new SignedEvidence<SignedTreeHead>(artifact.Json).Read();
            return archive.ReplaceArtifact("head", JsonSerializer.Serialize(head with { Signature = new byte[64] }));
        });
        var results = fixture.Classify();
        Assert.Equal(AssessmentOutcome.NoFinding, results[0].Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
        Assert.All(results.Skip(1), predictions => Assert.Equal(AssessmentOutcome.InvalidEvidence,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
        Assert.DoesNotContain(results.SelectMany(r => r), p => p.Outcome == AssessmentOutcome.Accusation);
    }

    [Fact]
    public void InvalidWitnessAffectsWitnessedBaselinesWithoutChangingB1()
    {
        var fixture = Create(corrupt: archive =>
        {
            var artifact = archive.Artifacts.Single(a => a.Id == "witness");
            var witness = new SignedEvidence<WitnessAttestation>(artifact.Json).Read();
            return archive.ReplaceArtifact("witness", JsonSerializer.Serialize(witness with { Signature = new byte[64] }));
        });
        var results = fixture.Classify();
        Assert.All(results.Take(2), predictions => Assert.Equal(AssessmentOutcome.NoFinding,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
        Assert.All(results.Skip(2), predictions => Assert.Equal(AssessmentOutcome.InvalidEvidence,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
    }

    [Fact]
    public void MissingEvidenceIsInconclusiveAcrossAllBaselines()
    {
        var fixture = Create(plan: EvidenceAcquisitionTests.Plan() with { Disclosure = [] });
        Assert.All(fixture.Classify().SelectMany(r => r), p => Assert.Equal(AssessmentOutcome.Inconclusive, p.Outcome));
    }

    [Fact]
    public void LateRetryPreservesPolicyTruthWhileAllBaselinesObservePresence()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(
            new(FaultKind.Crash, Start: 100_000, End: 110_000), new(FaultKind.Retry, 0, Delay: 60_000)));
        var results = fixture.Classify();
        Assert.All(results, predictions => Assert.Equal(AssessmentOutcome.NoFinding,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
        var report = fixture.Owner.Score("reviewer", BaselineId.B2, results[3], new(1_000_000));
        Assert.Equal(1, report.Omission.ActualPositives);
        Assert.Equal(0, report.Omission.EvidenceSupportedDetections);
    }

    [Fact]
    public void AlwaysAccusingCannotIncreaseSupportedDetectionsThroughUnsupportedClaims()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)));
        var baseline = fixture.Classify()[3];
        var alwaysAccuse = fixture.Acquisition.ProjectB2("reviewer").Witnessed.Bilateral.Context.Targets
            .Select(query => new Prediction(query.QueryId, AssessmentOutcome.Accusation)).ToImmutableArray();
        var honest = fixture.Owner.Score("reviewer", BaselineId.B2, baseline, new(1_000_000));
        var spam = fixture.Owner.Score("reviewer", BaselineId.B2, alwaysAccuse, new(1_000_000));
        Assert.Equal(honest.Omission.EvidenceSupportedDetections, spam.Omission.EvidenceSupportedDetections);
        Assert.Equal(1.0, honest.Omission.EvidenceSupportedPrecision);
        Assert.True(spam.Omission.EvidenceSupportedPrecision < honest.Omission.EvidenceSupportedPrecision);
        Assert.Equal(3, spam.Omission.FalseAccusations);
        Assert.Equal(3, spam.Omission.UnsupportedAccusations);
        Assert.Equal(1, spam.Equivocation.FalseAccusations);

        var hidden = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var claims = hidden.Acquisition.ProjectB1("reviewer").Context.Targets.Select(query =>
            new Prediction(query.QueryId, AssessmentOutcome.Accusation)).ToImmutableArray();
        var hiddenScore = hidden.Owner.Score("reviewer", BaselineId.B1, claims, new(1_000_000));
        Assert.Equal(1, hiddenScore.Equivocation.RawFactuallyCorrectAccusations);
        Assert.Equal(0, hiddenScore.Equivocation.EvidenceSupportedDetections);
        Assert.Equal(1, hiddenScore.Equivocation.UnsupportedAccusations);
        Assert.Equal(0.0, hiddenScore.Equivocation.EvidenceSupportedPrecision);
    }

    [Fact]
    public void BootstrapIsExplicitImmutableAndIndependentOfCollectedKeys()
    {
        var fixture = Create();
        var bootstrap = fixture.Bootstrap();
        Assert.Throws<ArgumentException>(() => new TrustedPublicKeyBootstrap([]));
        Assert.Throws<ArgumentNullException>(() => new B1Classifier(null!, Clock));
        var changed = fixture.Trust.ExportTrustedPublicKeys().SetItem(0,
            fixture.Trust.ExportTrustedPublicKeys()[0] with { Role = SignerRole.Auditor });
        var unauthorized = new B1Classifier(new TrustedPublicKeyBootstrap(changed), Clock)
            .Classify(fixture.Acquisition.ProjectB1("reviewer"));
        Assert.Equal(AssessmentOutcome.InvalidEvidence, unauthorized.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
        Assert.Equal(SignerRole.Gateway, bootstrap.Signers[0].Role);
        Assert.DoesNotContain(typeof(B1Classifier).GetProperties(), p => p.Name.Contains("Registry"));
        Assert.DoesNotContain(typeof(B1Classifier).Assembly.GetReferencedAssemblies(), a => a.Name == "Bsaap.Simulation");
        Assert.DoesNotContain("Seed", JsonSerializer.Serialize(bootstrap));
        Assert.DoesNotContain("PrivateKey", JsonSerializer.Serialize(bootstrap));
    }

    [Fact]
    public void DeterministicClassifierReplayUsesOnlyGivenEvidenceAndBootstrap()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)));
        var before = fixture.Trust.Serialize();
        var first = fixture.Classify();
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(fixture.Classify()));
        Assert.Equal(before, fixture.Trust.Serialize());
        var reconstructed = new TrustedPublicKeyBootstrap(fixture.Bootstrap().Signers);
        Assert.Equal(first[3].ToArray(), new B2Classifier(reconstructed, Clock)
            .Classify(fixture.Acquisition.ProjectB2("reviewer")).ToArray());
    }

    [Fact]
    public void UnsignedPayloadConflictIsAnObservationWithoutProof()
    {
        var fixture = Create();
        var evidence = fixture.Acquisition.ProjectB0("reviewer");
        var record = evidence.Records[0];
        evidence = evidence with { Records = evidence.Records.Add(record with
            { Event = record.Event with { AmountMinorUnits = record.Event.AmountMinorUnits + 1 } }) };
        var prediction = new B0Classifier().Classify(evidence).Single(p => p.QueryId == fixture.Omission.QueryId);
        Assert.Equal(AssessmentOutcome.Inconclusive, prediction.Outcome);
        Assert.Contains("conflict", prediction.Reason);
        Assert.Null(prediction.VerificationVerdict);
    }
    [Fact]
    public void AuthenticUnboundWitnessDoesNotBecomeAnEquivocationProofOrAnInvalidSignature()
    {
        var schedule = EvidenceAcquisitionTests.Schedule();
        schedule = schedule with
        {
            Witnesses = [schedule.Witnesses[0] with { CheckpointId = "fork" }]
        };
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)), schedule);
        var results = fixture.Classify();
        Assert.Equal(AssessmentOutcome.NoFinding, results[2].Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
        Assert.Equal(AssessmentOutcome.Inconclusive, results[3].Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
        Assert.All(results, predictions => Assert.Equal(AssessmentOutcome.Inconclusive,
            predictions.Single(p => p.QueryId == fixture.Equivocation.QueryId).Outcome));
    }

    [Fact]
    public void MalformedSignedArtifactsDoNotCrashClassifiersOrCreateAccusations()
    {
        var fixture = Create(corrupt: archive => archive.ReplaceArtifact("head", "{"));
        Assert.All(fixture.Classify().Skip(1), predictions => Assert.Equal(AssessmentOutcome.InvalidEvidence,
            predictions.Single(p => p.QueryId == fixture.Omission.QueryId).Outcome));
        var input = fixture.Acquisition.ProjectB2("reviewer") with { Obligations = default, TargetAcks = default };
        var result = new B2Classifier(fixture.Bootstrap(), Clock).Classify(input);
        Assert.DoesNotContain(result, p => p.Outcome == AssessmentOutcome.Accusation);
    }

    [Fact]
    public void MissingWitnessFallsBackToB1CapabilitiesWithoutInventingAnObligation()
    {
        var fixture = Create(plan: EvidenceAcquisitionTests.Plan(witnessed: false));
        var results = fixture.Classify();
        Assert.Equal(AssessmentOutcome.NoFinding, results[2].Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
        Assert.Equal(AssessmentOutcome.Inconclusive, results[3].Single(p => p.QueryId == fixture.Omission.QueryId).Outcome);
    }

    [Fact]
    public void ClassifierSuppliedProofLabelDoesNotChangeOwnerAdmissibility()
    {
        var fixture = Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var claims = ImmutableArray.Create(new Prediction(fixture.Equivocation.QueryId,
            AssessmentOutcome.Accusation, "Claimed proof", AuditVerdict.EquivocationDetected));
        var report = fixture.Owner.Score("reviewer", BaselineId.B1, claims, new(1_000_000));
        Assert.Equal(1, report.Equivocation.RawFactuallyCorrectAccusations);
        Assert.Equal(0, report.Equivocation.EvidenceSupportedDetections);
        Assert.Equal(1, report.Equivocation.UnsupportedAccusations);
    }

}
