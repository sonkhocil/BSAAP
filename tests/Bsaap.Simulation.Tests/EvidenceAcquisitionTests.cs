using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class EvidenceAcquisitionTests
{
    internal static SimulationConfiguration Workload(params FaultRule[] faults) =>
        new(2027, "synthetic-evidence", 1, ["SYN-A-B"], 100_000, 40_000, 10_000, [.. faults]);

    internal static ProtocolSchedule Schedule(bool ack = true, bool witnessed = true,
        long observedAt = 180_000, bool challenge = true) =>
        new(new UnixTimeMapping(1_800_000_000),
            [new("obligation", 0, "B", new(90_000), new(150_000),
                ack ? new LogicalInstant(95_000) : null, ack ? new LogicalInstant(95_000) : null)],
            challenge ? [new("challenge", "obligation", new(160_000), new(200_000))] : [],
            [new("head", "A", "SYN-A-B", "primary", new(170_000), challenge ? "challenge" : null),
             new("fork", "A", "SYN-A-B", "alternate", new(170_000), challenge ? "challenge" : null),
             new("peer", "B", "SYN-A-B", "primary", new(170_000))],
            witnessed ? [new("witness", "head", new(observedAt), new(observedAt))] : []);

    internal static AcquisitionPlan Plan(bool ack = true, bool witnessed = true, bool challenge = true,
        bool fork = false, bool snapshot = true, long cutoff = 210_000)
    {
        var rules = ImmutableArray.CreateBuilder<DisclosureRule>();
        rules.Add(new("reviewer", "b", "obligation"));
        rules.Add(new("reviewer", "b", "peer"));
        rules.Add(new("reviewer", "b", "peer/snapshot"));
        rules.Add(new("reviewer", "a", "head"));
        if (snapshot) rules.Add(new("reviewer", "a", "head/snapshot"));
        if (ack) rules.Add(new("reviewer", "a", "obligation/ack"));
        if (fork) rules.Add(new("reviewer", "a", "fork"));
        if (witnessed) rules.Add(new("reviewer", "w", "witness"));
        if (challenge) rules.Add(new("reviewer", "aud", "challenge"));
        return new(new(4, 6),
            [new("reviewer", "A", new(cutoff),
                [new("a", "A", CollectionChannel.Direct, new(170_000), new(210_000)),
                 new("b", "B", CollectionChannel.Direct, new(160_000), new(210_000)),
                 new("w", "W", CollectionChannel.Direct, new(180_000), new(210_000)),
                 new("aud", "AUDITOR", CollectionChannel.Direct, new(160_000), new(210_000))])],
            rules.ToImmutable());
    }

    private static (SimulationRun Run, ProtocolArchive Archive, EvidenceAcquisition Acquisition, ExperimentOwner Owner)
        Create(SimulationConfiguration workload, ProtocolSchedule? schedule = null, AcquisitionPlan? plan = null)
    {
        schedule ??= Schedule();
        var run = SimulationRun.Create(workload);
        var archive = ProtocolArchive.Create(run, schedule);
        var acquisition = new EvidenceAcquisition(run, archive, plan ?? Plan());
        return (run, archive, acquisition, new ExperimentOwner(run, schedule, archive, acquisition, new(300_000)));
    }

    private static AuditQuery Omission(EvidenceAcquisition acquisition) =>
        acquisition.ProjectB1("reviewer").Context.Targets.First(q => q.Kind == ClaimKind.OmissionPolicyViolation);
    private static AuditQuery Equivocation(EvidenceAcquisition acquisition) =>
        acquisition.ProjectB1("reviewer").Context.Targets.Single(q => q.Kind == ClaimKind.SignedLogEquivocation);

    private static AuditVerdict Verify(B2Evidence evidence, ProtocolArchive trust, long now = 1_800_001_000)
    {
        var obligation = evidence.TargetAcks.IsEmpty ? evidence.Obligations[0].Artifact.Read() :
            evidence.TargetAcks[0].Artifact.Read();
        var snapshot = evidence.Witnessed.Bilateral.Snapshots.Select(s => s.Artifact.Read()).First(s => s.GatewayId == "A");
        return ForensicAuditEngine.AuditLogSnapshot(obligation, evidence.Witnessed.Witnesses[0].Artifact.Read(),
            snapshot, evidence.Witnessed.Bilateral.Checkpoints.Select(h => h.Artifact.Read()).ToArray(),
            trust.CreateRegistry(), now, "A", "SYN-A-B/A", evidence.Challenges[0].Artifact.Read());
    }

    [Fact]
    public void ArchivedSignedOmissionProofIsVerifiedAndScored()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)));
        Assert.Equal(AuditVerdict.ProvenLoggingPolicyViolation, Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
        var query = Omission(fixture.Acquisition);
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(query.QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(1, score.Detections);
        Assert.Equal(1, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.EvidenceConditionalDetections);
        Assert.Equal(0, score.UnsupportedAccusations);
        Assert.Equal(1.0, score.UnconditionalDetectionRate);
    }

    [Fact]
    public void PhysicallyMissingWriteWithoutTargetAcceptanceIsNotAPolicyViolation()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)), Schedule(ack: false), Plan(ack: false));
        Assert.True(fixture.Run.PhysicalTruth(new(300_000)).First().PhysicallyAbsent);
        Assert.False(fixture.Run.PolicyTruth(Schedule(ack: false), new(300_000)).First().DeadlineMiss);
        Assert.Equal(AuditVerdict.UnprovenObligation, Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(Omission(fixture.Acquisition).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(0, score.ActualPositives);
        Assert.Equal(1, score.FalseAccusations);
        Assert.Equal(1, score.UnsupportedAccusations);
    }

    [Fact]
    public void ACreatedAckMayBeUnavailableToTheObserver()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)), plan: Plan(ack: false));
        Assert.Empty(fixture.Acquisition.ProjectB2("reviewer").TargetAcks);
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(Omission(fixture.Acquisition).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(1, score.Detections);
        Assert.Equal(0, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.UnsupportedAccusations);
    }

    [Fact]
    public void SignedAckAloneIsInsufficientOmissionProof()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)), plan: Plan(snapshot: false));
        Assert.Single(fixture.Acquisition.ProjectB2("reviewer").TargetAcks);
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(Omission(fixture.Acquisition).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(0, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.UnsupportedAccusations);
    }

    [Fact]
    public void LateRetryPreservesDeadlineMissWhileGate2CompliantMeansSnapshotPresence()
    {
        var workload = Workload(new(FaultKind.Crash, Start: 100_000, End: 110_000),
            new(FaultKind.Retry, 0, Delay: 60_000));
        var fixture = Create(workload);
        var truth = fixture.Run.PolicyTruth(Schedule(), new(300_000)).First();
        Assert.True(truth.DeadlineMiss);
        Assert.True(truth.PresentAtHorizon);
        Assert.False(truth.PresentByDeadline);
        Assert.False(fixture.Run.PhysicalTruth(new(300_000)).First().PhysicallyAbsent);
        Assert.Equal(AuditVerdict.Compliant, Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(Omission(fixture.Acquisition).QueryId, AssessmentOutcome.NoFinding)], new(1_000_000)).Omission;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(0, score.Detections);
        Assert.Equal(0, score.EvidenceCoveredPositives);
    }

    [Fact]
    public void AlteredPayloadIsNotLabeledAsAPhysicallyMissingWrite()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var physical = fixture.Run.PhysicalTruth(new(300_000)).First(t => t.InternalView == "alternate");
        Assert.False(physical.PhysicallyAbsent);
        Assert.Empty(physical.MatchingWrites);
        var policy = fixture.Run.PolicyTruth(Schedule(), new(300_000)).First(t => t.InternalView == "alternate");
        Assert.False(policy.DeadlineMiss);
        Assert.False(policy.CorrectPayloadByDeadline);
    }

    [Fact]
    public void HiddenForkDoesNotReachAnyProjectionButRemainsActualSignedEquivocation()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var baseline = fixture.Acquisition.ProjectB1("reviewer");
        Assert.False(ForensicAuditEngine.CheckEquivocation(
            baseline.Checkpoints.Select(h => h.Artifact.Read()).ToArray(), fixture.Archive.CreateRegistry()).IsEquivocation);
        var score = fixture.Owner.Score("reviewer", BaselineId.B1,
            [new(Equivocation(fixture.Acquisition).QueryId, AssessmentOutcome.Inconclusive)], new(1_000_000)).Equivocation;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(0, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.Inconclusive);
        Assert.Equal(0, score.Detections);
        var json = JsonSerializer.Serialize(fixture.Acquisition.ProjectB2("reviewer"));
        foreach (string privateName in new[] { "InternalView", "primary", "alternate", "Faults", "Seed", "GroundTruth" })
            Assert.DoesNotContain("\"" + privateName + "\"", json);
    }

    [Fact]
    public void B1MayDetectAcquiredAuthenticatedConflictWithoutWitnessOrChallenge()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Equivocation, 0)),
            Schedule(witnessed: false, challenge: false), Plan(witnessed: false, challenge: false, fork: true));
        var evidence = fixture.Acquisition.ProjectB1("reviewer");
        Assert.True(ForensicAuditEngine.CheckEquivocation(evidence.Checkpoints.Select(h => h.Artifact.Read()).ToArray(),
            fixture.Archive.CreateRegistry()).IsEquivocation);
        var score = fixture.Owner.Score("reviewer", BaselineId.B1,
            [new(Equivocation(fixture.Acquisition).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Equivocation;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(1, score.Detections);
        Assert.Equal(1, score.EvidenceCoveredPositives);
        Assert.Equal(0, score.UnsupportedAccusations);
    }

    [Fact]
    public void TypedProjectionsUseIdenticalQueriesAndBudgetsWithoutForbiddenArtifacts()
    {
        var fixture = Create(Workload());
        var b0 = fixture.Acquisition.ProjectB0("reviewer");
        var b1 = fixture.Acquisition.ProjectB1("reviewer");
        var b1w = fixture.Acquisition.ProjectB1Witness("reviewer");
        var b2 = fixture.Acquisition.ProjectB2("reviewer");
        Assert.Equal(b0.Context, b1.Context);
        Assert.Equal(b1.Context, b1w.Bilateral.Context);
        Assert.Equal(b1.Context, b2.Witnessed.Bilateral.Context);
        Assert.All(b0.Records, r => Assert.Equal("A", r.Gateway));
        Assert.Contains(b1.Snapshots, s => s.Artifact.Read().GatewayId == "B");
        Assert.Single(b1w.Witnesses);
        Assert.Single(b2.Challenges);
        Assert.Single(b2.TargetAcks);
        Assert.DoesNotContain(typeof(IB0Baseline).Assembly.GetReferencedAssemblies(), a => a.Name == "Bsaap.Simulation");
        Assert.Equal(typeof(B0Evidence), typeof(IB0Baseline).GetMethod("Classify")!.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(B1Evidence), typeof(IB1Baseline).GetMethod("Classify")!.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(B1WitnessEvidence), typeof(IB1WitnessBaseline).GetMethod("Classify")!.GetParameters()[0].ParameterType);
        Assert.Equal(typeof(B2Evidence), typeof(IB2Baseline).GetMethod("Classify")!.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(typeof(B1Evidence).GetProperties(), p => p.Name is "Obligations" or "Witnesses" or "Challenges");
    }

    [Fact]
    public void B0ReceivesOnlyOneLocalViewEvenIfTwoSnapshotsWereAcquired()
    {
        var plan = Plan(fork: true);
        plan = plan with { Disclosure = plan.Disclosure.Add(new("reviewer", "a", "fork/snapshot")) };
        var fixture = Create(Workload(new FaultRule(FaultKind.Equivocation, 0)), plan: plan);
        var records = fixture.Acquisition.ProjectB0("reviewer").Records;
        Assert.Equal(4, records.Length);
        Assert.Equal(4, records.Select(r => r.LeafIndex).Distinct().Count());
        Assert.Equal(2, fixture.Acquisition.ProjectB1("reviewer").Snapshots.Count(s => s.Artifact.Read().GatewayId == "A"));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void WitnessAndChallengeAvailabilityAreIndependent(bool witness, bool challenge)
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)),
            Schedule(witnessed: witness, challenge: challenge), Plan(witnessed: witness, challenge: challenge));
        var evidence = fixture.Acquisition.ProjectB2("reviewer");
        Assert.Single(evidence.TargetAcks);
        Assert.Equal(witness ? 1 : 0, evidence.Witnessed.Witnesses.Length);
        Assert.Equal(challenge ? 1 : 0, evidence.Challenges.Length);
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(Omission(fixture.Acquisition).QueryId, AssessmentOutcome.Inconclusive)], new(1_000_000)).Omission;
        Assert.Equal(0, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.Inconclusive);
    }

    [Fact]
    public void LateWitnessObservationRemainsInsufficientForArchivedProof()
    {
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)), Schedule(observedAt: 201_000));
        Assert.Equal(AuditVerdict.UnprovenWithinWindow, Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
        var eligibility = OwnerEvaluation.Eligibility("reviewer", BaselineId.B2,
            fixture.Acquisition, fixture.Archive, Schedule().Clock, new(1_000_000));
        Assert.False(eligibility.Single(e => e.QueryId == Omission(fixture.Acquisition).QueryId).AdmissibleEvidence);
    }

    [Fact]
    public void BackdatedSignedCheckpointDoesNotEstablishFreshness()
    {
        var schedule = Schedule();
        schedule = schedule with
        {
            Checkpoints = schedule.Checkpoints.SetItem(0,
                schedule.Checkpoints[0] with { ClaimedTimestamp = new(159_000) })
        };
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)), schedule);
        Assert.Equal(AuditVerdict.UnprovenWithinWindow, Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
    }

    [Theory]
    [InlineData("head/snapshot")]
    [InlineData("obligation/ack")]
    [InlineData("witness")]
    [InlineData("challenge")]
    public void MalformedDeliveredArtifactsRemainUnusableForProof(string id)
    {
        var run = SimulationRun.Create(Workload(new FaultRule(FaultKind.Omission, 0)));
        var schedule = Schedule();
        var production = ProtocolArchive.Create(run, schedule);
        var acquired = new EvidenceAcquisition(run, production.ReplaceArtifact(id, "{"), Plan());
        var owner = new ExperimentOwner(run, schedule, production, acquired, new(300_000));
        var result = owner.Score("reviewer", BaselineId.B2,
            [new(Omission(acquired).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(1, result.Detections);
        Assert.Equal(0, result.EvidenceCoveredPositives);
        Assert.Equal(1, result.UnsupportedAccusations);
    }

    [Fact]
    public void TargetAckDeliveryAndWitnessDeliveryCanBeDelayedIndependently()
    {
        var run = SimulationRun.Create(Workload(new FaultRule(FaultKind.Omission, 0)));
        var archive = ProtocolArchive.Create(run, Schedule());
        var ackPlan = Plan() with
        {
            Disclosure = Plan().Disclosure.Select(rule => rule.ArtifactId == "obligation/ack"
                ? rule with { DeliveryDelayMilliseconds = 100_000 } : rule).ToImmutableArray()
        };
        var withoutAck = new EvidenceAcquisition(run, archive, ackPlan).ProjectB2("reviewer");
        Assert.Empty(withoutAck.TargetAcks);
        Assert.Single(withoutAck.Witnessed.Witnesses);
        Assert.Single(withoutAck.Challenges);
        var witnessPlan = Plan() with
        {
            Disclosure = Plan().Disclosure.Select(rule => rule.ArtifactId == "witness"
                ? rule with { DeliveryDelayMilliseconds = 100_000 } : rule).ToImmutableArray()
        };
        var withoutWitness = new EvidenceAcquisition(run, archive, witnessPlan).ProjectB2("reviewer");
        Assert.Single(withoutWitness.TargetAcks);
        Assert.Empty(withoutWitness.Witnessed.Witnesses);
        Assert.Single(withoutWitness.Challenges);
    }

    [Fact]
    public void ProtocolSchedulesCannotUseFutureChallengesOrRetroactiveTargetAcceptance()
    {
        var run = SimulationRun.Create(Workload());
        var schedule = Schedule();
        var earlyHead = schedule with
        {
            Checkpoints = schedule.Checkpoints.SetItem(0,
                schedule.Checkpoints[0] with { CreatedAt = new(159_000) })
        };
        Assert.Throws<ArgumentException>(() => ProtocolArchive.Create(run, earlyHead));
        var lateAck = schedule with
        {
            Obligations = schedule.Obligations.SetItem(0,
                schedule.Obligations[0] with { TargetAckAt = new(151_000), AckAvailableAt = new(151_000) })
        };
        Assert.Throws<ArgumentException>(() => ProtocolArchive.Create(run, lateAck));
    }

    [Fact]
    public void SnapshotBuffersCannotMutateOtherProjectionsOrOwnerArchive()
    {
        var fixture = Create(Workload());
        var first = fixture.Acquisition.ProjectB1("reviewer").Snapshots[0].Artifact;
        var snapshot = first.Read();
        snapshot.Checkpoint.Signature[0] ^= 0xff;
        snapshot.Entries.Clear();
        Assert.NotEmpty(first.Read().Entries);
        Assert.NotEqual(snapshot.Checkpoint.Signature, first.Read().Checkpoint.Signature);
        Assert.Equal(AuditVerdict.Compliant, Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
    }

    [Theory]
    [InlineData("head/snapshot")]
    [InlineData("obligation/ack")]
    [InlineData("witness")]
    [InlineData("challenge")]
    public void ForgedCollectedEvidenceDoesNotBecomeAdmissibleProof(string artifactId)
    {
        var workload = Workload(new FaultRule(FaultKind.Omission, 0));
        var run = SimulationRun.Create(workload);
        var schedule = Schedule();
        var production = ProtocolArchive.Create(run, schedule);
        var artifact = production.Artifacts.Single(a => a.Id == artifactId);
        string forged = artifactId switch
        {
            "head/snapshot" => JsonSerializer.Serialize(
                new SignedEvidence<LogSnapshot>(artifact.Json).Read() with
                { Checkpoint = new SignedEvidence<LogSnapshot>(artifact.Json).Read().Checkpoint with { Signature = new byte[64] } }),
            "obligation/ack" => JsonSerializer.Serialize(
                new SignedEvidence<SignedLoggingObligation>(artifact.Json).Read() with { TargetAckSignature = new byte[64] }),
            "witness" => JsonSerializer.Serialize(
                new SignedEvidence<WitnessAttestation>(artifact.Json).Read() with { Signature = new byte[64] }),
            _ => JsonSerializer.Serialize(
                new SignedEvidence<SignedAuditChallenge>(artifact.Json).Read() with { Signature = new byte[64] })
        };
        var acquired = new EvidenceAcquisition(run, production.ReplaceArtifact(artifactId, forged), Plan());
        var owner = new ExperimentOwner(run, schedule, production, acquired, new(300_000));
        var score = owner.Score("reviewer", BaselineId.B2,
            [new(Omission(acquired).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(0, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.UnsupportedAccusations);
        var invalid = owner.Score("reviewer", BaselineId.B2,
            [new(Omission(acquired).QueryId, AssessmentOutcome.InvalidEvidence)], new(1_000_000)).Omission;
        Assert.Equal(1, invalid.InvalidEvidence);
        Assert.Equal(0, invalid.Inconclusive);
        Assert.Equal(0, invalid.UnsupportedAccusations);
    }

    [Fact]
    public void ForgedConflictingCheckpointCannotSupportB1Accusation()
    {
        var run = SimulationRun.Create(Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var schedule = Schedule();
        var production = ProtocolArchive.Create(run, schedule);
        var fork = new SignedEvidence<SignedTreeHead>(production.Artifacts.Single(a => a.Id == "fork").Json).Read();
        var tampered = production.ReplaceArtifact("fork", JsonSerializer.Serialize(fork with { Signature = new byte[64] }));
        var acquisition = new EvidenceAcquisition(run, tampered, Plan(fork: true));
        var owner = new ExperimentOwner(run, schedule, production, acquisition, new(300_000));
        var score = owner.Score("reviewer", BaselineId.B1,
            [new(Equivocation(acquisition).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Equivocation;
        Assert.Equal(1, score.ActualPositives);
        Assert.Equal(0, score.EvidenceCoveredPositives);
        Assert.Equal(1, score.UnsupportedAccusations);
    }

    [Fact]
    public void ExactArchiveReplayPreservesAllProjectionsAndIndependentWorkload()
    {
        var configuration = Workload(new FaultRule(FaultKind.Omission, 0));
        var fixture = Create(configuration);
        var manifest = EvidenceManifest.Create(configuration, Schedule(), Plan(), fixture.Archive, ExperimentManifest.FrozenGate2);
        var replayManifest = JsonSerializer.Deserialize<EvidenceManifest>(manifest.ToJson())!;
        var archive = ProtocolArchive.Restore(fixture.Archive.Serialize());
        replayManifest.VerifyArchive(archive);
        var replayRun = SimulationRun.Create(replayManifest.Workload.Configuration);
        var replay = new EvidenceAcquisition(replayRun, archive, replayManifest.Acquisition);
        Assert.Equal(JsonSerializer.Serialize(fixture.Acquisition.ProjectB0("reviewer")),
            JsonSerializer.Serialize(replay.ProjectB0("reviewer")));
        Assert.Equal(JsonSerializer.Serialize(fixture.Acquisition.ProjectB2("reviewer")),
            JsonSerializer.Serialize(replay.ProjectB2("reviewer")));
        Assert.Equal(fixture.Run.Pristine.ToArray(), replayRun.Pristine.ToArray());
        var changedSchedule = Schedule(witnessed: false);
        var changedArchive = ProtocolArchive.Create(replayRun, changedSchedule);
        Assert.Throws<ArgumentException>(() => replayManifest.VerifyArchive(changedArchive));
        Assert.Equal(fixture.Run.Pristine.ToArray(), SyntheticGenerator.Generate(configuration).ToArray());
        Assert.DoesNotContain("PrivateKey", fixture.Archive.Serialize());
    }

    [Fact]
    public void OwnerReplayRetainsTruthAndScoresWithoutProvidingLabelsToClassifiers()
    {
        var workload = Workload(new FaultRule(FaultKind.Omission, 0));
        var owner = ExperimentOwner.Create(workload, Schedule(), Plan(), new(300_000));
        var archive = ProtocolArchive.Restore(owner.CaptureArchive());
        var manifest = EvidenceManifest.Create(workload, Schedule(), Plan(), archive, ExperimentManifest.FrozenGate2);
        var replay = ExperimentOwner.Replay(manifest, owner.CaptureArchive(), new(300_000));
        var predictions = owner.Acquisition.ProjectB1("reviewer").Context.Targets
            .Select(q => new Prediction(q.QueryId, AssessmentOutcome.Inconclusive)).ToImmutableArray();
        Assert.Equal(owner.Score("reviewer", BaselineId.B2, predictions, new(1_000_000)),
            replay.Score("reviewer", BaselineId.B2, predictions, new(1_000_000)));
    }

    [Fact]
    public void SelfSignedTargetObligationDoesNotRequireACounterpartyAck()
    {
        var schedule = Schedule(ack: false);
        schedule = schedule with
        {
            Obligations = schedule.Obligations.SetItem(0,
                schedule.Obligations[0] with { IssuerGateway = "A" })
        };
        var plan = Plan(ack: false);
        plan = plan with
        {
            Disclosure = plan.Disclosure.Select(rule => rule.ArtifactId == "obligation"
                ? rule with { RequestId = "a" } : rule).ToImmutableArray()
        };
        var fixture = Create(Workload(new FaultRule(FaultKind.Omission, 0)), schedule, plan);
        Assert.Equal(AuditVerdict.ProvenLoggingPolicyViolation,
            Verify(fixture.Acquisition.ProjectB2("reviewer"), fixture.Archive));
        var score = fixture.Owner.Score("reviewer", BaselineId.B2,
            [new(Omission(fixture.Acquisition).QueryId, AssessmentOutcome.Accusation)], new(1_000_000)).Omission;
        Assert.Equal(1, score.EvidenceConditionalDetections);
    }

    [Fact]
    public void OmissionAndEquivocationTruthAreIndependentAndEquivocationIsCountedOncePerLog()
    {
        var fixture = Create(Workload(new(FaultKind.Omission, 0), new(FaultKind.Equivocation, 1)),
            plan: Plan(fork: true));
        var context = fixture.Acquisition.ProjectB1("reviewer").Context;
        Assert.Single(context.Targets.Where(q => q.Kind == ClaimKind.SignedLogEquivocation));
        var truth = OwnerEvaluation.ActualFacts(fixture.Run, Schedule(), fixture.Archive, context, new(300_000));
        Assert.Single(truth.Where(t => t.ActualOmissionPolicyViolation));
        Assert.Single(truth.Where(t => t.ActualSignedLogEquivocation));
    }

    [Fact]
    public void FutureForksDoNotChangeTruthForAnEarlierCollectionCutoff()
    {
        var run = SimulationRun.Create(Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var schedule = Schedule();
        schedule = schedule with
        {
            Checkpoints = schedule.Checkpoints.SetItem(1, schedule.Checkpoints[1] with { CreatedAt = new(220_000) })
        };
        var archive = ProtocolArchive.Create(run, schedule);
        var originalPlan = Plan();
        var later = originalPlan.Observers[0] with { Observer = "later", Cutoff = new(250_000) };
        var plan = originalPlan with { Observers = originalPlan.Observers.Add(later) };
        var acquisition = new EvidenceAcquisition(run, archive, plan);
        var owner = new ExperimentOwner(run, schedule, archive, acquisition, new(300_000));
        var query = Equivocation(acquisition);
        var early = owner.Score("reviewer", BaselineId.B1,
            [new(query.QueryId, AssessmentOutcome.Inconclusive)], new(1_000_000));
        var late = owner.Score("later", BaselineId.B1,
            [new(query.QueryId, AssessmentOutcome.Inconclusive)], new(1_000_000));
        Assert.Equal(0, early.Equivocation.ActualPositives);
        Assert.Equal(1, late.Equivocation.ActualPositives);
        Assert.Equal(0, late.Equivocation.EvidenceCoveredPositives);
    }

    [Fact]
    public void CutoffsAndTimeoutsExcludeLateDeliveriesWithInclusiveBoundary()
    {
        var run = SimulationRun.Create(Workload());
        var archive = ProtocolArchive.Create(run, Schedule());
        var plan = Plan(cutoff: 180_000) with
        {
            Disclosure = [new("reviewer", "a", "head", 10_000),
                new("reviewer", "a", "fork", 10_001)]
        };
        var evidence = new EvidenceAcquisition(run, archive, plan).ProjectB1("reviewer");
        Assert.Single(evidence.Checkpoints);
        Assert.Equal(180_000, evidence.Checkpoints[0].ReceivedAt.Milliseconds);
        plan = plan with
        {
            Observers = [plan.Observers[0] with
            {
                Cutoff = new(210_000),
                Requests = plan.Observers[0].Requests.SetItem(0,
                    plan.Observers[0].Requests[0] with { TimeoutAt = new(179_000) })
            }]
        };
        Assert.Empty(new EvidenceAcquisition(run, archive, plan).ProjectB1("reviewer").Checkpoints);
    }

    [Fact]
    public void CheckpointExchangeRequiresPriorSenderAcquisition()
    {
        var run = SimulationRun.Create(Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var archive = ProtocolArchive.Create(run, Schedule());
        var plan = new AcquisitionPlan(new(2, 1),
            [new("one", "A", new(210_000),
                [new("local", "A", CollectionChannel.Direct, new(170_000), new(210_000)),
                 new("exchange", "two", CollectionChannel.CheckpointExchange, new(190_000), new(210_000))]),
             new("two", "A", new(210_000),
                [new("remote", "A", CollectionChannel.Direct, new(180_000), new(210_000))])],
            [new("one", "local", "head"), new("two", "remote", "fork"),
             new("one", "exchange", "fork")]);
        var collected = new EvidenceAcquisition(run, archive, plan);
        Assert.Equal(2, collected.ProjectB1("one").Checkpoints.Length);
        Assert.Single(collected.ProjectB1("two").Checkpoints);
        var withheld = new EvidenceAcquisition(run, archive, plan with
        { Disclosure = plan.Disclosure.RemoveAt(1) });
        Assert.Single(withheld.ProjectB1("one").Checkpoints);
        Assert.Empty(withheld.ProjectB1("two").Checkpoints);
    }

    [Fact]
    public void UnequalOrUnauthorizedCollectionCannotBypassSharedBudget()
    {
        var run = SimulationRun.Create(Workload());
        var archive = ProtocolArchive.Create(run, Schedule());
        Assert.Throws<ArgumentException>(() =>
            new EvidenceAcquisition(run, archive, Plan() with { Budget = new(1, 1) }));
        Assert.Throws<ArgumentException>(() => new EvidenceAcquisition(run, archive, Plan() with
        { Disclosure = [new("reviewer", "b", "head")] }));
    }
}
