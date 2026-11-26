using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bsaap.Baselines;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class PilotMethodologyTests
{
    [Theory]
    [InlineData("primary")]
    [InlineData("alternate")]
    public void AnyCommittedViewDeadlineMissSurvivesComplianceInTheOtherView(string delayedView)
    {
        var workload = EvidenceAcquisitionTests.Workload(
            new FaultRule(FaultKind.Delay, 0, Delay: 60_000, InternalView: delayedView));
        var run = SimulationRun.Create(workload);
        var schedule = EvidenceAcquisitionTests.Schedule();
        var policies = run.PolicyTruth(schedule, new(300_000));
        Assert.True(policies.Single(p => p.InternalView == delayedView).DeadlineMiss);
        Assert.False(policies.Single(p => p.InternalView != delayedView).DeadlineMiss);
        Assert.All(policies, p => Assert.True(p.PresentAtHorizon));
        var archive = ProtocolArchive.Create(run, schedule);
        var acquired = new EvidenceAcquisition(run, archive, EvidenceAcquisitionTests.Plan());
        var facts = OwnerEvaluation.ActualFacts(run, schedule, archive,
            acquired.ProjectB1("reviewer").Context, new(300_000));
        Assert.Single(facts.Where(f => f.ActualOmissionPolicyViolation));
        Assert.Single(facts.Where(f => f.ActualSignedLogEquivocation));
    }

    [Fact]
    public void AnUnsignedInternalBranchDoesNotCreateOmissionPolicyTruth()
    {
        var run = SimulationRun.Create(EvidenceAcquisitionTests.Workload(
            new FaultRule(FaultKind.Delay, 0, Delay: 60_000, InternalView: "alternate")));
        var schedule = EvidenceAcquisitionTests.Schedule();
        schedule = schedule with { Checkpoints = schedule.Checkpoints.RemoveAt(1) };
        var archive = ProtocolArchive.Create(run, schedule);
        var acquired = new EvidenceAcquisition(run, archive, EvidenceAcquisitionTests.Plan());
        var facts = OwnerEvaluation.ActualFacts(run, schedule, archive,
            acquired.ProjectB1("reviewer").Context, new(300_000));
        Assert.Contains(run.PolicyTruth(schedule, new(300_000)), p => p.DeadlineMiss);
        Assert.DoesNotContain(facts, f => f.ActualOmissionPolicyViolation || f.ActualSignedLogEquivocation);
    }

    [Fact]
    public void WithholdingAllCheckpointsDoesNotRemoveThePrimaryJournalsAcceptedDuty()
    {
        var run = SimulationRun.Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Omission, 0)));
        var schedule = EvidenceAcquisitionTests.Schedule() with { Checkpoints = [], Witnesses = [] };
        var archive = ProtocolArchive.Create(run, schedule);
        var plan = EvidenceAcquisitionTests.Plan() with
        {
            Disclosure = [new("reviewer", "a", "obligation/ack"), new("reviewer", "b", "obligation")]
        };
        var acquired = new EvidenceAcquisition(run, archive, plan);
        var facts = OwnerEvaluation.ActualFacts(run, schedule, archive,
            acquired.ProjectB1("reviewer").Context, new(300_000));
        Assert.Single(facts.Where(f => f.ActualOmissionPolicyViolation));
        Assert.DoesNotContain(OwnerEvaluation.Eligibility("reviewer", BaselineId.B2, acquired, archive,
            schedule.Clock, new(1_000_000)), e => e.AdmissibleEvidence);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public void WitnessAuthenticationAndDiscoveryAreIndependent(bool attestationDelivered, bool retrieve)
    {
        var run = SimulationRun.Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var schedule = RetentionSchedule();
        var archive = ProtocolArchive.Create(run, schedule);
        var plan = RetrievalPlan(retrieve);
        if (!attestationDelivered)
            plan = plan with { Disclosure = plan.Disclosure.Select(rule => rule.ArtifactId == "witness"
                ? rule with { DeliveryDelayMilliseconds = 500_000 } : rule).ToImmutableArray() };
        var acquired = new EvidenceAcquisition(run, archive, plan);
        var trust = new TrustedPublicKeyBootstrap(archive.ExportTrustedPublicKeys());
        var clock = new VerificationClock(1_800_000_000, 1_800_001_000);
        var b1 = acquired.ProjectB1("reviewer");
        int roots = b1.Checkpoints.Select(h => h.Artifact.Read()).Where(h => h.GatewayId == "A")
            .Select(h => Convert.ToHexString(h.RootHash)).Distinct().Count();
        Assert.Equal(retrieve ? 2 : 1, roots);
        Assert.Equal(attestationDelivered ? 1 : 0, acquired.ProjectB1Witness("reviewer").Witnesses.Length);
        string query = b1.Context.Targets.Single(q => q.Kind == ClaimKind.SignedLogEquivocation).QueryId;
        var expected = retrieve ? AssessmentOutcome.Accusation : AssessmentOutcome.Inconclusive;
        Assert.Equal(expected, new B1Classifier(trust, clock).Classify(b1).Single(p => p.QueryId == query).Outcome);
        Assert.Equal(expected, new B1WitnessClassifier(trust, clock)
            .Classify(acquired.ProjectB1Witness("reviewer")).Single(p => p.QueryId == query).Outcome);
        Assert.Equal(expected, new B2Classifier(trust, clock)
            .Classify(acquired.ProjectB2("reviewer")).Single(p => p.QueryId == query).Outcome);
    }

    [Fact]
    public void ChangingOnlyAttestationDeliveryDoesNotChangeAcquiredGatewayEvidence()
    {
        var run = SimulationRun.Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var archive = ProtocolArchive.Create(run, RetentionSchedule());
        var plan = RetrievalPlan(retrieve: true);
        var available = new EvidenceAcquisition(run, archive, plan);
        var unavailable = new EvidenceAcquisition(run, archive, plan with
        {
            Disclosure = plan.Disclosure.Select(d => d.ArtifactId == "witness"
                ? d with { DeliveryDelayMilliseconds = 500_000 } : d).ToImmutableArray()
        });
        Assert.Equal(available.ProjectB1("reviewer").Checkpoints.Select(h => h.Artifact.Json),
            unavailable.ProjectB1("reviewer").Checkpoints.Select(h => h.Artifact.Json));
        Assert.Single(available.ProjectB1Witness("reviewer").Witnesses);
        Assert.Empty(unavailable.ProjectB1Witness("reviewer").Witnesses);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void DiscoveryRequiresObservationRetentionAndAnUnexpiredWindow(bool observed, bool retained)
    {
        var run = SimulationRun.Create(EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0)));
        var schedule = RetentionSchedule();
        schedule = schedule with
        {
            Witnesses = observed ? [schedule.Witnesses[0] with
            {
                RetainCheckpoint = retained,
                RetainedUntil = retained ? new(185_000) : null,
                CheckpointAvailableAt = retained ? new(180_000) : null
            }] : []
        };
        var archive = ProtocolArchive.Create(run, schedule);
        var plan = RetrievalPlan(retrieve: true);
        if (!observed)
            plan = plan with { Disclosure = plan.Disclosure.Where(d => d.ArtifactId != "witness").ToImmutableArray() };
        var acquired = new EvidenceAcquisition(run, archive, plan);
        Assert.DoesNotContain(acquired.Deliveries, d => d.ArtifactId == "fork");
    }

    [Fact]
    public void WitnessRetentionIsPreservedInPinnedArchiveReplay()
    {
        var workload = EvidenceAcquisitionTests.Workload(new FaultRule(FaultKind.Equivocation, 0));
        var schedule = RetentionSchedule();
        var plan = RetrievalPlan(retrieve: true);
        var owner = ExperimentOwner.Create(workload, schedule, plan, new(300_000));
        var archive = ProtocolArchive.Restore(owner.CaptureArchive());
        var manifest = EvidenceManifest.Create(workload, schedule, plan, archive, ExperimentManifest.FrozenGate2);
        var replay = ExperimentOwner.Replay(manifest, owner.CaptureArchive(), new(300_000));
        Assert.Equal(JsonSerializer.Serialize(owner.Acquisition.ProjectB2("reviewer")),
            JsonSerializer.Serialize(replay.Acquisition.ProjectB2("reviewer")));
    }

    [Fact]
    public void Gate3CSavedInputsRetainTheirConfigurationAndArchiveDigests()
    {
        string path = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory,
            "../../../../../verification/gate3c/functional/scenario-1.json"));
        var options = new JsonSerializerOptions();
        options.Converters.Add(new JsonStringEnumConverter());
        var saved = JsonSerializer.Deserialize<SavedInput>(File.ReadAllText(path), options)!;
        var archive = ProtocolArchive.Restore(saved.ProductionArchive);
        Assert.Equal(saved.ProductionArchive, archive.Serialize());
        saved.Manifest.VerifyArchive(archive);
        var owner = ExperimentOwner.Replay(saved.Manifest, saved.ProductionArchive, new(300_000));
        Assert.NotEmpty(owner.Acquisition.ProjectB1("reviewer").Snapshots);
    }

    private static ProtocolSchedule RetentionSchedule()
    {
        var schedule = EvidenceAcquisitionTests.Schedule();
        return schedule with { Witnesses = [schedule.Witnesses[0] with
        {
            CheckpointId = "fork", RetainCheckpoint = true,
            CheckpointAvailableAt = new(180_000), RetainedUntil = new(220_000)
        }] };
    }

    private static AcquisitionPlan RetrievalPlan(bool retrieve)
    {
        var plan = EvidenceAcquisitionTests.Plan();
        var observer = plan.Observers[0];
        observer = observer with { Requests = observer.Requests.Add(
            new("retained", "W", CollectionChannel.WitnessCheckpointRetrieval, new(190_000), new(210_000))) };
        return plan with
        {
            Budget = new(5, 6), Observers = [observer],
            Disclosure = retrieve ? plan.Disclosure.Add(new("reviewer", "retained", "fork")) : plan.Disclosure
        };
    }

    private sealed record SavedInput(EvidenceManifest Manifest, string ProductionArchive,
        ImmutableDictionary<string, string> DeliveredBodyOverrides);
}
