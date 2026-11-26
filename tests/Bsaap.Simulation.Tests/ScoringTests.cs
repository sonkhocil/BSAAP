using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;
using Xunit;

namespace Bsaap.Simulation.Tests;

public sealed class ScoringTests
{
    [Fact]
    public void TruthEvidenceAndOutcomesAreCountedIndependently()
    {
        ImmutableArray<ActualTruthFlags> truth = [
            new("o1", ClaimKind.OmissionPolicyViolation, true, false),
            new("o2", ClaimKind.OmissionPolicyViolation, true, false),
            new("o3", ClaimKind.OmissionPolicyViolation, true, false),
            new("o4", ClaimKind.OmissionPolicyViolation, true, false),
            new("o5", ClaimKind.OmissionPolicyViolation, true, false),
            new("o6", ClaimKind.OmissionPolicyViolation, false, false),
            new("o7", ClaimKind.OmissionPolicyViolation, false, false),
            new("e1", ClaimKind.SignedLogEquivocation, false, true),
            new("e2", ClaimKind.SignedLogEquivocation, false, true),
            new("e3", ClaimKind.SignedLogEquivocation, false, false),
            new("e4", ClaimKind.SignedLogEquivocation, false, false)];
        var eligibility = truth.Select(t => new EvidenceEligibility("observer", BaselineId.B2, t.QueryId,
            t.QueryId is "o1" or "o3" or "e1")).ToImmutableArray();
        ImmutableArray<Prediction> predictions = [
            new("o1", AssessmentOutcome.Accusation), new("o2", AssessmentOutcome.Accusation),
            new("o3", AssessmentOutcome.InvalidEvidence), new("o4", AssessmentOutcome.Inconclusive),
            new("o6", AssessmentOutcome.Accusation), new("o7", AssessmentOutcome.NoFinding),
            new("e1", AssessmentOutcome.Accusation), new("e2", AssessmentOutcome.Inconclusive),
            new("e3", AssessmentOutcome.Accusation), new("e4", AssessmentOutcome.InvalidEvidence)];
        var score = OwnerEvaluation.Score(truth, eligibility, predictions);
        Assert.Equal(new DetectionScore(5, 2, 2, 1, 2, 1, 2, 1, 1, 1, 1, 3), score.Omission);
        Assert.Equal(0.4, score.Omission.UnconditionalDetectionRate);
        Assert.Equal(0.5, score.Omission.FalseAccusationRate);
        Assert.Equal(0.4, score.Omission.EvidenceCoverage);
        Assert.Equal(0.5, score.Omission.EvidenceConditionalDetectionRate);
        Assert.Equal(new DetectionScore(2, 2, 1, 1, 1, 1, 1, 1, 1, 0, 0, 2), score.Equivocation);
    }

    [Fact]
    public void EmptyDenominatorsAreExplicitlyUndefined()
    {
        var score = OwnerEvaluation.Score([], [], []);
        Assert.Null(score.Omission.UnconditionalDetectionRate);
        Assert.Null(score.Equivocation.FalseAccusationRate);
        Assert.Null(score.Omission.EvidenceCoverage);
        Assert.Null(score.Equivocation.EvidenceConditionalDetectionRate);
    }

    [Fact]
    public void ScoringRejectsUnknownDuplicateAndMixedObserverInputs()
    {
        ImmutableArray<ActualTruthFlags> truth = [new("one", ClaimKind.OmissionPolicyViolation, true, false)];
        ImmutableArray<EvidenceEligibility> eligibility = [new("observer", BaselineId.B1, "one", false)];
        Assert.Throws<ArgumentException>(() => OwnerEvaluation.Score(truth, eligibility,
            [new("unknown", AssessmentOutcome.Accusation)]));
        Assert.Throws<ArgumentException>(() => OwnerEvaluation.Score(truth, eligibility,
            [new("one", AssessmentOutcome.NoFinding), new("one", AssessmentOutcome.Inconclusive)]));
        Assert.Throws<ArgumentException>(() => OwnerEvaluation.Score(truth, [], []));
        var expanded = truth.Add(new("two", ClaimKind.SignedLogEquivocation, false, true));
        var mixed = eligibility.Add(new("other", BaselineId.B2, "two", true));
        Assert.Throws<ArgumentException>(() => OwnerEvaluation.Score(expanded, mixed, []));
    }

    [Theory]
    [InlineData(BaselineId.B0)]
    [InlineData(BaselineId.B1)]
    [InlineData(BaselineId.B1W)]
    [InlineData(BaselineId.B2)]
    public void EveryBaselineCanSubmitInconclusiveWithoutAnExpectedVerdict(BaselineId baseline)
    {
        var owner = ExperimentOwner.Create(EvidenceAcquisitionTests.Workload(),
            EvidenceAcquisitionTests.Schedule(), EvidenceAcquisitionTests.Plan(), new(300_000));
        var context = owner.Acquisition.ProjectB1("reviewer").Context;
        var predictions = context.Targets.Select(q =>
            new Prediction(q.QueryId, AssessmentOutcome.Inconclusive)).ToImmutableArray();
        var report = owner.Score("reviewer", baseline, predictions, new(1_000_000));
        Assert.Equal(4, report.Omission.Inconclusive);
        Assert.Equal(1, report.Equivocation.Inconclusive);
        Assert.Equal(0, report.Omission.Accusations);
        Assert.Equal(0, report.Equivocation.Accusations);
    }
}
