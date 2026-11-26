using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

public sealed class B1WitnessClassifier : IB1WitnessBaseline
{
    private readonly TrustedPublicKeyBootstrap _trust;
    private readonly VerificationClock _clock;
    public B1WitnessClassifier(TrustedPublicKeyBootstrap trust, VerificationClock clock)
    {
        ArgumentNullException.ThrowIfNull(trust);
        ArgumentNullException.ThrowIfNull(clock);
        _trust = trust;
        _clock = clock;
    }

    public ImmutableArray<Prediction> Classify(B1WitnessEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        _clock.Validate(evidence.Bilateral.Context);
        return evidence.Bilateral.Context.Targets.Select(query =>
        {
            if (!EvidenceValidation.QueryValid(query))
                return new Prediction(query.QueryId, AssessmentOutcome.InvalidEvidence, "Malformed public query.");
            var log = EvidenceValidation.Log(evidence.Bilateral, query, _trust.VerificationKeys, _clock);
            bool conflict = log.Equivocates(_trust.VerificationKeys);
            var baseline = B1Classifier.Assess(query, log, conflict);
            // A genuine gateway conflict remains a proof without witness assistance.
            if (conflict) return baseline;
            var observation = EvidenceValidation.Witnesses(evidence, query, log, _trust.VerificationKeys, _clock);
            if (observation.Invalid)
                return new Prediction(query.QueryId, AssessmentOutcome.InvalidEvidence, "Witness authentication or binding failed.");
            return baseline with { Reason = baseline.Reason + (observation.Bound
                ? " Independent observation is bound to an acquired head."
                : " No independently bound observation was acquired.") };
        }).ToImmutableArray();
    }
}
