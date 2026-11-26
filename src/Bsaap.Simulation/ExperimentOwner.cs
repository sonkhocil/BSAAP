using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// This object stays with the experiment owner. Only typed projections are sent
// across the classifier boundary, and scoring occurs after outputs are collected.
public sealed class ExperimentOwner
{
    private readonly ImmutableDictionary<string, ImmutableArray<ActualTruthFlags>> _truth;
    private readonly ProtocolArchive _productionArchive;
    private readonly UnixTimeMapping _clock;
    public EvidenceAcquisition Acquisition { get; }

    internal ExperimentOwner(SimulationRun run, ProtocolSchedule schedule, ProtocolArchive productionArchive,
        EvidenceAcquisition acquisition, LogicalInstant truthHorizon)
    {
        _productionArchive = productionArchive;
        _clock = schedule.Clock;
        Acquisition = acquisition;
        if (acquisition.ObserverIds.Any(observer =>
            acquisition.ProjectB1(observer).Context.CollectionCutoff.Milliseconds > truthHorizon.Milliseconds))
            throw new ArgumentException("The owner truth horizon must cover every collection cutoff.");
        _truth = acquisition.ObserverIds.ToImmutableDictionary(observer => observer, observer =>
            OwnerEvaluation.ActualFacts(run, schedule, productionArchive,
                acquisition.ProjectB1(observer).Context, truthHorizon), StringComparer.Ordinal);
    }

    public static ExperimentOwner Create(SimulationConfiguration configuration, ProtocolSchedule schedule,
        AcquisitionPlan plan, LogicalInstant truthHorizon)
    {
        var run = SimulationRun.Create(configuration);
        var archive = ProtocolArchive.Create(run, schedule);
        return new(run, schedule, archive, new EvidenceAcquisition(run, archive, plan), truthHorizon);
    }

    public string CaptureArchive() => _productionArchive.Serialize();

    public static ExperimentOwner Replay(EvidenceManifest manifest, string archiveJson, LogicalInstant truthHorizon)
    {
        var archive = ProtocolArchive.Restore(archiveJson);
        manifest.VerifyArchive(archive);
        var run = SimulationRun.Create(manifest.Workload.Configuration);
        var acquisition = new EvidenceAcquisition(run, archive, manifest.Acquisition);
        return new(run, manifest.Protocol, archive, acquisition, truthHorizon);
    }

    public ScoreReport Score(string observer, BaselineId baseline,
        ImmutableArray<Prediction> predictions, LogicalInstant verificationTime)
    {
        if (!Enum.IsDefined(baseline))
            throw new ArgumentOutOfRangeException(nameof(baseline));
        var eligibility = OwnerEvaluation.Eligibility(observer, baseline, Acquisition,
            _productionArchive, _clock, verificationTime);
        return OwnerEvaluation.Score(_truth[observer], eligibility, predictions);
    }
}
