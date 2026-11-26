using System.Collections.Immutable;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

// This object stays with the experiment owner. Only typed projections are sent
// across the classifier boundary, and scoring occurs after outputs are collected.
public sealed class ExperimentOwner
{
    private readonly ImmutableDictionary<string, ImmutableArray<ActualTruthFlags>> _truth;
    private readonly ProtocolArchive _productionArchive;
    private readonly SimulationRun _run;
    private readonly ProtocolSchedule _schedule;
    private readonly LogicalInstant _truthHorizon;
    private readonly UnixTimeMapping _clock;
    public EvidenceAcquisition Acquisition { get; }

    internal ExperimentOwner(SimulationRun run, ProtocolSchedule schedule, ProtocolArchive productionArchive,
        EvidenceAcquisition acquisition, LogicalInstant truthHorizon)
    {
        _run = run;
        _schedule = schedule;
        _truthHorizon = truthHorizon;
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

    public ImmutableArray<TrustedPublicSigner> ExportTrustedPublicKeys() =>
        _productionArchive.ExportTrustedPublicKeys();

    public string CaptureArchive() => _productionArchive.Serialize();

    public static ExperimentOwner Replay(EvidenceManifest manifest, string archiveJson, LogicalInstant truthHorizon)
    {
        var archive = ProtocolArchive.Restore(archiveJson);
        manifest.VerifyArchive(archive);
        var run = SimulationRun.Create(manifest.Workload.Configuration);
        var acquisition = new EvidenceAcquisition(run, archive, manifest.Acquisition);
        return new(run, manifest.Protocol, archive, acquisition, truthHorizon);
    }

    // Owner-controlled transport corruption changes delivered bodies only. Trust,
    // original production facts, routing, budgets and physical truth stay bound to
    // the original run. Persist these overrides with the replay manifest.
    public ExperimentOwner WithDeliveredArtifactBodies(ImmutableDictionary<string, string> bodies)
    {
        ArgumentNullException.ThrowIfNull(bodies);
        var delivered = _productionArchive;
        foreach (var body in bodies)
        {
            if (!delivered.Artifacts.Any(a => a.Id == body.Key))
                throw new ArgumentException("Unknown delivered artifact ID.");
            delivered = delivered.ReplaceArtifact(body.Key, body.Value);
        }
        var acquisition = new EvidenceAcquisition(_run, delivered, Acquisition.Plan);
        return new(_run, _schedule, _productionArchive, acquisition, _truthHorizon);
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
