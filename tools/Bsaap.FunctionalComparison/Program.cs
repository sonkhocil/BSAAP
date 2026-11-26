using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bsaap.Baselines;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;

if (args.Length != 2)
    throw new ArgumentException("Supply an output directory and the full clean implementation commit SHA.");
string outputDirectory = Path.GetFullPath(args[0]);
string sourceSha = args[1];
Directory.CreateDirectory(outputDirectory);
var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
jsonOptions.Converters.Add(new JsonStringEnumConverter());
var records = new List<ComparisonResult>();
var negativeControls = new List<ComparisonResult>();
var matrix = new StringBuilder();
matrix.AppendLine("| Scenario | Claim | B0 | B1 | B1-W | B2 |");
matrix.AppendLine("| --- | --- | --- | --- | --- | --- |");
Scenario[] scenarios = [
    new("Compliant", []),
    new("Proven omission", [new(FaultKind.Omission, 0)]),
    new("Missing ACK", [new(FaultKind.Omission, 0)], AckDisclosed: false),
    new("Hidden fork", [new(FaultKind.Equivocation, 0)]),
    new("Disclosed fork", [new(FaultKind.Equivocation, 0)], ForkDisclosed: true),
    new("Forged checkpoint", [], CorruptArtifact: "head"),
    new("Invalid witness", [], CorruptArtifact: "witness"),
    new("Missing evidence", [], MissingEvidence: true),
    new("Late retry", [new(FaultKind.Crash, Start: 100_000, End: 110_000),
        new(FaultKind.Retry, 0, Delay: 60_000)])
];
for (int index = 0; index < scenarios.Length; index++)
{
    var scenario = scenarios[index];
    var workload = new SimulationConfiguration(2027, "gate3c-functional", 1, ["SYN-A-B"],
        100_000, 40_000, 10_000, scenario.Faults);
    var schedule = Protocol();
    var plan = Collection(scenario);
    var owner = ExperimentOwner.Create(workload, schedule, plan, new(300_000));
    var archive = ProtocolArchive.Restore(owner.CaptureArchive());
    var manifest = EvidenceManifest.Create(workload, schedule, plan, archive, sourceSha);
    // Bootstrap is provisioned from original production keys before corruption.
    var bootstrap = new TrustedPublicKeyBootstrap(owner.ExportTrustedPublicKeys());
    var overrides = ImmutableDictionary<string, string>.Empty;
    if (scenario.CorruptArtifact is not null)
    {
        string body = DeliveredCorruption(scenario.CorruptArtifact, archive.Serialize());
        overrides = overrides.Add(scenario.CorruptArtifact, body);
        owner = owner.WithDeliveredArtifactBodies(overrides);
    }
    var clock = new VerificationClock(1_800_000_000, 1_800_001_000);
    var predictions = ClassifyAll(owner, bootstrap, clock);
    var context = owner.Acquisition.ProjectB1("reviewer").Context;
    var omission = context.Targets.First(q => q.Kind == ClaimKind.OmissionPolicyViolation);
    var equivocation = context.Targets.Single(q => q.Kind == ClaimKind.SignedLogEquivocation);
    matrix.AppendLine("| " + scenario.Name + " | Omission | " +
        string.Join(" | ", predictions.Select(p => p.Single(result => result.QueryId == omission.QueryId).Outcome)) + " |");
    matrix.AppendLine("| " + scenario.Name + " | Equivocation | " +
        string.Join(" | ", predictions.Select(p => p.Single(result => result.QueryId == equivocation.QueryId).Outcome)) + " |");
    for (int baseline = 0; baseline < predictions.Length; baseline++)
        records.Add(new(scenario.Name, (BaselineId)baseline, predictions[baseline],
            owner.Score("reviewer", (BaselineId)baseline, predictions[baseline], new(1_000_000))));
    var alwaysAccuse = context.Targets.Select(query =>
        new Prediction(query.QueryId, AssessmentOutcome.Accusation, "Always-accuse negative control.")).ToImmutableArray();
    negativeControls.Add(new(scenario.Name, BaselineId.B2, alwaysAccuse,
        owner.Score("reviewer", BaselineId.B2, alwaysAccuse, new(1_000_000))));
    var replayInput = new ReplayInput(manifest, archive.Serialize(), overrides);
    string replayJson = JsonSerializer.Serialize(replayInput, jsonOptions);
    File.WriteAllText(Path.Combine(outputDirectory, $"scenario-{index + 1}.json"), replayJson + "\n");

    // Replay the serialized owner inputs and verify all four classifiers.
    var saved = JsonSerializer.Deserialize<ReplayInput>(replayJson, jsonOptions)!;
    var replay = ExperimentOwner.Replay(saved.Manifest, saved.ProductionArchive, new(300_000))
        .WithDeliveredArtifactBodies(saved.DeliveredBodyOverrides);
    var replayTrust = new TrustedPublicKeyBootstrap(replay.ExportTrustedPublicKeys());
    var replayPredictions = ClassifyAll(replay, replayTrust, clock);
    for (int baseline = 0; baseline < predictions.Length; baseline++)
    {
        if (!predictions[baseline].SequenceEqual(replayPredictions[baseline]))
            throw new InvalidOperationException("Functional replay changed classifications.");
    }
}
File.WriteAllText(Path.Combine(outputDirectory, "verdict-matrix.md"), matrix.ToString());
File.WriteAllText(Path.Combine(outputDirectory, "results.json"),
    JsonSerializer.Serialize(new { SourceCommitSha = sourceSha, Seed = 2027, Results = records, AlwaysAccuseNegativeControl = negativeControls }, jsonOptions) + "\n");
Console.Write(matrix.ToString());
Console.WriteLine($"Completed {scenarios.Length} functional scenarios and {records.Count} baseline evaluations.");

static ImmutableArray<Prediction>[] ClassifyAll(ExperimentOwner owner,
    TrustedPublicKeyBootstrap bootstrap, VerificationClock clock) =>
[
    new B0Classifier().Classify(owner.Acquisition.ProjectB0("reviewer")),
    new B1Classifier(bootstrap, clock).Classify(owner.Acquisition.ProjectB1("reviewer")),
    new B1WitnessClassifier(bootstrap, clock).Classify(owner.Acquisition.ProjectB1Witness("reviewer")),
    new B2Classifier(bootstrap, clock).Classify(owner.Acquisition.ProjectB2("reviewer"))
];

static ProtocolSchedule Protocol() => new(new(1_800_000_000),
    [new("obligation", 0, "B", new(90_000), new(150_000), new(95_000), new(95_000))],
    [new("challenge", "obligation", new(160_000), new(200_000))],
    [new("head", "A", "SYN-A-B", "primary", new(170_000), "challenge"),
     new("fork", "A", "SYN-A-B", "alternate", new(170_000), "challenge"),
     new("peer", "B", "SYN-A-B", "primary", new(170_000))],
    [new("witness", "head", new(180_000), new(180_000))]);

static AcquisitionPlan Collection(Scenario scenario)
{
    ImmutableArray<DisclosureRule> rules = [
        new("reviewer", "b", "obligation"), new("reviewer", "b", "peer"),
        new("reviewer", "b", "peer/snapshot"), new("reviewer", "a", "head"),
        new("reviewer", "a", "head/snapshot"), new("reviewer", "w", "witness"),
        new("reviewer", "aud", "challenge")];
    if (scenario.AckDisclosed) rules = rules.Add(new("reviewer", "a", "obligation/ack"));
    if (scenario.ForkDisclosed) rules = rules.Add(new("reviewer", "a", "fork"));
    if (scenario.MissingEvidence) rules = [];
    return new(new(4, 6), [new("reviewer", "A", new(210_000),
        [new("a", "A", CollectionChannel.Direct, new(170_000), new(210_000)),
         new("b", "B", CollectionChannel.Direct, new(160_000), new(210_000)),
         new("w", "W", CollectionChannel.Direct, new(180_000), new(210_000)),
         new("aud", "AUDITOR", CollectionChannel.Direct, new(160_000), new(210_000))])], rules);
}

static string DeliveredCorruption(string artifactId, string ownerArchive)
{
    // Archive routing metadata stays in the owner runner. The classifiers receive
    // only projected bodies, and their trust bootstrap is never replaced.
    using var parsed = JsonDocument.Parse(ownerArchive);
    string body = parsed.RootElement.GetProperty("Artifacts").EnumerateArray()
        .Single(a => a.GetProperty("Id").GetString() == artifactId).GetProperty("Json").GetString()!;
    if (artifactId == "head")
    {
        var head = new SignedEvidence<SignedTreeHead>(body).Read();
        return JsonSerializer.Serialize(head with { Signature = new byte[64] });
    }
    var witness = new SignedEvidence<WitnessAttestation>(body).Read();
    return JsonSerializer.Serialize(witness with { Signature = new byte[64] });
}

sealed record Scenario(string Name, ImmutableArray<FaultRule> Faults,
    bool AckDisclosed = true, bool ForkDisclosed = false, bool MissingEvidence = false, string? CorruptArtifact = null);
sealed record ComparisonResult(string Scenario, BaselineId Baseline,
    ImmutableArray<Prediction> Predictions, ScoreReport Score);
sealed record ReplayInput(EvidenceManifest Manifest, string ProductionArchive,
    ImmutableDictionary<string, string> DeliveredBodyOverrides);
