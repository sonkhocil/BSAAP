using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Bsaap.ControlledPilot;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;

if (args.Length != 2)
    throw new ArgumentException("Supply output directory and clean implementation SHA, or --replay and an input file.");
if (Debugger.IsAttached) throw new InvalidOperationException("Attached debugger prohibits pilot measurement.");
if (args[0] == "--replay")
{
    var saved = PilotStorage.Load(Path.GetFullPath(args[1]));
    Provenance.RequireCleanCommit(saved.Manifest.Workload.SourceCommitSha);
    var replay = PilotExecution.Run(saved, saved.Definition.Condition, 0);
    Console.WriteLine(JsonSerializer.Serialize(replay, PilotStorage.JsonOptions()));
    return;
}
#if DEBUG
if (args.Length == 2) throw new InvalidOperationException("Controlled pilots require a Release build.");
#endif
Provenance.RequireCleanCommit(args[1]);
string directory = Path.GetFullPath(args[0]);
string sourceSha = args[1];
Directory.CreateDirectory(directory);
var options = PilotStorage.JsonOptions();
var archives = new Dictionary<string, string>(StringComparer.Ordinal);
var productions = new List<ArtifactProductionCost>();
var results = ImmutableArray.CreateBuilder<PilotCaseResult>();
ulong[] seeds = [2027, 2028];
// These are feasibility epochs. The two public event queries are fixed independently
// of faults; snapshots continue to contain the complete nominal 100/1,000-leaf log.
int[] sizes = [25, 250];
var cases = Enum.GetValues<PilotCondition>();
int runIndex = 0;
foreach (ulong seed in seeds)
foreach (int size in sizes)
foreach (var condition in cases)
{
    var definition = PilotScenarios.Create(seed, size, condition);
    string productionKey = PilotExecution.Hash(JsonSerializer.Serialize(new { definition.Workload, definition.Protocol }));
    if (!archives.TryGetValue(productionKey, out var archiveJson))
    {
        var generated = Measurement.Capture(() => SimulationRun.Create(definition.Workload));
        var produced = Measurement.Capture(() => ProtocolArchive.Create(generated.Value, definition.Protocol));
        archiveJson = produced.Value.Serialize();
        archives.Add(productionKey, archiveJson);
        productions.Add(new(productionKey, PilotExecution.Hash(archiveJson), seed, size, generated.Cost, produced.Cost));
    }
    var archive = ProtocolArchive.Restore(archiveJson);
    var manifest = EvidenceManifest.Create(definition.Workload, definition.Protocol, definition.Acquisition,
        archive, sourceSha);
    var overrides = DeliveredCorruption.Create(condition, archive);
    var input = new PilotReplayInput(definition, manifest, archiveJson, overrides, PilotExecution.HashOverrides(overrides));
    string path = PilotStorage.Save(directory, runIndex + 1, input);
    var saved = PilotStorage.Load(path);
    var result = PilotExecution.Run(saved, condition, runIndex % PilotExecution.Configurations.Length);
    if (results.Any(r => r.Seed == seed && r.Transactions == size && r.Condition == condition))
        throw new InvalidOperationException("Duplicate paired case.");
    results.Add(result);
    runIndex++;
    Console.WriteLine($"Completed {runIndex}/{seeds.Length * sizes.Length * cases.Length} seed={seed} nominalLeaves={size * 4} condition={condition} replay={result.ReplayEquivalent}");
}
if (results.Count != seeds.Length * sizes.Length * cases.Length ||
    results.Any(r => r.Baselines.Length != PilotExecution.Configurations.Length || !r.ReplayEquivalent))
    throw new InvalidOperationException("Missing paired results or replay failures.");

string ReadOptional(string path) => File.Exists(path) ? File.ReadAllText(path).Trim() : "unavailable";
string cpu = File.Exists("/proc/cpuinfo") ? File.ReadLines("/proc/cpuinfo")
    .FirstOrDefault(line => line.StartsWith("model name", StringComparison.Ordinal)) ?? "unavailable" : "unavailable";
var runtime = new
{
    Framework = RuntimeInformation.FrameworkDescription, RuntimeVersion = Environment.Version.ToString(),
    OperatingSystem = RuntimeInformation.OSDescription, RuntimeIdentifier = RuntimeInformation.RuntimeIdentifier,
    Architecture = RuntimeInformation.ProcessArchitecture.ToString(), CpuModel = cpu,
    ProcessorCount = Environment.ProcessorCount, CpuQuota = ReadOptional("/sys/fs/cgroup/cpu.max"),
    MemoryLimit = ReadOptional("/sys/fs/cgroup/memory.max"), ServerGarbageCollection = GCSettings.IsServerGC,
    GarbageCollectionLatency = GCSettings.LatencyMode.ToString(),
    StopwatchFrequency = Stopwatch.Frequency, StopwatchHighResolution = Stopwatch.IsHighResolution,
    DebuggerAttached = Debugger.IsAttached, BuildConfiguration = "Release",
    PilotAssemblyVersion = typeof(PilotExecution).Assembly.GetCustomAttributes(false)
        .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion,
    PilotAssemblySha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
        File.ReadAllBytes(typeof(PilotExecution).Assembly.Location))).ToLowerInvariant(),
    TieredCompilationOverride = Environment.GetEnvironmentVariable("DOTNET_TieredCompilation"),
    ServerGcOverride = Environment.GetEnvironmentVariable("DOTNET_gcServer"),
    HeapHardLimitOverride = Environment.GetEnvironmentVariable("DOTNET_GCHeapHardLimit")
};
var aggregates = cases.SelectMany(condition => PilotExecution.Configurations.Select(baseline => new
{
    Condition = condition, Baseline = baseline,
    Score = PilotExecution.Pool(results.Where(r => r.Condition == condition).SelectMany(r => r.Baselines)
        .Where(r => r.Baseline == baseline).Select(r => r.Score))
})).ToArray();
var report = new
{
    SchemaVersion = "BSAAP-CONTROLLED-PILOT/2", SourceCommitSha = sourceSha,
    FrozenGate2CommitSha = ExperimentManifest.FrozenGate2, Seeds = seeds,
    TransactionCounts = sizes, NominalLeaves = sizes.Select(n => n * 4).ToArray(),
    PublicAuditEventOrdinals = new[] { 0, 1 }, ReceiptObligationEventOrdinals = new[] { 0 },
    Configurations = PilotExecution.Configurations, PilotExecution.WarmupInvocations, PilotExecution.MeasuredRepetitions,
    OmissionPolicy = "ANY obligated operational primary or authenticated committed alternative misses an accepted deadline.",
    EvidenceCoverageDenominator = "Actual positives. Undefined when zero.",
    Measurement = "Synchronous classifier invocation. Full-snapshot authentication is a separate overlapping diagnostic; phase costs must not be summed as end-to-end latency.",
    Runtime = runtime, ArtifactProductions = productions, Aggregates = aggregates, Results = results.ToImmutable()
};
File.WriteAllText(Path.Combine(directory, "results.json"), JsonSerializer.Serialize(report, options) + "\n");
CsvExports.Write(directory, results, productions);
var matrix = new StringBuilder();
matrix.AppendLine("| Condition | Query | B0 | B1 | B1-W | B1-R | B2 |");
matrix.AppendLine("| --- | --- | --- | --- | --- | --- | --- |");
foreach (var run in results.Where(r => r.Seed == seeds[0] && r.Transactions == sizes[0]))
foreach (string query in run.Baselines[0].Predictions.Select(p => p.QueryId))
    matrix.AppendLine("| " + run.Condition + " | " + query + " | " +
        string.Join(" | ", run.Baselines.Select(b => b.Predictions.Single(p => p.QueryId == query).Outcome)) + " |");
File.WriteAllText(Path.Combine(directory, "verdict-matrix.md"), matrix.ToString());
Console.WriteLine($"Saved {results.Count} paired cases, {results.Sum(r => r.Baselines.Length)} baseline results, " +
    $"{results.Sum(r => r.Baselines.Sum(b => b.Samples.Length))} timing samples and {productions.Count} unique artifact productions.");
