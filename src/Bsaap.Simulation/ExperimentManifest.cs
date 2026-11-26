using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bsaap.Simulation;

public sealed record RuntimeDescription(string Framework, string OperatingSystem, string Architecture)
{
    public static RuntimeDescription Current() =>
        new(RuntimeInformation.FrameworkDescription, RuntimeInformation.OSDescription,
            RuntimeInformation.ProcessArchitecture.ToString());
}

public sealed record ExperimentManifest(
    string SchemaVersion, string GeneratorVersion, string SourceCommitSha, string FrozenGate2CommitSha,
    ulong Seed, string Scenario, RuntimeDescription Runtime, SimulationConfiguration Configuration,
    string ConfigurationSha256)
{
    public const string FrozenGate2 = "ac1b997f3732483ae8d6df60774458111703f0eb";

    // The harness supplies its checked-out, clean source commit. It must retain this
    // manifest outside the classifier input. No wall-clock fields affect replay.
    public static ExperimentManifest Create(SimulationConfiguration configuration, string sourceCommitSha,
        RuntimeDescription? runtime = null)
    {
        configuration.Validate();
        if (sourceCommitSha is null || sourceCommitSha.Length != 40 || !sourceCommitSha.All(Uri.IsHexDigit))
            throw new ArgumentException("A full Git source commit SHA is required.", nameof(sourceCommitSha));
        string json = JsonSerializer.Serialize(configuration);
        string digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
        return new("BSAAP-EXPERIMENT/1", "sha256-counter-v1", sourceCommitSha.ToLowerInvariant(),
            FrozenGate2, configuration.Seed, configuration.Scenario, runtime ?? RuntimeDescription.Current(),
            configuration, digest);
    }

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
}
