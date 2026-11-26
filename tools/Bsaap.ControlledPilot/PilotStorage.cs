using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Serialization;
using Bsaap.Simulation;

namespace Bsaap.ControlledPilot;

public sealed record SavedPilotCase(
    string SchemaVersion, PilotDefinition Definition, EvidenceManifest Manifest,
    string ArchiveRelativePath, string ArchiveFileSha256,
    System.Collections.Immutable.ImmutableDictionary<string, string> DeliveredBodyOverrides, string OverridesSha256);

public static class PilotStorage
{
    public static JsonSerializerOptions JsonOptions()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }

    public static string Save(string directory, int index, PilotReplayInput input)
    {
        Directory.CreateDirectory(Path.Combine(directory, "archives"));
        string relative = "archives/" + input.Manifest.ArchiveSha256 + ".json.gz";
        string archivePath = Path.Combine(directory, relative);
        if (!File.Exists(archivePath))
        {
            using var file = File.Create(archivePath);
            using var gzip = new GZipStream(file, CompressionLevel.SmallestSize);
            using var writer = new StreamWriter(gzip);
            writer.Write(input.ProductionArchive);
        }
        string compressedHash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(archivePath))).ToLowerInvariant();
        var overrides = input.DeliveredBodyOverrides ??
            System.Collections.Immutable.ImmutableDictionary<string, string>.Empty;
        var saved = new SavedPilotCase("BSAAP-PILOT-INPUT/2", input.Definition, input.Manifest, relative,
            compressedHash, overrides, PilotExecution.HashOverrides(overrides));
        string path = Path.Combine(directory, $"input-{index:D3}.json");
        File.WriteAllText(path, JsonSerializer.Serialize(saved, JsonOptions()) + "\n");
        return path;
    }

    public static PilotReplayInput Load(string path)
    {
        var saved = JsonSerializer.Deserialize<SavedPilotCase>(File.ReadAllText(path), JsonOptions())
            ?? throw new ArgumentException("Missing pilot input.");
        if (saved.SchemaVersion != "BSAAP-PILOT-INPUT/2" || Path.IsPathRooted(saved.ArchiveRelativePath))
            throw new ArgumentException("Unsupported input schema or archive reference.");
        string root = Path.GetDirectoryName(Path.GetFullPath(path))!;
        string archivePath = Path.GetFullPath(Path.Combine(root, saved.ArchiveRelativePath));
        if (!archivePath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new ArgumentException("Archive reference escapes the replay directory.");
        string hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(archivePath))).ToLowerInvariant();
        if (hash != saved.ArchiveFileSha256) throw new ArgumentException("Compressed archive digest mismatch.");
        using var file = File.OpenRead(archivePath);
        using var gzip = new GZipStream(file, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip);
        string archive = reader.ReadToEnd();
        saved.Manifest.VerifyArchive(ProtocolArchive.Restore(archive));
        if (PilotExecution.HashOverrides(saved.DeliveredBodyOverrides) != saved.OverridesSha256)
            throw new ArgumentException("Delivery override digest mismatch.");
        return new(saved.Definition, saved.Manifest, archive, saved.DeliveredBodyOverrides, saved.OverridesSha256);
    }
}
