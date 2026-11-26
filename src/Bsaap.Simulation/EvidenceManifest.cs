using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Bsaap.Simulation;

// Owner-only provenance. The archive hash pins real signatures, public keys and
// nonces for exact replay. Private signing keys are never serialized.
public sealed record EvidenceManifest(
    string SchemaVersion, ExperimentManifest Workload, ProtocolSchedule Protocol,
    AcquisitionPlan Acquisition, string ArchiveSha256, string ConfigurationSha256)
{
    public static EvidenceManifest Create(SimulationConfiguration workload, ProtocolSchedule protocol,
        AcquisitionPlan acquisition, ProtocolArchive archive, string sourceCommitSha)
    {
        var baseManifest = ExperimentManifest.Create(workload, sourceCommitSha);
        var configuration = JsonSerializer.Serialize(new { Workload = workload, Protocol = protocol, Acquisition = acquisition });
        return new("BSAAP-EVIDENCE/1", baseManifest, protocol, acquisition, Hash(archive.Serialize()), Hash(configuration));
    }

    public void VerifyArchive(ProtocolArchive archive)
    {
        if (Hash(archive.Serialize()) != ArchiveSha256)
            throw new ArgumentException("Protocol archive does not match the manifest.");
        var configuration = JsonSerializer.Serialize(new { Workload = Workload.Configuration, Protocol, Acquisition });
        if (Hash(configuration) != ConfigurationSha256)
            throw new ArgumentException("Evidence configuration does not match its digest.");
    }

    public string ToJson() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
    private static string Hash(string json) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
}
