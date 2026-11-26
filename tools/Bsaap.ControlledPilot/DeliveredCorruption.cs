using System.Collections.Immutable;
using System.Text.Json;
using Bsaap.ForensicLog.Contracts;
using Bsaap.Simulation;
using Bsaap.Simulation.Contracts;

namespace Bsaap.ControlledPilot;

public static class DeliveredCorruption
{
    public static ImmutableDictionary<string, string> Create(PilotCondition condition, ProtocolArchive archive)
    {
        string? id = condition switch
        {
            PilotCondition.ForgedCheckpoint => "head",
            PilotCondition.ForgedAck => "obligation/ack",
            PilotCondition.InvalidWitness => "witness",
            _ => null
        };
        if (id is null) return ImmutableDictionary<string, string>.Empty;
        using var document = JsonDocument.Parse(archive.Serialize());
        string json = document.RootElement.GetProperty("Artifacts").EnumerateArray()
            .Single(a => a.GetProperty("Id").GetString() == id).GetProperty("Json").GetString()!;
        string changed = condition switch
        {
            PilotCondition.ForgedCheckpoint => JsonSerializer.Serialize(
                new SignedEvidence<SignedTreeHead>(json).Read() with { Signature = new byte[64] }),
            PilotCondition.ForgedAck => JsonSerializer.Serialize(
                new SignedEvidence<SignedLoggingObligation>(json).Read() with { TargetAckSignature = new byte[64] }),
            _ => JsonSerializer.Serialize(
                new SignedEvidence<WitnessAttestation>(json).Read() with { Signature = new byte[64] })
        };
        return ImmutableDictionary<string, string>.Empty.Add(id, changed);
    }
}
