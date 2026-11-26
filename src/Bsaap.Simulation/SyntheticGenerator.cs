using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Simulation;

public static class SyntheticGenerator
{
    // SHA-256 counter derivation avoids dependence on System.Random implementation versions.
    private static byte[] Derive(ulong seed, string domain, int ordinal)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8);
        writer.Write("BSAAP-SIM/1");
        writer.Write(seed);
        writer.Write(domain);
        writer.Write(ordinal);
        writer.Flush();
        return SHA256.HashData(stream.ToArray());
    }

    public static ImmutableArray<SyntheticEvent> Generate(SimulationConfiguration configuration)
    {
        configuration.Validate();
        var events = ImmutableArray.CreateBuilder<SyntheticEvent>();
        var sequences = configuration.Corridors.ToDictionary(c => c, _ => 0UL, StringComparer.Ordinal);
        for (int transaction = 0; transaction < configuration.TransactionCount; transaction++)
        {
            string corridor = configuration.Corridors[transaction % configuration.Corridors.Length];
            var id = new TransactionId(new Guid(Derive(configuration.Seed, "transaction", transaction).AsSpan(0, 16)));
            var material = Derive(configuration.Seed, "payment", transaction);
            long amount = 1 + BinaryPrimitives.ReadUInt32LittleEndian(material) % 100_000;
            SyntheticEventType[] types = [
                SyntheticEventType.Pacs008Dispatch, SyntheticEventType.TransportAck,
                SyntheticEventType.Pacs002Actc,
                material[4] % 5 == 0 ? SyntheticEventType.Pacs002Rjct : SyntheticEventType.Pacs002Accc];
            for (int stage = 0; stage < types.Length; stage++)
            {
                int ordinal = checked(transaction * 4 + stage);
                events.Add(new(id,
                    new EventId(new Guid(Derive(configuration.Seed, "event", ordinal).AsSpan(0, 16))),
                    corridor, new CorridorSequence(++sequences[corridor]), types[stage],
                    checked(configuration.StartTime + transaction * configuration.TransactionSpacing +
                        stage * configuration.EventSpacing),
                    amount, "XTS", "SYNTHETIC-DEBTOR", "SYNTHETIC-CREDITOR"));
            }
        }
        return events.ToImmutable();
    }
}
