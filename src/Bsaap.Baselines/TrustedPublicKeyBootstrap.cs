using System.Collections.Immutable;
using Bsaap.ForensicLog.Contracts;
using Bsaap.ForensicLog.Engine;
using Bsaap.Simulation.Contracts;

namespace Bsaap.Baselines;

// Construct this from an authenticated provisioning channel before giving the
// classifier any evidence. Evidence cannot register keys or change authorization.
public sealed class TrustedPublicKeyBootstrap
{
    private readonly TrustedKeyRegistry _registry = new();
    public ImmutableArray<TrustedPublicSigner> Signers { get; }

    public TrustedPublicKeyBootstrap(ImmutableArray<TrustedPublicSigner> signers)
    {
        if (signers.IsDefaultOrEmpty || signers.Any(s => s is null ||
            s.Gateways.IsDefault || s.Logs.IsDefault || s.Corridors.IsDefault))
            throw new ArgumentException("Explicit public-key provisioning is required.", nameof(signers));
        Signers = signers;
        foreach (var signer in signers)
            _registry.RegisterSigner(signer.Id, Convert.FromBase64String(signer.SubjectPublicKeyInfo),
                signer.Role, signer.Gateways, signer.Logs, signer.Corridors);
    }

    internal ITrustedKeyRegistry VerificationKeys => _registry;
}

// Seconds are compatible with the frozen Gate 2 contracts. Logical simulation
// timestamps are converted explicitly, without consulting wall-clock time.
public sealed record VerificationClock(long LogicalEpochUnixSeconds, long VerificationUnixSeconds)
{
    public long UnixSeconds(LogicalInstant instant)
    {
        if (LogicalEpochUnixSeconds < 0 || instant.Milliseconds < 0 || instant.Milliseconds % 1000 != 0)
            throw new ArgumentException("Verification requires second-aligned logical instants.");
        return checked(LogicalEpochUnixSeconds + instant.Milliseconds / 1000);
    }

    internal void Validate(AuditContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Targets.IsDefault || VerificationUnixSeconds < UnixSeconds(context.CollectionCutoff))
            throw new ArgumentException("Verification must follow collection.");
    }
}
