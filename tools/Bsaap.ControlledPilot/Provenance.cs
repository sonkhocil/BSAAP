using System.Diagnostics;

namespace Bsaap.ControlledPilot;

public static class Provenance
{
    public static void RequireCleanCommit(string sourceSha)
    {
        if (sourceSha.Length != 40 || !sourceSha.All(Uri.IsHexDigit))
            throw new ArgumentException("A complete source SHA is required.");
        string informational = typeof(Provenance).Assembly.GetCustomAttributes(false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>().Single().InformationalVersion;
        if (!informational.EndsWith(sourceSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Rebuild the pilot with SourceRevisionId set to the clean source SHA.");
        string actual = Git("rev-parse HEAD").Trim();
        if (!string.Equals(actual, sourceSha, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Source SHA does not match the checked-out commit.");
        if (Git("status --porcelain --untracked-files=no").Length != 0)
            throw new InvalidOperationException("Tracked source changes require a clean implementation commit.");
        // Untracked generated result directories are permitted. Untracked C# or
        // project sources would make the claimed source provenance incomplete.
        string untracked = Git("ls-files --others --exclude-standard");
        if (untracked.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Any(p => p.EndsWith(".cs", StringComparison.OrdinalIgnoreCase) ||
                p.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
                p.EndsWith(".props", StringComparison.OrdinalIgnoreCase) ||
                p.EndsWith(".targets", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Untracked implementation files invalidate provenance.");
    }

    private static string Git(string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo("git", arguments)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        }) ?? throw new InvalidOperationException("Git was unavailable.");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new InvalidOperationException("Git provenance check failed. " + error);
        return output;
    }
}
