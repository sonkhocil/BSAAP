using System.Diagnostics;
using System.Runtime;
using Bsaap.Simulation.Contracts;

namespace Bsaap.ControlledPilot;

public sealed record OperationMeasurement(
    long MonotonicTicks, ElapsedDuration Elapsed, long ManagedAllocatedBytes,
    long WorkingSetBeforeBytes, long WorkingSetAfterBytes, long ProcessPeakWorkingSetBytes,
    long ManagedHeapAfterBytes, int Gen0Collections, int Gen1Collections, int Gen2Collections);

public static class Measurement
{
    public static (T Value, OperationMeasurement Cost) Capture<T>(Func<T> operation)
    {
        if (Debugger.IsAttached) throw new InvalidOperationException("Pilot measurement requires a detached debugger.");
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        long before = process.WorkingSet64;
        int gen0 = GC.CollectionCount(0), gen1 = GC.CollectionCount(1), gen2 = GC.CollectionCount(2);
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        long start = Stopwatch.GetTimestamp();
        var value = operation();
        long stop = Stopwatch.GetTimestamp();
        long bytes = GC.GetAllocatedBytesForCurrentThread() - allocated;
        process.Refresh();
        var sample = new OperationMeasurement(stop - start, new(Stopwatch.GetElapsedTime(start, stop)), bytes,
            before, process.WorkingSet64, process.PeakWorkingSet64, GC.GetTotalMemory(false),
            GC.CollectionCount(0) - gen0, GC.CollectionCount(1) - gen1, GC.CollectionCount(2) - gen2);
        return (value, sample);
    }
}
