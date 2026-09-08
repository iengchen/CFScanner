using CFScanner;
using CFScanner.Core;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class GlobalContextCounterTests
{
    [Fact, Trait("Category", "Unit")]
    public void Increment_SingleThreaded_IsVisibleImmediately()
    {
        TestState.Reset();
        Assert.Equal(0, GlobalContext.ScannedCount);
        GlobalContext.IncrementScannedCount();
        GlobalContext.IncrementScannedCount();
        Assert.Equal(2, GlobalContext.ScannedCount);

        Assert.Equal(0, GlobalContext.TcpOpenTotal);
        GlobalContext.IncrementTcpOpenTotal();
        Assert.Equal(1, GlobalContext.TcpOpenTotal);

        Assert.Equal(0, GlobalContext.SignaturePassed);
        GlobalContext.IncrementSignaturePassed();
        Assert.Equal(1, GlobalContext.SignaturePassed);

        Assert.Equal(0, GlobalContext.V2RayPassed);
        GlobalContext.IncrementV2RayPassed();
        Assert.Equal(1, GlobalContext.V2RayPassed);

        Assert.Equal(0, GlobalContext.SpeedTestPassed);
        GlobalContext.IncrementSpeedTestPassed();
        Assert.Equal(1, GlobalContext.SpeedTestPassed);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task Increment_Concurrent_ProducesExactSum()
    {
        TestState.Reset();
        const int parallel = 8;
        const int perWorker = 5000;

        var tasks = Enumerable.Range(0, parallel)
            .Select(_ => Task.Run(() =>
            {
                for (int i = 0; i < perWorker; i++)
                {
                    GlobalContext.IncrementScannedCount();
                    GlobalContext.IncrementTcpOpenTotal();
                    GlobalContext.IncrementSignaturePassed();
                    GlobalContext.IncrementV2RayPassed();
                    GlobalContext.IncrementSpeedTestPassed();
                }
            }))
            .ToArray();
        await Task.WhenAll(tasks);

        int expected = parallel * perWorker;
        Assert.Equal(expected, GlobalContext.ScannedCount);
        Assert.Equal(expected, GlobalContext.TcpOpenTotal);
        Assert.Equal(expected, GlobalContext.SignaturePassed);
        Assert.Equal(expected, GlobalContext.V2RayPassed);
        Assert.Equal(expected, GlobalContext.SpeedTestPassed);
    }

    [Fact, Trait("Category", "Unit")]
    public void ResetCounters_ZerosAllCounters()
    {
        TestState.Reset();
        GlobalContext.IncrementScannedCount();
        GlobalContext.IncrementTcpOpenTotal();
        GlobalContext.IncrementSignaturePassed();
        GlobalContext.IncrementV2RayPassed();
        GlobalContext.IncrementSpeedTestPassed();
        Assert.NotEqual(0, GlobalContext.ScannedCount);

        GlobalContext.ResetCounters();

        Assert.Equal(0, GlobalContext.ScannedCount);
        Assert.Equal(0, GlobalContext.TcpOpenTotal);
        Assert.Equal(0, GlobalContext.SignaturePassed);
        Assert.Equal(0, GlobalContext.V2RayPassed);
        Assert.Equal(0, GlobalContext.SpeedTestPassed);
    }

    [Fact, Trait("Category", "Unit")]
    public void RestoreCounters_LoadsCheckpointStatistics()
    {
        TestState.Reset();
        GlobalContext.RestoreCounters(new CheckpointStats
        {
            Scanned = 42,
            TcpOpen = 11,
            SignaturePassed = 7,
            V2RayPassed = 3,
            SpeedTestPassed = 2
        });

        Assert.Equal(42, GlobalContext.ScannedCount);
        Assert.Equal(11, GlobalContext.TcpOpenTotal);
        Assert.Equal(7, GlobalContext.SignaturePassed);
        Assert.Equal(3, GlobalContext.V2RayPassed);
        Assert.Equal(2, GlobalContext.SpeedTestPassed);
    }

    [Fact, Trait("Category", "Unit")]
    public void RestoreCounters_PreservesValuesBeyondInt32MaxValue()
    {
        TestState.Reset();
        const long large = (long)int.MaxValue + 42;

        GlobalContext.RestoreCounters(new CheckpointStats
        {
            Scanned = large,
            TcpOpen = large,
            SignaturePassed = large,
            V2RayPassed = large,
            SpeedTestPassed = large
        });

        Assert.Equal(large, GlobalContext.ScannedCount);
        Assert.Equal(large, GlobalContext.TcpOpenTotal);
        Assert.Equal(large, GlobalContext.SignaturePassed);
        Assert.Equal(large, GlobalContext.V2RayPassed);
        Assert.Equal(large, GlobalContext.SpeedTestPassed);
    }

    [Fact, Trait("Category", "Unit")]
    public void TotalIpsAndModeRoundTrip()
    {
        TestState.Reset();
        GlobalContext.TotalIps = 12345;
        GlobalContext.IsInfiniteMode = true;
        Assert.Equal(12345, GlobalContext.TotalIps);
        Assert.True(GlobalContext.IsInfiniteMode);
    }
}
