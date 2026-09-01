using CFScanner;
using CFScanner.Core;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class PauseManagerTests
{
    [Fact, Trait("Category", "Unit")]
    public void IsPaused_StartsFalseAfterReset()
    {
        TestState.Reset();
        Assert.False(PauseManager.IsPaused);
    }

    [Fact, Trait("Category", "Unit")]
    public void Toggle_FlipsStateAndStopsStopwatch()
    {
        TestState.Reset();
        GlobalContext.Stopwatch.Restart();
        Assert.True(GlobalContext.Stopwatch.IsRunning);

        PauseManager.Toggle();
        Assert.True(PauseManager.IsPaused);
        Assert.False(GlobalContext.Stopwatch.IsRunning);

        PauseManager.Toggle();
        Assert.False(PauseManager.IsPaused);
        Assert.True(GlobalContext.Stopwatch.IsRunning);

        GlobalContext.Stopwatch.Stop();
    }

    [Fact, Trait("Category", "Unit")]
    public async Task WaitIfPausedAsync_NotPaused_ReturnsImmediately()
    {
        TestState.Reset();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await PauseManager.WaitIfPausedAsync(CancellationToken.None);
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < 100);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task WaitIfPausedAsync_PausedButImmediatelyCancelled_DoesNotBlock()
    {
        TestState.Reset();
        PauseManager.Toggle();
        try
        {
            using var cts = new CancellationTokenSource();
            cts.Cancel();
            var sw = System.Diagnostics.Stopwatch.StartNew();
            // Loop exits because !IsCancellationRequested is false on the next check,
            // so the method returns silently without throwing.
            await PauseManager.WaitIfPausedAsync(cts.Token);
            sw.Stop();
            Assert.True(sw.ElapsedMilliseconds < 200,
                $"wait loop did not honour cancellation promptly: {sw.ElapsedMilliseconds}ms");
        }
        finally { PauseManager.Reset(); }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task WaitIfPausedAsync_ResumesOnceUnpaused()
    {
        TestState.Reset();
        PauseManager.Toggle();
        var resumeTask = Task.Run(async () =>
        {
            await Task.Delay(120);
            PauseManager.Toggle(); // unpause
        });
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await PauseManager.WaitIfPausedAsync(CancellationToken.None);
        sw.Stop();
        PauseManager.Reset();

        // Should have waited ~120ms but not indefinitely.
        Assert.True(sw.ElapsedMilliseconds >= 100, $"waited {sw.ElapsedMilliseconds}ms");
        Assert.True(sw.ElapsedMilliseconds < 2000, $"waited {sw.ElapsedMilliseconds}ms (too long)");
        await resumeTask;
    }

    [Fact, Trait("Category", "Unit")]
    public void Reset_FromPausedStateRestoresRunning()
    {
        TestState.Reset();
        GlobalContext.Stopwatch.Restart();
        PauseManager.Toggle();
        Assert.True(PauseManager.IsPaused);
        Assert.False(GlobalContext.Stopwatch.IsRunning);

        PauseManager.Reset();
        Assert.False(PauseManager.IsPaused);
        Assert.True(GlobalContext.Stopwatch.IsRunning);
        GlobalContext.Stopwatch.Stop();
    }
}