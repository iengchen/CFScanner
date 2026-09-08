using CFScanner;
using CFScanner.Core;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class InfiniteResumeTests
{
    [Fact]
    public void InfiniteResume_ReplaysIssuedButUnfinishedTargetsBeforeNewOnes()
    {
        TestState.Reset();
        GlobalContext.IsInfiniteMode = true;
        GlobalContext.Config.Ports = [443];
        GlobalContext.ResumeGenerator = new DeterministicRandomIpv4Generator(12345);

        var issued = GlobalContext.GenerateResumableInfiniteIps().Take(3).ToArray();
        GlobalContext.MarkResumeSequenceCompleted(0);
        var checkpoint = GlobalContext.CaptureInfiniteResumeState();

        Assert.Equal(new[] { issued[1].ToString(), issued[2].ToString() }, checkpoint.PendingIps);

        TestState.Reset();
        GlobalContext.IsInfiniteMode = true;
        GlobalContext.Config.Ports = [443];
        GlobalContext.ResumeGenerator = new DeterministicRandomIpv4Generator(
            checkpoint.Seed, checkpoint.State, checkpoint.ValuesConsumed, checkpoint.Rejections);
        GlobalContext.RestoreInfinitePendingIps(checkpoint.PendingIps);

        var resumed = GlobalContext.GenerateResumableInfiniteIps().Take(3).ToArray();

        Assert.Equal(issued[1], resumed[0]);
        Assert.Equal(issued[2], resumed[1]);
        Assert.NotEqual(issued[2], resumed[2]);
    }
}
