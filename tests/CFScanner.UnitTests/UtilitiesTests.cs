using System.Net;
using CFScanner;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class UtilitiesTests
{
    [Fact, Trait("Category", "Unit")]
    public void IpConversion_RoundTripsBoundaries()
    {
        foreach (var text in new[] { "0.0.0.0", "1.2.3.4", "255.255.255.255" })
            Assert.Equal(text, NetUtils.UintToIp(NetUtils.IpToUint(IPAddress.Parse(text))).ToString());
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_UsesStartAndCap()
    {
        Assert.Equal(new[] { "192.0.2.8", "192.0.2.9", "192.0.2.10", "192.0.2.11" },
            NetUtils.ExpandCidr("192.0.2.8/30").Select(x => x.ToString()));
        Assert.Equal(Defaults.CidrExpandCap, NetUtils.ExpandCidr("198.51.100.0/8").Count());
    }

    [Fact, Trait("Category", "Unit")]
    public async Task IpFilter_MergesRangesAndChecksBoundaries()
    {
        var filter = new IpFilter();
        await filter.BuildAsync([], ["203.0.113.0/25", "203.0.113.64/26"], [], "missing.tsv");
        Assert.Equal(1, filter.RangeCount);
        Assert.True(filter.IsBlocked(IPAddress.Parse("203.0.113.0")));
        Assert.True(filter.IsBlocked(IPAddress.Parse("203.0.113.127")));
        Assert.False(filter.IsBlocked(IPAddress.Parse("203.0.113.128")));
    }

    [Fact, Trait("Category", "Unit")]
    public void ArgParser_AppliesOverridesAndAutoBuffers()
    {
        var c = GlobalContext.Config;
        c.InputFiles.Clear(); c.InputAsns.Clear(); c.InputCidrs.Clear();
        c.Ports = [Defaults.Port]; c.TcpWorkers = Defaults.TcpWorkers;
        c.SpeedTestWorkers = Defaults.SpeedTestWorkers; c.SpeedTestBuffer = Defaults.SpeedTestBuffer;
        c.SaveLatency = true; c.Shuffle = false; c.SortResults = false; c.RandomSNI = false;
        Assert.True(ArgParser.ParseArguments(["--fast", "--tcp-workers", "7", "--speed-workers", "3",
            "--port", "443,8443,443", "-r", "192.0.2.1", "-y", "--no-latency", "--shuffle", "--sort", "--random-sni", "-vc", "xray.json"]));
        Assert.Equal(7, c.TcpWorkers); Assert.Equal(100, c.TcpChannelBuffer);
        Assert.Equal(4, c.SpeedTestBuffer); Assert.Equal([443, 8443], c.Ports);
        Assert.False(c.SaveLatency); Assert.True(c.Shuffle); Assert.True(c.SortResults); Assert.True(c.RandomSNI);
    }
}
