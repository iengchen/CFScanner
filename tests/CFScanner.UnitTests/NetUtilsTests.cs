using System.Net;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class NetUtilsTests
{
    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_SingleIpShortcut()
    {
        Assert.Equal(["192.0.2.5"], NetUtils.ExpandCidr("192.0.2.5").Select(x => x.ToString()));
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_Slash31ReturnsBothAddresses()
    {
        Assert.Equal(new[] { "192.0.2.0", "192.0.2.1" },
            NetUtils.ExpandCidr("192.0.2.0/31").Select(x => x.ToString()));
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_Slash32ReturnsSingleAddress()
    {
        Assert.Equal(["192.0.2.7"],
            NetUtils.ExpandCidr("192.0.2.7/32").Select(x => x.ToString()));
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_MalformedMaskYieldsNothing()
    {
        // Bare IP (without /mask) is a valid single-IP shortcut and yields one item.
        Assert.Single(NetUtils.ExpandCidr("192.0.2.0"));
        Assert.Empty(NetUtils.ExpandCidr("192.0.2.0/"));
        Assert.Empty(NetUtils.ExpandCidr("192.0.2.0/abc"));
        Assert.Empty(NetUtils.ExpandCidr("192.0.2.0/33"));
        Assert.Empty(NetUtils.ExpandCidr("not-an-ip/24"));
        Assert.Empty(NetUtils.ExpandCidr("192.0.2.0/-1"));
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_SlashZeroExpandsEntireSpace()
    {
        // /0 is 2^32 IPs and must be capped to the configured limit.
        Assert.Equal(Defaults.CidrExpandCap, NetUtils.ExpandCidr("0.0.0.0/0").Count());
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_NormalizesHostBitsToNetworkBase()
    {
        var ips = NetUtils.ExpandCidr("10.0.0.250/30").Select(x => x.ToString()).ToList();
        Assert.Equal(new[] { "10.0.0.248", "10.0.0.249", "10.0.0.250", "10.0.0.251" }, ips);
    }

    [Fact, Trait("Category", "Unit")]
    public void ExpandCidr_NormalizesHostBitsForLargerAndSlashZeroNetworks()
    {
        Assert.Equal("1.2.3.0", NetUtils.ExpandCidr("1.2.3.5/24").First().ToString());
        Assert.Equal("0.0.0.0", NetUtils.ExpandCidr("1.2.3.5/0").First().ToString());
    }

    [Fact, Trait("Category", "Unit")]
    public void IpToUint_RejectsIPv6()
    {
        Assert.Throws<NotSupportedException>(() =>
            NetUtils.IpToUint(IPAddress.Parse("2001:db8::1")));
    }

    [Fact, Trait("Category", "Unit")]
    public void Shuffle_PreservesAllElements()
    {
        var arr = new uint[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var snapshot = arr.ToArray();
        NetUtils.Shuffle(arr, arr.Length);
        Assert.Equal(snapshot.OrderBy(x => x), arr.OrderBy(x => x));
        Assert.Equal(snapshot.Length, arr.Length);
    }

    [Fact, Trait("Category", "Unit")]
    public void Shuffle_PartialShuffleKeepsTail()
    {
        var arr = new uint[] { 10, 20, 30, 99, 99, 99 };
        NetUtils.Shuffle(arr, 3); // only first three are in the live range
        Assert.Equal(99u, arr[3]);
        Assert.Equal(99u, arr[4]);
        Assert.Equal(99u, arr[5]);
        Assert.Equal(new uint[] { 10, 20, 30 }, arr.Take(3).OrderBy(x => x));
    }

    [Fact, Trait("Category", "Unit")]
    public void GenerateRandomIps_OnlyProducesPublicAddresses()
    {
        TestState.Reset();
        var first = NetUtils.GenerateRandomIps().Take(2000).ToList();
        Assert.NotEmpty(first);

        foreach (var ip in first)
        {
            var b = ip.GetAddressBytes();
            Assert.NotEqual((byte)0, b[0]);
            Assert.NotEqual((byte)10, b[0]);
            Assert.NotEqual((byte)127, b[0]);
            Assert.False(b[0] == 192 && b[1] == 168);
            Assert.False(b[0] == 172 && b[1] >= 16 && b[1] <= 31);
            Assert.True(b[0] < 224);
        }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task GenerateRandomIps_HonorsFilterExclusions()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], ["203.0.113.0/24"], [], "missing.tsv");
        var taken = NetUtils.GenerateRandomIps().Take(5000).ToList();
        Assert.NotEmpty(taken);
        // 203.0.113.x should be excluded; other IPs starting with 203.x.x.x are still valid.
        Assert.DoesNotContain(taken, ip =>
        {
            var b = ip.GetAddressBytes();
            return b[0] == 203 && b[1] == 0 && b[2] == 113;
        });
    }
}
