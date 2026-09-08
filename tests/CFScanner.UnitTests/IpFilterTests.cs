using System.Net;
using CFScanner;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class IpFilterTests
{
    [Fact, Trait("Category", "Unit")]
    public void IsBlocked_NoRangesReturnsFalse()
    {
        TestState.Reset();
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("8.8.8.8")));
        Assert.False(GlobalContext.IpFilter.IsBlocked(0x01020304u));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_FileWithMalformedLinesIsSkipped()
    {
        TestState.Reset();
        var path = Path.Combine(Path.GetTempPath(), $"cfscanner-filter-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path,
            "# leading comment\n" +
            "10.0.0.0/8 # private\n" +
            "\n" +
            "not-an-ip/24\n" +
            "::1/128\n" +
            "192.0.2.0\n" +          // missing /mask -> skipped (treated as single IP without mask)
            "192.0.2.0/99\n" +        // bad mask
            "192.0.2.128/25\n");      // valid
        try
        {
            await GlobalContext.IpFilter.BuildAsync([path], [], [], "missing.tsv");
            Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.1.2.3")));
            Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("192.0.2.200")));
            Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("192.0.3.1")));
        }
        finally { File.Delete(path); }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_OverlappingAdjacentRangesAreMerged()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], [
            "10.0.0.0/24",     // ..255
            "10.0.0.128/25",   // ..255  (adjacent to previous)
            "10.0.1.0/25"      // ..127  (adjacent to previous)
        ], [], "missing.tsv");

        // All three inputs are adjacent and collapse into a single merged range.
        Assert.Equal(1, GlobalContext.IpFilter.RangeCount);
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.0.255")));
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.1.127")));
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.2.0")));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_DisjointRangesAreKeptSeparate()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], [
            "10.0.0.0/24",
            "10.0.2.0/24",     // gap on 10.0.1.0/24 -> distinct ranges
            "10.0.3.0/26"      // distinct from 10.0.2.0/24
        ], [], "missing.tsv");

        // 10.0.2.0/24 ends at 10.0.2.255; 10.0.3.0/26 starts at 10.0.3.0, which is adjacent,
        // so the merger collapses the second and third input into a single range.
        Assert.Equal(2, GlobalContext.IpFilter.RangeCount);
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.0.5")));
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.1.5")));
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.2.5")));
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.3.10")));
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.0.4.0")));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_SlashZeroBlocksEverything()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], ["0.0.0.0/0"], [], "missing.tsv");
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("8.8.8.8")));
        Assert.True(GlobalContext.IpFilter.IsBlocked(uint.MaxValue));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_SlashZeroMergesWithFollowingRanges()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], [
            "0.0.0.0/0",
            "192.0.2.0/24"
        ], [], "missing.tsv");

        Assert.Equal(1, GlobalContext.IpFilter.RangeCount);
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("203.0.113.10")));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_Slash32BlocksSingleAddress()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], ["192.0.2.42/32"], [], "missing.tsv");
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("192.0.2.42")));
        Assert.True(GlobalContext.IpFilter.IsBlocked(NetUtils.IpToUint(IPAddress.Parse("192.0.2.42"))));
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("192.0.2.43")));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_NormalizesCidrHostBits()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], ["1.2.3.5/30"], [], "missing.tsv");

        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.2.3.4")));
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.2.3.7")));
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.2.3.8")));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_NoAsnDbSkipsAsnProcessing()
    {
        TestState.Reset();
        // Missing ASN DB but valid ASN list must not throw and must produce no ranges.
        await GlobalContext.IpFilter.BuildAsync([], [], ["13335"], "definitely-not-here.tsv");
        Assert.Equal(0, GlobalContext.IpFilter.RangeCount);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_AsnRangeMatchingByNumberAndPrefixAndDescription()
    {
        TestState.Reset();
        var dbPath = Path.Combine(Path.GetTempPath(), $"cfscanner-asn-{Guid.NewGuid():N}.tsv");
        await File.WriteAllTextAsync(dbPath,
            "1.0.0.0\t1.0.0.255\t13335\tCLOUDFLARE INC\n" +
            "1.0.1.0\t1.0.1.255\t12345\tAS12345 Other ASN\n" +
            "8.8.8.0\t8.8.8.255\t15169\tAS15169 GOOGLE LLC\n");
        try
        {
            // 1. ASN number match
            await GlobalContext.IpFilter.BuildAsync([], [], ["13335"], dbPath);
            Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.0.0.5")));
            Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.0.1.100"))); // ASN 12345
            Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("8.8.8.8")));

            TestState.Reset();

            // 2. AS-prefix variant must match the ASN column even when the
            // description does not contain the prefix.
            await GlobalContext.IpFilter.BuildAsync([], [], ["AS13335"], dbPath);
            Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.0.0.1")));

            TestState.Reset();

            // 3. Description fragment match (case insensitive)
            await GlobalContext.IpFilter.BuildAsync([], [], ["google"], dbPath);
            Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("8.8.8.8")));
            Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("1.0.0.1")));
        }
        finally { File.Delete(dbPath); }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildAsync_AsnBlankOrMalformedLinesSkipped()
    {
        TestState.Reset();
        var dbPath = Path.Combine(Path.GetTempPath(), $"cfscanner-asn2-{Guid.NewGuid():N}.tsv");
        await File.WriteAllTextAsync(dbPath,
            "\n" +
            "1.0.0.0 1.0.0.255\n" + // only 2 fields, too short
            "1.0.0.0\t1.0.0.255\t13335\tCLOUDFLARE\n" + // valid
            "garbage line\n");
        try
        {
            await GlobalContext.IpFilter.BuildAsync([], [], ["13335"], dbPath);
            Assert.Equal(1, GlobalContext.IpFilter.RangeCount);
        }
        finally { File.Delete(dbPath); }
    }

    [Fact(Timeout = 5_000), Trait("Category", "Unit")]
    public async Task GetIps_RangeEndingAtUintMaxValueTerminates()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"cfscanner-asn-max-{Guid.NewGuid():N}.tsv");
        await File.WriteAllTextAsync(dbPath, "255.255.255.254\t255.255.255.255\t13335\tTEST\n");
        try
        {
            var ips = IpFilter.IpAsnSource.GetIps(dbPath, ["13335"]).Select(ip => ip.ToString()).ToList();
            Assert.Equal(["255.255.255.254", "255.255.255.255"], ips);
        }
        finally { File.Delete(dbPath); }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task Clear_ResetsAccumulatedRanges()
    {
        TestState.Reset();
        await GlobalContext.IpFilter.BuildAsync([], ["10.0.0.0/8"], [], "missing.tsv");
        Assert.Equal(1, GlobalContext.IpFilter.RangeCount);
        GlobalContext.IpFilter.Clear();
        Assert.Equal(0, GlobalContext.IpFilter.RangeCount);
        Assert.False(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("10.1.2.3")));
    }
}
