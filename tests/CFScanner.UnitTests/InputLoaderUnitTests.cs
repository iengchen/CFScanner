using System.Net;
using CFScanner;
using CFScanner.Core;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class InputLoaderTests
{
    [Fact, Trait("Category", "Unit")]
    public async Task LoadTargetsAsync_NoInputs_UsesInfiniteRandomMode()
    {
        TestState.Reset();
        var (source, total, infinite) = await InputLoader.LoadTargetsAsync();
        Assert.True(infinite);
        Assert.Equal(-1, total);

        // Drain a bounded slice; should not throw and should yield IPs.
        var head = source.Take(5).ToList();
        Assert.Equal(5, head.Count);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadTargetsAsync_SingleInlineIpIsIncludedAndDeduplicated()
    {
        TestState.Reset();
        GlobalContext.Config.InputCidrs.Add("192.0.2.1");
        GlobalContext.Config.InputCidrs.Add("192.0.2.1"); // duplicate entry

        var (source, total, infinite) = await InputLoader.LoadTargetsAsync();
        Assert.False(infinite);
        Assert.Equal(1, total);
        Assert.Equal(new[] { "192.0.2.1" }, source.Select(ip => ip.ToString()));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadTargetsAsync_InvalidIpv6InputsAreRejected()
    {
        TestState.Reset();
        GlobalContext.Config.InputCidrs.Add("::1");
        GlobalContext.Config.InputCidrs.Add("::1/128");

        var (_, total, infinite) = await InputLoader.LoadTargetsAsync();

        Assert.False(infinite);
        Assert.Equal(0, total);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadTargetsAsync_FileWithSingleIPsAndCidrsIsExpanded()
    {
        TestState.Reset();
        var path = Path.Combine(Path.GetTempPath(), $"cfscanner-input-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path, "192.0.2.5\n192.0.2.8/30\n");
        try
        {
            GlobalContext.Config.InputFiles.Add(path);
            var (source, total, infinite) = await InputLoader.LoadTargetsAsync();
            Assert.False(infinite);
            Assert.Equal(5, total); // 1 single IP + 4 from /30 (.8..11)
            Assert.Equal(new[] { "192.0.2.5", "192.0.2.8", "192.0.2.9", "192.0.2.10", "192.0.2.11" },
                source.Select(ip => ip.ToString()));
        }
        finally { File.Delete(path); }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadTargetsAsync_ExcludedRangesAreRemoved()
    {
        TestState.Reset();
        GlobalContext.Config.InputCidrs.Add("192.0.2.0/24");
        await GlobalContext.IpFilter.BuildAsync([], ["192.0.2.10/32"], [], "missing.tsv");

        var (source, total, infinite) = await InputLoader.LoadTargetsAsync();
        Assert.False(infinite);
        Assert.Equal(255, total);
        var ips = source.Select(ip => ip.ToString()).ToList();
        Assert.DoesNotContain("192.0.2.10", ips);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadTargetsAsync_ShuffleKeepsElementsAndChangesOrder()
    {
        TestState.Reset();
        for (uint i = 0; i < 16; i++)
            GlobalContext.Config.InputCidrs.Add(IPAddress.Parse("192.0.2." + i).ToString());
        GlobalContext.Config.Shuffle = true;

        var (source, total, _) = await InputLoader.LoadTargetsAsync();
        Assert.Equal(16, total);
        var original = Enumerable.Range(0, 16).Select(i => "192.0.2." + i).ToArray();

        // Fisher-Yates with a uniform RNG will virtually never leave the list untouched;
        // we only assert the set is preserved and order differs.
        var shuffled = source.Select(ip => ip.ToString()).ToList();
        Assert.Equal(original.OrderBy(x => x), shuffled.OrderBy(x => x));
        // Soft check: at least one element moved.
        Assert.NotEqual(original, shuffled);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildExclusionsAsync_NoSources_NoOp()
    {
        TestState.Reset();
        await InputLoader.BuildExclusionsAsync();
        Assert.Equal(0, GlobalContext.IpFilter.RangeCount);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task BuildExclusionsAsync_WithSources_PopulatesFilter()
    {
        TestState.Reset();
        GlobalContext.Config.ExcludeCidrs.Add("192.0.2.0/24");
        await InputLoader.BuildExclusionsAsync();
        Assert.Equal(1, GlobalContext.IpFilter.RangeCount);
        Assert.True(GlobalContext.IpFilter.IsBlocked(IPAddress.Parse("192.0.2.42")));
    }
}
