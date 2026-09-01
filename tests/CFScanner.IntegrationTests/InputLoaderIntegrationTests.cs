using System.Net;
using CFScanner;
using CFScanner.Core;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.IntegrationTests;

public sealed class InputLoaderIntegrationTests
{
    [Fact, Trait("Category", "Integration")]
    public async Task Combined_FileAndRangeAndExclusion_DedupesFiltersSorts()
    {
        TestState.Reset();

        var path = Path.Combine(Path.GetTempPath(), $"cfscanner-int-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path,
            "192.0.2.50\n" +
            "192.0.2.10/31\n" + // .10 and .11
            "192.0.2.50\n" +    // duplicate
            "\n" +
            "# comment line\n");
        try
        {
            GlobalContext.Config.InputFiles.Add(path);
            GlobalContext.Config.InputCidrs.Add("192.0.2.10");
            GlobalContext.Config.ExcludeCidrs.Add("192.0.2.10/32");

            await InputLoader.BuildExclusionsAsync();
            var result = await InputLoader.LoadTargetsAsync();

            Assert.False(result.IsInfinite);
            // From file: 192.0.2.50, 192.0.2.10, 192.0.2.11 (file-side duplicate dropped)
            // From range: 192.0.2.10 (excluded -> removed)
            // Final: .50, .11 -> 2 entries
            Assert.Equal(2, result.Total);
            var ips = result.Source.Select(ip => ip.ToString()).ToList();
            Assert.Contains("192.0.2.11", ips);
            Assert.Contains("192.0.2.50", ips);
            Assert.DoesNotContain("192.0.2.10", ips);
        }
        finally { File.Delete(path); }
    }

    [Fact, Trait("Category", "Integration")]
    public async Task ShuffleEnabled_RandomizesButKeepsAll()
    {
        TestState.Reset();
        for (uint i = 0; i < 8; i++)
            GlobalContext.Config.InputCidrs.Add(IPAddress.Parse("192.0.2." + i).ToString());
        GlobalContext.Config.Shuffle = true;

        var result = await InputLoader.LoadTargetsAsync();
        Assert.False(result.IsInfinite);
        Assert.Equal(8, result.Total);
        var ordered = result.Source.Select(ip => ip.ToString()).OrderBy(x => x).ToList();
        Assert.Equal(
            Enumerable.Range(0, 8).Select(i => "192.0.2." + i).ToList(),
            ordered);
    }

    [Fact, Trait("Category", "Integration")]
    public async Task NoInputs_FallsBackToInfiniteRandomMode()
    {
        TestState.Reset();
        var result = await InputLoader.LoadTargetsAsync();
        Assert.True(result.IsInfinite);
        Assert.Equal(-1, result.Total);

        // Drain a bounded slice; should not block and should yield IPs.
        var head = new List<IPAddress>();
        foreach (var ip in result.Source)
        {
            head.Add(ip);
            if (head.Count >= 3) break;
        }
        Assert.Equal(3, head.Count);
    }

    [Fact, Trait("Category", "Integration")]
    public async Task ExclusionsFromFileAndCidrAreApplied()
    {
        TestState.Reset();

        var path = Path.Combine(Path.GetTempPath(), $"cfscanner-excl-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path, "192.0.2.20/30\n");
        try
        {
            GlobalContext.Config.InputCidrs.Add("192.0.2.0/24");
            GlobalContext.Config.ExcludeFiles.Add(path);
            GlobalContext.Config.ExcludeCidrs.Add("192.0.2.50/31"); // .50, .51

            await InputLoader.BuildExclusionsAsync();
            var result = await InputLoader.LoadTargetsAsync();

            Assert.False(result.IsInfinite);
            // /24 = 256; excluded: 20..23 (4) + 50..51 (2) = 6 -> 250 remain.
            Assert.Equal(250, result.Total);
        }
        finally { File.Delete(path); }
    }
}