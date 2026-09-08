using CFScanner;
using CFScanner.Core;
using Xunit;

namespace CFScanner.IntegrationTests;

public sealed class InputLoaderTests
{
    [Fact, Trait("Category", "Integration")]
    public async Task LoadsCombinedFileAndInlineInputs_Deduplicated()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cfscanner-{Guid.NewGuid():N}.txt");
        await File.WriteAllTextAsync(path, "# comment\n192.0.2.2\n192.0.2.1 # note\n192.0.2.2\n",
            TestContext.Current.CancellationToken);
        try
        {
            TestState.Reset();
            GlobalContext.Config.InputFiles.Add(path);
            GlobalContext.Config.InputCidrs.Add("192.0.2.3/32");
            var result = await InputLoader.LoadTargetsAsync();
            Assert.False(result.IsInfinite);
            Assert.Equal(3, result.Total);
            Assert.Equal(new[] { "192.0.2.1", "192.0.2.2", "192.0.2.3" },
                result.Source.Select(x => x.ToString()));
        }
        finally { File.Delete(path); }
    }

    [Fact, Trait("Category", "Integration")]
    public async Task FiniteLoader_ResumesFromContiguousCursor()
    {
        TestState.Reset();
        GlobalContext.Config.InputCidrs.Add("192.0.2.1/30");
        GlobalContext.Config.ResumeEnabled = true;
        GlobalContext.ResumeCursor = 2;
        GlobalContext.ResumeShuffleSeed = 123;

        var result = await InputLoader.LoadTargetsAsync();

        Assert.False(result.IsInfinite);
        Assert.Equal(new[] { "192.0.2.2", "192.0.2.3" },
            result.Source.Select(x => x.ToString()));
    }
}
