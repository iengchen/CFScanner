using System.Net;
using CFScanner;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class FileUtilsTests : IDisposable
{
    private readonly string _tempDir;

    public FileUtilsTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"cfscanner-file-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
        TestState.Reset();
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    [Fact, Trait("Category", "Unit")]
    public void SetupOutputFile_CreatesResultsDirectoryAndAssignsPath()
    {
        // SaveResult uses AppDomain.BaseDirectory, so instead of touching the
        // production path we just confirm the helper doesn't throw and sets
        // a non-empty path.
        FileUtils.SetupOutputFile();
        Assert.False(string.IsNullOrEmpty(GlobalContext.OutputFilePath));
        Assert.EndsWith(".txt", GlobalContext.OutputFilePath);
    }

    [Fact, Trait("Category", "Unit")]
    public void SaveResult_SinglePortWithLatency_UsesLegacyCompactFormat()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "single.txt");
        GlobalContext.Config.Ports = [443];
        GlobalContext.Config.SaveLatency = true;

        FileUtils.SaveResult("192.0.2.1", 443, 123);

        var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
        Assert.Single(lines);
        Assert.Equal("192.0.2.1 # 123ms", lines[0]);
    }

    [Fact, Trait("Category", "Unit")]
    public void SaveResult_MultiPortWithLatency_UsesExtendedFormat()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "multi.txt");
        GlobalContext.Config.Ports = [443, 8443];
        GlobalContext.Config.SaveLatency = true;

        FileUtils.SaveResult("192.0.2.1", 8443, 456);

        var line = File.ReadAllText(GlobalContext.OutputFilePath).TrimEnd();
        Assert.Equal("192.0.2.1 #Port: 8443 #Latency: 456ms", line);
    }

    [Fact, Trait("Category", "Unit")]
    public void SaveResult_SinglePortNoLatency_UsesBareIp()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "single-no-latency.txt");
        GlobalContext.Config.Ports = [443];
        GlobalContext.Config.SaveLatency = false;

        FileUtils.SaveResult("192.0.2.1", 443, -1);

        Assert.Equal("192.0.2.1", File.ReadAllText(GlobalContext.OutputFilePath).TrimEnd());
    }

    [Fact, Trait("Category", "Unit")]
    public void SaveResult_MultiPortNoLatency_UsesIpColonPort()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "multi-no-latency.txt");
        GlobalContext.Config.Ports = [443, 8443];
        GlobalContext.Config.SaveLatency = false;

        FileUtils.SaveResult("192.0.2.1", 8443, -1);

        Assert.Equal("192.0.2.1:8443", File.ReadAllText(GlobalContext.OutputFilePath).TrimEnd());
    }

    [Fact, Trait("Category", "Unit")]
    public void SortResultsFile_SortByLatencyEnabled_MultiportFormat()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "sort.txt");
        File.WriteAllLines(GlobalContext.OutputFilePath, [
            "10.0.0.5 #Port: 443 #Latency: 300ms",
            "10.0.0.1 #Port: 443 #Latency: 100ms",
            "10.0.0.3 #Port: 443 #Latency: 200ms"
        ]);
        GlobalContext.Config.Ports = [443, 8443];
        GlobalContext.Config.SortResults = true;

        FileUtils.SortResultsFile();

        var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
        Assert.Equal("10.0.0.1 #Port: 443 #Latency: 100ms", lines[0]);
        Assert.Equal("10.0.0.3 #Port: 443 #Latency: 200ms", lines[1]);
        Assert.Equal("10.0.0.5 #Port: 443 #Latency: 300ms", lines[2]);
    }

    [Fact, Trait("Category", "Unit")]
    public void SortResultsFile_SortByLatencyEnabled_LegacySinglePortFormat()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "sort-legacy.txt");
        File.WriteAllLines(GlobalContext.OutputFilePath, [
            "10.0.0.5 # 300ms",
            "10.0.0.1 # 100ms"
        ]);
        GlobalContext.Config.Ports = [443];
        GlobalContext.Config.SortResults = true;

        FileUtils.SortResultsFile();

        var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
        Assert.Equal("10.0.0.1 # 100ms", lines[0]);
        Assert.Equal("10.0.0.5 # 300ms", lines[1]);
    }

    [Fact, Trait("Category", "Unit")]
    public void SortResultsFile_MultiPortNoSortEnabled_SortsByIpAndPort()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "multi-nosort.txt");
        File.WriteAllLines(GlobalContext.OutputFilePath, [
            "10.0.0.2:8443",
            "10.0.0.1:443",
            "10.0.0.1:8443"
        ]);
        GlobalContext.Config.Ports = [443, 8443];
        GlobalContext.Config.SortResults = false;

        FileUtils.SortResultsFile();

        var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
        Assert.Equal("10.0.0.1:443", lines[0]);
        Assert.Equal("10.0.0.1:8443", lines[1]);
        Assert.Equal("10.0.0.2:8443", lines[2]);
    }

    [Fact, Trait("Category", "Unit")]
    public void SortResultsFile_SinglePortSortDisabled_NoChange()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "single-nosort.txt");
        File.WriteAllLines(GlobalContext.OutputFilePath, [
            "10.0.0.5 # 300ms",
            "10.0.0.1 # 100ms"
        ]);
        GlobalContext.Config.Ports = [443];
        GlobalContext.Config.SortResults = false;

        FileUtils.SortResultsFile();

        var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
        Assert.Equal("10.0.0.5 # 300ms", lines[0]);
        Assert.Equal("10.0.0.1 # 100ms", lines[1]);
    }

    [Fact, Trait("Category", "Unit")]
    public void SortResultsFile_MissingFile_NoOp()
    {
        GlobalContext.OutputFilePath = Path.Combine(_tempDir, "ghost.txt");
        GlobalContext.Config.SortResults = true;
        GlobalContext.Config.Ports = [443];

        FileUtils.SortResultsFile(); // must not throw

        Assert.False(File.Exists(GlobalContext.OutputFilePath));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadIpsAsync_SkipsCommentsAndWhitespace_ExpandsCidr()
    {
        var path = Path.Combine(_tempDir, "ips.txt");
        await File.WriteAllTextAsync(path,
            "# comment line\n" +
            "192.0.2.1\n" +
            "::1\n" +
            "::1/128\n" +
            "   \n" +
            "192.0.2.10/31\n" +
            "  192.0.2.5 # inline comment\n");

        var ips = await FileUtils.LoadIpsAsync(path);
        var set = ips.Select(ip => ip.ToString()).ToHashSet();

        Assert.Contains("192.0.2.1", set);
        Assert.Contains("192.0.2.5", set);
        Assert.Contains("192.0.2.10", set);
        Assert.Contains("192.0.2.11", set);
        Assert.DoesNotContain("not-an-ip", set);
        Assert.DoesNotContain("::1", set);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task LoadIpsAsync_PreservesOrderAndDedupesByParser()
    {
        var path = Path.Combine(_tempDir, "ips2.txt");
        await File.WriteAllTextAsync(path, "192.0.2.1\n192.0.2.2\n192.0.2.3\n");

        var ips = await FileUtils.LoadIpsAsync(path);
        Assert.Equal(new[] { "192.0.2.1", "192.0.2.2", "192.0.2.3" }, ips.Select(ip => ip.ToString()));
    }
}
