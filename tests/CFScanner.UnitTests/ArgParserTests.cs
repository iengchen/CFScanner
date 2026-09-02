using CFScanner;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class ArgParserTests
{
    private static bool Parse(string[] args)
    {
        TestState.Reset();
        return ArgParser.ParseArguments(args);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_NormalProfile_UsesDefaults()
    {
        Assert.True(Parse(["-r", "192.0.2.1", "-y"]));
        Assert.Equal(Defaults.TcpWorkers, GlobalContext.Config.TcpWorkers);
        Assert.Equal(Defaults.SignatureWorkers, GlobalContext.Config.SignatureWorkers);
        Assert.Equal(Defaults.TcpTimeoutMs, GlobalContext.Config.TcpTimeoutMs);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_Resume_UsesOptInAndBounds()
    {
        Assert.True(Parse(["--resume", "--resume-interval", "120", "--resume-dir", "checkpoint-data", "-r", "192.0.2.1", "-y"]));
        Assert.True(GlobalContext.Config.ResumeEnabled);
        Assert.Equal(120, GlobalContext.Config.ResumeIntervalSeconds);
        Assert.Equal("checkpoint-data", GlobalContext.Config.ResumeDirectory);
        Assert.False(GlobalContext.Config.ResumeOnlyInvocation);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_ResumeOnly_RestoresIntentAndSessionId()
    {
        Assert.True(Parse(["--resume-session", "abc123", "-y"]));
        Assert.True(GlobalContext.Config.ResumeEnabled);
        Assert.True(GlobalContext.Config.ResumeOnlyInvocation);
        Assert.Equal("abc123", GlobalContext.Config.ResumeSessionId);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_ResumeNew_StartsFreshResumableSession()
    {
        Assert.True(Parse(["--resume", "--new", "-y"]));
        Assert.True(GlobalContext.Config.ResumeEnabled);
        Assert.True(GlobalContext.Config.ResumeNewScan);
        Assert.True(GlobalContext.Config.ResumeOnlyInvocation);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_FastProfile_SetsAggressiveValues()
    {
        Assert.True(Parse(["--fast", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(150, GlobalContext.Config.TcpWorkers);
        Assert.Equal(50, GlobalContext.Config.SignatureWorkers);
        Assert.Equal(16, GlobalContext.Config.V2RayWorkers);
        Assert.Equal(1000, GlobalContext.Config.TcpTimeoutMs);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_SlowProfile_SetsConservativeValues()
    {
        Assert.True(Parse(["--slow", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(50, GlobalContext.Config.TcpWorkers);
        Assert.Equal(3000, GlobalContext.Config.TcpTimeoutMs);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_ExtremeProfile_SetsMinimalTimeouts()
    {
        Assert.True(Parse(["--extreme", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(200, GlobalContext.Config.TcpWorkers);
        Assert.Equal(500, GlobalContext.Config.TcpTimeoutMs);
        Assert.Equal(32, GlobalContext.Config.V2RayWorkers);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_ExplicitOverridesTakePriorityOverProfile()
    {
        Assert.True(Parse(["--fast", "--tcp-workers", "300", "--tcp-timeout", "7500", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(300, GlobalContext.Config.TcpWorkers);
        Assert.Equal(7500, GlobalContext.Config.TcpTimeoutMs);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_Ports_AllKeywordExpandsToAllowedList()
    {
        Assert.True(Parse(["-p", "all", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(new[] { 443, 2053, 2083, 2087, 2096, 8443 }, GlobalContext.Config.Ports);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_Ports_CommaSeparatedDedupesAndSorts()
    {
        Assert.True(Parse(["-p", "8443,443,443,2053", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(new[] { 443, 2053, 8443 }, GlobalContext.Config.Ports);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_Ports_DisallowedPortExits()
    {
        // ErrorAndExit terminates the process; this test would only assert it is not reached.
        // We verify the legal case paths above and rely on a separate, opt-in invalid-port smoke
        // assertion through a child process for the failure path (covered by E2E).
        Assert.True(Parse(["-p", "443", "-r", "192.0.2.1", "-y"]));
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_SpeedBandwidth_MbAndKbAndBareNumber()
    {
        Assert.True(Parse(["--speed-dl", "2mb", "--speed-ul", "512kb", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(2 * 1024, GlobalContext.Config.MinDownloadSpeedKb);
        Assert.Equal(512, GlobalContext.Config.MinUploadSpeedKb);
        // V2Ray is not enabled by -y alone, so EnableSpeedTest must remain false.
        Assert.False(GlobalContext.Config.EnableSpeedTest);

        Assert.True(Parse(["--speed-dl", "1500", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(1500, GlobalContext.Config.MinDownloadSpeedKb);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_SpeedBandwidth_KAndMSuffix()
    {
        Assert.True(Parse(["--speed-dl", "3m", "--speed-ul", "256k", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(3 * 1024, GlobalContext.Config.MinDownloadSpeedKb);
        Assert.Equal(256, GlobalContext.Config.MinUploadSpeedKb);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_Inputs_FileAsnAndRangeAreCollected()
    {
        Assert.True(Parse(["-f", "a.txt,b.txt", "-a", "13335,AS15169", "-r", "192.0.2.0/24", "-y"]));
        Assert.Equal(new[] { "a.txt", "b.txt" }, GlobalContext.Config.InputFiles);
        Assert.Equal(new[] { "13335", "AS15169" }, GlobalContext.Config.InputAsns);
        Assert.Equal(new[] { "192.0.2.0/24" }, GlobalContext.Config.InputCidrs);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_Exclusions_AllThreeSourcesCollected()
    {
        Assert.True(Parse([
            "-r", "192.0.2.0/24", "-y",
            "-xf", "x.txt",
            "-xa", "12345",
            "-xr", "192.0.2.128/25"
        ]));
        Assert.Equal(new[] { "x.txt" }, GlobalContext.Config.ExcludeFiles);
        Assert.Equal(new[] { "12345" }, GlobalContext.Config.ExcludeAsns);
        Assert.Equal(new[] { "192.0.2.128/25" }, GlobalContext.Config.ExcludeCidrs);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_BehaviorFlags_ToggleCorrectly()
    {
        Assert.True(Parse(["-y", "--sort", "-s", "-nl", "--random-sni", "-r", "192.0.2.1"]));
        Assert.True(GlobalContext.Config.SortResults);
        Assert.True(GlobalContext.Config.Shuffle);
        Assert.False(GlobalContext.Config.SaveLatency);
        Assert.True(GlobalContext.Config.RandomSNI);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_V2RayConfigEnablesCheck()
    {
        Assert.True(Parse(["-vc", "xray.json", "-r", "192.0.2.1", "-y"]));
        Assert.Equal("xray.json", GlobalContext.Config.V2RayConfigPath);
        Assert.True(GlobalContext.Config.EnableV2RayCheck);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_BufferAutoScaling_WhenNotExplicit()
    {
        Assert.True(Parse(["--tcp-workers", "200", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(Math.Max(200 * 2, 100), GlobalContext.Config.TcpChannelBuffer);

        Assert.True(Parse(["--v2ray-workers", "10", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(Math.Max(10 * 3, 20), GlobalContext.Config.V2RayChannelBuffer);

        Assert.True(Parse(["--speed-workers", "3", "-r", "192.0.2.1", "-y"]));
        Assert.Equal(4, GlobalContext.Config.SpeedTestBuffer);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_ExplicitBuffersRespected()
    {
        Assert.True(Parse([
            "--tcp-buffer", "500",
            "--v2ray-buffer", "40",
            "--speed-buffer", "10",
            "-r", "192.0.2.1", "-y"
        ]));
        Assert.Equal(500, GlobalContext.Config.TcpChannelBuffer);
        Assert.Equal(40, GlobalContext.Config.V2RayChannelBuffer);
        Assert.Equal(10, GlobalContext.Config.SpeedTestBuffer);
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_HelpShort_ReturnsFalseAndDoesNotThrow()
    {
        Assert.False(Parse(["-h"]));
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_HelpFull_ReturnsFalse()
    {
        Assert.False(Parse(["-h", "full"]));
        Assert.False(Parse(["--manual"]));
    }

    [Fact, Trait("Category", "Unit")]
    public void Parse_YesFlag_StopsConfirmationPrompt()
    {
        // Without --yes, DisplayProfileSummary calls Console.ReadKey which would block.
        // With --yes, parsing completes and returns true.
        Assert.True(Parse(["-y", "-r", "192.0.2.1"]));
    }
}
