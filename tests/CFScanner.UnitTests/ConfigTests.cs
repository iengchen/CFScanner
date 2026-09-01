using CFScanner;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class ConfigTests
{
    [Fact, Trait("Category", "Unit")]
    public void EnableV2RayCheck_ReflectsConfigPath()
    {
        TestState.Reset();
        Assert.False(GlobalContext.Config.EnableV2RayCheck);

        GlobalContext.Config.V2RayConfigPath = "xray.json";
        Assert.True(GlobalContext.Config.EnableV2RayCheck);

        GlobalContext.Config.V2RayConfigPath = "   ";
        Assert.False(GlobalContext.Config.EnableV2RayCheck);

        GlobalContext.Config.V2RayConfigPath = null;
        Assert.False(GlobalContext.Config.EnableV2RayCheck);
    }

    [Fact, Trait("Category", "Unit")]
    public void EnableSpeedTest_RequiresBothV2RayAndThreshold()
    {
        TestState.Reset();

        // No v2ray config -> never enabled regardless of speed.
        GlobalContext.Config.MinDownloadSpeedKb = 100;
        GlobalContext.Config.MinUploadSpeedKb = 100;
        Assert.False(GlobalContext.Config.EnableSpeedTest);

        // With v2ray but no thresholds -> still disabled.
        GlobalContext.Config.V2RayConfigPath = "xray.json";
        GlobalContext.Config.MinDownloadSpeedKb = 0;
        GlobalContext.Config.MinUploadSpeedKb = 0;
        Assert.False(GlobalContext.Config.EnableSpeedTest);

        // Upload only threshold.
        GlobalContext.Config.MinUploadSpeedKb = 50;
        Assert.True(GlobalContext.Config.EnableSpeedTest);

        // Download only threshold.
        GlobalContext.Config.MinUploadSpeedKb = 0;
        GlobalContext.Config.MinDownloadSpeedKb = 50;
        Assert.True(GlobalContext.Config.EnableSpeedTest);

        // Both thresholds.
        GlobalContext.Config.MinUploadSpeedKb = 50;
        Assert.True(GlobalContext.Config.EnableSpeedTest);
    }
}