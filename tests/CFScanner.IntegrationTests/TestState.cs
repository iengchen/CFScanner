using CFScanner;
using CFScanner.Core;
using CFScanner.Utils;

namespace CFScanner.IntegrationTests;

// Provides a clean global state per-test. Production state is static, so
// tests must reset it explicitly to avoid order dependence.
internal static class TestState
{
    public static void Reset()
    {
        var c = GlobalContext.Config;
        c.InputFiles.Clear(); c.InputAsns.Clear(); c.InputCidrs.Clear();
        c.ExcludeFiles.Clear(); c.ExcludeAsns.Clear(); c.ExcludeCidrs.Clear();
        c.Ports = [Defaults.Port];
        c.TcpWorkers = Defaults.TcpWorkers;
        c.SignatureWorkers = Defaults.SignatureWorkers;
        c.V2RayWorkers = Defaults.V2RayWorkers;
        c.SpeedTestWorkers = Defaults.SpeedTestWorkers;
        c.SpeedTestBuffer = Defaults.SpeedTestBuffer;
        c.TcpChannelBuffer = Defaults.TcpChannelBuffer;
        c.V2RayChannelBuffer = Defaults.V2RayChannelBuffer;
        c.SaveLatency = Defaults.SaveLatency;
        c.Shuffle = Defaults.Shuffle;
        c.SortResults = Defaults.SortResults;
        c.RandomSNI = Defaults.RandomSNI;
        c.ResumeEnabled = Defaults.ResumeEnabled;
        c.ResumeIntervalSeconds = Defaults.ResumeIntervalSeconds;
        c.ResumeDirectory = Defaults.ResumeDirectory;
        c.ResumeSessionId = null;
        c.ResumeOnlyInvocation = false;
        c.ResumeNewScan = false;
        c.V2RayConfigPath = null;

        GlobalContext.OutputFilePath = string.Empty;
        GlobalContext.TotalIps = 0;
        GlobalContext.IsInfiniteMode = false;
        GlobalContext.ResumeCursor = 0;
        GlobalContext.ResumeShuffleSeed = 0;
        GlobalContext.ResumeGenerator = null;
        GlobalContext.ResetInfiniteResumeState();
        GlobalContext.ResumeCheckpointPath = string.Empty;
        GlobalContext.RawV2RayTemplate = string.Empty;
        GlobalContext.IpFilter.Clear();
        GlobalContext.ResetCounters();
        GlobalContext.ResetCancellationTokenSource();
        PauseManager.Reset();
    }
}
