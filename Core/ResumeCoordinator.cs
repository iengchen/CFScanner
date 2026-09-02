using CFScanner.UI;
using System.Diagnostics;

namespace CFScanner.Core;

public static class ResumeCoordinator
{
    private static FileStream? _lock;
    private static string? _lockPath;
    private static readonly SemaphoreSlim SaveGate = new(1, 1);
    public static ScanCheckpoint? Current { get; private set; }

    public static async Task<bool> RestoreConfigurationFromCheckpointAsync(CancellationToken token = default)
    {
        var config = GlobalContext.Config;
        if (!config.ResumeEnabled || !config.ResumeOnlyInvocation) return true;
        var dir = Path.GetFullPath(config.ResumeDirectory);
        if (!Directory.Exists(dir))
        {
            ConsoleInterface.PrintError($"[Resume] No saved sessions found in '{dir}'.");
            return false;
        }
        var sessions = new List<ScanCheckpoint>();
        foreach (var file in Directory.EnumerateFiles(dir, "*.json"))
        {
            var cp = await ScanCheckpointStore.ReadValidAsync(file, token);
            if (cp is not null && !cp.Completed) sessions.Add(cp);
        }
        var selected = string.IsNullOrWhiteSpace(config.ResumeSessionId)
            ? sessions.OrderByDescending(x => x.UpdatedUtc).FirstOrDefault()
            : sessions.FirstOrDefault(x => string.Equals(x.SessionId, config.ResumeSessionId, StringComparison.OrdinalIgnoreCase));
        if (selected is null)
        {
            ConsoleInterface.PrintError($"[Resume] Saved session '{config.ResumeSessionId ?? "(latest)"}' was not found.");
            return false;
        }
        if (selected.ConfigSnapshot is null)
        {
            ConsoleInterface.PrintError("[Resume] This checkpoint has no saved configuration. Re-run with the original scan arguments.");
            return false;
        }
        ApplySnapshot(config, selected);
        Console.WriteLine($"[Resume] Restored configuration from session {selected.SessionId}");
        return true;
    }

    public static async Task InitializeAsync(bool assumeYes, CancellationToken token = default)
    {
        if (!GlobalContext.Config.ResumeEnabled) return;
        var dir = Path.GetFullPath(GlobalContext.Config.ResumeDirectory);
        Directory.CreateDirectory(dir);
        ScanCheckpointStore.CleanupTemporaryFiles(dir);
        var existing = new List<ScanCheckpoint>();
        foreach (var file in Directory.EnumerateFiles(dir, "*.json"))
        {
            var cp = await ScanCheckpointStore.ReadValidAsync(file, token);
            if (cp is not null && !cp.Completed) existing.Add(cp);
        }
        var fingerprint = ScanConfigurationFingerprint.Compute(GlobalContext.Config, GlobalContext.IsInfiniteMode);
        var candidate = GlobalContext.Config.ResumeNewScan ? null : existing.OrderByDescending(x => x.UpdatedUtc).FirstOrDefault(x =>
            (string.IsNullOrWhiteSpace(GlobalContext.Config.ResumeSessionId) ||
             string.Equals(x.SessionId, GlobalContext.Config.ResumeSessionId, StringComparison.OrdinalIgnoreCase)) &&
            x.ConfigFingerprint == fingerprint && IsResultsFileCompatible(x));
        var incompatible = GlobalContext.Config.ResumeNewScan
            ? null
            : existing.OrderByDescending(x => x.UpdatedUtc).FirstOrDefault(x =>
                string.IsNullOrWhiteSpace(GlobalContext.Config.ResumeSessionId) ||
                string.Equals(x.SessionId, GlobalContext.Config.ResumeSessionId, StringComparison.OrdinalIgnoreCase));
        bool resume = false;
        if (candidate is not null)
        {
            if (assumeYes) resume = true;
            else if (!Console.IsInputRedirected)
            {
                var key = ConsoleInterface.PromptResume(candidate.SessionId);
                Console.WriteLine();
                // KeyChar can be culture/layout dependent; use ConsoleKey for
                // reliable decisions (especially with non-Latin keyboard layouts).
                resume = key.Key == ConsoleKey.C;
                if (key.Key == ConsoleKey.D)
                    ScanCheckpointStore.Delete(ScanCheckpointStore.GetPath(dir, candidate.SessionId));
            }
            else if (Console.IsInputRedirected)
                ConsoleInterface.PrintWarning("[Resume] Matching checkpoint found but input is redirected; use -y to continue explicitly.");
        }
        else if (incompatible is not null)
        {
            var differences = ScanConfigurationFingerprint.DescribeDifferences(
                GlobalContext.Config, incompatible, GlobalContext.IsInfiniteMode);
            var detail = differences.Count == 0 ? "fingerprint or result file identity" : string.Join(", ", differences);
            if (!assumeYes && !Console.IsInputRedirected)
            {
                var key = ConsoleInterface.PromptIncompatibleResume(incompatible.SessionId, detail);
                if (key.Key == ConsoleKey.D)
                    ScanCheckpointStore.Delete(ScanCheckpointStore.GetPath(dir, incompatible.SessionId));
            }
            else
                ConsoleInterface.PrintWarning($"[Resume] Existing checkpoint is incompatible ({detail}); starting a new scan.");
        }
        if (resume)
        {
            var selected = candidate!;
            Current = selected;
            GlobalContext.RestoreCounters(selected.Stats);
            GlobalContext.ResumeCursor = selected.Finite?.NextContiguousSequence ?? 0;
            GlobalContext.ResumeShuffleSeed = selected.Finite?.ShuffleSeed ?? 0;
            if (selected.Infinite is { } infinite)
                GlobalContext.ResumeGenerator = new DeterministicRandomIpv4Generator(
                    infinite.Seed, infinite.State, infinite.ValuesConsumed, infinite.Rejections);
            GlobalContext.ResumeCheckpointPath = ScanCheckpointStore.GetPath(dir, selected.SessionId);
            if (!string.IsNullOrWhiteSpace(selected.ResultsPath))
            {
                var initialOutput = GlobalContext.OutputFilePath;
                if (!string.Equals(initialOutput, selected.ResultsPath, StringComparison.OrdinalIgnoreCase) &&
                    File.Exists(initialOutput) && new FileInfo(initialOutput).Length == 0)
                    try { File.Delete(initialOutput); } catch { }
                GlobalContext.OutputFilePath = selected.ResultsPath;
            }
            ConsoleInterface.PrintResumeContinuation(
                selected.SessionId,
                GlobalContext.ResumeCursor,
                GlobalContext.OutputFilePath);
        }
        else
        {
            if (!GlobalContext.Config.ResumeNewScan && candidate is not null && !assumeYes && !Console.IsInputRedirected)
                ConsoleInterface.PrintWarning("[Resume] Starting a new scan; saved session was kept.");
            Current = new ScanCheckpoint
            {
                Mode = GlobalContext.IsInfiniteMode ? "infinite" : "finite",
                ConfigFingerprint = fingerprint,
                ResultsPath = GlobalContext.OutputFilePath
            };
            GlobalContext.ResumeCursor = 0;
            GlobalContext.ResumeShuffleSeed = (ulong)Random.Shared.NextInt64();
            GlobalContext.ResumeCheckpointPath = ScanCheckpointStore.GetPath(dir, Current.SessionId);
        }
        GlobalContext.InitializeResumeProgress(GlobalContext.ResumeCursor);
        var lockPath = GlobalContext.ResumeCheckpointPath + ".lock";
        _lockPath = lockPath;
        try
        {
            _lock = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            await using var writer = new StreamWriter(_lock, leaveOpen: true);
            await writer.WriteAsync(Environment.ProcessId.ToString());
            await writer.FlushAsync();
        }
        catch (IOException)
        {
            bool stale = false;
            try
            {
                var pidText = await File.ReadAllTextAsync(lockPath, token);
                stale = !int.TryParse(pidText, out var pid) || !IsProcessRunning(pid);
            }
            catch { stale = true; }
            if (!stale)
            {
                ConsoleInterface.PrintError("[Resume] Another scanner instance owns this session.");
                throw;
            }
            try { File.Delete(lockPath); } catch { throw; }
            _lock = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        }
    }

    public static async Task SaveAsync(long total, bool completed, CancellationToken token = default, bool durable = false)
    {
        if (!GlobalContext.Config.ResumeEnabled || Current is null) return;
        await SaveGate.WaitAsync(token);
        try
        {
        Current.ConfigFingerprint = ScanConfigurationFingerprint.Compute(GlobalContext.Config, GlobalContext.IsInfiniteMode);
        Current.ResultsPath = GlobalContext.OutputFilePath;
        if (File.Exists(Current.ResultsPath))
        {
            var info = new FileInfo(Current.ResultsPath);
            Current.ResultsFileLength = info.Length;
            Current.ResultsFileCreatedUtc = info.CreationTimeUtc;
            Current.ResultsFileLastWriteUtc = info.LastWriteTimeUtc;
        }
        Current.ResultSessionId = Current.SessionId;
        Current.InputFiles = [.. GlobalContext.Config.InputFiles];
        Current.InputAsns = [.. GlobalContext.Config.InputAsns];
        Current.InputRanges = [.. GlobalContext.Config.InputCidrs];
        Current.ExcludeFiles = [.. GlobalContext.Config.ExcludeFiles];
        Current.ExcludeAsns = [.. GlobalContext.Config.ExcludeAsns];
        Current.ExcludeRanges = [.. GlobalContext.Config.ExcludeCidrs];
        Current.ConfigSnapshot = CaptureSnapshot(GlobalContext.Config);
        Current.AsnDatabaseIdentity = ScanConfigurationFingerprint.GetFileIdentity(GlobalContext.Config.AsnDbPath);
        Current.Completed = completed;
        Current.Mode = GlobalContext.IsInfiniteMode ? "infinite" : "finite";
        if (GlobalContext.IsInfiniteMode && GlobalContext.ResumeGenerator is { } generator)
        {
            var snapshot = generator.Snapshot();
            Current.Infinite = new InfiniteCheckpointState
            {
                Seed = snapshot.Seed, State = snapshot.State,
                ValuesConsumed = snapshot.ValuesConsumed, Rejections = snapshot.Rejections
            };
            Current.Finite = null;
        }
        else
        {
            Current.Finite = new FiniteCheckpointState
            {
                SequenceLength = total < 0 ? 0 : total * Math.Max(1, GlobalContext.Config.Ports.Count),
                NextContiguousSequence = Math.Clamp(
                    GlobalContext.NextContiguousSequence,
                    0,
                    Math.Max(0, total * Math.Max(1, GlobalContext.Config.Ports.Count))),
                ShuffleSeed = GlobalContext.ResumeShuffleSeed
            };
            Current.Infinite = null;
        }
        Current.Stats = new CheckpointStats
        {
            Scanned = GlobalContext.ScannedCount, TcpOpen = GlobalContext.TcpOpenTotal,
            SignaturePassed = GlobalContext.SignaturePassed, V2RayPassed = GlobalContext.V2RayPassed,
            SpeedTestPassed = GlobalContext.SpeedTestPassed
        };
        await ScanCheckpointStore.WriteAsync(GlobalContext.ResumeCheckpointPath, Current, token, durable);
        }
        finally
        {
            SaveGate.Release();
        }
    }

    private static CheckpointConfigSnapshot CaptureSnapshot(Config c) => new()
    {
        AsnDbPath = c.AsnDbPath, BaseSni = c.BaseSni, Ports = [.. c.Ports],
        Shuffle = c.Shuffle, SortResults = c.SortResults, SaveLatency = c.SaveLatency,
        TcpWorkers = c.TcpWorkers, SignatureWorkers = c.SignatureWorkers, V2RayWorkers = c.V2RayWorkers,
        TcpChannelBuffer = c.TcpChannelBuffer, V2RayChannelBuffer = c.V2RayChannelBuffer,
        MinDownloadSpeedKb = c.MinDownloadSpeedKb, MinUploadSpeedKb = c.MinUploadSpeedKb,
        SpeedTestWorkers = c.SpeedTestWorkers, SpeedTestBuffer = c.SpeedTestBuffer,
        V2RayConfigPath = c.V2RayConfigPath, RandomSNI = c.RandomSNI,
        TcpTimeoutMs = c.TcpTimeoutMs, TlsTimeoutMs = c.TlsTimeoutMs,
        HttpReadTimeoutMs = c.HttpReadTimeoutMs, SignatureTotalTimeoutMs = c.SignatureTotalTimeoutMs,
        XrayStartupTimeoutMs = c.XrayStartupTimeoutMs, XrayConnectionTimeoutMs = c.XrayConnectionTimeoutMs,
        XrayProcessKillTimeoutMs = c.XrayProcessKillTimeoutMs
    };

    private static void ApplySnapshot(Config c, ScanCheckpoint cp)
    {
        var s = cp.ConfigSnapshot!;
        c.InputFiles = [.. cp.InputFiles];
        c.InputAsns = [.. cp.InputAsns];
        c.InputCidrs = [.. cp.InputRanges];
        c.ExcludeFiles = [.. cp.ExcludeFiles];
        c.ExcludeAsns = [.. cp.ExcludeAsns];
        c.ExcludeCidrs = [.. cp.ExcludeRanges];
        c.AsnDbPath = s.AsnDbPath; c.BaseSni = s.BaseSni; c.Ports = [.. s.Ports];
        c.Shuffle = s.Shuffle; c.SortResults = s.SortResults; c.SaveLatency = s.SaveLatency;
        c.TcpWorkers = s.TcpWorkers; c.SignatureWorkers = s.SignatureWorkers; c.V2RayWorkers = s.V2RayWorkers;
        c.TcpChannelBuffer = s.TcpChannelBuffer; c.V2RayChannelBuffer = s.V2RayChannelBuffer;
        c.MinDownloadSpeedKb = s.MinDownloadSpeedKb; c.MinUploadSpeedKb = s.MinUploadSpeedKb;
        c.SpeedTestWorkers = s.SpeedTestWorkers; c.SpeedTestBuffer = s.SpeedTestBuffer;
        c.V2RayConfigPath = s.V2RayConfigPath; c.RandomSNI = s.RandomSNI;
        c.TcpTimeoutMs = s.TcpTimeoutMs; c.TlsTimeoutMs = s.TlsTimeoutMs;
        c.HttpReadTimeoutMs = s.HttpReadTimeoutMs; c.SignatureTotalTimeoutMs = s.SignatureTotalTimeoutMs;
        c.XrayStartupTimeoutMs = s.XrayStartupTimeoutMs; c.XrayConnectionTimeoutMs = s.XrayConnectionTimeoutMs;
        c.XrayProcessKillTimeoutMs = s.XrayProcessKillTimeoutMs;
    }

    public static void RemoveCompletedCheckpoint()
    {
        if (Current is not null && Current.Completed)
            ScanCheckpointStore.Delete(GlobalContext.ResumeCheckpointPath);
    }

    public static void Dispose()
    {
        _lock?.Dispose();
        _lock = null;
        if (_lockPath is not null)
        {
            try { File.Delete(_lockPath); } catch { }
            _lockPath = null;
        }
    }

    private static bool IsProcessRunning(int pid)
    {
        try { using var process = Process.GetProcessById(pid); return !process.HasExited; }
        catch { return false; }
    }

    public static bool IsResultsFileCompatible(ScanCheckpoint checkpoint)
    {
        // A scan can be interrupted before its first successful result. In
        // that case final cleanup may remove the empty file; it is still safe
        // to resume because the append path recreates it.
        if (!File.Exists(checkpoint.ResultsPath))
            return checkpoint.ResultsFileLength < 0 &&
                   checkpoint.ResultsFileCreatedUtc is null &&
                   checkpoint.ResultsFileLastWriteUtc is null &&
                   !checkpoint.Completed;
        var info = new FileInfo(checkpoint.ResultsPath);
        if (checkpoint.ResultsFileLength >= 0 && info.Length < checkpoint.ResultsFileLength) return false;
        if (checkpoint.ResultsFileCreatedUtc is not null &&
            info.CreationTimeUtc != checkpoint.ResultsFileCreatedUtc.Value) return false;
        return checkpoint.ResultsFileLastWriteUtc is null ||
            info.LastWriteTimeUtc >= checkpoint.ResultsFileLastWriteUtc.Value;
    }
}
