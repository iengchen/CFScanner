using CFScanner;
using CFScanner.Core;
using Xunit;

namespace CFScanner.IntegrationTests;

public sealed class ResumeCoordinatorTests
{
    [Fact, Trait("Category", "Integration")]
    public async Task Continue_RestoresSavedStatistics()
    {
        TestState.Reset();
        var dir = Path.Combine(Path.GetTempPath(), $"cfscanner-resume-stats-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var results = Path.Combine(dir, "results.txt");
        await File.WriteAllTextAsync(results, "existing\n");
        try
        {
            GlobalContext.Config.ResumeEnabled = true;
            GlobalContext.Config.ResumeDirectory = dir;
            GlobalContext.Config.InputCidrs.Add("192.0.2.1/30");
            GlobalContext.OutputFilePath = results;
            GlobalContext.IsInfiniteMode = false;
            var fingerprint = ScanConfigurationFingerprint.Compute(GlobalContext.Config, false);
            var checkpoint = new ScanCheckpoint
            {
                Mode = "finite",
                ConfigFingerprint = fingerprint,
                ResultsPath = results,
                ResultSessionId = "session",
                InputRanges = ["192.0.2.1/30"],
                Finite = new FiniteCheckpointState { SequenceLength = 4, NextContiguousSequence = 2, ShuffleSeed = 123 },
                Stats = new CheckpointStats
                {
                    Scanned = 321,
                    TcpOpen = 100,
                    SignaturePassed = 50,
                    V2RayPassed = 20,
                    SpeedTestPassed = 10
                }
            };
            var path = ScanCheckpointStore.GetPath(dir, checkpoint.SessionId);
            await ScanCheckpointStore.WriteAsync(path, checkpoint);

            await ResumeCoordinator.InitializeAsync(assumeYes: true);

            Assert.Equal(321, GlobalContext.ScannedCount);
            Assert.Equal(100, GlobalContext.TcpOpenTotal);
            Assert.Equal(50, GlobalContext.SignaturePassed);
            Assert.Equal(20, GlobalContext.V2RayPassed);
            Assert.Equal(10, GlobalContext.SpeedTestPassed);
        }
        finally
        {
            ResumeCoordinator.Dispose();
            Directory.Delete(dir, true);
        }
    }

    [Fact, Trait("Category", "Integration")]
    public async Task Continue_RestoresFiniteCursorBeforeTargetEnumeration()
    {
        TestState.Reset();
        var dir = Path.Combine(Path.GetTempPath(), $"cfscanner-resume-int-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var results = Path.Combine(dir, "results.txt");
        await File.WriteAllTextAsync(results, "existing\n");
        try
        {
            GlobalContext.Config.ResumeEnabled = true;
            GlobalContext.Config.ResumeDirectory = dir;
            GlobalContext.Config.InputCidrs.Add("192.0.2.1/30");
            GlobalContext.OutputFilePath = results;
            GlobalContext.IsInfiniteMode = false;
            var fingerprint = ScanConfigurationFingerprint.Compute(GlobalContext.Config, false);
            var checkpoint = new ScanCheckpoint
            {
                Mode = "finite",
                ConfigFingerprint = fingerprint,
                ResultsPath = results,
                ResultSessionId = "session",
                InputRanges = ["192.0.2.1/30"],
                Finite = new FiniteCheckpointState { SequenceLength = 4, NextContiguousSequence = 2, ShuffleSeed = 123 }
            };
            var path = ScanCheckpointStore.GetPath(dir, checkpoint.SessionId);
            await ScanCheckpointStore.WriteAsync(path, checkpoint);

            await ResumeCoordinator.InitializeAsync(assumeYes: true);
            var loaded = await InputLoader.LoadTargetsAsync();

            Assert.Equal(new[] { "192.0.2.3", "192.0.2.4" },
                loaded.Source.Select(x => x.ToString()));
        }
        finally
        {
            ResumeCoordinator.Dispose();
            Directory.Delete(dir, true);
        }
    }
}
