using CFScanner.Core;
using CFScanner.Utils;
using Xunit;

namespace CFScanner.UnitTests;

public sealed class ResumeCheckpointTests
{
    [Fact, Trait("Category", "Unit")]
    public async Task Checkpoint_RoundTrips_AndRejectsWrongSchema()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cfscanner-resume-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "session.json");
            var cp = new ScanCheckpoint
            {
                Mode = "finite",
                ConfigFingerprint = "abc",
                ResultsPath = Path.Combine(dir, "results.txt"),
                ResultSessionId = "session",
                Finite = new FiniteCheckpointState { SequenceLength = 10, NextContiguousSequence = 3 }
            };
            await ScanCheckpointStore.WriteAsync(path, cp);
            var loaded = await ScanCheckpointStore.ReadValidAsync(path);
            Assert.NotNull(loaded);
            Assert.Equal(3, loaded!.Finite!.NextContiguousSequence);
            loaded.SchemaVersion = 99;
            Assert.False(ScanCheckpointStore.Validate(loaded));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact, Trait("Category", "Unit")]
    public void DeterministicGenerator_RestoresSequence()
    {
        var filter = new IpFilter();
        var first = new DeterministicRandomIpv4Generator(1234);
        _ = first.NextPublic(filter);
        var state = new DeterministicRandomIpv4Generator(
            first.Seed, first.State, first.ValuesConsumed, first.Rejections);
        Assert.Equal(first.NextPublic(filter), state.NextPublic(filter));
    }

    [Fact, Trait("Category", "Unit")]
    public void ResumeProgress_TracksHighestContiguousSequence()
    {
        GlobalContext.InitializeResumeProgress(0);
        GlobalContext.MarkResumeSequenceCompleted(2);
        Assert.Equal(0, GlobalContext.NextContiguousSequence);
        GlobalContext.MarkResumeSequenceCompleted(0);
        GlobalContext.MarkResumeSequenceCompleted(1);
        Assert.Equal(3, GlobalContext.NextContiguousSequence);
    }

    [Fact, Trait("Category", "Unit")]
    public void Checkpoint_RejectsMissingIdentityFields()
    {
        var cp = new ScanCheckpoint
        {
            Mode = "finite",
            ResultSessionId = "session",
            Finite = new FiniteCheckpointState { SequenceLength = 1 }
        };

        Assert.False(ScanCheckpointStore.Validate(cp));
    }

    [Fact, Trait("Category", "Unit")]
    public void Checkpoint_RejectsInvalidStatsAndGeneratorState()
    {
        var cp = new ScanCheckpoint
        {
            Mode = "infinite",
            ConfigFingerprint = "abc",
            ResultsPath = "results.txt",
            ResultSessionId = "session",
            Stats = new CheckpointStats { Scanned = -1 },
            Infinite = new InfiniteCheckpointState
            {
                Generator = DeterministicRandomIpv4Generator.Algorithm,
                GeneratorVersion = 1,
                Seed = 1,
                State = 1
            }
        };
        Assert.False(ScanCheckpointStore.Validate(cp));

        cp.Stats.Scanned = 0;
        cp.Infinite.GeneratorVersion = 2;
        Assert.False(ScanCheckpointStore.Validate(cp));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task Checkpoint_StoresAsnDatabaseIdentity()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "asn database");
            var identity = await ScanConfigurationFingerprint.GetFileIdentity(path);
            Assert.Contains(Path.GetFullPath(path), identity);
            Assert.NotEqual(path, identity);
            Assert.Equal(identity, await ScanConfigurationFingerprint.GetFileIdentity(path));
        }
        finally { File.Delete(path); }
    }

    [Fact, Trait("Category", "Unit")]
    public void MissingEmptyResultsFile_IsCompatibleForIncompleteSession()
    {
        var checkpoint = new ScanCheckpoint
        {
            Mode = "finite",
            ConfigFingerprint = "abc",
            ResultsPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".txt"),
            ResultSessionId = "session",
            Completed = false,
            Finite = new FiniteCheckpointState { SequenceLength = 10 }
        };

        Assert.True(ResumeCoordinator.IsResultsFileCompatible(checkpoint));
        checkpoint.ResultsFileLength = 0;
        checkpoint.ResultsFileCreatedUtc = DateTime.UtcNow;
        checkpoint.ResultsFileLastWriteUtc = DateTime.UtcNow;
        Assert.True(ResumeCoordinator.IsResultsFileCompatible(checkpoint));
        checkpoint.Completed = true;
        Assert.False(ResumeCoordinator.IsResultsFileCompatible(checkpoint));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task Fingerprint_DistinguishesInputAndExclusionSourcesAndMode()
    {
        var input = Path.GetTempFileName();
        var exclude = Path.GetTempFileName();
        try
        {
            var config = new Config { InputFiles = [input], ExcludeFiles = [exclude] };
            var finite = await ScanConfigurationFingerprint.Compute(config, false);
            var swapped = new Config { InputFiles = [exclude], ExcludeFiles = [input] };
            var swappedFingerprint = await ScanConfigurationFingerprint.Compute(swapped, false);
            var infinite = await ScanConfigurationFingerprint.Compute(config, true);

            Assert.NotEqual(finite, swappedFingerprint);
            Assert.NotEqual(finite, infinite);
        }
        finally
        {
            File.Delete(input);
            File.Delete(exclude);
        }
    }

    [Fact, Trait("Category", "Unit")]
    public async Task Fingerprint_PreservesOrderedPorts()
    {
        var first = new Config { Ports = [443, 8443] };
        var second = new Config { Ports = [8443, 443] };
        Assert.NotEqual(
            await ScanConfigurationFingerprint.Compute(first, true),
            await ScanConfigurationFingerprint.Compute(second, true));
    }

    [Fact, Trait("Category", "Unit")]
    public async Task Fingerprint_DistinguishesXrayTimeouts()
    {
        var first = new Config { V2RayConfigPath = "xray.json" };
        var second = new Config
        {
            V2RayConfigPath = "xray.json",
            XrayConnectionTimeoutMs = Defaults.XrayConnectionTimeoutMs + 1
        };

        Assert.NotEqual(
            await ScanConfigurationFingerprint.Compute(first, true),
            await ScanConfigurationFingerprint.Compute(second, true));
    }

    [Fact, Trait("Category", "Unit")]
    public void DeterministicGenerator_SnapshotIsConsistent()
    {
        var generator = new DeterministicRandomIpv4Generator(1234);
        _ = generator.NextPublic(new IpFilter());
        var snapshot = generator.Snapshot();
        Assert.Equal(generator.Seed, snapshot.Seed);
        Assert.Equal(generator.State, snapshot.State);
        Assert.Equal(generator.ValuesConsumed, snapshot.ValuesConsumed);
        Assert.Equal(generator.Rejections, snapshot.Rejections);
    }

    [Fact, Trait("Category", "Unit")]
    public async Task CheckpointStore_FallsBackToBackupAndCleansTemporaryFiles()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cfscanner-resume-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "session.json");
            var cp = new ScanCheckpoint
            {
                Mode = "finite",
                ConfigFingerprint = "abc",
                ResultsPath = Path.Combine(dir, "results.txt"),
                ResultSessionId = "session",
                Finite = new FiniteCheckpointState { SequenceLength = 10, NextContiguousSequence = 3 }
            };
            await ScanCheckpointStore.WriteAsync(path, cp);
            cp.Finite!.NextContiguousSequence = 5;
            await ScanCheckpointStore.WriteAsync(path, cp);
            File.WriteAllText(path, "{truncated");
            File.WriteAllText(path + ".stale.tmp", "stale");

            var loaded = await ScanCheckpointStore.ReadValidAsync(path);
            Assert.NotNull(loaded);
            Assert.Equal(3, loaded!.Finite!.NextContiguousSequence);
            ScanCheckpointStore.CleanupTemporaryFiles(dir);
            Assert.False(File.Exists(path + ".stale.tmp"));
        }
        finally { Directory.Delete(dir, true); }
    }
}
