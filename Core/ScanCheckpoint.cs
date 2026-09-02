using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CFScanner.Utils;

namespace CFScanner.Core;

public static class ScanCheckpointDefaults
{
    public const int SchemaVersion = 1;
    // Schema changes are fail-closed for now: unknown versions are rejected
    // rather than guessed. A future version must add an explicit migration
    // before increasing this value.
}

public sealed class ScanCheckpoint
{
    public int SchemaVersion { get; set; } = ScanCheckpointDefaults.SchemaVersion;
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");
    public string Mode { get; set; } = "finite";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
    public string ConfigFingerprint { get; set; } = string.Empty;
    public string ResultsPath { get; set; } = string.Empty;
    public long ResultsFileLength { get; set; } = -1;
    public DateTime? ResultsFileCreatedUtc { get; set; }
    public DateTime? ResultsFileLastWriteUtc { get; set; }
    public string ResultSessionId { get; set; } = string.Empty;
    public string AsnDatabaseIdentity { get; set; } = string.Empty;
    public string[] InputFiles { get; set; } = [];
    public string[] InputAsns { get; set; } = [];
    public string[] InputRanges { get; set; } = [];
    public string[] ExcludeFiles { get; set; } = [];
    public string[] ExcludeAsns { get; set; } = [];
    public string[] ExcludeRanges { get; set; } = [];
    public CheckpointConfigSnapshot? ConfigSnapshot { get; set; }
    public bool Completed { get; set; }
    public FiniteCheckpointState? Finite { get; set; }
    public InfiniteCheckpointState? Infinite { get; set; }
    public CheckpointStats Stats { get; set; } = new();
}

public sealed class CheckpointConfigSnapshot
{
    public string AsnDbPath { get; set; } = Defaults.AsnDbPath;
    public string BaseSni { get; set; } = Defaults.BaseSni;
    public int[] Ports { get; set; } = [Defaults.Port];
    public bool Shuffle { get; set; }
    public bool SortResults { get; set; }
    public bool SaveLatency { get; set; } = true;
    public int TcpWorkers { get; set; }
    public int SignatureWorkers { get; set; }
    public int V2RayWorkers { get; set; }
    public int TcpChannelBuffer { get; set; }
    public int V2RayChannelBuffer { get; set; }
    public int MinDownloadSpeedKb { get; set; }
    public int MinUploadSpeedKb { get; set; }
    public int SpeedTestWorkers { get; set; }
    public int SpeedTestBuffer { get; set; }
    public string? V2RayConfigPath { get; set; }
    public bool RandomSNI { get; set; }
    public int TcpTimeoutMs { get; set; }
    public int TlsTimeoutMs { get; set; }
    public int HttpReadTimeoutMs { get; set; }
    public int SignatureTotalTimeoutMs { get; set; }
    public int XrayStartupTimeoutMs { get; set; }
    public int XrayConnectionTimeoutMs { get; set; }
    public int XrayProcessKillTimeoutMs { get; set; }
}

public sealed class FiniteCheckpointState
{
    public long SequenceLength { get; set; }
    public long NextContiguousSequence { get; set; }
    public ulong ShuffleSeed { get; set; }
}

public sealed class InfiniteCheckpointState
{
    public string Generator { get; set; } = DeterministicRandomIpv4Generator.Algorithm;
    public int GeneratorVersion { get; set; } = 1;
    public ulong Seed { get; set; }
    public ulong State { get; set; }
    public long ValuesConsumed { get; set; }
    public long Rejections { get; set; }
}

public sealed class CheckpointStats
{
    public long Scanned { get; set; }
    public long TcpOpen { get; set; }
    public long SignaturePassed { get; set; }
    public long V2RayPassed { get; set; }
    public long SpeedTestPassed { get; set; }
}

public static class ScanConfigurationFingerprint
{
    public static IReadOnlyList<string> DescribeDifferences(Config config, ScanCheckpoint checkpoint, bool infiniteMode)
    {
        var prior = checkpoint.ConfigFingerprint;
        // Fingerprints are intentionally opaque; callers still get a useful
        // high-level explanation for the most common incompatible fields.
        var differences = new List<string>();
        if (checkpoint.Mode != (infiniteMode ? "infinite" : "finite")) differences.Add("mode");
        if (checkpoint.InputFiles.Length != config.InputFiles.Count ||
            !checkpoint.InputFiles.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .SequenceEqual(config.InputFiles.Select(Path.GetFullPath).OrderBy(x => x, StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase))
            differences.Add("input files");
        if (!SameValues(checkpoint.ExcludeFiles, config.ExcludeFiles, paths: true)) differences.Add("exclude files");
        if (!SameValues(checkpoint.InputAsns, config.InputAsns)) differences.Add("input ASNs");
        if (!SameValues(checkpoint.ExcludeAsns, config.ExcludeAsns)) differences.Add("exclude ASNs");
        if (!SameValues(checkpoint.InputRanges, config.InputCidrs)) differences.Add("input ranges");
        if (!SameValues(checkpoint.ExcludeRanges, config.ExcludeCidrs)) differences.Add("exclude ranges");
        if (!string.Equals(checkpoint.AsnDatabaseIdentity, GetFileIdentity(config.AsnDbPath), StringComparison.OrdinalIgnoreCase))
            differences.Add("ASN database");
        if (!string.Equals(prior, Compute(config, infiniteMode), StringComparison.Ordinal)) differences.Add("effective scan settings");
        return differences.Distinct(StringComparer.Ordinal).ToArray();

        static bool SameValues(IEnumerable<string> saved, IEnumerable<string> current, bool paths = false)
        {
            var left = saved.Select(x => paths ? Path.GetFullPath(x) : x.Trim())
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase);
            var right = current.Select(x => paths ? Path.GetFullPath(x) : x.Trim())
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase);
            return left.SequenceEqual(right, StringComparer.OrdinalIgnoreCase);
        }
    }

    public static string Compute(Config config, bool? infiniteMode = null)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join("\n", CanonicalFields(config, infiniteMode))))) .ToLowerInvariant();
    }

    private static string[] CanonicalFields(Config config, bool? infiniteMode)
    {
        static string FileIdentities(IEnumerable<string> paths) =>
            string.Join("|", paths.Select(Path.GetFullPath)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .Select(x => File.Exists(x)
                    ? $"{x}|{new FileInfo(x).Length}|{File.GetLastWriteTimeUtc(x).Ticks}"
                    : $"{x}|missing"));
        static string Values(IEnumerable<string> values, StringComparer comparer) =>
            string.Join(",", values.Select(x => x.Trim()).OrderBy(x => x, comparer));
        var canonical = string.Join("\n", new[]
        {
            "v1",
            $"mode={((infiniteMode ?? (config.InputFiles.Count == 0 && config.InputAsns.Count == 0 && config.InputCidrs.Count == 0)) ? "infinite" : "finite")}",
            $"inputFiles={FileIdentities(config.InputFiles)}",
            $"excludeFiles={FileIdentities(config.ExcludeFiles)}",
            $"inputAsns={Values(config.InputAsns.Select(x => x.ToUpperInvariant()), StringComparer.Ordinal)}",
            $"excludeAsns={Values(config.ExcludeAsns.Select(x => x.ToUpperInvariant()), StringComparer.Ordinal)}",
            $"inputRanges={Values(config.InputCidrs, StringComparer.Ordinal)}",
            $"excludeRanges={Values(config.ExcludeCidrs, StringComparer.Ordinal)}",
            $"asnDb={Identity(config.AsnDbPath)}",
            $"ports={string.Join(",", config.Ports)}",
            $"sni={config.BaseSni}",
            $"latency={config.SaveLatency}",
            $"shuffle={config.Shuffle}",
            $"randomSni={config.RandomSNI}",
            $"v2ray={Identity(config.V2RayConfigPath)}",
            $"speed={config.MinDownloadSpeedKb},{config.MinUploadSpeedKb}",
            $"workers={config.TcpWorkers},{config.SignatureWorkers},{config.V2RayWorkers},{config.SpeedTestWorkers}",
            $"timeouts={config.TcpTimeoutMs},{config.TlsTimeoutMs},{config.HttpReadTimeoutMs},{config.SignatureTotalTimeoutMs}"
        });
        return canonical.Split('\n');
    }

    private static string Identity(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) return $"{fullPath}|missing";
        return $"{fullPath}|{Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(fullPath))).ToLowerInvariant()}";
    }

    public static string GetFileIdentity(string? path) => Identity(path);
}

public static class ScanCheckpointStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip
    };

    public static string GetPath(string directory, string sessionId) =>
        Path.Combine(directory, $"{sessionId}.json");

    public static void CleanupTemporaryFiles(string directory)
    {
        if (!Directory.Exists(directory)) return;
        foreach (var temp in Directory.EnumerateFiles(directory, "*.tmp"))
            TryDelete(temp);
    }

    public static async Task WriteAsync(string path, ScanCheckpoint checkpoint, CancellationToken token = default, bool durable = false)
    {
        checkpoint.UpdatedUtc = DateTime.UtcNow;
        var directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        Directory.CreateDirectory(directory);
        foreach (var temp in Directory.EnumerateFiles(directory, $"{Path.GetFileName(path)}.*.tmp"))
            TryDelete(temp);
        var tempPath = Path.Combine(directory, $"{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        await using (var stream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
        {
            await JsonSerializer.SerializeAsync(stream, checkpoint, JsonOptions, token);
            await stream.FlushAsync(token);
            if (durable) stream.Flush(flushToDisk: true);
        }
        var backup = path + ".bak";
        if (File.Exists(path))
            File.Replace(tempPath, path, backup, ignoreMetadataErrors: true);
        else
            File.Move(tempPath, path);
    }

    public static async Task<ScanCheckpoint?> ReadValidAsync(string path, CancellationToken token = default)
    {
        foreach (var candidate in new[] { path, path + ".bak" })
        {
            if (!File.Exists(candidate)) continue;
            try
            {
                await using var stream = new FileStream(candidate, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous);
                var checkpoint = await JsonSerializer.DeserializeAsync<ScanCheckpoint>(stream, JsonOptions, token);
                if (checkpoint is not null && Validate(checkpoint)) return checkpoint;
            }
            catch (JsonException) { }
            catch (IOException) { }
        }
        return null;
    }

    public static bool Validate(ScanCheckpoint checkpoint)
    {
        if (checkpoint.SchemaVersion != ScanCheckpointDefaults.SchemaVersion ||
            !Guid.TryParse(checkpoint.SessionId, out _) ||
            checkpoint.Mode is not ("finite" or "infinite") ||
            string.IsNullOrWhiteSpace(checkpoint.ConfigFingerprint) ||
            string.IsNullOrWhiteSpace(checkpoint.ResultsPath) ||
            string.IsNullOrWhiteSpace(checkpoint.ResultSessionId) ||
            checkpoint.UpdatedUtc < checkpoint.CreatedUtc ||
            checkpoint.ResultsFileLength < -1 ||
            (checkpoint.ResultsFileCreatedUtc is { } created && created.Kind == DateTimeKind.Unspecified) ||
            (checkpoint.ResultsFileLastWriteUtc is { } written && written.Kind == DateTimeKind.Unspecified) ||
            checkpoint.Stats.Scanned < 0 || checkpoint.Stats.TcpOpen < 0 ||
            checkpoint.Stats.SignaturePassed < 0 || checkpoint.Stats.V2RayPassed < 0 ||
            checkpoint.Stats.SpeedTestPassed < 0)
            return false;
        if (checkpoint.Mode == "finite")
            return checkpoint.Finite is not null && checkpoint.Finite.SequenceLength >= 0 &&
                   checkpoint.Finite.NextContiguousSequence >= 0 &&
                   checkpoint.Finite.NextContiguousSequence <= checkpoint.Finite.SequenceLength;
        return checkpoint.Infinite is not null && checkpoint.Infinite.GeneratorVersion == 1 &&
               checkpoint.Infinite.Seed != 0 && checkpoint.Infinite.State != 0 &&
               checkpoint.Infinite.ValuesConsumed >= 0 &&
               checkpoint.Infinite.Rejections >= 0 &&
               checkpoint.Infinite.Generator == DeterministicRandomIpv4Generator.Algorithm;
    }

    public static void Delete(string path)
    {
        TryDelete(path);
        TryDelete(path + ".bak");
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}

public sealed class DeterministicRandomIpv4Generator
{
    public const string Algorithm = "xorshift64star-public-ipv4";
    private readonly object _sync = new();
    private ulong _state;
    public ulong Seed { get; }
    public long ValuesConsumed { get; private set; }
    public long Rejections { get; private set; }
    public ulong State { get { lock (_sync) return _state; } }

    public (ulong Seed, ulong State, long ValuesConsumed, long Rejections) Snapshot()
    {
        lock (_sync) return (Seed, _state, ValuesConsumed, Rejections);
    }

    public DeterministicRandomIpv4Generator(ulong seed, ulong? state = null, long valuesConsumed = 0, long rejections = 0)
    {
        Seed = seed == 0 ? 0x9E3779B97F4A7C15UL : seed;
        _state = state.GetValueOrDefault(Seed);
        if (_state == 0) _state = Seed;
        ValuesConsumed = valuesConsumed;
        Rejections = rejections;
    }

    public uint NextPublic(IpFilter filter)
    {
        lock (_sync)
        {
            while (true)
            {
                uint x = (uint)Next();
                ValuesConsumed++;
                var b0 = (byte)(x >> 24); var b1 = (byte)(x >> 16);
                if (b0 == 0 || b0 == 10 || b0 == 127 || (b0 == 192 && b1 == 168) ||
                    (b0 == 172 && b1 is >= 16 and <= 31) || b0 >= 224 || filter.IsBlocked(x))
                { Rejections++; continue; }
                return x;
            }
        }
    }

    public uint NextUInt32() { lock (_sync) return (uint)Next(); }

    private ulong Next()
    {
        _state ^= _state >> 12; _state ^= _state << 25; _state ^= _state >> 27;
        return _state * 2685821657736338717UL;
    }
}
