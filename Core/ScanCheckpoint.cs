using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using CFScanner.Utils;

namespace CFScanner.Core;

/// <summary>
/// Defines constants for scan checkpoint schema versioning.
/// Used to detect and reject incompatible checkpoint formats during resume.
/// </summary>
public static class ScanCheckpointDefaults
{
    /// <summary>
    /// Current checkpoint schema version.
    /// Schema changes are fail-closed: unknown versions are rejected rather than guessed.
    /// </summary>
    public const int SchemaVersion = 1;
    // Schema changes are fail-closed for now: unknown versions are rejected
    // rather than guessed. A future version must add an explicit migration
    // before increasing this value.
}

/// <summary>
/// Represents the complete state of a resumable scan session, persisted as JSON.
/// Contains configuration fingerprints, scan progress, file metadata, and mode-specific
/// state (finite cursor or infinite generator snapshot).
/// </summary>
public sealed class ScanCheckpoint
{
    /// <summary>Schema version for compatibility checking during deserialization.</summary>
    public int SchemaVersion { get; set; } = ScanCheckpointDefaults.SchemaVersion;
    /// <summary>Unique identifier for this scan session (GUID format).</summary>
    public string SessionId { get; set; } = Guid.NewGuid().ToString("N");
    /// <summary>Scan mode: <c>"finite"</c> for file/ASN/range inputs, <c>"infinite"</c> for random IP generation.</summary>
    public string Mode { get; set; } = "finite";
    /// <summary>UTC timestamp when this checkpoint was originally created.</summary>
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    /// <summary>UTC timestamp of the most recent checkpoint update.</summary>
    public DateTime UpdatedUtc { get; set; } = DateTime.UtcNow;
    /// <summary>
    /// Opaque hash of the effective scan configuration.
    /// Used to detect configuration drift between checkpoint and current invocation.
    /// </summary>
    public string ConfigFingerprint { get; set; } = string.Empty;
    /// <summary>Absolute path to the results file associated with this session.</summary>
    public string ResultsPath { get; set; } = string.Empty;
    /// <summary>Byte length of the results file at checkpoint time; <c>-1</c> if the file did not exist.</summary>
    public long ResultsFileLength { get; set; } = -1;
    /// <summary>Creation timestamp of the results file at checkpoint time.</summary>
    public DateTime? ResultsFileCreatedUtc { get; set; }
    /// <summary>Last-write timestamp of the results file at checkpoint time.</summary>
    public DateTime? ResultsFileLastWriteUtc { get; set; }
    /// <summary>Session identifier embedded in the results file for correlation.</summary>
    public string ResultSessionId { get; set; } = string.Empty;
    /// <summary>Identity hash of the ASN database file used in this session.</summary>
    public string AsnDatabaseIdentity { get; set; } = string.Empty;
    /// <summary>Input file paths specified in the scan configuration.</summary>
    public string[] InputFiles { get; set; } = [];
    /// <summary>Input ASN identifiers specified in the scan configuration.</summary>
    public string[] InputAsns { get; set; } = [];
    /// <summary>Input CIDR ranges specified in the scan configuration.</summary>
    public string[] InputRanges { get; set; } = [];
    /// <summary>Exclusion file paths specified in the scan configuration.</summary>
    public string[] ExcludeFiles { get; set; } = [];
    /// <summary>Exclusion ASN identifiers specified in the scan configuration.</summary>
    public string[] ExcludeAsns { get; set; } = [];
    /// <summary>Exclusion CIDR ranges specified in the scan configuration.</summary>
    public string[] ExcludeRanges { get; set; } = [];
    /// <summary>Full configuration snapshot captured at checkpoint time.</summary>
    public CheckpointConfigSnapshot? ConfigSnapshot { get; set; }
    /// <summary><c>true</c> if the scan completed successfully and this checkpoint is finalized.</summary>
    public bool Completed { get; set; }
    /// <summary>Finite-mode checkpoint state (sequence cursor and shuffle seed).</summary>
    public FiniteCheckpointState? Finite { get; set; }
    /// <summary>Infinite-mode checkpoint state (deterministic generator snapshot).</summary>
    public InfiniteCheckpointState? Infinite { get; set; }
    /// <summary>Scan progress counters at checkpoint time.</summary>
    public CheckpointStats Stats { get; set; } = new();
}

/// <summary>
/// Captures a complete snapshot of the <see cref="Config"/> at checkpoint time.
/// Used to detect configuration drift between the original and resumed scan sessions.
/// </summary>
public sealed class CheckpointConfigSnapshot
{
    /// <summary>Path to the ASN database file.</summary>
    public string AsnDbPath { get; set; } = Defaults.AsnDbPath;
    /// <summary>Base SNI hostname for TLS/HTTP signature detection.</summary>
    public string BaseSni { get; set; } = Defaults.BaseSni;
    /// <summary>Allowed HTTPS ports for scanning.</summary>
    public int[] Ports { get; set; } = [Defaults.Port];
    /// <summary>Whether IP scan order is randomized.</summary>
    public bool Shuffle { get; set; }
    /// <summary>Whether results are sorted by latency before writing.</summary>
    public bool SortResults { get; set; }
    /// <summary>Whether latency measurements are included in results.</summary>
    public bool SaveLatency { get; set; } = true;
    /// <summary>Number of concurrent TCP connection workers.</summary>
    public int TcpWorkers { get; set; }
    /// <summary>Number of concurrent TLS/HTTP signature workers.</summary>
    public int SignatureWorkers { get; set; }
    /// <summary>Number of concurrent Xray/V2Ray verification workers.</summary>
    public int V2RayWorkers { get; set; }
    /// <summary>Channel buffer size for TCP connection results.</summary>
    public int TcpChannelBuffer { get; set; }
    /// <summary>Channel buffer size for V2Ray verification results.</summary>
    public int V2RayChannelBuffer { get; set; }
    /// <summary>Minimum download speed threshold in KB/s for speed tests.</summary>
    public int MinDownloadSpeedKb { get; set; }
    /// <summary>Minimum upload speed threshold in KB/s for speed tests.</summary>
    public int MinUploadSpeedKb { get; set; }
    /// <summary>Number of concurrent speed test workers.</summary>
    public int SpeedTestWorkers { get; set; }
    /// <summary>Channel buffer size for speed test stage.</summary>
    public int SpeedTestBuffer { get; set; }
    /// <summary>Path to the Xray/V2Ray configuration file.</summary>
    public string? V2RayConfigPath { get; set; }
    /// <summary>Whether per-request random SNI subdomains are enabled.</summary>
    public bool RandomSNI { get; set; }
    /// <summary>TCP connect timeout in milliseconds.</summary>
    public int TcpTimeoutMs { get; set; }
    /// <summary>TLS handshake timeout in milliseconds.</summary>
    public int TlsTimeoutMs { get; set; }
    /// <summary>HTTP response read timeout in milliseconds.</summary>
    public int HttpReadTimeoutMs { get; set; }
    /// <summary>Combined TLS+HTTP signature stage timeout in milliseconds.</summary>
    public int SignatureTotalTimeoutMs { get; set; }
    /// <summary>Maximum wait time for Xray process startup in milliseconds.</summary>
    public int XrayStartupTimeoutMs { get; set; }
    /// <summary>Timeout for Xray proxy connectivity verification in milliseconds.</summary>
    public int XrayConnectionTimeoutMs { get; set; }
    /// <summary>Maximum time to wait for Xray process termination during cleanup.</summary>
    public int XrayProcessKillTimeoutMs { get; set; }
}

/// <summary>
/// Persists resume progress for finite-mode scans (file/ASN/range inputs).
/// Tracks the total sequence length and the next contiguous sequence to resume from.
/// </summary>
public sealed class FiniteCheckpointState
{
    /// <summary>Total number of IP:port sequences in the scan.</summary>
    public long SequenceLength { get; set; }
    /// <summary>Next contiguous sequence number to resume scanning from.</summary>
    public long NextContiguousSequence { get; set; }
    /// <summary>Random seed used for IP shuffling (deterministic replay).</summary>
    public ulong ShuffleSeed { get; set; }
}

/// <summary>
/// Persists the state of the deterministic random IPv4 generator for infinite-mode scans.
/// Enables exact continuation of the generator sequence after interruption.
/// </summary>
public sealed class InfiniteCheckpointState
{
    /// <summary>Algorithm identifier for the random number generator.</summary>
    public string Generator { get; set; } = DeterministicRandomIpv4Generator.Algorithm;
    /// <summary>Version of the generator algorithm (for future migration).</summary>
    public int GeneratorVersion { get; set; } = 1;
    /// <summary>Initial seed used to initialize the generator.</summary>
    public ulong Seed { get; set; }
    /// <summary>Current internal state of the xorshift64* generator.</summary>
    public ulong State { get; set; }
    /// <summary>Number of candidate IPs generated so far.</summary>
    public long ValuesConsumed { get; set; }
    /// <summary>Number of candidate IPs rejected (private/reserved/blocked).</summary>
    public long Rejections { get; set; }
}

/// <summary>
/// Thread-safe scan progress counters, persisted as part of the checkpoint.
/// Used to restore aggregate statistics when resuming a scan.
/// </summary>
public sealed class CheckpointStats
{
    /// <summary>Total number of IPs scanned so far.</summary>
    public long Scanned { get; set; }
    /// <summary>Number of IPs that established a TCP connection.</summary>
    public long TcpOpen { get; set; }
    /// <summary>Number of IPs that passed TLS/HTTP signature detection.</summary>
    public long SignaturePassed { get; set; }
    /// <summary>Number of IPs that passed real Xray/V2Ray proxy verification.</summary>
    public long V2RayPassed { get; set; }
    /// <summary>Number of IPs that passed speed test thresholds.</summary>
    public long SpeedTestPassed { get; set; }
}

/// <summary>
/// Computes and compares configuration fingerprints to detect incompatible scan sessions.
/// Fingerprints are SHA-256 hashes of canonical configuration fields, providing an
/// opaque but deterministic comparison mechanism.
/// </summary>
public static class ScanConfigurationFingerprint
{
    /// <summary>
    /// Describes the high-level differences between a current configuration and a checkpoint.
    /// Provides user-friendly labels (e.g., "input files", "ASN database") for incompatible fields.
    /// </summary>
    /// <param name="config">The current scan configuration.</param>
    /// <param name="checkpoint">The checkpoint to compare against.</param>
    /// <param name="infiniteMode">Whether the current invocation uses infinite random-IP mode.</param>
    /// <returns>List of human-readable difference descriptions.</returns>
    public static async Task<IReadOnlyList<string>> DescribeDifferences(Config config, ScanCheckpoint checkpoint, bool infiniteMode)
    {
        var prior = checkpoint.ConfigFingerprint;
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
        if (!string.Equals(checkpoint.AsnDatabaseIdentity, await GetFileIdentity(config.AsnDbPath), StringComparison.OrdinalIgnoreCase))
            differences.Add("ASN database");
        if (!string.Equals(prior, await Compute(config, infiniteMode), StringComparison.Ordinal)) differences.Add("effective scan settings");
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

    /// <summary>
    /// Computes an opaque SHA-256 fingerprint of the effective scan configuration.
    /// Two scans with identical effective settings produce the same fingerprint.
    /// </summary>
    /// <param name="config">The scan configuration to fingerprint.</param>
    /// <param name="infiniteMode">
    /// Explicit infinite-mode flag, or <c>null</c> to infer from the config inputs.
    /// </param>
    /// <returns>Lowercase hex-encoded SHA-256 hash of the canonical configuration.</returns>
    public static async Task<string> Compute(Config config, bool? infiniteMode = null)
    {
        var fields = await CanonicalFields(config, infiniteMode);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            string.Join("\n", fields)))).ToLowerInvariant();
    }

    private static async Task<string[]> CanonicalFields(Config config, bool? infiniteMode)
    {
        static string FileIdentities(IEnumerable<string> paths) =>
            string.Join("|", paths.Select(Path.GetFullPath)
                .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .Select(x => File.Exists(x)
                    ? $"{x}|{new FileInfo(x).Length}|{File.GetLastWriteTimeUtc(x).Ticks}"
                    : $"{x}|missing"));
        static string Values(IEnumerable<string> values, StringComparer comparer) =>
            string.Join(",", values.Select(x => x.Trim()).OrderBy(x => x, comparer));
        var asnDb = await Identity(config.AsnDbPath);
        var v2ray = await Identity(config.V2RayConfigPath);
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
            $"asnDb={asnDb}",
            $"ports={string.Join(",", config.Ports)}",
            $"sni={config.BaseSni}",
            $"latency={config.SaveLatency}",
            $"shuffle={config.Shuffle}",
            $"randomSni={config.RandomSNI}",
            $"v2ray={v2ray}",
            $"speed={config.MinDownloadSpeedKb},{config.MinUploadSpeedKb}",
            $"workers={config.TcpWorkers},{config.SignatureWorkers},{config.V2RayWorkers},{config.SpeedTestWorkers}",
            $"timeouts={config.TcpTimeoutMs},{config.TlsTimeoutMs},{config.HttpReadTimeoutMs},{config.SignatureTotalTimeoutMs}"
        });
        return canonical.Split('\n');
    }

    private static async Task<string> Identity(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) return $"{fullPath}|missing";
        var bytes = await File.ReadAllBytesAsync(fullPath);
        return $"{fullPath}|{Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant()}";
    }

    public static async Task<string> GetFileIdentity(string? path) => await Identity(path);
}

/// <summary>
/// Provides atomic read/write operations for scan checkpoint files.
/// Uses temporary files and file replacement to ensure crash-safe persistence.
/// Supports backup files for recovery from partial writes.
/// </summary>
public static class ScanCheckpointStore
{
    /// <summary>JSON serialization options for checkpoint files.</summary>
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip
    };

    /// <summary>
    /// Constructs the full file path for a checkpoint JSON file.
    /// </summary>
    /// <param name="directory">Checkpoint directory path.</param>
    /// <param name="sessionId">Session identifier.</param>
    /// <returns>Combined path in the format <c>directory/sessionId.json</c>.</returns>
    public static string GetPath(string directory, string sessionId) =>
        Path.Combine(directory, $"{sessionId}.json");

    /// <summary>
    /// Removes stale temporary files (*.tmp) from the checkpoint directory.
    /// Called during initialization to clean up abandoned writes from prior sessions.
    /// </summary>
    /// <param name="directory">Checkpoint directory to clean.</param>
    public static void CleanupTemporaryFiles(string directory)
    {
        if (!Directory.Exists(directory)) return;
        foreach (var temp in Directory.EnumerateFiles(directory, "*.tmp"))
            TryDelete(temp);
    }

    /// <summary>
    /// Atomically writes a checkpoint to disk.
    /// Writes to a temporary file first, then replaces the target (with backup).
    /// </summary>
    /// <param name="path">Target checkpoint file path.</param>
    /// <param name="checkpoint">Checkpoint state to serialize.</param>
    /// <param name="token">Cancellation token for the async write.</param>
    /// <param name="durable">
    /// When <c>true</c>, flushes the file stream to physical disk for crash-resilience.
    /// </param>
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
        await Task.Run(() =>
        {
            if (File.Exists(path))
                File.Replace(tempPath, path, backup, ignoreMetadataErrors: true);
            else
                File.Move(tempPath, path);
        }, token);
    }

    /// <summary>
    /// Reads and validates a checkpoint file, falling back to the backup file on failure.
    /// </summary>
    /// <param name="path">Primary checkpoint file path.</param>
    /// <param name="token">Cancellation token for the async read.</param>
    /// <returns>
    /// The deserialized and validated checkpoint, or <c>null</c> if the file
    /// is missing, corrupt, or fails validation.
    /// </returns>
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

    /// <summary>
    /// Validates the structural integrity of a checkpoint.
    /// Checks schema version, field constraints, and mode-specific state consistency.
    /// </summary>
    /// <param name="checkpoint">The checkpoint to validate.</param>
    /// <returns><c>true</c> if the checkpoint is structurally valid; otherwise <c>false</c>.</returns>
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

    /// <summary>
    /// Deletes a checkpoint file and its associated backup file.
    /// </summary>
    /// <param name="path">Checkpoint file path (backup <c>.bak</c> is derived automatically).</param>
    public static void Delete(string path)
    {
        TryDelete(path);
        TryDelete(path + ".bak");
    }

    private static void TryDelete(string path) { try { if (File.Exists(path)) File.Delete(path); } catch { } }
}

/// <summary>
/// Deterministic xorshift64* random IPv4 generator for infinite-mode scans.
/// Produces a reproducible sequence of public IPv4 addresses from a seed,
/// enabling exact resume of infinite scans from any interruption point.
///
/// Thread-safe: all state mutations are synchronized via a lock.
/// </summary>
public sealed class DeterministicRandomIpv4Generator
{
    /// <summary>Algorithm identifier stored in checkpoints for future migration.</summary>
    public const string Algorithm = "xorshift64star-public-ipv4";
    private readonly object _sync = new();
    private ulong _state;
    /// <summary>Original seed used to initialize the generator.</summary>
    public ulong Seed { get; }
    /// <summary>Number of candidate IPs generated so far (including rejections).</summary>
    public long ValuesConsumed { get; private set; }
    /// <summary>Number of candidate IPs rejected (private/reserved/blocked).</summary>
    public long Rejections { get; private set; }
    /// <summary>Current internal state of the xorshift64* generator.</summary>
    public ulong State { get { lock (_sync) return _state; } }

    /// <summary>
    /// Creates a snapshot of the generator state for checkpoint persistence.
    /// </summary>
    /// <returns>Tuple of seed, state, values consumed, and rejections.</returns>
    public (ulong Seed, ulong State, long ValuesConsumed, long Rejections) Snapshot()
    {
        lock (_sync) return (Seed, _state, ValuesConsumed, Rejections);
    }

    /// <summary>
    /// Initializes a new generator or restores from a checkpoint snapshot.
    /// </summary>
    /// <param name="seed">Original seed; zero is replaced with the golden ratio constant.</param>
    /// <param name="state">Restored internal state, or <c>null</c> to initialize from seed.</param>
    /// <param name="valuesConsumed">Restored count of generated candidates.</param>
    /// <param name="rejections">Restored count of rejected candidates.</param>
    public DeterministicRandomIpv4Generator(ulong seed, ulong? state = null, long valuesConsumed = 0, long rejections = 0)
    {
        Seed = seed == 0 ? 0x9E3779B97F4A7C15UL : seed;
        _state = state.GetValueOrDefault(Seed);
        if (_state == 0) _state = Seed;
        ValuesConsumed = valuesConsumed;
        Rejections = rejections;
    }

    /// <summary>
    /// Generates the next public (non-reserved) IPv4 address, skipping private,
    /// loopback, multicast, and blocked ranges. Loops until a valid candidate is found.
    /// </summary>
    /// <param name="filter">IP exclusion filter for ASN/range-based blocking.</param>
    /// <returns>A valid public IPv4 address as <see cref="uint"/>.</returns>
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

    /// <summary>
    /// Returns the next raw 32-bit unsigned integer from the xorshift64* sequence.
    /// No filtering is applied; callers use <see cref="NextPublic"/> for valid IPs.
    /// </summary>
    /// <returns>A pseudo-random 32-bit unsigned integer.</returns>
    public uint NextUInt32() { lock (_sync) return (uint)Next(); }

    private ulong Next()
    {
        _state ^= _state >> 12; _state ^= _state << 25; _state ^= _state >> 27;
        return _state * 2685821657736338717UL;
    }
}
