using System.Diagnostics;
using System.Net;
using CFScanner.Core;
using CFScanner.Utils;

namespace CFScanner;

/// <summary>
/// Provides a process-wide shared context for runtime configuration,
/// global counters, cancellation signaling, and immutable scan resources.
///
/// This type is intentionally static to guarantee a single authoritative
/// source of truth across all worker threads and pipeline stages.
/// </summary>
public static class GlobalContext
{
    // ---------------------------------------------------------------------
    // Core Runtime State
    // ---------------------------------------------------------------------

    /// <summary>
    /// Effective runtime configuration composed from defaults
    /// and command-line overrides.
    /// </summary>
    public static Config Config { get; } = new();

    /// <summary>
    /// Global cancellation token source used to coordinate
    /// cooperative shutdown across all running tasks
    /// (e.g. Ctrl+C or graceful completion).
    /// </summary>
    private static CancellationTokenSource _cts = new();

    /// <summary>
    /// Exposes the global cancellation token source for registering
    /// cooperative shutdown across all pipeline stages.
    /// </summary>
    public static CancellationTokenSource Cts => _cts;

    /// <summary>
    /// Measures total wall-clock duration of the scan.
    /// </summary>
    public static Stopwatch Stopwatch { get; } = new();

    // ---------------------------------------------------------------------
    // Private Backing Fields
    // All counters are mutated exclusively via Interlocked
    // to ensure thread-safety under high contention.
    // ---------------------------------------------------------------------

    // Output file path, assigned once during initialization
    private static string _outputFilePath = string.Empty;

    // Total number of IPs scheduled for scanning (finite mode only)
    private static long _totalIps;

    // Concurrent scan statistics
    private static int _scannedCount;
    private static long _tcpOpenTotal;
    private static int _signaturePassed;
    private static int _v2RayPassed;
    private static int _speedTestPassed;

    // Scan mode flags and shared immutable resources
    private static bool _isInfiniteMode;
    private static string _rawV2RayTemplate = string.Empty;
    private static long _resumeCursor;
    private static string _resumeCheckpointPath = string.Empty;
    private static ulong _resumeShuffleSeed;
    private static readonly object ResumeProgressLock = new();
    private static readonly SortedSet<long> CompletedSequences = [];
    private static long _nextContiguousSequence;
    private static readonly object InfiniteResumeLock = new();
    private static readonly Queue<IPAddress> InfinitePendingIps = [];
    private static List<IPAddress> _infiniteReplayIps = [];
    private static int _infiniteReplayIndex;
    private static long _infiniteCommittedIps;
    /// <summary>Active deterministic random IPv4 generator for infinite-mode scans.</summary>
    public static DeterministicRandomIpv4Generator? ResumeGenerator { get; set; }

    // ---------------------------------------------------------------------
    // Public Read-Only State Accessors
    // ---------------------------------------------------------------------

    /// <summary>
    /// Absolute path to the output results file.
    /// Set once during startup and treated as immutable thereafter.
    /// </summary>
    public static string OutputFilePath
    {
        get => _outputFilePath;
        set => _outputFilePath = value;
    }

    /// <summary>
    /// Total number of IPs scheduled for scanning.
    /// Meaningful only when running in finite (non-random) mode.
    /// </summary>
    public static long TotalIps
    {
        get => _totalIps;
        set => _totalIps = value;
    }

    /// <summary>
    /// Total number of IPs that completed scanning,
    /// regardless of success or failure.
    /// </summary>
    public static int ScannedCount => _scannedCount;

    /// <summary>
    /// Number of IPs that successfully established a TCP connection
    /// to the target port.
    /// </summary>
    public static long TcpOpenTotal => _tcpOpenTotal;

    /// <summary>
    /// Number of IPs that passed the TLS/HTTP signature validation stage.
    /// </summary>
    public static int SignaturePassed => _signaturePassed;

    /// <summary>
    /// Number of IPs that passed real Xray/V2Ray proxy verification.
    /// </summary>
    public static int V2RayPassed => _v2RayPassed;

    /// <summary>
    /// Number of IPs that passed the speed test stage
    /// (after real proxy verification).
    /// </summary>
    public static int SpeedTestPassed => _speedTestPassed;

    /// <summary>
    /// Indicates whether the scanner is running in infinite random-IP mode.
    /// </summary>
    public static bool IsInfiniteMode
    {
        get => _isInfiniteMode;
        set => _isInfiniteMode = value;
    }

    /// <summary>
    /// Raw JSON template for Xray/V2Ray configuration.
    /// Loaded once from disk and reused for all proxy tests
    /// to minimize I/O and parsing overhead.
    /// </summary>
    public static string RawV2RayTemplate
    {
        get => _rawV2RayTemplate;
        set => _rawV2RayTemplate = value;
    }

    /// <summary>
    /// Centralized IP exclusion filter built from
    /// exclude files, CIDR ranges, and ASNs.
    /// </summary>
    public static IpFilter IpFilter { get; } = new IpFilter();

    // ---------------------------------------------------------------------
    // Thread-Safe Counter Mutations
    // ---------------------------------------------------------------------

    /// <summary>
    /// Atomically increments the total scanned IP count.
    /// </summary>
    public static void IncrementScannedCount() =>
        Interlocked.Increment(ref _scannedCount);

    /// <summary>
    /// Atomically increments the count of successful TCP connections.
    /// </summary>
    public static void IncrementTcpOpenTotal() =>
        Interlocked.Increment(ref _tcpOpenTotal);

    /// <summary>
    /// Atomically increments the count of signature-passed IPs.
    /// </summary>
    public static void IncrementSignaturePassed() =>
        Interlocked.Increment(ref _signaturePassed);

    /// <summary>
    /// Atomically increments the count of Xray/V2Ray verified IPs.
    /// </summary>
    public static void IncrementV2RayPassed() =>
        Interlocked.Increment(ref _v2RayPassed);

    /// <summary>
    /// Atomically increments the count of speed-test-passed IPs.
    /// </summary>
    public static void IncrementSpeedTestPassed() =>
        Interlocked.Increment(ref _speedTestPassed);

    /// <summary>
    /// Resets all scan counters to zero. Intended for test isolation;
    /// production callers invoke increments exactly once per scan.
    /// </summary>
    public static void ResetCounters()
    {
        Interlocked.Exchange(ref _scannedCount, 0);
        Interlocked.Exchange(ref _tcpOpenTotal, 0);
        Interlocked.Exchange(ref _signaturePassed, 0);
        Interlocked.Exchange(ref _v2RayPassed, 0);
        Interlocked.Exchange(ref _speedTestPassed, 0);
        lock (ResumeProgressLock)
        {
            CompletedSequences.Clear();
            Interlocked.Exchange(ref _nextContiguousSequence, 0);
        }
    }

    /// <summary>
    /// Produces random infinite-mode targets while atomically recording each
    /// issued IP. A checkpoint can therefore replay targets that were issued
    /// to the pipeline but had not yet completed.
    /// </summary>
    public static IEnumerable<IPAddress> GenerateResumableInfiniteIps()
    {
        while (true)
        {
            IPAddress ip;
            lock (InfiniteResumeLock)
            {
                if (_infiniteReplayIndex < _infiniteReplayIps.Count)
                {
                    ip = _infiniteReplayIps[_infiniteReplayIndex++];
                }
                else
                {
                    if (ResumeGenerator is null)
                        throw new InvalidOperationException("Resume generator is not initialized.");

                    ip = NetUtils.UintToIp(ResumeGenerator.NextPublic(IpFilter));
                    InfinitePendingIps.Enqueue(ip);
                }
            }

            yield return ip;
        }
    }

    /// <summary>
    /// Restores unfinished infinite-mode targets from a checkpoint. They are
    /// yielded before new generator values and remain tracked until completion.
    /// </summary>
    public static void RestoreInfinitePendingIps(IEnumerable<string> ips)
    {
        lock (InfiniteResumeLock)
        {
            InfinitePendingIps.Clear();
            _infiniteReplayIps = [];
            _infiniteReplayIndex = 0;
            _infiniteCommittedIps = 0;

            foreach (var value in ips)
            {
                if (!NetUtils.TryParseIpv4(value, out var ip))
                    continue;
                InfinitePendingIps.Enqueue(ip);
                _infiniteReplayIps.Add(ip);
            }
        }
    }

    /// <summary>Clears in-memory infinite-resume state for a new scan or test.</summary>
    public static void ResetInfiniteResumeState() => RestoreInfinitePendingIps([]);

    /// <summary>Captures generator and unfinished-target state as one atomic checkpoint snapshot.</summary>
    public static (ulong Seed, ulong State, long ValuesConsumed, long Rejections, string[] PendingIps)
        CaptureInfiniteResumeState()
    {
        lock (InfiniteResumeLock)
        {
            if (ResumeGenerator is null)
                throw new InvalidOperationException("Resume generator is not initialized.");

            var snapshot = ResumeGenerator.Snapshot();
            return (snapshot.Seed, snapshot.State, snapshot.ValuesConsumed,
                snapshot.Rejections, [.. InfinitePendingIps.Select(ip => ip.ToString())]);
        }
    }

    /// <summary>
    /// Restores scan counters from a checkpoint to resume aggregate statistics.
    /// Values are clamped to valid ranges to prevent overflow.
    /// </summary>
    /// <param name="stats">Checkpoint statistics to restore.</param>
    public static void RestoreCounters(CheckpointStats stats)
    {
        Interlocked.Exchange(ref _scannedCount, (int)Math.Clamp(stats.Scanned, 0, int.MaxValue));
        Interlocked.Exchange(ref _tcpOpenTotal, Math.Max(0, stats.TcpOpen));
        Interlocked.Exchange(ref _signaturePassed, (int)Math.Clamp(stats.SignaturePassed, 0, int.MaxValue));
        Interlocked.Exchange(ref _v2RayPassed, (int)Math.Clamp(stats.V2RayPassed, 0, int.MaxValue));
        Interlocked.Exchange(ref _speedTestPassed, (int)Math.Clamp(stats.SpeedTestPassed, 0, int.MaxValue));
    }

    /// <summary>
    /// Current contiguous sequence cursor for finite-mode scan resume.
    /// Updated atomically via <see cref="Interlocked"/> for thread-safe reads.
    /// </summary>
    public static long ResumeCursor { get => Interlocked.Read(ref _resumeCursor); set => Interlocked.Exchange(ref _resumeCursor, value); }
    /// <summary>
    /// Absolute path to the checkpoint file for the current session.
    /// Set once during <see cref="ResumeCoordinator.InitializeAsync"/>.
    /// </summary>
    public static string ResumeCheckpointPath { get => _resumeCheckpointPath; set => _resumeCheckpointPath = value; }
    /// <summary>Random seed used for deterministic IP shuffling in finite mode.</summary>
    public static ulong ResumeShuffleSeed { get => _resumeShuffleSeed; set => _resumeShuffleSeed = value; }
    /// <summary>
    /// The next sequence number that is guaranteed to have completed.
    /// Used by the contiguous-cursor progress tracker for accurate resume.
    /// </summary>
    public static long NextContiguousSequence => Interlocked.Read(ref _nextContiguousSequence);
    /// <summary>
    /// Initializes the resume progress tracker with a starting sequence number.
    /// Clears the completed-sequence set and resets the contiguous cursor.
    /// </summary>
    /// <param name="start">Starting sequence number (typically from checkpoint).</param>
    public static void InitializeResumeProgress(long start)
    {
        lock (ResumeProgressLock)
        {
            CompletedSequences.Clear();
            Interlocked.Exchange(ref _nextContiguousSequence, Math.Max(0, start));
        }
    }
    /// <summary>
    /// Marks a specific sequence as completed and advances the contiguous cursor.
    /// The cursor moves forward past any completed sequences at the head of the range.
    /// </summary>
    /// <param name="sequence">Sequence number that completed processing.</param>
    public static void MarkResumeSequenceCompleted(long sequence)
    {
        if (sequence < 0) return;
        lock (ResumeProgressLock)
        {
            if (sequence < _nextContiguousSequence) return;
            CompletedSequences.Add(sequence);
            while (CompletedSequences.Remove(_nextContiguousSequence))
                Interlocked.Increment(ref _nextContiguousSequence);
        }

        if (IsInfiniteMode)
            MarkInfiniteIpsCommitted();
    }

    private static void MarkInfiniteIpsCommitted()
    {
        var portCount = Math.Max(1, Config.Ports.Count);
        var completedIps = NextContiguousSequence / portCount;
        lock (InfiniteResumeLock)
        {
            while (_infiniteCommittedIps < completedIps && InfinitePendingIps.Count > 0)
            {
                InfinitePendingIps.Dequeue();
                _infiniteCommittedIps++;
            }
        }
    }

    /// <summary>
    /// Replaces the process cancellation source for test isolation.
    /// Production initializes it once and never calls this method.
    /// </summary>
    public static void ResetCancellationTokenSource()
    {
        var previous = Interlocked.Exchange(ref _cts, new CancellationTokenSource());
        previous.Dispose();
    }
}
