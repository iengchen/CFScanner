namespace CFScanner;

/// <summary>
/// Defines immutable default values for the scanner.
/// These values represent safe and well-tested defaults
/// and can be overridden via command-line arguments.
/// </summary>
public static class Defaults
{
    // ---------------------------------------------------------------------
    // Data Sources
    // ---------------------------------------------------------------------

    /// <summary>Default path to the IP-to-ASN mapping database file (TSV format).</summary>
    public const string AsnDbPath = "ip2asn-v4.tsv";
    /// <summary>Default SNI hostname used for TLS handshake and HTTP signature detection.</summary>
    public const string BaseSni = "speed.cloudflare.com";
    /// <summary>Default HTTPS port to scan.</summary>
    public const int Port = 443;

    // ---------------------------------------------------------------------
    // Behavioral Flags
    // ---------------------------------------------------------------------

    /// <summary>Whether IP scan order is randomized by default.</summary>
    public const bool Shuffle = false;
    /// <summary>Whether results are sorted by latency before writing by default.</summary>
    public const bool SortResults = false;
    /// <summary>Whether latency measurements are included in results by default.</summary>
    public const bool SaveLatency = true;
    /// <summary>Whether scan resume/checkpointing is disabled by default.</summary>
    public const bool ResumeEnabled = false;
    /// <summary>Default interval in seconds between checkpoint saves.</summary>
    public const int ResumeIntervalSeconds = 60;
    /// <summary>Default directory for storing checkpoint files.</summary>
    public const string ResumeDirectory = "resume";

    // ---------------------------------------------------------------------
    // Xray / V2Ray
    // ---------------------------------------------------------------------

    /// <summary>Executable name for the Xray binary (resolved at runtime).</summary>
    public static string XrayExeName { get; set; } = "xray";
    /// <summary>Whether per-request random SNI subdomains are disabled by default.</summary>
    public const bool RandomSNI  = false;

    // ---------------------------------------------------------------------
    // Concurrency & Buffering
    // ---------------------------------------------------------------------

    /// <summary>Default number of concurrent TCP connection workers.</summary>
    public const int TcpWorkers = 100;
    /// <summary>Default number of concurrent TLS/HTTP signature workers.</summary>
    public const int SignatureWorkers = 30;
    /// <summary>Default number of concurrent Xray/V2Ray verification workers.</summary>
    public const int V2RayWorkers = 8;

    /// <summary>Default channel buffer size for TCP connection results.</summary>
    public const int TcpChannelBuffer = 100;
    /// <summary>Default channel buffer size for V2Ray verification results.</summary>
    public const int V2RayChannelBuffer = 30;

    /// <summary>Maximum number of addresses expanded from a single CIDR range.</summary>
    public const int CidrExpandCap = 65_536;

    // ---------------------------------------------------------------------
    // Speed Test (Stage 4) Defaults
    // ---------------------------------------------------------------------

    /// <summary>
    /// Default minimum download speed in KB/s.
    /// Zero means speed test is disabled unless user specifies otherwise.
    /// </summary>
    public const int MinDownloadSpeedKb = 0;

    /// <summary>
    /// Default minimum upload speed in KB/s.
    /// </summary>
    public const int MinUploadSpeedKb = 0;

    /// <summary>
    /// Default number of concurrent speed test workers.
    /// Kept intentionally low because each worker spawns a real Xray process.
    /// </summary>
    public const int SpeedTestWorkers = 1;

    /// <summary>
    /// Default buffer size for speed test stage.
    /// This is a soft default; ArgParser may auto-scale it.
    /// </summary>
    public const int SpeedTestBuffer = 2;

    // ---------------------------------------------------------------------
    // Timeouts (Milliseconds)
    // ---------------------------------------------------------------------

    /// <summary>Default TCP connect timeout in milliseconds.</summary>
    public const int TcpTimeoutMs = 2_000;
    /// <summary>Default TLS handshake timeout in milliseconds.</summary>
    public const int TlsTimeoutMs = 2_500;
    /// <summary>Default HTTP response read timeout in milliseconds.</summary>
    public const int HttpReadTimeoutMs = 2_000;
    /// <summary>Default combined TLS+HTTP signature stage timeout in milliseconds.</summary>
    public const int SignatureTotalTimeoutMs = 5_000;

    /// <summary>Default maximum wait time for Xray process startup in milliseconds.</summary>
    public const int XrayStartupTimeoutMs = 4_000;
    /// <summary>Default timeout for Xray proxy connectivity verification in milliseconds.</summary>
    public const int XrayConnectionTimeoutMs = 3_000;
    /// <summary>Default maximum time to wait for Xray process termination during cleanup.</summary>
    public const int XrayProcessKillTimeoutMs = 2_000;
}

/// <summary>
/// Represents the runtime configuration of the scanner.
/// This class is populated from command-line arguments
/// and overrides values from <see cref="Defaults"/> where specified.
/// </summary>
public class Config
{
    // ---------------------------------------------------------------------
    // Input Sources
    // ---------------------------------------------------------------------

    /// <summary>File paths containing IP addresses or CIDR ranges to scan.</summary>
    public List<string> InputFiles { get; set; } = [];
    /// <summary>ASN identifiers (numbers or names) to scan.</summary>
    public List<string> InputAsns { get; set; } = [];
    /// <summary>CIDR ranges to scan (comma-separated).</summary>
    public List<string> InputCidrs { get; set; } = [];

    // ---------------------------------------------------------------------
    // Exclusion Sources
    // ---------------------------------------------------------------------

    /// <summary>File paths containing IPs or CIDRs to exclude from scanning.</summary>
    public List<string> ExcludeFiles { get; set; } = [];
    /// <summary>ASN identifiers to exclude from scanning.</summary>
    public List<string> ExcludeAsns { get; set; } = [];
    /// <summary>CIDR ranges to exclude from scanning.</summary>
    public List<string> ExcludeCidrs { get; set; } = [];

    // ---------------------------------------------------------------------
    // General Settings
    // ---------------------------------------------------------------------

    /// <summary>Path to the IP-to-ASN mapping database file.</summary>
    public string AsnDbPath { get; set; } = Defaults.AsnDbPath;
    /// <summary>SNI hostname for TLS handshake and HTTP signature detection.</summary>
    public string BaseSni { get; set; } = Defaults.BaseSni;
    /// <summary>Allowed HTTPS ports for scanning.</summary>
    public List<int> Ports { get; set; } = [Defaults.Port];

    /// <summary>Whether IP scan order is randomized.</summary>
    public bool Shuffle { get; set; } = Defaults.Shuffle;
    /// <summary>Whether results are sorted by latency before writing.</summary>
    public bool SortResults { get; set; } = Defaults.SortResults;
    /// <summary>Whether latency measurements are included in results.</summary>
    public bool SaveLatency { get; set; } = Defaults.SaveLatency;
    /// <summary>Whether scan resume/checkpointing is enabled.</summary>
    public bool ResumeEnabled { get; set; } = Defaults.ResumeEnabled;
    /// <summary>Interval in seconds between periodic checkpoint saves.</summary>
    public int ResumeIntervalSeconds { get; set; } = Defaults.ResumeIntervalSeconds;
    /// <summary>Directory path for storing checkpoint files.</summary>
    public string ResumeDirectory { get; set; } = Defaults.ResumeDirectory;
    /// <summary>Specific session ID to resume, or <c>null</c> for the latest session.</summary>
    public string? ResumeSessionId { get; set; }
    /// <summary>When <c>true</c>, resume is invoked without explicit scan arguments to restore saved configuration.</summary>
    public bool ResumeOnlyInvocation { get; set; }
    /// <summary>When <c>true</c>, starts a new resumable session ignoring existing checkpoints.</summary>
    public bool ResumeNewScan { get; set; }

    // ---------------------------------------------------------------------
    // Concurrency & Buffering
    // ---------------------------------------------------------------------

    /// <summary>Number of concurrent TCP connection workers.</summary>
    public int TcpWorkers { get; set; } = Defaults.TcpWorkers;
    /// <summary>Number of concurrent TLS/HTTP signature workers.</summary>
    public int SignatureWorkers { get; set; } = Defaults.SignatureWorkers;
    /// <summary>Number of concurrent Xray/V2Ray verification workers.</summary>
    public int V2RayWorkers { get; set; } = Defaults.V2RayWorkers;

    /// <summary>Channel buffer size for TCP connection results.</summary>
    public int TcpChannelBuffer { get; set; } = Defaults.TcpChannelBuffer;
    /// <summary>Channel buffer size for V2Ray verification results.</summary>
    public int V2RayChannelBuffer { get; set; } = Defaults.V2RayChannelBuffer;

    // ---------------------------------------------------------------------
    // Speed Test (Stage 4)
    // ---------------------------------------------------------------------

    /// <summary>
    /// Minimum acceptable download speed in KB/s.
    /// Parsed and normalized by ArgParser.
    /// 
    /// Examples:
    ///   --speed-dl 2mb   => 2048
    ///   --speed-dl 500   => 500 (default KB)
    /// 
    /// A value of 0 disables download speed filtering.
    /// </summary>
    public int MinDownloadSpeedKb { get; set; } =
        Defaults.MinDownloadSpeedKb;

    /// <summary>
    /// Minimum acceptable upload speed in KB/s.
    /// A value of 0 disables upload speed filtering.
    /// </summary>
    public int MinUploadSpeedKb { get; set; } =
        Defaults.MinUploadSpeedKb;

    /// <summary>
    /// Number of concurrent speed test workers.
    /// Each worker runs a real Xray process.
    /// </summary>
    public int SpeedTestWorkers { get; set; } =
        Defaults.SpeedTestWorkers;

    /// <summary>
    /// Buffer size for speed test stage.
    /// Each buffered item represents a live Xray instance,
    /// so this value must remain small.
    /// 
    /// If not explicitly set by the user, ArgParser
    /// automatically sets this to (SpeedTestWorkers + 1).
    /// </summary>
    public int SpeedTestBuffer { get; set; } =
        Defaults.SpeedTestBuffer;

    // ---------------------------------------------------------------------
    // V2Ray / Xray
    // ---------------------------------------------------------------------

    /// <summary>Path to the Xray/V2Ray configuration file.</summary>
    public string? V2RayConfigPath { get; set; }

    /// <summary>
    /// Indicates whether V2Ray/Xray proxy verification is enabled.
    /// Derived from <see cref="V2RayConfigPath"/> being non-empty.
    /// </summary>
    public bool EnableV2RayCheck =>
        !string.IsNullOrWhiteSpace(V2RayConfigPath);

    /// <summary>
    /// Indicates whether speed testing is enabled.
    /// Requires both a V2Ray config and at least one non-zero speed threshold.
    /// </summary>
    public bool EnableSpeedTest =>
        EnableV2RayCheck && (MinDownloadSpeedKb > 0 || MinUploadSpeedKb > 0);

    /// <summary>Whether per-request random SNI subdomains are enabled.</summary>
    public bool RandomSNI { get; set; } = Defaults.RandomSNI;

    // ---------------------------------------------------------------------
    // Timeouts (Milliseconds)
    // ---------------------------------------------------------------------

    /// <summary>TCP connect timeout in milliseconds.</summary>
    public int TcpTimeoutMs { get; set; } = Defaults.TcpTimeoutMs;
    /// <summary>TLS handshake timeout in milliseconds.</summary>
    public int TlsTimeoutMs { get; set; } = Defaults.TlsTimeoutMs;
    /// <summary>HTTP response read timeout in milliseconds.</summary>
    public int HttpReadTimeoutMs { get; set; } = Defaults.HttpReadTimeoutMs;
    /// <summary>Combined TLS+HTTP signature stage timeout in milliseconds.</summary>
    public int SignatureTotalTimeoutMs { get; set; } =
        Defaults.SignatureTotalTimeoutMs;

    /// <summary>Maximum wait time for Xray process startup in milliseconds.</summary>
    public int XrayStartupTimeoutMs { get; set; } =
        Defaults.XrayStartupTimeoutMs;

    /// <summary>Timeout for Xray proxy connectivity verification in milliseconds.</summary>
    public int XrayConnectionTimeoutMs { get; set; } =
        Defaults.XrayConnectionTimeoutMs;

    /// <summary>Maximum time to wait for Xray process termination during cleanup.</summary>
    public int XrayProcessKillTimeoutMs { get; set; } =
        Defaults.XrayProcessKillTimeoutMs;
}
