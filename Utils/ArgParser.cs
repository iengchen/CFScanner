using CFScanner.UI;
using System.Globalization;

namespace CFScanner.Utils;

/// <summary>
/// Handles parsing and validation of command-line arguments.
/// Supports scan profiles, strictly validated numeric inputs, and automatic tuning.
/// </summary>
public static class ArgParser
{
    /// <summary>
    /// Parses arguments, applies configuration, and validates inputs.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>True if scanning should proceed; False if help/manual was requested.</returns>
    public static bool ParseArguments(string[] args)
    {
        try
        {
        // 1. Check for Help/Manual requests immediately (Early Exit)
        if (ShouldShowHelp(args)) return false;
        var skipConfirmation = false;

        // 2. Identify and Apply Profile (Pre-scan)
        // We do this BEFORE parsing other args so user can override profile settings manually.
        var profile = DetectProfile(args);
        ApplyProfileDefaults(profile);

        // Track explicit buffer settings to avoid auto-scaling them later if user set them
        bool tcpBufferExplicitlySet = false;
        bool v2rayBufferExplicitlySet = false;
        bool speedBufferExplicitlySet = false;

        // 3. Parse and Override Configuration
        for (int i = 0; i < args.Length; i++)
        {
            string option = args[i].ToLowerInvariant();
            string? value = (i + 1 < args.Length) ? args[i + 1] : null;

            // Helper for parsing lists
            static List<string> ParseList(string v) =>
                [.. v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

            switch (option)
            {
                // --- Input Sources ---
                case "-f": case "--file": RequireValue(value, option); GlobalContext.Config.InputFiles.AddRange(ParseList(value!)); i++; break;
                case "-a": case "--asn": RequireValue(value, option); GlobalContext.Config.InputAsns.AddRange(ParseList(value!)); i++; break;
                case "-r": case "--range": RequireValue(value, option); GlobalContext.Config.InputCidrs.AddRange(ParseList(value!)); i++; break;

                // --- Exclusion Rules ---
                case "-xf": case "--exclude-file": RequireValue(value, option); GlobalContext.Config.ExcludeFiles.AddRange(ParseList(value!)); i++; break;
                case "-xa": case "--exclude-asn": RequireValue(value, option); GlobalContext.Config.ExcludeAsns.AddRange(ParseList(value!)); i++; break;
                case "-xr": case "--exclude-range": RequireValue(value, option); GlobalContext.Config.ExcludeCidrs.AddRange(ParseList(value!)); i++; break;

                // --- Performance Tuning (User Overrides) ---
                case "--tcp-workers": GlobalContext.Config.TcpWorkers = ParseInt(value, option, 1, 5000); i++; break;
                case "--signature-workers": GlobalContext.Config.SignatureWorkers = ParseInt(value, option, 1, 2000); i++; break;
                case "--v2ray-workers": GlobalContext.Config.V2RayWorkers = ParseInt(value, option, 1, 500); i++; break;

                case "--tcp-buffer":
                    GlobalContext.Config.TcpChannelBuffer = ParseInt(value, option, 1, 50000);
                    tcpBufferExplicitlySet = true;
                    i++;
                    break;

                case "--v2ray-buffer":
                    GlobalContext.Config.V2RayChannelBuffer = ParseInt(value, option, 1, 10000);
                    v2rayBufferExplicitlySet = true;
                    i++;
                    break;

                // --- Speed Test Configuration ---
                case "--speed-dl":
                    GlobalContext.Config.MinDownloadSpeedKb = ParseBandwidthKb(value, option);
                    i++;
                    break;
                case "--speed-ul":
                    GlobalContext.Config.MinUploadSpeedKb = ParseBandwidthKb(value, option);
                    i++;
                    break;
                case "--speed-workers":
                    GlobalContext.Config.SpeedTestWorkers = ParseInt(value, option, 1, 50);
                    i++;
                    break;

                case "--speed-buffer":
                    GlobalContext.Config.SpeedTestBuffer = ParseInt(value, option, 1, 100);
                    speedBufferExplicitlySet = true;
                    i++;
                    break;

                // --- Timeouts ---
                case "--tcp-timeout": GlobalContext.Config.TcpTimeoutMs = ParseInt(value, option, 100, 30000); i++; break;
                case "--tls-timeout": GlobalContext.Config.TlsTimeoutMs = ParseInt(value, option, 100, 30000); i++; break;
                case "--http-timeout": GlobalContext.Config.HttpReadTimeoutMs = ParseInt(value, option, 100, 30000); i++; break;
                case "--sign-timeout": GlobalContext.Config.SignatureTotalTimeoutMs = ParseInt(value, option, 500, 60000); i++; break;
                case "--xray-start-timeout": GlobalContext.Config.XrayStartupTimeoutMs = ParseInt(value, option, 1000, 60000); i++; break;
                case "--xray-conn-timeout": GlobalContext.Config.XrayConnectionTimeoutMs = ParseInt(value, option, 1000, 60000); i++; break;
                case "--xray-kill-timeout": GlobalContext.Config.XrayProcessKillTimeoutMs = ParseInt(value, option, 100, 10000); i++; break;

                // --- V2Ray & Output ---
                case "-vc": case "--v2ray-config": RequireValue(value, option); GlobalContext.Config.V2RayConfigPath = value!; i++; break;
                case "--sort": GlobalContext.Config.SortResults = true; break;
                case "-nl": case "--no-latency": GlobalContext.Config.SaveLatency = false; break;
                case "-s": case "--shuffle": GlobalContext.Config.Shuffle = true; break;
                case "--random-sni": GlobalContext.Config.RandomSNI = true; break;
                case "--resume": case "--checkpoint": GlobalContext.Config.ResumeEnabled = true; break;
                case "--resume-interval":
                    GlobalContext.Config.ResumeIntervalSeconds = ParseInt(value, option, 10, 86400); i++; break;
                case "--resume-dir":
                    RequireValue(value, option);
                    GlobalContext.Config.ResumeDirectory = value!.Trim();
                    i++;
                    break;
                case "--resume-session":
                    RequireValue(value, option);
                    GlobalContext.Config.ResumeEnabled = true;
                    GlobalContext.Config.ResumeSessionId = value!.Trim();
                    i++;
                    break;
                case "--new":
                    GlobalContext.Config.ResumeNewScan = true;
                    break;

                // --- Profiles (Already handled in pre-scan, skip here) ---
                case "--fast": case "--slow": case "--extreme": case "--normal": break;
                case "-y": case "--yes": case "--no-confirm": skipConfirmation = true; break;

                // --- Port Selection (UPDATED) ---
                case "-p":
                case "--port":
                    GlobalContext.Config.Ports = ParsePort(value, option);
                    i++;
                    break;

                default:
                    ErrorAndExit($"Unknown option: {args[i]}");
                    return false;
            }
        }

        // 4. Auto-scale Buffers (if not explicitly set by user)
        if (!tcpBufferExplicitlySet)
            GlobalContext.Config.TcpChannelBuffer = Math.Max(GlobalContext.Config.TcpWorkers * 2, 100);

        if (!v2rayBufferExplicitlySet)
            GlobalContext.Config.V2RayChannelBuffer = Math.Max(GlobalContext.Config.V2RayWorkers * 3, 20);

        if (!speedBufferExplicitlySet)
            GlobalContext.Config.SpeedTestBuffer = GlobalContext.Config.SpeedTestWorkers + 1;

        GlobalContext.Config.ResumeOnlyInvocation =
            GlobalContext.Config.ResumeEnabled && !HasExplicitScanArguments(args);
        if (GlobalContext.Config.ResumeNewScan && !GlobalContext.Config.ResumeEnabled)
            ErrorAndExit("'--new' requires '--resume'.");
        if (GlobalContext.Config.ResumeNewScan && !string.IsNullOrWhiteSpace(GlobalContext.Config.ResumeSessionId))
            ErrorAndExit("'--new' cannot be combined with '--resume-session'.");

        // 5. User Feedback
        if (!skipConfirmation &&
            (!GlobalContext.Config.ResumeEnabled || GlobalContext.Config.ResumeNewScan))
            DisplayProfileSummary(profile);

        return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>
    /// Checks whether any explicit scan-related arguments are present.
    /// Used to distinguish a configuration-restoring resume from a resuming scan.
    /// </summary>
    /// <param name="args">Command-line arguments to check.</param>
    /// <returns><c>true</c> if at least one scan-related option is found.</returns>
    private static bool HasExplicitScanArguments(string[] args)
    {
        var scanOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "-f","--file","-a","--asn","-r","--range",
            "-xf","--exclude-file","-xa","--exclude-asn","-xr","--exclude-range",
            "-p","--port","-vc","--v2ray-config","--speed-dl","--speed-ul",
            "--speed-workers","--speed-buffer","--tcp-workers","--signature-workers",
            "--v2ray-workers","--tcp-buffer","--v2ray-buffer","--tcp-timeout",
            "--tls-timeout","--http-timeout","--sign-timeout","--xray-start-timeout",
            "--xray-conn-timeout","--xray-kill-timeout","--sort","-nl","--no-latency",
            "-s","--shuffle","--random-sni","--fast","--slow","--extreme","--normal"
        };
        return args.Any(a => scanOptions.Contains(a));
    }

    // =========================================================================
    // HELPER METHODS: Logic & UX
    // =========================================================================

    private enum ScanProfile { Normal, Fast, Slow, Extreme }

    /// <summary>
    /// Detects the scan profile from command-line arguments.
    /// Returns <see cref="ScanProfile.Normal"/> if no profile flag is found.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>The detected <see cref="ScanProfile"/>.</returns>
    private static ScanProfile DetectProfile(string[] args)
    {
        if (args.Any(a => a.Equals("--extreme", StringComparison.OrdinalIgnoreCase))) return ScanProfile.Extreme;
        if (args.Any(a => a.Equals("--fast", StringComparison.OrdinalIgnoreCase))) return ScanProfile.Fast;
        if (args.Any(a => a.Equals("--slow", StringComparison.OrdinalIgnoreCase))) return ScanProfile.Slow;
        return ScanProfile.Normal;
    }

    /// <summary>
    /// Allowed cloudflare HTTPS ports
    /// </summary>
    private static readonly HashSet<int> AllowedPorts =
    [
        443, 2053, 2083, 2087, 2096, 8443
    ];

    /// <summary>
    /// Extract HTTPS port(s) from arguments.
    /// Supports single port, comma-separated ports, or 'all'.
    /// </summary>
    private static List<int> ParsePort(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value))
            ErrorAndExit($"Missing value for option: {option}");

        value = value!.Trim().ToLowerInvariant();

        if (value == "all")
            return [.. AllowedPorts.OrderBy(p => p)];

        var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            ErrorAndExit($"Invalid port value: {value} for option: {option}");

        var ports = new List<int>();

        foreach (var part in parts)
        {
            if (!int.TryParse(part, out int port))
                ErrorAndExit($"Invalid port value: {part} for option: {option}");

            if (!AllowedPorts.Contains(port))
                ErrorAndExit($"Port {port} is not allowed. Allowed ports are: {string.Join(", ", AllowedPorts)}");

            ports.Add(port);
        }

        return [.. ports.Distinct().OrderBy(p => p)];
    }

    /// <summary>
    /// Applies the preset concurrency and timeout values for the given scan profile.
    /// Profile values serve as defaults; explicit CLI arguments override them later.
    /// </summary>
    /// <param name="profile">The scan profile to apply.</param>
    private static void ApplyProfileDefaults(ScanProfile profile)
    {
        switch (profile)
        {
            case ScanProfile.Extreme:
                GlobalContext.Config.TcpWorkers = 200;
                GlobalContext.Config.SignatureWorkers = 80;
                GlobalContext.Config.V2RayWorkers = 32;
                GlobalContext.Config.TcpTimeoutMs = 500;
                GlobalContext.Config.TlsTimeoutMs = 800;
                GlobalContext.Config.HttpReadTimeoutMs = 1000;
                GlobalContext.Config.SignatureTotalTimeoutMs = 1000;
                GlobalContext.Config.XrayStartupTimeoutMs = 2000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 1000;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Fast:
                GlobalContext.Config.TcpWorkers = 150;
                GlobalContext.Config.SignatureWorkers = 50;
                GlobalContext.Config.V2RayWorkers = 16;
                GlobalContext.Config.TcpTimeoutMs = 1000;
                GlobalContext.Config.TlsTimeoutMs = 1500;
                GlobalContext.Config.HttpReadTimeoutMs = 1500;
                GlobalContext.Config.SignatureTotalTimeoutMs = 2500;
                GlobalContext.Config.XrayStartupTimeoutMs = 2000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 1500;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Slow:
                GlobalContext.Config.TcpWorkers = 50;
                GlobalContext.Config.SignatureWorkers = 20;
                GlobalContext.Config.V2RayWorkers = 4;
                GlobalContext.Config.TcpTimeoutMs = 3000;
                GlobalContext.Config.TlsTimeoutMs = 3000;
                GlobalContext.Config.HttpReadTimeoutMs = 3000;
                GlobalContext.Config.SignatureTotalTimeoutMs = 8000;
                GlobalContext.Config.XrayStartupTimeoutMs = 3000;
                GlobalContext.Config.XrayConnectionTimeoutMs = 8000;
                GlobalContext.Config.XrayProcessKillTimeoutMs = 1500;
                break;

            case ScanProfile.Normal:
            default:
                break;
        }
    }

    /// <summary>
    /// Displays a comprehensive summary of the active configuration and waits for user confirmation.
    /// </summary>
    /// <param name="profile">The active scanning profile.</param>
    /// <summary>
    /// Displays the restored configuration summary (used when resuming without explicit arguments).
    /// </summary>
    public static void DisplayRestoredConfigurationSummary()
    {
        DisplayConfigurationSummary("RESUMED SESSION");
    }

    /// <summary>
    /// Displays the effective configuration summary after all CLI overrides are applied.
    /// </summary>
    public static void DisplayEffectiveConfigurationSummary()
    {
        DisplayConfigurationSummary("EFFECTIVE");
    }

    private static void DisplayProfileSummary(ScanProfile profile) =>
        DisplayConfigurationSummary(profile.ToString().ToUpperInvariant());

    /// <summary>
    /// Renders the configuration summary table and waits for user confirmation.
    /// Clears the console before scanning begins to provide a clean status area.
    /// </summary>
    /// <param name="profileLabel">Label for the active profile (e.g., "NORMAL", "FAST").</param>
    private static void DisplayConfigurationSummary(string profileLabel)
    {
        var config = GlobalContext.Config;

        Console.Clear();
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("============================================================");
        Console.WriteLine($" SCAN CONFIGURATION | PROFILE: {profileLabel}");
        Console.WriteLine("============================================================");
        Console.ResetColor();
        // -----------------------------------------------------------------
        // 1. Concurrency & Buffers
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(" [Concurrency & Buffers]");
        Console.ResetColor();

        Console.WriteLine($"   TCP Workers:           {config.TcpWorkers,-6} | Buffer: {config.TcpChannelBuffer}");
        Console.WriteLine($"   Signature Workers:     {config.SignatureWorkers,-6} | (Internal)");

        if (config.EnableV2RayCheck)
        {
            Console.WriteLine($"   V2Ray Workers:         {config.V2RayWorkers,-6} | Buffer: {config.V2RayChannelBuffer}");
        }
        // -----------------------------------------------------------------
        // 2. Speed Test Summary
        // -----------------------------------------------------------------
        if (config.MinDownloadSpeedKb > 0 || config.MinUploadSpeedKb > 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n [Speed Test Criteria]");
            Console.ResetColor();

            string minDl = config.MinDownloadSpeedKb > 0 ? $"{config.MinDownloadSpeedKb} KB/s" : "N/A";
            string minUl = config.MinUploadSpeedKb > 0 ? $"{config.MinUploadSpeedKb} KB/s" : "N/A";

            Console.WriteLine($"   Min Download:     {minDl,-10} | Workers: {config.SpeedTestWorkers}");
            Console.WriteLine($"   Min Upload:       {minUl,-10} | Buffer:  {config.SpeedTestBuffer}");
        }
        // -----------------------------------------------------------------
        // 3. Timeouts
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n [Timeouts (ms)]");
        Console.ResetColor();

        Console.WriteLine($"   TCP Connect:      {config.TcpTimeoutMs,-6} | TLS Handshake: {config.TlsTimeoutMs}");
        Console.WriteLine($"   HTTP Read:        {config.HttpReadTimeoutMs,-6} | Signature Total:  {config.SignatureTotalTimeoutMs}");

        if (config.EnableV2RayCheck)
        {
            Console.WriteLine($"   Xray Start:       {config.XrayStartupTimeoutMs,-6} | Xray Conn:   {config.XrayConnectionTimeoutMs}");
            Console.WriteLine($"   Xray Kill:        {config.XrayProcessKillTimeoutMs,-6}");
        }
        // -----------------------------------------------------------------
        // 4. Behavior & Settings
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("\n [Settings]");
        Console.ResetColor();

        string v2rayStatus = config.EnableV2RayCheck ? "Enabled" : "Disabled";
        string randomSniPart = config.EnableV2RayCheck
            ? $"   | Random SNI: {(config.RandomSNI ? "Enabled" : "Disabled")}"
            : string.Empty;

        Console.WriteLine($"   V2Ray Check:      {v2rayStatus}");
        Console.WriteLine($"   Shuffle IPs:      {config.Shuffle,-6} | Sort Results: {config.SortResults}");
        Console.WriteLine($"   Save Latency:     {config.SaveLatency}");
        Console.WriteLine($"   Ports:            {string.Join(", ", config.Ports)}{randomSniPart}");

        Console.WriteLine("============================================================");
        // -----------------------------------------------------------------
        // Confirmation
        // -----------------------------------------------------------------
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write(" Press any key to start scanning...");
        Console.ResetColor();

        Console.ReadKey(true);
        Console.WriteLine();
        // Start the scan phase on a clean console so target-loading and
        // live progress messages are not mixed with the configuration table.
        Console.Clear();
    }

    /// <summary>
    /// Checks if the user requested help or manual.
    /// </summary>
    private static bool ShouldShowHelp(string[] args)
    {
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] is "-h" or "--help" or "/?")
            {
                if (i + 1 < args.Length &&
                   (args[i + 1].Equals("full", StringComparison.OrdinalIgnoreCase) ||
                    args[i + 1].Equals("advanced", StringComparison.OrdinalIgnoreCase)))
                    PrintHelpFull();
                else
                    PrintHelpShort();
                return true;
            }
            if (args[i].Equals("--manual", StringComparison.OrdinalIgnoreCase))
            {
                PrintHelpFull();
                return true;
            }
        }
        return false;
    }

    // =========================================================================
    // HELPER METHODS: Validation
    // =========================================================================

    /// <summary>
    /// Ensures that the given CLI option has a non-null, non-whitespace value.
    /// Calls <see cref="ErrorAndExit"/> if the value is missing.
    /// </summary>
    /// <param name="value">The parsed value from the argument.</param>
    /// <param name="option">The option name for error messaging.</param>
    private static void RequireValue(string? value, string option)
    {
        if (string.IsNullOrWhiteSpace(value))
            ErrorAndExit($"Option '{option}' requires a value.");
    }

    /// <summary>
    /// Parses and validates an integer CLI argument within the specified range.
    /// Calls <see cref="ErrorAndExit"/> on parse failure or out-of-range values.
    /// </summary>
    /// <param name="value">The raw string value to parse.</param>
    /// <param name="option">The option name for error messaging.</param>
    /// <param name="min">Minimum allowed value (inclusive).</param>
    /// <param name="max">Maximum allowed value (inclusive).</param>
    /// <returns>The parsed integer value.</returns>
    private static int ParseInt(string? value, string option, int min, int max)
    {
        RequireValue(value, option);
        if (!int.TryParse(value, out int result))
            ErrorAndExit($"Invalid numeric value for '{option}': {value}");
        if (result < min || result > max)
            ErrorAndExit($"Value for '{option}' must be between {min} and {max}.");
        return result;
    }

    /// <summary>
    /// Parses bandwidth strings like "2mb", "500kb" into integer Kilobytes.
    /// Defaults to KB if no suffix is provided.
    /// </summary>
    private static int ParseBandwidthKb(string? value, string option)
    {
        RequireValue(value, option);

        string cleanValue = value!.Trim().ToLowerInvariant();
        double multiplier = 1; // Default is KB
        string numberPart = cleanValue;

        if (cleanValue.EndsWith("mb") || cleanValue.EndsWith("m"))
        {
            multiplier = 1024;
            numberPart = cleanValue.TrimEnd('m', 'b');
        }
        else if (cleanValue.EndsWith("kb") || cleanValue.EndsWith("k"))
        {
            multiplier = 1;
            numberPart = cleanValue.TrimEnd('k', 'b');
        }

        if (!double.TryParse(numberPart, NumberStyles.Any, CultureInfo.InvariantCulture, out double result))
            ErrorAndExit($"Invalid bandwidth value for '{option}': {value}. Examples: 500kb, 2mb.");

        int finalKb = (int)(result * multiplier);
        if (finalKb < 0) ErrorAndExit($"Value for '{option}' cannot be negative.");

        return finalKb;
    }

    /// <summary>
    /// Prints an error message and terminates the application with exit code 1.
    /// </summary>
    /// <param name="message">Error message to display.</param>
    private static void ErrorAndExit(string message)
    {
        ConsoleInterface.PrintError(message);
        throw new InvalidOperationException(message);
    }

    // =========================================================================
    // HELPER METHODS: Help Text
    // =========================================================================

    /// <summary>
    /// Prints the short help text to the console.
    /// </summary>
    public static void PrintHelpShort()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Cloudflare IP Scanner");
        Console.ResetColor();
        Console.WriteLine(@"
USAGE: CFScanner [PROFILE] [INPUT] [OPTIONS]

PROFILES:
  --normal (Default) | --fast | --slow | --extreme

INPUT:
  -f <FILE> | -a <ASN> | -r <CIDR>

OPTIONS:
  -p, --port <PORT|PORTS|all>    HTTPS port(s) to scan
  -vc <CONFIG>   Enable real V2Ray verification
  --speed-dl     Min download speed (e.g., 2mb, 500kb)
  --speed-ul     Min upload speed (e.g., 1mb)
  --sort         Sort results by latency
  --resume       Save and recover interrupted scans (default: disabled)
  --resume-session <ID>  Select a specific saved session (with --resume)
  --new                  Start a new resumable session and ignore saved sessions
  --resume-interval <SEC>  Checkpoint interval (10–86400, default: 60)
  --resume-dir <PATH>      Checkpoint directory (default: resume)
  --manual       Show full documentation

EXAMPLE:
  CFScanner --range 104.16.0.0/24 --fast --speed-dl 500kb
");
    }

    /// <summary>
    /// Prints the full documentation (manual) to the console, including
    /// all options, profiles, examples, and pipeline description.
    /// </summary>
    public static void PrintHelpFull()
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("CFScanner - Advanced Cloudflare IP Scanner");
        Console.WriteLine("Author: Mohammad Rambod");
        Console.WriteLine("For educational and research purposes only");
        Console.ResetColor();

        Console.WriteLine(@"
DESCRIPTION
-----------
High-performance IPv4 scanner for Cloudflare edge nodes.

Scanning Pipeline:
  TCP Connectivity
    -> TLS / HTTP Signature
      -> Real Xray (V2Ray) Verification (Optional)
        -> Speed Test (Optional)

Profiles define baseline performance parameters and can be
manually overridden by explicit command-line options.

PROFILES (PRESETS)
------------------
  --normal     Balanced defaults (implicit)
  --fast       Aggressive scanning, moderate stability
  --slow       Conservative and stable
  --extreme    Datacenter-grade, minimal timeouts

INPUT SOURCES
-------------
  -f,  --file <PATH,...>         Load IP/CIDR file(s);
                                 (one entry per line, '#' comments ignored)
  -a,  --asn <ASN,...>           Scan by ASN
                                 (number or name, comma-separated)
  -r,  --range <CIDR,...>        Scan CIDRs (comma-separated)

Multiple inputs can be combined.

EXCLUSION RULES
---------------
  -xf, --exclude-file <PATH,...>   Exclude IPs or CIDRs from file(s) 
                                   (one entry per line, '#' comments ignored)
  -xa, --exclude-asn <ASN,...>     Exclude ASNs
                                   (number or name via iptoasn, comma-separated)
  -xr, --exclude-range <CIDR,...>  Exclude CIDR ranges (comma-separated)

PERFORMANCE (CONCURRENCY)
-------------------------
  --tcp-workers <N>              TCP probe workers        (1–5000)
  --signature-workers <N>        Signature workers        (1–2000)
  --v2ray-workers <N>            Xray verification workers (1–500)
  --speed-workers <N>            Speed test workers       (1–50)

QUEUE / BUFFER SIZES
--------------------
  --tcp-buffer <N>               TCP result queue size
  --v2ray-buffer <N>             V2Ray result queue size
  --speed-buffer <N>             Speed test queue size

If buffers are not specified, they are auto-scaled
based on final worker counts.

SPEED TEST CRITERIA
-------------------
  --speed-dl <VAL>               Min download speed (e.g. 50kb)
  --speed-ul <VAL>               Min upload speed   (e.g. 0.5mb)

If neither is specified, speed testing is disabled.
NOTE: High concurrency may stress the network interface and cause false negatives.
      Keep speed thresholds low.

XRAY / V2RAY
------------
  -vc, --v2ray-config <PATH>     Enable real Xray verification
                                 (Requires valid Xray config)
  --random-sni                   Enable per-request random SNI (random subdomain)

PORT SELECTION
--------------
  -p, --port <PORT|PORTS|all>    HTTPS port(s) to scan
                                 Single port, comma-separated ports,
                                 or keyword 'all'

                                 Allowed:
                                 443, 2053, 2083, 2087, 2096, 8443

TIMEOUTS (MILLISECONDS)
----------------------
  --tcp-timeout <MS>             TCP connect timeout
  --tls-timeout <MS>             TLS handshake timeout
  --http-timeout <MS>            HTTP read timeout
  --sign-timeout <MS>            Signature stage timeout

  --xray-start-timeout <MS>      Xray startup timeout
  --xray-conn-timeout <MS>       Proxy connectivity timeout
  --xray-kill-timeout <MS>       Process termination timeout

OUTPUT & BEHAVIOR
-----------------
  --sort                         Sort results by latency
  -nl, --no-latency              Do not store latency values in result file
  -s,  --shuffle                 Randomize IP scan order
  -y,  --yes                     Skip configuration summary and start scanning immediately

RESUME / CRASH RECOVERY
-----------------------
  --resume                       Opt in to resumable scans
  --resume-session <ID>          Select a specific saved session
  --new                          Start a new resumable session; ignore saved sessions
  --resume-interval <SECONDS>    Atomic checkpoint interval (10–86400; default 60)
  --resume-dir <PATH>            Checkpoint directory (default: ./resume)
  Checkpoints are small JSON files. Finite scans resume from a conservative
  cursor and may repeat a short tail after interruption; infinite scans use
  a deterministic generator. Existing sessions are never continued silently.
  Interactive startup choices: [C] continue, [N] new scan, [D] delete.
  With -y, continuation requires matching configuration and result file.
  Running only --resume restores the saved scan configuration automatically.
  Checkpoints are atomic and written at most once per interval; credentials
  and raw Xray templates are never stored. Infinite sessions remain recoverable
  after cancellation. The default 60-second cadence minimizes SSD writes.

HELP
----
  -h, --help                     Show short help
  -h full | --help full          Show full documentation
  --manual                       Same as  -h full

EXAMPLES
--------
  Fast scan with speed test:
    CFScanner --range 104.16.0.0/24 --fast --speed-dl 1mb

  ASN scan with Xray verification:
    CFScanner --asn 13335 -vc xray.json --slow

  Aggressive datacenter scan:
    CFScanner --range 172.64.0.0/16 --extreme -y
");
    }
}
