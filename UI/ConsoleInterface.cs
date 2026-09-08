using CFScanner.Core;
using CFScanner.Utils; // For Accessing Config
using System.Text;
using System.Threading.Channels;

namespace CFScanner.UI;

/// <summary>
/// Centralized console UI handler.
/// Responsible for all user-facing output:
/// headers, errors, success messages, live status line,
/// and the final summary report.
/// </summary>
public static class ConsoleInterface
{
    // ---------------------------------------------------------------------
    // Status Line State & Synchronization
    // ---------------------------------------------------------------------

    // Global lock to serialize all console cursor operations
    private static readonly Lock ConsoleLock = new();

    // Last rendered status line text
    private static volatile string _lastStatusLine = string.Empty;

    // Indicates whether the status line is currently visible
    private static volatile bool _statusLineVisible = false;

    // Console row index where the status line is rendered
    private static volatile int _statusLineRow = -1;

    // ---------------------------------------------------------------------
    // Basic Output Helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Prints the application banner and clears the console.
    /// </summary>
    public static void PrintHeader()
    {
        Console.Clear();
        Console.WriteLine("=== CFScanner - Advanced Cloudflare IP Scanner ===");
        Console.WriteLine(new string('-', 60));
    }

    /// <summary>
    /// Prints an error message in red to the console.
    /// </summary>
    /// <param name="msg">Error message to display.</param>
    public static void PrintError(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"[Error] {msg}");
        Console.ResetColor();
    }

    /// <summary>
    /// Prints a warning message in yellow. Optionally prompts the user
    /// to confirm continuation.
    /// </summary>
    /// <param name="msg">Warning message to display.</param>
    /// <param name="requireConfirmation">
    /// When <c>true</c>, prompts the user with a Y/any-key confirmation dialog.
    /// </param>
    /// <param name="prependNewLine">
    /// When <c>true</c>, inserts a blank line before the warning for visual separation.
    /// </param>
    /// <returns>
    /// <c>true</c> if no confirmation was required or the user confirmed;
    /// <c>false</c> if the user declined.
    /// </returns>
    public static bool PrintWarning(
        string msg,
        bool requireConfirmation = false,
        bool prependNewLine = false)
    {
        if (prependNewLine)
            Console.WriteLine();

        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"[Warning] {msg}");
        Console.ResetColor();

        if (!requireConfirmation)
            return true;

        // A confirmation cannot be safely collected when either end of the
        // console is redirected. Fail closed instead of silently approving
        // a warning or calling ReadKey on redirected input.
        if (Console.IsInputRedirected || Console.IsOutputRedirected)
            return false;

        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.Write("Continue? Press 'Y' to proceed, any other key to cancel: ");
        Console.ResetColor();

        var key = Console.ReadKey(intercept: true);
        Console.WriteLine();

        return key.Key == ConsoleKey.Y;
    }

    /// <summary>
    /// Prompts the user to continue, start a new scan, or delete a resumable session.
    /// </summary>
    /// <param name="sessionId">Session identifier to display in the prompt.</param>
    /// <returns>The key pressed by the user (ConsoleKey.C, D, or N).</returns>
    public static ConsoleKeyInfo PromptResume(string sessionId)
    {
        lock (ConsoleLock)
        {
            Console.WriteLine($"[Resume] Recoverable session found: {sessionId}");
            Console.Write("[Resume] [C] Continue  [N] New scan  [D] Delete: ");
            return Console.ReadKey(true);
        }
    }

    /// <summary>
    /// Prompts the user when an incompatible checkpoint is detected.
    /// Offers options to start a new scan or delete the saved session.
    /// </summary>
    /// <param name="sessionId">Session identifier to display.</param>
    /// <param name="differences">Description of configuration differences.</param>
    /// <returns>The key pressed by the user (ConsoleKey.D or N).</returns>
    public static ConsoleKeyInfo PromptIncompatibleResume(string sessionId, string differences)
    {
        lock (ConsoleLock)
        {
            Console.WriteLine($"[Resume] Checkpoint {sessionId} is incompatible: {differences}");
            Console.Write("[Resume] [N] New scan  [D] Delete saved session: ");
            return Console.ReadKey(true);
        }
    }

    /// <summary>
    /// Prints information about a resumed scan session, including the
    /// starting sequence and results file path.
    /// </summary>
    /// <param name="sessionId">Session identifier being resumed.</param>
    /// <param name="cursor">Starting sequence number for the resumed scan.</param>
    /// <param name="resultsPath">Path to the results file being appended to.</param>
    public static void PrintResumeContinuation(string sessionId, long cursor, string resultsPath)
    {
        lock (ConsoleLock)
        {
            Console.WriteLine($"[Resume] Continuing session {sessionId} from sequence {cursor:N0}.");
            Console.WriteLine($"[Resume] Appending to results: {resultsPath}");
        }
    }

    /// <summary>
    /// Prints the final checkpoint progress percentage for finite-mode scans.
    /// </summary>
    /// <param name="totalIps">Total number of IPs in the scan.</param>
    public static void PrintFinalCheckpointProgress(long totalIps)
    {
        if (GlobalContext.IsInfiniteMode || totalIps <= 0)
            return;

        var ports = Math.Max(1, GlobalContext.Config.Ports.Count);
        var totalProbes = totalIps * (long)ports;
        var completed = Math.Clamp(GlobalContext.NextContiguousSequence, 0, totalProbes);
        var percent = completed * 100.0 / Math.Max(totalProbes, 1);
        Console.WriteLine($"[Resume] Final checkpoint progress: {percent:F2}% ({completed:N0}/{totalProbes:N0})");
    }

    /// <summary>
    /// Prints a successful verification line (signature or real proxy test).
    /// Ensures the live status line is temporarily cleared and then restored
    /// to prevent console corruption.
    /// </summary>
    /// <param name="ip">The verified IP address.</param>
    /// <param name="port">The verified Port.</param>
    /// <param name="latency">Measured latency in milliseconds.</param>
    /// <param name="type">Stage identifier (e.g. SIGNATURE, REAL-XRAY).</param>
    public static void PrintSuccess(string ip, int port, long latency, string type, ConsoleColor color = ConsoleColor.Green)
    {
        lock (ConsoleLock)
        {
            if (_statusLineVisible && !Console.IsOutputRedirected)
                ClearStatusLineInternal();

            Console.ForegroundColor = color;
            Console.Write($"[{type}] {ip} : {port} - Latency: ");

            if (latency < 800)
                Console.ForegroundColor = ConsoleColor.Cyan;
            else if (latency < 1500)
                Console.ForegroundColor = ConsoleColor.Yellow;
            else
                Console.ForegroundColor = ConsoleColor.Red;

            Console.WriteLine($"{latency}ms");
            Console.ResetColor();

            if (_statusLineVisible && !Console.IsOutputRedirected)
            {
                _statusLineRow = Console.CursorTop;
                RenderStatusLineInternal();
            }
        }
    }

    // ---------------------------------------------------------------------
    // Final Report
    // ---------------------------------------------------------------------

    /// <summary>
    /// Prints the final scan summary report, including total counts,
    /// duration, and output file information.
    /// </summary>
    /// <param name="totalTime">Total wall-clock duration of the scan.</param>
    public static void PrintFinalReport(TimeSpan totalTime)
    {
        HideStatusLine();

        int portsCount = Math.Max(1, GlobalContext.Config.Ports.Count);
        long totalProbes = GlobalContext.TotalIps * portsCount;

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("\n══════════════════════════════════");
        Console.WriteLine($" Unique IPs       : {(GlobalContext.IsInfiniteMode ? "Infinite" : GlobalContext.TotalIps.ToString("N0"))}");
        Console.WriteLine($" Ports per IP     : {portsCount}");
        if (!GlobalContext.IsInfiniteMode)
            Console.WriteLine($" Total Checks     : {totalProbes:N0}");

        Console.WriteLine($" Scanned (Probes) : {GlobalContext.ScannedCount:N0}");
        Console.WriteLine($" Signature Passed : {GlobalContext.SignaturePassed:N0}");

        if (GlobalContext.Config.EnableV2RayCheck)
            Console.WriteLine($" V2Ray Verified   : {GlobalContext.V2RayPassed:N0}");

        if (GlobalContext.Config.EnableSpeedTest)
            Console.WriteLine($" Speed Verified   : {GlobalContext.SpeedTestPassed:N0}");

        Console.WriteLine($" Duration         : {totalTime:hh\\:mm\\:ss}");

        if (File.Exists(GlobalContext.OutputFilePath))
        {
            var lines = File.ReadAllLines(GlobalContext.OutputFilePath);
            if (lines.Length > 0)
            {
                Console.WriteLine($" Output File      : {GlobalContext.OutputFilePath}");
                Console.WriteLine($" Results Count    : {lines.Length:N0}");
            }
            else
            {
                try { File.Delete(GlobalContext.OutputFilePath); } catch { }
                Console.WriteLine(" Output File      : No results saved (empty file deleted).");
            }
        }
        else
        {
            Console.WriteLine(" Output File      : No results saved.");
        }

        Console.WriteLine("══════════════════════════════════");
        Console.ResetColor();
    }

    // ---------------------------------------------------------------------
    // Live Status Line Monitor
    // ---------------------------------------------------------------------

    /// <summary>
    /// Main UI monitor loop that renders a live status line with scan progress,
    /// throughput, buffer fill levels, and counters. Also listens for the 'P' key
    /// to toggle pause/resume.
    /// </summary>
    /// <param name="tcpReader">Channel reader for monitoring TCP connection throughput.</param>
    /// <param name="v2rayReader">Channel reader for monitoring V2Ray verification throughput.</param>
    /// <param name="speedTestReader">Channel reader for monitoring speed test throughput.</param>
    /// <param name="token">Cancellation token that stops the monitor loop.</param>
    public static async Task MonitorUi(
      ChannelReader<ScannerWorkers.LiveConnection> tcpReader,
      ChannelReader<ScannerWorkers.SignatureResult>? v2rayReader,
      ChannelReader<ScannerWorkers.SpeedTestRequest>? speedTestReader,
      CancellationToken token)
    {
        Task? keyListenerTask = null;

        // Task for reading keys (fixes P key lag)
        if (!Console.IsInputRedirected && !Console.IsOutputRedirected)
        {
            keyListenerTask = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.P)
                        {
                            PauseManager.Toggle();

                            lock (ConsoleLock)
                            {
                                if (_statusLineVisible && !Console.IsOutputRedirected)
                                    RenderStatusLineInternal();
                            }
                        }
                    }

                    await Task.Delay(50, token); // Check input every 50ms
                }
            }, token);
        }

        try
        {
            // Calculate total expected probes (IPs * Ports)
            int portsCount = Math.Max(1, GlobalContext.Config.Ports.Count);
            string speedUnit = portsCount > 1 ? "chk/s" : "ip/s";
            long totalProbes = GlobalContext.IsInfiniteMode ? 0 : GlobalContext.TotalIps * portsCount;

            while (!token.IsCancellationRequested)
            {
                double elapsedSeconds = GlobalContext.Stopwatch.Elapsed.TotalSeconds;
                // The contiguous sequence cursor already includes all probes
                // completed before a resume and during the current run.
                // Do not add the restored Scanned counter again, otherwise
                // resumed progress is double-counted.
                long completedProbes = GlobalContext.IsInfiniteMode
                    ? 0
                    : Math.Clamp(GlobalContext.NextContiguousSequence, 0, totalProbes);

                // Speed is now "Probes per second" (chk/s)
                double scanSpeed = GlobalContext.ScannedCount / Math.Max(elapsedSeconds, 1);

                string progressStr;
                if (GlobalContext.IsInfiniteMode)
                {
                    progressStr = $"Scanned {GlobalContext.ScannedCount:N0}";
                }
                else
                {
                    // Percentage based on Total Probes (IPs * Ports)
                double percent = completedProbes * 100.0 / Math.Max(totalProbes, 1);
                progressStr = $"{percent:F2}% ({completedProbes:N0}/{totalProbes:N0})";
                }

                int tcpBuf = (int)(tcpReader.Count * 100.0 / Math.Max(GlobalContext.Config.TcpChannelBuffer, 1));
                int v2Buf = 0;
                if (GlobalContext.Config.EnableV2RayCheck && v2rayReader != null)
                    v2Buf = (int)(v2rayReader.Count * 100.0 / Math.Max(GlobalContext.Config.V2RayChannelBuffer, 1));
                int spdBuf = 0;
                if (GlobalContext.Config.EnableSpeedTest && speedTestReader != null)
                    spdBuf = (int)(speedTestReader.Count * 100.0 / Math.Max(GlobalContext.Config.SpeedTestBuffer, 1));

                bool hasActivity = GlobalContext.ScannedCount > 0 || GlobalContext.TcpOpenTotal > 0;

                var sb = new StringBuilder(256);

                if (PauseManager.IsPaused)
                    sb.Append("[PAUSED - Press P to resume] ");

                if (!hasActivity)
                    sb.Append("[Idle - waiting for first workers] ");

                TimeSpan ts = TimeSpan.FromSeconds(elapsedSeconds);
                string timeStr = $"{(int)ts.TotalHours:D2}:{ts.Minutes:D2}:{ts.Seconds:D2}";
                sb.Append($"[Time {timeStr}] ");

                //sb.Append($"[Time {TimeSpan.FromSeconds(elapsedSeconds):hh\\:mm\\:ss}] ");
                sb.Append($"[Prog {progressStr}] ");

                
                sb.Append($"[Speed {scanSpeed:F0} {speedUnit}] ");

                sb.Append($"[Open {GlobalContext.TcpOpenTotal:N0}] ");
                sb.Append($"[Sign {GlobalContext.SignaturePassed:N0}] ");

                if (GlobalContext.Config.EnableV2RayCheck)
                    sb.Append($"[V2Ray {GlobalContext.V2RayPassed:N0}] ");

                if (GlobalContext.Config.EnableSpeedTest)
                    sb.Append($"[Spd {GlobalContext.SpeedTestPassed:N0}] ");

                sb.Append("[Buf ");
                sb.Append($"TCP {tcpBuf}%");
                if (GlobalContext.Config.EnableV2RayCheck) sb.Append($" | V2R {v2Buf}%");
                if (GlobalContext.Config.EnableSpeedTest) sb.Append($" | SPD {spdBuf}%");
                sb.Append(']');

                string newStatusLine = sb.ToString();

                lock (ConsoleLock)
                {
                    _lastStatusLine = newStatusLine;
                    EnsureStatusLine();
                    RenderStatusLine();
                }

                await Task.Delay(hasActivity ? 500 : 200, token);
            }
        }
        catch (TaskCanceledException)
        {
            // ignore
        }
        finally
        {
            if (keyListenerTask is not null)
            {
                try { await keyListenerTask; }
                catch (TaskCanceledException) { }
            }
        }
    }

    // ---------------------------------------------------------------------
    // Status Line Control Helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Ensures the status line region is reserved on the console.
    /// If not yet visible, allocates the current cursor row for status rendering.
    /// </summary>
    public static void EnsureStatusLine()
    {
        if (Console.IsOutputRedirected) return;

        lock (ConsoleLock)
        {
            if (!_statusLineVisible)
            {
                _statusLineRow = Console.CursorTop;
                _statusLineVisible = true;
            }
        }
    }

    /// <summary>
    /// Hides the live status line by clearing its console row and marking it invisible.
    /// </summary>
    public static void HideStatusLine()
    {
        if (Console.IsOutputRedirected || !_statusLineVisible)
            return;

        lock (ConsoleLock)
        {
            ClearStatusLineInternal();
            _statusLineVisible = false;
        }
    }

    /// <summary>
    /// Renders the current status line text to the reserved console row.
    /// No-op if the status line is not visible or output is redirected.
    /// </summary>
    public static void RenderStatusLine()
    {
        if (Console.IsOutputRedirected || !_statusLineVisible)
            return;

        lock (ConsoleLock)
        {
            RenderStatusLineInternal();
        }
    }

    // ---------------------------------------------------------------------
    // Low-level Console Cursor Operations (Internal)
    // ---------------------------------------------------------------------

    private static void RenderStatusLineInternal()
    {
        if (_statusLineRow < 0) return;

        int width = Math.Max(1, Console.BufferWidth - 1);
        int saveLeft = Console.CursorLeft;
        int saveTop = Console.CursorTop;

        Console.SetCursorPosition(0, _statusLineRow);
        Console.ForegroundColor = PauseManager.IsPaused ? ConsoleColor.Red : ConsoleColor.White;

        string line = _lastStatusLine.Length > width
                ? _lastStatusLine[..width]
                : _lastStatusLine.PadRight(width);

        Console.Write(line);
        Console.SetCursorPosition(saveLeft, saveTop);
        Console.ResetColor();
    }

    private static void ClearStatusLineInternal()
    {
        if (_statusLineRow < 0) return;

        int width = Math.Max(1, Console.BufferWidth - 1);
        int saveLeft = Console.CursorLeft;
        int saveTop = Console.CursorTop;

        Console.SetCursorPosition(0, _statusLineRow);
        Console.Write(new string(' ', width));
        Console.SetCursorPosition(saveLeft, saveTop);
    }
}
