using System.Net;
using System.Threading.Channels;
using CFScanner.UI;

namespace CFScanner.Core;

/// <summary>
/// Orchestrates the entire multi-stage scanning pipeline.
/// Responsible for channel lifecycle management, worker coordination,
/// backpressure control, and graceful startup/shutdown of all stages.
/// </summary>
public static class ScanEngine
{
    /// <summary>
    /// Executes the complete scanning workflow across all enabled stages.
    /// </summary>
    /// <param name="ipSource">
    /// Source of IP addresses to scan.
    /// Can be a finite fixed-range collection or an infinite generator.
    /// </param>
    public static async Task RunScanAsync(IEnumerable<IPAddress> ipSource)
    {
        // ---------------------------------------------------------------------
        // 0. Configuration & Runtime Mode Detection
        // ---------------------------------------------------------------------

        bool v2rayEnabled = GlobalContext.Config.EnableV2RayCheck;
        bool speedTestEnabled = GlobalContext.Config.EnableSpeedTest;

        if (v2rayEnabled)
            Console.WriteLine("[Mode] V2Ray verification ENABLED");

        if (speedTestEnabled)
            Console.WriteLine("[Mode] Speed Test ENABLED");

        Console.WriteLine("[Info] Press P to pause/resume");
        Console.WriteLine(new string('-', 60));
        GlobalContext.Stopwatch.Start();
        Task? checkpointTask = null;
        if (GlobalContext.Config.ResumeEnabled)
        {
            checkpointTask = Task.Run(async () =>
            {
                try
                {
                    using var timer = new PeriodicTimer(
                        TimeSpan.FromSeconds(GlobalContext.Config.ResumeIntervalSeconds));
                    while (await timer.WaitForNextTickAsync(GlobalContext.Cts.Token))
                        await ResumeCoordinator.SaveAsync(
                            GlobalContext.TotalIps, false, GlobalContext.Cts.Token);
                }
                catch (OperationCanceledException) { }
                catch (Exception ex)
                {
                    ConsoleInterface.PrintWarning(
                        $"[Resume] Checkpoint unavailable: {ex.Message}");
                }
            });
        }

        // ---------------------------------------------------------------------
        // 1. Channel Initialization (Backpressure & Flow Control)
        // ---------------------------------------------------------------------

        // Stage 1 → Stage 2: TCP connection results
        var tcpChannel = Channel.CreateBounded<ScannerWorkers.LiveConnection>(
            new BoundedChannelOptions(GlobalContext.Config.TcpChannelBuffer)
            {
                SingleWriter = false,
                SingleReader = false,
                FullMode = BoundedChannelFullMode.Wait
            });

        // Stage 2 → Stage 3: Signature validation results
        var v2rayChannel = v2rayEnabled
            ? Channel.CreateBounded<ScannerWorkers.SignatureResult>(
                new BoundedChannelOptions(GlobalContext.Config.V2RayChannelBuffer)
                {
                    SingleWriter = false,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.Wait
                })
            : null;

        // Stage 3 → Stage 4: Verified endpoints for speed testing
        var speedTestChannel = speedTestEnabled
            ? Channel.CreateBounded<ScannerWorkers.SpeedTestRequest>(
                new BoundedChannelOptions(GlobalContext.Config.SpeedTestBuffer)
                {
                    SingleWriter = false,
                    SingleReader = false,
                    FullMode = BoundedChannelFullMode.Wait
                })
            : null;

        // ---------------------------------------------------------------------
        // 2. UI Monitoring Task
        // ---------------------------------------------------------------------
        // The monitor observes channel readers and terminates via cancellation.
        var monitorTask = Task.Run(() =>
            ConsoleInterface.MonitorUi(
                tcpChannel.Reader,
                v2rayChannel?.Reader,
                speedTestChannel?.Reader,
                GlobalContext.Cts.Token));

        // ---------------------------------------------------------------------
        // 3. Stage 2 Workers (Signature Analysis)
        // ---------------------------------------------------------------------
        var signatureTasks = new Task[GlobalContext.Config.SignatureWorkers];

        for (int i = 0; i < signatureTasks.Length; i++)
        {
            signatureTasks[i] = Task.Run(() =>
                ScannerWorkers.ConsumerWorker_Signature(
                    tcpChannel.Reader,
                    v2rayChannel?.Writer,
                    GlobalContext.Cts.Token));
        }

        // ---------------------------------------------------------------------
        // 4. Stage 3 Workers (Real V2Ray/Xray Validation)
        // ---------------------------------------------------------------------
        Task[] v2rayTasks = [];

        if (v2rayEnabled && v2rayChannel != null)
        {
            v2rayTasks = new Task[GlobalContext.Config.V2RayWorkers];

            for (int i = 0; i < v2rayTasks.Length; i++)
            {
                v2rayTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_V2Ray(
                        v2rayChannel.Reader,
                        speedTestChannel?.Writer,
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 5. Stage 4 Workers (Throughput & Latency Testing)
        // ---------------------------------------------------------------------
        Task[] speedTestTasks = [];

        if (speedTestEnabled && speedTestChannel != null)
        {
            speedTestTasks = new Task[GlobalContext.Config.SpeedTestWorkers];

            for (int i = 0; i < speedTestTasks.Length; i++)
            {
                speedTestTasks[i] = Task.Run(() =>
                    ScannerWorkers.ConsumerWorker_SpeedTest(
                        speedTestChannel.Reader,
                        GlobalContext.Cts.Token));
            }
        }

        // ---------------------------------------------------------------------
        // 6. Stage 1 Producer (Parallel TCP Connection Attempts)
        // ---------------------------------------------------------------------
        Exception? pipelineFailure = null;
        var allWorkerTasks = signatureTasks.Concat(v2rayTasks).Concat(speedTestTasks).ToArray();
        var workerFailureTask = WaitForWorkerFailureAsync(allWorkerTasks);

        try
        {
            var ports = GlobalContext.Config.Ports;
            var portCount = Math.Max(1, ports.Count);
            var sequenceOffset = GlobalContext.IsInfiniteMode
                ? 0
                : GlobalContext.ResumeCursor / portCount * portCount;
            var ipPortSource = EnumerateEndpoints(
                ipSource, ports, sequenceOffset, GlobalContext.ResumeCursor);

            var producerTask = Parallel.ForEachAsync(
                ipPortSource,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = GlobalContext.Config.TcpWorkers,
                    CancellationToken = GlobalContext.Cts.Token
                },

            async (item, ct) =>
                {
                    await PauseManager.WaitIfPausedAsync(ct);

                    await ScannerWorkers.ProducerWorker(
                        item.ip,
                        item.port,
                        tcpChannel.Writer,
                        ct,
                        item.sequence);
                });

            if (await Task.WhenAny(producerTask, workerFailureTask) == workerFailureTask)
            {
                pipelineFailure = await workerFailureTask;
                if (pipelineFailure is not null)
                    GlobalContext.Cts.Cancel();
            }

            await producerTask;
        }
        catch (OperationCanceledException)
        {
            // Expected during controlled shutdown (e.g. Ctrl+C).
        }
        catch (Exception ex)
        {
            pipelineFailure ??= ex;
            GlobalContext.Cts.Cancel();
        }

        // ---------------------------------------------------------------------
        // 7. Graceful Shutdown (Cascading Channel Completion)
        // ---------------------------------------------------------------------
        // Complete each channel and await every worker even after cancellation.
        // This guarantees no pipeline/Xray task outlives ScanEngine shutdown.
        tcpChannel.Writer.TryComplete(pipelineFailure);
        pipelineFailure ??= await AwaitWorkersAsync(signatureTasks);
        if (pipelineFailure is not null)
            GlobalContext.Cts.Cancel();
        DrainTcpConnections(tcpChannel.Reader);

        if (v2rayChannel != null)
        {
            v2rayChannel.Writer.TryComplete(pipelineFailure);
            pipelineFailure ??= await AwaitWorkersAsync(v2rayTasks);
            if (pipelineFailure is not null)
                GlobalContext.Cts.Cancel();
        }

        if (speedTestChannel != null)
        {
            speedTestChannel.Writer.TryComplete(pipelineFailure);
            pipelineFailure ??= await AwaitWorkersAsync(speedTestTasks);
            if (pipelineFailure is not null)
                GlobalContext.Cts.Cancel();
            await DrainSpeedTestRequestsAsync(speedTestChannel.Reader);
        }

        // Explicitly terminate UI monitoring after normal completion.
        if (!GlobalContext.Cts.IsCancellationRequested)
            GlobalContext.Cts.Cancel();

        // Ensure UI task exits cleanly
        try { await monitorTask; } catch { }
        if (checkpointTask is not null)
        {
            try { await checkpointTask; } catch (OperationCanceledException) { }
        }

        ConsoleInterface.HideStatusLine();
        GlobalContext.Stopwatch.Stop();

        if (pipelineFailure is not null)
            throw pipelineFailure;
    }

    private static async Task<Exception?> AwaitWorkersAsync(IEnumerable<Task> workers)
    {
        try
        {
            await Task.WhenAll(workers);
            return null;
        }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex) { return ex; }
    }

    private static async Task<Exception?> WaitForWorkerFailureAsync(IEnumerable<Task> workers)
    {
        var pending = workers.ToList();
        while (pending.Count > 0)
        {
            var completed = await Task.WhenAny(pending);
            pending.Remove(completed);
            if (completed.IsFaulted)
                return completed.Exception?.GetBaseException();
        }

        return null;
    }

    private static IEnumerable<(IPAddress ip, int port, long sequence)> EnumerateEndpoints(
        IEnumerable<IPAddress> ipSource,
        IReadOnlyList<int> ports,
        long sequenceOffset,
        long resumeCursor)
    {
        long ipIndex = 0;
        foreach (var ip in ipSource)
        {
            for (int portIndex = 0; portIndex < ports.Count; portIndex++)
            {
                var sequence = checked(sequenceOffset + ipIndex * ports.Count + portIndex);
                if (sequence >= resumeCursor)
                    yield return (ip, ports[portIndex], sequence);
            }

            ipIndex = checked(ipIndex + 1);
        }
    }

    private static void DrainTcpConnections(ChannelReader<ScannerWorkers.LiveConnection> reader)
    {
        while (reader.TryRead(out var item))
            item.Client.Dispose();
    }

    private static async Task DrainSpeedTestRequestsAsync(ChannelReader<ScannerWorkers.SpeedTestRequest> reader)
    {
        while (reader.TryRead(out var item))
            await V2RayController.TerminateProcessAsync(item.XrayProcess);
    }
}
