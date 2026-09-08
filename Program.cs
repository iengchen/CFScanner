using CFScanner;
using CFScanner.Core;
using CFScanner.UI;
using CFScanner.Utils;

// -------------------------------------------------------------------------
// Application Entry Point (Top-Level Program)
// This file defines the full startup and execution flow of CFScanner.
// -------------------------------------------------------------------------


// 1. Parse command-line arguments
// Populates GlobalContext.Config and validates basic syntax.
if (!ArgParser.ParseArguments(args))
    return;

CancellationManager.Setup();

if (!AppValidator.CheckVpnRisk())
    return;

if (GlobalContext.Config.ResumeEnabled && !GlobalContext.Config.ResumeNewScan &&
    GlobalContext.Config.ResumeOnlyInvocation &&
    !await ResumeCoordinator.RestoreConfigurationFromCheckpointAsync())
    return;

if (!await AppValidator.ValidateInputs())
    return;

if (GlobalContext.Config.EnableV2RayCheck)
{
    if (!await XraySetup.InitializeAsync())
        return;
}

// 5. Prepare output file and print application header
// Output file is created early to catch permission issues.
FileUtils.SetupOutputFile();
ConsoleInterface.PrintHeader();

// 6. Load exclusions and scan targets
// Builds exclusion filters first, then resolves input sources.
IEnumerable<System.Net.IPAddress> ipSource;
long totalIps;
bool isInfinite;
try
{
    await InputLoader.BuildExclusionsAsync(GlobalContext.Cts.Token);
    if (GlobalContext.Config.ResumeEnabled)
    {
        // InputLoader's documented fallback is infinite mode only when no
        // explicit finite source was supplied; establish that identity before
        // selecting a checkpoint.
        GlobalContext.IsInfiniteMode =
            GlobalContext.Config.InputFiles.Count == 0 &&
            GlobalContext.Config.InputAsns.Count == 0 &&
            GlobalContext.Config.InputCidrs.Count == 0;
        var assumeYes = args.Any(a => a.Equals("-y", StringComparison.OrdinalIgnoreCase) ||
                                      a.Equals("--yes", StringComparison.OrdinalIgnoreCase) ||
                                      a.Equals("--no-confirm", StringComparison.OrdinalIgnoreCase));
        await ResumeCoordinator.InitializeAsync(assumeYes, GlobalContext.Cts.Token);
        if (!GlobalContext.Config.ResumeNewScan && !assumeYes)
            ArgParser.DisplayEffectiveConfigurationSummary();
    }
    (ipSource, totalIps, isInfinite) =
        await InputLoader.LoadTargetsAsync(GlobalContext.Cts.Token);
}
catch (OperationCanceledException) when (GlobalContext.Cts.IsCancellationRequested)
{
    FileUtils.DeleteEmptyOutputFile();
    if (GlobalContext.Config.ResumeEnabled) ResumeCoordinator.Dispose();
    return;
}

// 7. Configure global scan mode
// Used by UI, progress reporting, and final statistics.
GlobalContext.TotalIps = totalIps;
GlobalContext.IsInfiniteMode = isInfinite;

// Abort if no targets were resolved in fixed-range mode
if (totalIps == 0 && !isInfinite)
{
    ConsoleInterface.PrintError(
        "No IPs found to scan (check inputs or exclusions).");
    FileUtils.DeleteEmptyOutputFile();
    if (GlobalContext.Config.ResumeEnabled) ResumeCoordinator.Dispose();
    return;
}

// 8. Run the scanning engine
// This call blocks until the scan completes or is cancelled.
bool finalCheckpointSaved = false;
try
{
    await ScanEngine.RunScanAsync(ipSource);
    FileUtils.SortResultsFile();
    var completed = !isInfinite &&
        GlobalContext.NextContiguousSequence >= totalIps * Math.Max(1, GlobalContext.Config.Ports.Count);
    if (GlobalContext.Config.ResumeEnabled)
    {
        await ResumeCoordinator.SaveAsync(totalIps, completed, durable: true);
        finalCheckpointSaved = true;
    }
}
finally
{
    if (GlobalContext.Config.ResumeEnabled)
    {
        try
        {
            if (!finalCheckpointSaved)
            {
                await ResumeCoordinator.SaveAsync(
                    totalIps,
                    completed: false,
                    durable: true);
                ConsoleInterface.PrintFinalCheckpointProgress(totalIps);
            }
        }
        catch (Exception ex) { ConsoleInterface.PrintWarning($"[Resume] Final checkpoint failed: {ex.Message}"); }
        finally { ResumeCoordinator.Dispose(); }
    }
}

// 9. Finalize results and print summary
// Optionally sorts output and prints final statistics.
if (GlobalContext.Config.ResumeEnabled &&
    !isInfinite &&
    GlobalContext.NextContiguousSequence >= totalIps * Math.Max(1, GlobalContext.Config.Ports.Count))
    ResumeCoordinator.RemoveCompletedCheckpoint();
ConsoleInterface.PrintFinalReport(
    GlobalContext.Stopwatch.Elapsed);

// -------------------------------------------------------------------------
// Graceful Exit
// -------------------------------------------------------------------------
Console.WriteLine("\nPress any key to exit...");
Console.ReadKey();
