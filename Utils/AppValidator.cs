using System.Text.Json;
using CFScanner.UI;

namespace CFScanner.Utils;

/// <summary>
/// Performs pre-flight validation of the scanner environment and user inputs.
///
/// Responsibilities:
/// - Detects active VPN/proxy connections that may cause abuse reports or IP bans.
/// - Validates existence of input files, exclusion files, and ASN database.
/// - Optionally downloads the ASN database when required but missing.
/// - Validates V2Ray/Xray configuration file presence.
/// </summary>
public static class AppValidator
{
    /// <summary>
    /// Checks for active VPN or proxy connections and warns the user if detected.
    /// Displays a confirmation prompt unless output is redirected.
    /// </summary>
    /// <returns>
    /// <c>true</c> if scanning should proceed (no VPN/proxy or user confirmed);
    /// <c>false</c> if the user declined after the warning.
    /// </returns>
    public static bool CheckVpnRisk()
    {
        if (!VpnDetector.ShouldWarn())
            return true;

        return ConsoleInterface.PrintWarning(
            "Potential VPN or proxy connection detected.\n" +
            "Scanning through a VPN may cause abuse reports or IP bans.\n" +
            "It is strongly recommended to disable it before scanning.",
            requireConfirmation: true);
    }

    /// <summary>
    /// Validates all user inputs and the execution environment before scanning begins.
    /// Checks include:
    /// <list type="bullet">
    ///   <item>Resume directory writability (when resume is enabled).</item>
    ///   <item>Existence of all input and exclusion files.</item>
    ///   <item>V2Ray/Xray configuration file presence (when V2Ray check is enabled).</item>
    ///   <item>ASN database availability (prompts for download if missing).</item>
    /// </list>
    /// </summary>
    /// <returns><c>true</c> if all validations pass; <c>false</c> if any critical error is found.</returns>
    public static async Task<bool> ValidateInputs()
    {
        bool hasError = false;

        if (GlobalContext.Config.ResumeEnabled)
        {
            try
            {
                var resumeDir = Path.GetFullPath(GlobalContext.Config.ResumeDirectory);
                Directory.CreateDirectory(resumeDir);
                var probe = Path.Combine(resumeDir, $".write-test-{Guid.NewGuid():N}");
                using (File.Create(probe)) { }
                File.Delete(probe);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                ConsoleInterface.PrintError($"Resume directory is not writable: {GlobalContext.Config.ResumeDirectory}");
                hasError = true;
            }
        }

        // -----------------------------------------------------------------
        // Input and exclusion file validation
        // -----------------------------------------------------------------
        foreach (var file in GlobalContext.Config.InputFiles)
        {
            if (!File.Exists(file))
            {
                ConsoleInterface.PrintError($"Input file not found: {file}");
                hasError = true;
            }
        }

        foreach (var file in GlobalContext.Config.ExcludeFiles)
        {
            if (!File.Exists(file))
            {
                ConsoleInterface.PrintError($"Exclude file not found: {file}");
                hasError = true;
            }
        }

        // -----------------------------------------------------------------
        // V2Ray configuration validation (optional feature)
        // -----------------------------------------------------------------
        if (GlobalContext.Config.EnableV2RayCheck)
        {
            var configPath = GlobalContext.Config.V2RayConfigPath!;

            if (!File.Exists(configPath))
            {
                ConsoleInterface.PrintError(
                    $"V2Ray config file not found: {configPath}");
                hasError = true;
            }
            //else
            //{
            //    // Port consistency check (WARNING ONLY)
            //    TryWarnOnV2RayPortMismatch(configPath);
            //}
        }

        // -----------------------------------------------------------------
        // ASN database validation
        // -----------------------------------------------------------------
        bool usesAsn =
            GlobalContext.Config.InputAsns.Count > 0 ||
            GlobalContext.Config.ExcludeAsns.Count > 0;

        if (usesAsn && !FileUtils.IsValidAsnDatabase(GlobalContext.Config.AsnDbPath))
        {
            bool confirmed = ConsoleInterface.PrintWarning(
                $"ASN database is missing or invalid: {GlobalContext.Config.AsnDbPath}\n" +
                "The ASN database is required for ASN-based scanning.\n" +
                "Do you want to download it from iptoasn.com now?",
                requireConfirmation: true);

            if (confirmed)
            {
                if (!await FileUtils.DownloadAndExtractAsnDb(GlobalContext.Config.AsnDbPath))
                {
                    ConsoleInterface.PrintError("Failed to download ASN database.");
                    hasError = true;
                }
            }
            else
            {
                ConsoleInterface.PrintError(
                    "ASN database is required for -a or -xa switches.");
                hasError = true;
            }
        }

        return !hasError;
    }

    // ---------------------------------------------------------------------
    // Helper: V2Ray Port Consistency Warning
    // ---------------------------------------------------------------------

    //private static void TryWarnOnV2RayPortMismatch(string configPath)
    //{
    //    try
    //    {
    //        using var doc = JsonDocument.Parse(File.ReadAllText(configPath));

    //        if (!doc.RootElement.TryGetProperty("outbounds", out var outbounds) ||
    //            outbounds.GetArrayLength() == 0)
    //            return;

    //        var outbound = outbounds[0];

    //        if (!outbound.TryGetProperty("settings", out var settings) ||
    //            !settings.TryGetProperty("vnext", out var vnext) ||
    //            vnext.GetArrayLength() == 0)
    //            return;

    //        var target = vnext[0];

    //        if (!target.TryGetProperty("port", out var portProp))
    //            return;

    //        int configPort = portProp.GetInt32();
    //        var scannerPorts = GlobalContext.Config.Ports;

    //        if (configPort == scannerPort)
    //            return;

    //        bool continueScan = ConsoleInterface.PrintWarning(
    //            "V2Ray port mismatch detected:\n" +
    //            $"  • Scanner port : {scannerPort}\n" +
    //            $"  • Config port  : {configPort}\n\n" +
    //            "TCP and Signature stages will use the scanner port,\n" +
    //            "while Real Xray verification will use the config port.\n" +
    //            "This may work, but results may be inconsistent.\n\n" +
    //            "Do you want to continue anyway?",
    //            requireConfirmation: true);

    //        if (!continueScan)
    //            Environment.Exit(1);
    //    }
    //    catch
    //    {
    //        // Silently ignore malformed or non-standard configs
    //    }
    //}
}
