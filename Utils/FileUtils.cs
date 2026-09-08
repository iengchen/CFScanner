using System.Net;

namespace CFScanner.Utils;

/// <summary>
/// Utility methods for file I/O: output file management, saving results, loading IP lists, and downloading the ASN database.
/// </summary>
public static class FileUtils
{
    private static readonly Lock FileLock = new();
    private static readonly HashSet<string> WrittenEndpoints =
        new(StringComparer.Ordinal);
    private static string? _indexedOutputPath;

    /// <summary>
    /// Creates the output directory and sets the full path of the results file in <see cref="GlobalContext.OutputFilePath"/>.
    /// </summary>
    public static string SetupOutputFile()
    {
        string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "results");
        Directory.CreateDirectory(dir);

        // Reserve the output path while choosing it. Timestamp-only names can
        // collide when two scanner processes start in the same second.
        for (int attempt = 0; attempt < 100; attempt++)
        {
            var path = Path.Combine(dir,
                $"verified_{DateTime.Now:yyyyMMdd_HHmmss_fff}_{Guid.NewGuid():N}.txt");
            try
            {
                using var _ = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
                GlobalContext.OutputFilePath = path;
                return path;
            }
            catch (IOException) when (attempt < 99)
            {
                // A collision is extraordinarily unlikely with a GUID, but
                // retry keeps the operation correct even in that case.
            }
        }

        throw new IOException("Unable to reserve a unique results file path.");
    }

    /// <summary>Deletes the current output file only when no results were written.</summary>
    public static void DeleteEmptyOutputFile()
    {
        lock (FileLock)
        {
            if (File.Exists(GlobalContext.OutputFilePath) &&
                new FileInfo(GlobalContext.OutputFilePath).Length == 0)
                File.Delete(GlobalContext.OutputFilePath);
        }
    }

    /// <summary>
    /// Appends a successfully verified IP and port (optionally with latency)
    /// to the results file in a thread-safe manner.
    /// </summary>
    /// <param name="ip">The verified IP address.</param>
    /// <param name="port">The verified port number.</param>
    /// <param name="latency">Measured latency in milliseconds.</param>
    public static void SaveResult(string ip, int port, long latency)
    {
        lock (FileLock)
        {
            EnsureResultIndex();
            if (!WrittenEndpoints.Add(CreateEndpointKey(ip, port)))
                return;

            string line;
            bool isMultiPort = GlobalContext.Config.Ports.Count > 1;

            if (GlobalContext.Config.SaveLatency)
            {
                // Multi-port format includes explicit port and latency
                if (isMultiPort)
                {
                    line = $"{ip} #Port: {port} #Latency: {latency}ms";
                }
                // Single-port format preserves legacy compact output
                else
                {
                    line = $"{ip} # {latency}ms";
                }
            }
            else
            {
                // Output without latency information
                if (isMultiPort)
                {
                    line = $"{ip}:{port}";
                }
                else
                {
                    line = ip;
                }
            }

            File.AppendAllText(GlobalContext.OutputFilePath, line + Environment.NewLine);
        }
    }

    private static void EnsureResultIndex()
    {
        if (string.Equals(_indexedOutputPath, GlobalContext.OutputFilePath,
                StringComparison.OrdinalIgnoreCase))
            return;

        WrittenEndpoints.Clear();
        _indexedOutputPath = GlobalContext.OutputFilePath;

        if (!GlobalContext.Config.ResumeEnabled ||
            !File.Exists(GlobalContext.OutputFilePath))
            return;

        foreach (var line in File.ReadLines(GlobalContext.OutputFilePath))
        {
            if (TryGetEndpointKey(line, out var key))
                WrittenEndpoints.Add(key);
        }
    }

    private static string CreateEndpointKey(string ip, int port) => $"{ip}:{port}";

    private static bool TryGetEndpointKey(string line, out string key)
    {
        key = string.Empty;
        var value = line.Trim();
        if (value.Length == 0)
            return false;

        const string portMarker = "#Port:";
        var markerIndex = value.IndexOf(portMarker, StringComparison.Ordinal);
        if (markerIndex >= 0)
        {
            var ip = value[..markerIndex].Trim();
            var remaining = value[(markerIndex + portMarker.Length)..];
            var portText = remaining.Split('#', 2)[0].Trim();
            if (NetUtils.TryParseIpv4(ip, out _) && int.TryParse(portText, out var port))
            {
                key = CreateEndpointKey(ip, port);
                return true;
            }
            return false;
        }

        if (GlobalContext.Config.Ports.Count > 1)
        {
            var separator = value.LastIndexOf(':');
            if (separator > 0 &&
                NetUtils.TryParseIpv4(value[..separator], out _) &&
                int.TryParse(value[(separator + 1)..], out var port))
            {
                key = CreateEndpointKey(value[..separator], port);
                return true;
            }
            return false;
        }

        var singlePortIp = value.Split('#', 2)[0].Trim();
        if (!NetUtils.TryParseIpv4(singlePortIp, out _))
            return false;

        key = CreateEndpointKey(singlePortIp, GlobalContext.Config.Ports[0]);
        return true;
    }

    /// <summary>
    /// Sorts the results file based on configuration:
    /// - By latency if sorting is enabled.
    /// - By IP and port only when multiple ports are configured.
    /// No sorting is performed for single-port scans when sorting is disabled.
    /// </summary>
    public static void SortResultsFile()
    {
        if (!File.Exists(GlobalContext.OutputFilePath))
            return;

        bool isMultiPort = GlobalContext.Config.Ports.Count > 1;

        // Skip sorting entirely for single-port scans when sorting is disabled
        if (!GlobalContext.Config.SortResults && !isMultiPort)
        {
            return;
        }

        Console.WriteLine("\n[Info] Sorting results...");

        try
        {
            var lines = File.ReadAllLines(GlobalContext.OutputFilePath)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToList();

            List<string> sortedLines;

            if (GlobalContext.Config.SortResults)
            {
                // Sort by latency (ascending), supporting both legacy and new formats
                sortedLines = [.. lines.OrderBy(line =>
            {
                long latency = long.MaxValue;
                string latencyStr = "";

                if (line.Contains("#Latency:"))
                    latencyStr = line.Split(["#Latency:"], StringSplitOptions.None)[1];
                else if (line.Contains('#'))
                    latencyStr = line.Split('#')[1];

                if (!string.IsNullOrEmpty(latencyStr))
                {
                    latencyStr = latencyStr.Replace("ms", "").Trim();
                    long.TryParse(latencyStr, out latency);
                }

                return latency;
            })];
            }
            else
            {
                // Sort by IP and port (only applicable in multi-port mode)
                sortedLines = [.. lines.Select(line =>
            {
                string ipStr = line;
                int port = 0;

                if (line.Contains("#Port:"))
                {
                    var parts = line.Split(["#Port:"], StringSplitOptions.None);
                    ipStr = parts[0].Trim();
                    var portPart = parts[1].Split('#')[0].Trim();
                    int.TryParse(portPart, out port);
                }
                else if (line.Contains(':'))
                {
                    var parts = line.Split(':');
                    ipStr = parts[0].Trim();
                    if (parts.Length > 1)
                        int.TryParse(parts[1], out port);
                }

                Version.TryParse(ipStr, out Version? v);
                return new { Line = line, IpVer = v, Port = port };
            })
            .OrderBy(x => x.IpVer)
            .ThenBy(x => x.Port)
            .Select(x => x.Line)];
            }

            File.WriteAllLines(GlobalContext.OutputFilePath, sortedLines);
            Console.WriteLine("[Info] Sorting completed.");
        }
        catch
        {
            // Errors during sorting are intentionally ignored to avoid interrupting execution
        }
    }

    /// <summary>
    /// Asynchronously loads IP addresses from a text file.
    /// Each line may be an IPv4 address, a CIDR range, or a comment (starting with #).
    /// CIDRs are expanded using <see cref="NetUtils.ExpandCidr"/>.
    /// </summary>
    /// <param name="path">Path to the input file.</param>
    /// <returns>List of IPAddress objects.</returns>
    public static async Task<List<IPAddress>> LoadIpsAsync(string path, CancellationToken ct = default)
    {
        var list = new List<IPAddress>();
        await Task.Run(() =>
        {
            foreach (var line in File.ReadLines(path))
            {
                ct.ThrowIfCancellationRequested();
                var span = line.AsSpan().Trim();
                if (span.IsEmpty || span.StartsWith("#")) continue;

                // Strip trailing comments or whitespace
                int index = span.IndexOfAny(' ', '\t', '#');
                if (index >= 0) span = span[..index];

                var cleanPart = span.ToString();
                if (cleanPart.Contains('/'))
                {
                    if (NetUtils.TryParseIpv4Cidr(cleanPart, out _, out _))
                    {
                        foreach (var ip in NetUtils.ExpandCidr(cleanPart))
                        {
                            ct.ThrowIfCancellationRequested();
                            list.Add(ip);
                        }
                    }
                    else
                        CFScanner.UI.ConsoleInterface.PrintWarning($"Invalid IPv4 CIDR in input file '{path}': {cleanPart}");
                }
                else if (NetUtils.TryParseIpv4(cleanPart, out var ip))
                    list.Add(ip);
                else
                    CFScanner.UI.ConsoleInterface.PrintWarning($"Invalid IPv4 address in input file '{path}': {cleanPart}");
            }
        }, ct);
        return list;
    }

    /// <summary>
    /// Downloads the compressed ASN database from iptoasn.com, extracts it, and saves it to the given path.
    /// </summary>
    /// <param name="outputPath">Desired path for the extracted TSV file.</param>
    /// <returns>True if download and extraction succeeded; otherwise false.</returns>
    public static async Task<bool> DownloadAndExtractAsnDb(string outputPath)
    {
        const string url = "https://iptoasn.com/data/ip2asn-v4.tsv.gz";
        var fullOutputPath = Path.GetFullPath(outputPath);
        var outputDirectory = Path.GetDirectoryName(fullOutputPath)!;
        Directory.CreateDirectory(outputDirectory);
        var temporaryPrefix = Path.Combine(
            outputDirectory,
            $".{Path.GetFileName(fullOutputPath)}.{Guid.NewGuid():N}");
        var gzPath = temporaryPrefix + ".gz";
        var extractedPath = temporaryPrefix + ".tsv";
        try
        {
            Console.WriteLine("[Info] Downloading ASN database...");
            using (var handler = new HttpClientHandler())
            using (var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(10) })
            {
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

                using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
                response.EnsureSuccessStatusCode();
                long? totalBytes = response.Content.Headers.ContentLength;

                using var input = await response.Content.ReadAsStreamAsync();
                using var output = new FileStream(gzPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);

                var buffer = new byte[64 * 1024];
                long totalRead = 0;
                int read;
                while ((read = await input.ReadAsync(buffer)) > 0)
                {
                    await output.WriteAsync(buffer, 0, read);
                    totalRead += read;
                    if (totalBytes.HasValue)
                    {
                        double percent = totalRead * 100d / totalBytes.Value;
                        Console.Write($"\r[Download] {percent:0.0}% ");
                    }
                }
            }

            Console.WriteLine("\n[Info] Extracting ASN database...");
            await using (var compressedFile = new FileStream(
                gzPath, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.Asynchronous))
            await using (var gzStream = new System.IO.Compression.GZipStream(
                compressedFile, System.IO.Compression.CompressionMode.Decompress))
            await using (var outFile = new FileStream(
                extractedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous))
            {
                await gzStream.CopyToAsync(outFile);
            }

            if (!IsValidAsnDatabase(extractedPath))
                throw new InvalidDataException("Downloaded ASN database has no valid data rows.");

            File.Move(extractedPath, fullOutputPath, overwrite: true);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[OK] ASN database downloaded and extracted successfully.");
            Console.ResetColor();
            return true;
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[Error] ASN download failed: {ex.Message}");
            Console.ResetColor();
            return false;
        }
        finally
        {
            TryDelete(gzPath);
            TryDelete(extractedPath);
        }
    }

    /// <summary>Checks whether a file contains at least one structurally valid IP-to-ASN TSV row.</summary>
    public static bool IsValidAsnDatabase(string path)
    {
        if (!File.Exists(path)) return false;

        try
        {
            foreach (var line in File.ReadLines(path))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var parts = line.Split('\t');
                if (parts.Length < 3) continue;
                if (NetUtils.TryParseIpv4(parts[0], out _) &&
                    NetUtils.TryParseIpv4(parts[1], out _) &&
                    long.TryParse(parts[2], out _))
                    return true;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        return false;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }
}
