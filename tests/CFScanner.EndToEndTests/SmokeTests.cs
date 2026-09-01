using System.Diagnostics;
using Xunit;

namespace CFScanner.EndToEndTests;

public sealed class SmokeTests
{
    [Fact, Trait("Category", "E2E")]
    public void HelpCommand_IsAvailableWhenOptedIn()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("CFSCANNER_RUN_E2E"), "1", StringComparison.Ordinal))
            Assert.Skip("Set CFSCANNER_RUN_E2E=1 to run executable tests.");
        using var process = Process.Start(new ProcessStartInfo("dotnet", "run --project CFScanner.csproj -- --help")
        {
            WorkingDirectory = Directory.GetParent(AppContext.BaseDirectory)!.Parent!.Parent!.Parent!.Parent!.Parent!.FullName,
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false
        })!;
        Assert.True(process.WaitForExit(15_000));
        Assert.Equal(0, process.ExitCode);
        Assert.Contains("CFScanner", process.StandardOutput.ReadToEnd());
    }
}
