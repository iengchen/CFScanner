# CFScanner - Agent Guide

## Scope

CFScanner is a cross-platform **.NET 10 console executable** for discovering
working Cloudflare IPv4 edge/fronting addresses. It performs network probes;
use only on systems/ranges you are authorized to scan.

## Build and run

```powershell
dotnet build CFScanner.sln
dotnet run --project CFScanner.csproj -- --help
dotnet run --project CFScanner.csproj -- --range 1.1.1.1 -y
```

- There are three xUnit v3 test projects under `tests/`. Always build the
  full solution and run the unit + integration suites for any non-trivial change:
  ```powershell
  dotnet build CFScanner.sln
  dotnet test tests/CFScanner.UnitTests/CFScanner.UnitTests.csproj
  dotnet test tests/CFScanner.IntegrationTests/CFScanner.IntegrationTests.csproj
  ```
  The end-to-end project (`tests/CFScanner.EndToEndTests/`) is opt-in via
  `CFSCANNER_RUN_E2E=1` and must not run in regular CI/dev loops.
- Source builds require .NET 10 SDK. ASN queries require `ip2asn-v4.tsv`
  (download is offered interactively). `-vc/--v2ray-config` additionally
  requires `xray(.exe)` beside the executable and a valid Xray JSON template.
- Build outputs (`bin/`, `obj/`, `results/`, `graphify-out/`) are generated or
  ignored; do not edit them.
- Console messages are the runtime log; there is no separate persistent log
  file. `results/` contains scan records only.

## Startup flow

`Program.cs` is the sole entry point:

1. `ArgParser.ParseArguments` -> profile defaults, CLI overrides, validation.
2. `AppValidator.CheckVpnRisk` -> warns/asks before VPN or proxy scans.
3. `AppValidator.ValidateInputs` -> files, ASN DB, optional Xray config.
4. Optional `XraySetup.InitializeAsync` -> resolves Xray, validates config,
   loads the raw template.
5. Register Ctrl+C handling; create output file and header.
6. `InputLoader.BuildExclusionsAsync` then `LoadTargetsAsync`.
7. `ScanEngine.RunScanAsync`; sort results and print final report.

## Architecture

All runtime state is process-wide in `GlobalContext` (`Config`, cancellation
token, stopwatch, counters, `IpFilter`, raw Xray template).

`ScanEngine` connects bounded `System.Threading.Channels` with async workers:

```text
IP x port
  -> Stage 1: TCP connect (`ScannerWorkers.ProducerWorker`)
  -> Stage 2: TLS 1.2/1.3 + HTTP Cloudflare signature
       (HTTP 200 + `server: cloudflare` + `cf-ray`)
  -> Stage 3 [optional]: real Xray proxy -> gstatic 204
  -> Stage 4 [optional]: Cloudflare download/upload thresholds
```

- Channel completion is cascading; Ctrl+C uses cooperative cancellation.
- `P` toggles pause/resume (`PauseManager`); stopwatch excludes paused time.
- Xray process ownership transfers from Stage 3 to Stage 4; every path must
  terminate/dispose the process.
- Finite mode combines file/ASN/inline inputs, sorts/deduplicates/filters, and
  streams IPs. With no explicit input it generates infinite random public IPv4s.
- CIDR expansion is capped at `Defaults.CidrExpandCap` (65,536 addresses).

## Key files and layout

- `Program.cs`: orchestration only; preserve startup order.
- `Config.cs`: defaults and runtime settings.
- `Utils/ArgParser.cs`: CLI grammar, profiles, ranges, auto-scaled buffers.
- `Core/InputLoaders.cs`: target/exclusion resolution and scan mode.
- `Core/ScanEngine.cs`: channels, worker counts, shutdown.
- `Core/ScannerWorkers.cs`: TCP/signature workers and stage contracts.
- `Core/V2RayController.cs`: Xray lifecycle, proxy validation, speed tests.
- `Utils/IpFilter.cs`, `NetUtils.cs`, `FileUtils.cs`: ranges/IP math/I/O.
- `UI/ConsoleInterface.cs`: all console output, live status, `P` key.
- `GlobalContext.cs`: atomic counters and shared resources.
- `Core/CancelationManager.cs`: Ctrl+C registration and cancellation signal.
- `Core/PauseManager.cs`: cooperative pause gate and stopwatch exclusion.
- `Utils/XrayUtils.cs`: Xray executable discovery and initialization.
- `tests/CFScanner.UnitTests/`: xUnit v3 unit tests (no I/O, no network).
  - `TestState.cs`: per-test reset of `GlobalContext.Config`, `IpFilter`,
    `PauseManager`, and atomic counters.
  - `UtilitiesTests.cs`: legacy seed tests (IP conversion, CIDR expand,
    `IpFilter` merge, `ArgParser` fast overrides).
  - `NetUtilsTests.cs`, `IpFilterTests.cs`, `ArgParserTests.cs`,
    `FileUtilsTests.cs`, `PauseManagerTests.cs`, `ConfigTests.cs`,
    `GlobalContextCounterTests.cs`, `InputLoaderUnitTests.cs`.
- `tests/CFScanner.IntegrationTests/`: xUnit v3 integration tests (temp
  files, in-process `InputLoader` flow, no external network).
  - `TestState.cs`: same reset helper as the unit project.
  - `InputLoaderTests.cs`: file + inline target merge.
  - `InputLoaderIntegrationTests.cs`: combined file/range/exclusion sources,
    shuffle, infinite fallback, exclusion resolution.
- `tests/CFScanner.EndToEndTests/`: opt-in end-to-end smoke tests
  (`CFSCANNER_RUN_E2E=1`).
- Keep new domain code in `Core/`, CLI/file/IP helpers in `Utils/`, and
  user-facing output in `UI/`; do not add alternate entry points or
  process-wide mutable state.
- `Utils/IpFilter.cs` (`Clear()`), `GlobalContext.cs` (`ResetCounters()`), and
  `Core/PauseManager.cs` (`Reset()`) expose **test-only** state-reset helpers
  consumed by `tests/CFScanner.UnitTests/TestState.cs` and
  `tests/CFScanner.IntegrationTests/TestState.cs`. They are behavior-preserving
  for production use; do not remove or rename them, and keep them opt-in
  (only the test projects call them). Both test projects suppress
  `xUnit1051;xUnit1031` via `<NoWarn>` to allow these `internal`/static
  state-reset helpers.

## CLI contracts

Inputs: `-f/--file`, `-a/--asn`, `-r/--range` (comma-separated; inputs may be
combined). Exclusions: `-xf`, `-xa`, `-xr`.

Ports: `-p/--port` accepts one or comma-separated allowed HTTPS ports
`443,2053,2083,2087,2096,8443`, or `all`.

Profiles: `--normal` (default), `--fast`, `--slow`, `--extreme`; explicit
worker/timeout options override profile values. Speed tests require `-vc` and
`--speed-dl` and/or `--speed-ul`; buffers auto-scale unless explicitly set.
Useful switches: `--sort`, `-nl/--no-latency`, `-s/--shuffle`,
`--random-sni`, `-y/--yes`, `-h/--help`, `--help full`/`--manual`.

## Output and implementation rules

- Results are written under `results/verified_yyyyMMdd_HHmmss.txt`.
- The results file is line-oriented text, not CSV and has no header. Each
  successful endpoint appends exactly one record under `FileUtils`'s lock:
  - single port + latency: `IP # 123ms` (legacy format);
  - multiple ports + latency: `IP #Port: 443 #Latency: 123ms`;
  - latency disabled (`-nl`): single port `IP`, multiple ports `IP:443`.
  Sorting rewrites the same file only at normal finalization; an empty result
  file may be deleted by the final-report path.
- Keep every socket, TLS, HTTP, stream, and delay operation asynchronous and
  cancellation-aware. Use `*Async` APIs with the pipeline token (or a linked
  timeout token); never introduce `.Result`, `.Wait()`, `GetAwaiter().GetResult()`,
  `Thread.Sleep`, blocking `TcpClient.Connect`, or synchronous `HttpClient`
  calls. Propagate `OperationCanceledException` and dispose owned clients,
  streams, responses, and linked token sources with `using`/`await using`.
- Preserve bounded channels/backpressure and finite worker lifetimes. Do not
  swallow cancellation as an ordinary error or create fire-and-forget network
  tasks.
- Ctrl+C must remain cooperative: `CancellationManager` cancels
  `GlobalContext.Cts`, `ScanEngine` completes channels in cascade and awaits all
  workers before returning. Every Xray process started by any stage—including
  validation, failed handoff, cancellation, timeout, and exceptions—must be
  terminated (kill after the configured grace period if needed), awaited with
  `WaitForExit`, and disposed. Ownership transfers from Stage 3 to Stage 4 only
  on a successful handoff; the owner on every other path is responsible for
  cleanup. Never leave zombie/orphan `xray`/`xray.exe` processes after Ctrl+C.
- Use `Interlocked` for shared counters; avoid introducing static mutable state
  outside `GlobalContext`/existing managers.
- Keep user-facing text in `ConsoleInterface`; do not write ad-hoc status lines
  from workers unless synchronized with the existing UI behavior.
- Preserve IPv4-only assumptions and the CIDR safety cap.
- When changing CLI behavior, update `ArgParser` help text and both READMEs.
- Do not commit secrets, Xray configs, ASN databases, generated results, or
  build artifacts. Preserve unrelated working-tree changes.
- Keep agent responses concise and direct; include only details needed for the
  result, important decisions, errors, and validation to reduce token usage.

## Validation checklist

1. `dotnet build CFScanner.sln`
2. `dotnet test tests/CFScanner.UnitTests/CFScanner.UnitTests.csproj`
3. `dotnet test tests/CFScanner.IntegrationTests/CFScanner.IntegrationTests.csproj`
4. `dotnet run -- --help` (or equivalent published executable)
5. For pipeline changes, exercise a small authorized `--range` with `-y`;
   test `-vc`/speed paths only with a valid local Xray setup.
6. Inspect `git diff` and `git status --short`; keep the patch focused.
