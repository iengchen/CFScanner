# CFScanner Testing Implementation Guide

This document is the implementation baseline for adding unit, integration, and end-to-end tests to CFScanner. It is intentionally prescriptive so future implementation work does not need to reinterpret tooling, execution modes, or test boundaries. This document-only change does not modify production code or the solution.

## 1. Goals and non-negotiable principles

Build a reliable test pyramid for the .NET 10 console application:

1. **Unit tests**: fast, deterministic, in-process, with no public network, real Xray, or shared global state.
2. **Integration tests**: multiple real CFScanner components connected to controlled local dependencies.
3. **End-to-end tests**: the real executable invoked through its CLI, with isolated fixtures and observable output.

All network tests must bind only to loopback. No default test may contact Cloudflare, public IPs, VPN/proxy infrastructure, or download the ASN database. Every asynchronous test needs cancellation and a bounded timeout. Temporary files, listeners, sockets, timers, and child processes must be disposed on success, failure, and cancellation.

## 2. Fixed toolchain and repository setup

Use **xUnit v3 with Microsoft.Testing.Platform (MTP)**. Do not leave the test runner mode or filter syntax open to interpretation.

Add these files at repository root before adding test projects:

- `global.json` pinning the required .NET 10 SDK version (including `rollForward` policy appropriate for CI).
- `Directory.Build.props` for shared target framework, nullable/implicit-usings, analyzers, warnings, and common test properties.
- `Directory.Packages.props` with Central Package Management and exact versions for all test packages.

Create these projects and add all three to `CFScanner.sln`:

```text
tests/
  CFScanner.UnitTests/
  CFScanner.IntegrationTests/
  CFScanner.EndToEndTests/
```

Each project targets `net10.0`, references the production project, and uses:

- `Microsoft.NET.Test.Sdk` compatible with the selected SDK
- xUnit v3 packages and the xUnit v3 MTP runner integration
- `Microsoft.Testing.Extensions.CodeCoverage` for coverage

Do **not** add `coverlet.collector` when using MTP coverage. The coverage command is:

```powershell
dotnet test CFScanner.sln --coverage
```

For assertions, prefer the built-in xUnit `Assert` APIs to avoid licensing and dependency risk. If a fluent library is genuinely useful, choose one of these explicitly and pin it in `Directory.Packages.props`: **FluentAssertions 7.x only** (last Apache 2.0 line), **AwesomeAssertions**, or **Shouldly**. Never add FluentAssertions 8+ without an explicit legal approval and license review.

## 3. Testability preparation

Make only small, behavior-preserving refactors before writing broad coverage:

- Inject `TimeProvider` (the native .NET 10 abstraction) wherever production code currently reads time, delays, or stopwatch-like timing. Use a fake/manual `TimeProvider` in deterministic tests.
- Put filesystem, DNS, TCP/HTTP, environment, random generation, and child-process execution behind injectable interfaces or narrow adapters.
- Make the random IPv4 generator seedable/injectable.
- Separate Xray process execution and ownership/lifecycle from orchestration so it can be faked.
- If important production types are `internal`, add an `InternalsVisibleTo` item in the production project for each test assembly, using the exact assembly names. Do not make types public solely for tests.
- Keep `ConsoleInterface` responsible for presentation; test stable output contracts rather than incidental spacing or ANSI formatting.

`GlobalContext` and other static/global state require an explicit isolation mechanism:

- Reset or recreate all context, cancellation sources, stopwatch state, counters, filters, and Xray template state per test.
- Use xUnit collection fixtures and `[Collection]` to serialize tests that touch unavoidable process-wide state.
- Set xUnit assembly-level `DisableTestParallelization` for the affected test assembly (or the whole suite if isolation cannot be made finer-grained).
- Never rely on test execution order.

## 4. Unit-test coverage plan

Unit tests must be deterministic and must not perform external I/O.

### 4.1 `ArgParser` and configuration

Cover profiles `normal`, `fast`, `slow`, and `extreme`; explicit worker/timeout/buffer overrides; single, comma-separated, and `all` ports; combined file/ASN/range inputs; malformed IP/CIDR/port/options; help/manual modes; `-y`, shuffle, sort, no-latency, random-SNI; speed-test prerequisites; and buffer auto-scaling only when no explicit buffer was supplied.

Assert both validation outcome and stable error categories/messages. Avoid assertions on incidental formatting.

### 4.2 IPv4, CIDR, and filtering

Cover IP conversion boundaries, network/broadcast and `/31`/`/32`, the `Defaults.CidrExpandCap` limit, private/reserved/multicast/malformed filtering, stable sort, and deduplication.

### 4.3 Input and file loading

Cover whitespace, blank lines, comments, malformed lines, missing files, encoding/I/O failures, combined sources, exclusions, finite mode, and random infinite mode. Infinite mode tests must always set an explicit item cap and pass a `CancellationToken`; never let a test depend on an unbounded producer.

ASN tests use a tiny checked-in fixture or an injected fake loader. The real downloader is not part of unit tests.

### 4.4 Scanner workers

Cover TCP success/failure, timeout, cancellation, TLS handshake failures, and Cloudflare signature detection. Header matching must be explicitly **case-insensitive** for both header names and values where HTTP semantics require it: status `200`, `server: cloudflare`, and presence of `cf-ray`.

Use fake streams/handlers or loopback fixtures, never public endpoints.

### 4.5 Pipeline, pause, and cancellation

Cover cascading channel completion after worker exceptions, draining, cooperative cancellation, pause/resume without item loss, pause-excluded elapsed time, bounded-channel backpressure, and invalid capacities/worker counts. Use synchronization primitives and controllable fakes instead of `Thread.Sleep`.

### 4.6 Xray

Cover executable resolution, JSON-template validation, command-line construction without secret leakage, process termination/disposal on every path, Stage 3→Stage 4 ownership transfer, proxy validation, timeout, and speed-threshold failures. Unit tests must use a fake process runner; they must not launch Xray.

## 5. Integration-test plan

Integration tests connect real components to local, deterministic dependencies.

### 5.1 Loopback fixtures

Bind listeners to `127.0.0.1` on **port 0**, then read the assigned port from `listener.LocalEndPoint`. Do not preselect a “random” port: that creates avoidable race/flakiness.

Provide HTTP responses for valid Cloudflare-like signatures, non-200 statuses, missing/incorrect headers, slow responses, disconnects, and cancellation. Dispose listeners and streams via async fixtures.

For TLS fixtures, generate a self-signed certificate at runtime with `CertificateRequest` and `X509Certificate2`; do not commit certificate files or private keys. TLS 1.3 loopback coverage is platform-dependent, so guard it with an explicit capability check and skip when unsupported. Always retain a TLS 1.2-compatible path.

### 5.2 Input-to-scan pipeline

Exercise `ArgParser → InputLoaders → ScanEngine` with temporary files and loopback endpoints. Verify exclusions, deduplication, sorting, multi-port output, bounded channels, cancellation during processing, counters, and known result counts.

### 5.3 Files, ASN, and Xray

Use a small versioned ASN fixture and an injected loader. Results must go to a unique temporary directory. Default CI uses fake process runners and fake proxy endpoints for Xray lifecycle/config tests.

Real Xray integration is opt-in only:

```text
CFSCANNER_RUN_XRAY_TESTS=1
```

It requires a valid local template and executable, and must be excluded from the default CI job.

## 6. End-to-end test plan

E2E tests build/publish and invoke the real executable as an external process. Capture stdout, stderr, exit code, and result files; apply a whole-process timeout; and terminate/clean up safely on timeout.

Cover help/manual behavior, invalid input, a small authorized loopback range with `-y`, result-file creation/header, single- and multi-port formats, clean cancellation/shutdown, and representative failure paths.

E2E tests are **skipped by default** unless:

```text
CFSCANNER_RUN_E2E=1
```

The test code must enforce this condition (for example with an explicit skip at runtime), so the default `dotnet test CFScanner.sln` does not require E2E infrastructure. A Trait alone does not skip a test.

Ctrl+C is not cross-platform in the same way. On Unix-like systems, send SIGINT. On Windows, `GenerateConsoleCtrlEvent` requires a console process group and different hosting mechanics; either implement and validate a dedicated Windows path or mark the Windows Ctrl+C case skipped with a documented alternative cancellation test. Never add a test that is expected to fail on one OS.

Public-Cloudflare E2E tests are outside default smoke/PR CI and require explicit authorization and a separate profile.

## 7. Traits and exact commands

Use traits/categories: `Unit`, `Integration`, `E2E`, `External`, `Xray`, and `Slow`.

With xUnit v3 + MTP, use these exact filters:

```powershell
dotnet test CFScanner.sln -- --filter-trait "Category=Unit"
dotnet test CFScanner.sln -- --filter-not-trait "Category=E2E"
dotnet test CFScanner.sln -- --filter-trait "Category=Integration"
dotnet test CFScanner.sln -- --filter-trait "Category=E2E"
dotnet test CFScanner.sln -- --coverage
```

The E2E command still skips tests unless `CFSCANNER_RUN_E2E=1` is set. Do not replace these commands with VSTest `--filter` syntax.

## 8. CI and quality gates

Recommended order: restore, build Debug/Release, Unit tests on every push/PR, Integration tests on every PR, coverage artifact, opt-in E2E job, and manually approved External/Xray jobs.

The normal build/test path must not require `ip2asn-v4.tsv`, Xray, VPN, or public network access. Do not hide flakiness with unlimited retries. Coverage is a signal, not a substitute for assertions around error paths, cancellation, concurrency, and cleanup.

## 9. Quantitative Definition of Done

The first implementation is complete only when:

- `ArgParser`, `IpFilter`, and `InputLoaders` have meaningful unit coverage, including invalid-input paths.
- Unit tests cover cancellation/resource cleanup for the relevant core components.
- Unit suite runtime is **under 30 seconds** on the supported developer machine/CI runner.
- Integration tests use only loopback and temporary resources.
- E2E is skipped by default and runs only with `CFSCANNER_RUN_E2E=1`.
- `dotnet build CFScanner.sln` is green.
- Default `dotnet test CFScanner.sln` is green without internet, ASN download, or Xray.
- Coverage is produced with `Microsoft.Testing.Extensions.CodeCoverage` and `--coverage`.
- No child process, socket, file handle, timer, or cancellation source leaks after tests.
- README documentation explains test commands, SDK/package pinning, opt-in variables, and platform skips.

## 10. Recommended implementation order

1. Add SDK/package pinning and test-project skeletons.
2. Add `InternalsVisibleTo`, `TimeProvider`, and narrow dependency seams as needed.
3. Implement unit tests for parser, IP/filter, and input loading.
4. Implement deterministic pipeline, pause, cancellation, and worker tests.
5. Add loopback HTTP/TLS fixtures with port 0 and runtime certificates.
6. Add integration tests for the local pipeline and fake Xray lifecycle.
7. Add externally invoked E2E tests with default skip and platform-aware cancellation.
8. Add MTP coverage, CI jobs, artifacts, and quantitative gates.
9. Add real Xray/external tests only as separately approved opt-in jobs.

## 11. Out of scope

Do not expand this work into benchmark/performance testing, load/stress testing, public-network scanning, production observability, pixel-perfect console UI testing, or real Cloudflare/Xray tests in the default suite. Those require separate goals, authorization, fixtures, and acceptance criteria.

## 12. Prohibited practices

- Public-IP or Cloudflare access from Unit/Integration tests
- Preselected “random” ports instead of binding to port 0
- `Thread.Sleep`, unbounded waits, or infinite producers without a cap and `CancellationToken`
- Shared mutable static state without collection/assembly isolation
- `coverlet.collector` in the MTP configuration
- FluentAssertions 8+ without explicit legal approval
- Real Xray in default CI
- Committing certificates, keys, tokens, real Xray configs, ASN databases, results, `bin/`, or `obj/`
- Changing CLI behavior solely to make tests easier without updating contracts and README files
