# CFScanner Resume and Crash-Recovery Feature Plan

## 1. Purpose

Add an opt-in resume capability for long-running scans. If the process is
stopped by power loss, OS termination, crash, or an unexpected interruption,
the next invocation can detect a recoverable session and ask whether to
continue it.

The feature is especially important for:

- Infinite random IPv4 scanning.
- Large finite file, ASN, or CIDR scans.
- Scans with Xray validation or speed tests that may run for many hours.

## 2. Proposed CLI contract

### 2.1 Primary switch

Introduce an opt-in boolean switch:

```text
--resume
```

Suggested aliases:

```text
--checkpoint
```

The short alias should be added only if it does not conflict with existing
CLI grammar. The initial implementation should use `--resume` as the
documented canonical spelling.

When omitted, the current behavior remains unchanged: no checkpoint is
created and startup never asks about an old scan.

### 2.2 Optional tuning switches

These are optional and should be added only if the first implementation needs
user control:

```text
--resume-interval <SECONDS>    Checkpoint interval; bounded to a safe range
--resume-dir <PATH>           Directory for checkpoint/session files
```

Prefer a safe default (for example, 60 seconds) before exposing additional
knobs. Avoid making the common command more complicated.

### 2.3 Startup choices

If a valid checkpoint is found, display a clear prompt:

```text
Previous interrupted scan found.
[C] Continue
[N] Start a new scan
[D] Delete the saved session
```

`-y/--yes` must not silently continue an old session. For unattended use,
define and document a deterministic policy, preferably:

- `--resume -y`: continue only when the checkpoint exactly matches the
  current command/configuration; otherwise start a new scan with a warning.
- An explicit future switch such as `--resume-force` may be added if needed.

Do not infer continuation from the existence of a file without user intent.

## 3. Integration with the existing startup flow

Preserve the documented `Program.cs` order. Add resume handling at these
points:

1. `ArgParser.ParseArguments`: parse `--resume` and any future tuning values.
2. `AppValidator.ValidateInputs`: validate checkpoint directory and reject
   unsafe/unwritable locations.
3. After exclusions are built and before target enumeration begins:
   resolve the effective scan identity and inspect existing checkpoints.
4. `InputLoader.LoadTargetsAsync`: build a deterministic finite target source
   or a resumable infinite source.
5. `ScanEngine.RunScanAsync`: report progress and periodically publish
   checkpoint snapshots.
6. Normal finalization: flush the final checkpoint, mark the session complete,
   then remove or archive the recoverable checkpoint.

The resume coordinator should be a focused component, preferably in
`Core/Resume/` or `Core/ScanCheckpoint.cs`. File-format and atomic-write
helpers belong in `Utils/` or a dedicated resume utility. Do not add another
entry point or unrelated global mutable state.

## 4. Session identity and compatibility

Every checkpoint must contain a versioned session document. At minimum store:

- Format/schema version.
- Session ID and creation time (UTC).
- Last checkpoint time (UTC).
- Scan mode: finite or infinite.
- Effective input sources:
  - normalized file paths and a safe file identity (size/last-write time or
    content hash);
  - normalized ASN values;
  - normalized CIDRs/IPs.
- Effective exclusions and ASN database identity.
- Ordered ports.
- Shuffle setting and deterministic shuffle seed.
- Random SNI setting.
- V2Ray/Xray configuration identity (path plus content hash, never secrets).
- Speed-test thresholds and relevant worker-stage settings.
- Resume cursor/state.
- Count of targets acknowledged by the producer.
- Results file path and a stable result-session identifier.

Create a canonical representation with stable ordering and hash it. On
startup, compare the current effective configuration with the checkpoint:

- Exact match: eligible for continuation.
- Mismatch: do not silently merge. Explain the differing fields and offer a
  new scan or explicit discard.
- Missing/changed source files: treat as incompatible unless a future format
  supports immutable snapshots.

Do not store credentials, raw proxy secrets, or the full Xray template unless
the existing security model explicitly permits it.

## 5. Progress model

### 5.1 Finite scans

The current finite loader materializes a sorted, deduplicated, exclusion-filtered
`uint[]`, optionally shuffles it, and streams it lazily. Resume must preserve
the exact effective sequence.

Preferred model:

- Generate the effective target sequence once.
- Assign each IP/port work item a monotonically increasing sequence number.
- Persist the next sequence number that is safe to resume.
- On restart, skip all sequence numbers below that cursor.

Because the pipeline is concurrent, “scheduled” and “completed” are not the
same. The checkpoint cursor must advance only according to an explicit policy:

1. **Conservative:** checkpoint the highest contiguous sequence completed.
   This avoids gaps but may repeat in-flight work.
2. **Batch acknowledgement:** divide the sequence into durable batches and
   acknowledge a batch after all its items finish.

Use the conservative approach first. Re-scanning a small tail after a crash is
acceptable; skipping targets is not.

If `--shuffle` is enabled, persist the shuffle seed and ensure the same
deterministic Fisher-Yates order is recreated on resume. A process-randomized
shuffle must not be used for resumable sessions.

### 5.2 Infinite random scans

The existing `NetUtils.GenerateRandomIps()` must become resumable without
storing every generated IP.

Use a deterministic, versioned PRNG owned by the scan session and persist:

- PRNG algorithm/version.
- Seed.
- Number of values consumed, or an equivalent serializable PRNG state.
- Any rejection-sampling counters needed to reproduce public IPv4 filtering.

The generator must reproduce the same sequence after restart. If the current
random generator cannot expose/restored state, introduce a separate
resumable generator rather than pretending that a timestamp or count alone is
enough.

The infinite scan has no completion state. Its checkpoint remains recoverable
until the user starts a new session, deletes it, or explicitly disables resume.

## 6. Checkpoint file format

Use a small, human-readable, versioned JSON document initially. Suggested
layout:

```json
{
  "schemaVersion": 1,
  "sessionId": "uuid",
  "mode": "finite|infinite",
  "createdUtc": "...",
  "updatedUtc": "...",
  "configFingerprint": "...",
  "resultsPath": "...",
  "finite": {
    "sequenceLength": 0,
    "nextContiguousSequence": 0,
    "shuffleSeed": 0
  },
  "infinite": {
    "generator": "algorithm-name",
    "generatorVersion": 1,
    "seed": 0,
    "valuesConsumed": 0
  },
  "stats": {
    "scanned": 0,
    "tcpOpen": 0,
    "signaturePassed": 0,
    "v2rayPassed": 0,
    "speedTestPassed": 0
  }
}
```

The exact field names may change during implementation, but the following
properties are mandatory:

- Explicit schema version and migration strategy.
- Strict validation and range checks.
- No dependence on partially written JSON.
- Forward-compatible handling of unknown fields.
- Atomic replacement of the active checkpoint.

Keep a single active checkpoint and, optionally, one previous good backup:

```text
resume/
  <session-id>.json
  <session-id>.json.bak
  <session-id>.lock
```

The directory and naming convention must be documented and excluded from
result sorting/cleanup logic.

## 7. Durable write strategy and SSD impact

Never rewrite a growing list of all scanned IPs. Checkpoints should be small
and periodic.

Recommended write sequence:

1. Serialize a complete snapshot in memory.
2. Write it to a uniquely named temporary file in the same directory.
3. Flush the file according to the selected durability policy.
4. Atomically replace the active checkpoint.
5. Optionally retain the previous file as `.bak`.
6. Clean up stale temporary files at startup.

Default interval should be approximately 60 seconds, with a configurable
minimum that prevents per-IP writes. A checkpoint lost during the interval
only causes a bounded amount of duplicate scanning.

Expected checkpoint traffic is negligible:

- 1 KB every minute is roughly 0.5 GB/year before filesystem amplification.
- 1 KB every 10 seconds is roughly 3 GB/year.

The larger write source may be `FileUtils.SaveResult`, which currently appends
one line per successful endpoint. Do not change result format. If performance
measurement shows excessive write calls, introduce buffered/batched result
writes while preserving flush-on-shutdown and the existing line-oriented
format.

Do not call `Flush(true)` for every work item. A normal checkpoint can use
periodic durable flushes; a final graceful checkpoint should use the strongest
available flush path. Document that no software can guarantee recovery from
filesystem/controller failure.

## 8. Crash, power-loss, and cancellation behavior

### 8.1 Unexpected termination

On the next startup:

- Ignore incomplete temporary files.
- Validate active checkpoint, then `.bak` if necessary.
- Verify the result file identity and configuration fingerprint.
- Offer continuation only when a valid recoverable state exists.

### 8.2 Ctrl+C

Keep cancellation cooperative. On the first Ctrl+C:

- Stop scheduling new work.
- Allow in-flight workers to observe cancellation.
- Capture the highest safe progress snapshot.
- Await pipeline tasks and dispose network/Xray resources.
- Write a final recoverable checkpoint unless the scan completed.

Never create a fire-and-forget checkpoint task that can outlive process
shutdown.

### 8.3 Normal completion

For finite scans:

- Write a final state with `completed = true`.
- Flush results first.
- Remove the recoverable checkpoint only after successful finalization.

For infinite scans, normal user cancellation should leave the checkpoint so it
can be continued.

### 8.4 Concurrent instances

Prevent two processes from writing the same session. Use an OS-level lock file
or equivalent exclusive file creation. A second process should report that the
session is active and exit or start a separate session.

## 9. Results-file semantics

The resume implementation must not break current output contracts:

- Keep the existing result filename and line formats.
- On continuation, append to the original results file.
- Do not create a second results file unless the user explicitly starts a new
  session.
- Avoid duplicate result lines where practical, but correctness of target
  coverage takes priority over perfect deduplication after a crash.
- Sorting remains a finalization operation and must not run during checkpoints.

If result-file deletion occurs for an empty final scan, remove the associated
checkpoint only after that decision is complete.

## 10. User-facing behavior and documentation

Add concise help text to `ArgParser.PrintHelpShort()` and full documentation to
`PrintHelpFull()`. Update both `README.md` and `README.fa_IR.md` with:

- `--resume` syntax.
- Default checkpoint interval and storage location.
- Startup prompt choices.
- Finite versus infinite resume behavior.
- Expected duplicate tail after abrupt termination.
- SSD write explanation.
- Security/privacy notes for checkpoint contents.
- `-y` unattended behavior.

Keep all runtime messages in `ConsoleInterface` or the existing synchronized
UI path. Suggested messages:

```text
[Resume] Recoverable session found: ...
[Resume] Configuration matches. Continue?
[Resume] Checkpoint is incompatible: ...
[Resume] Saved progress at sequence ... 
[Resume] Session completed; checkpoint removed.
```

## 11. Implementation phases

### Phase 1: Domain model and persistence

1. Define immutable checkpoint DTOs and schema version.
2. Implement canonical configuration fingerprinting.
3. Implement validation, atomic write, backup fallback, and stale-temp cleanup.
4. Add unit tests for serialization, corruption, compatibility, and atomic
   replacement.

### Phase 2: CLI/configuration

1. Add `Config.ResumeEnabled` and safe defaults.
2. Parse `--resume` and validate interval/directory if exposed.
3. Add help and README documentation.
4. Add parser/config tests and reset any new test state in both test projects.

### Phase 3: Finite-source resume

1. Make the post-filter target sequence reproducible.
2. Add sequence numbers and contiguous acknowledgements.
3. Integrate checkpoint publication with `ScanEngine`.
4. Resume from the stored cursor while preserving ports and ordering.
5. Test interruption and tail reprocessing.

### Phase 4: Infinite-source resume

1. Implement a versioned deterministic PRNG abstraction.
2. Persist and restore its state.
3. Integrate exclusion/rejection sampling deterministically.
4. Test sequence equivalence across process-like restarts.

### Phase 5: Lifecycle hardening

1. Integrate Ctrl+C and pause behavior.
2. Verify no checkpoint task outlives shutdown.
3. Add process lock handling.
4. Verify Xray ownership/cleanup on all cancellation and resume paths.

### Phase 6: End-to-end validation

1. Run full build and unit/integration suites.
2. Add opt-in local end-to-end resume tests where feasible.
3. Manually simulate:
   - Ctrl+C during finite scan.
   - Ctrl+C during infinite scan.
   - Process kill/power-loss approximation.
   - Truncated checkpoint.
   - Missing/changed input file.
   - Changed CLI settings.
   - Two simultaneous instances.
4. Inspect `git diff` and `git status --short`.

## 12. Required and recommended tests

### Unit tests (`tests/CFScanner.UnitTests`)

Add tests for:

- Default resume-disabled configuration.
- Parsing `--resume`.
- Interval bounds and invalid values.
- Canonical fingerprint stability despite input ordering where ordering is
  semantically irrelevant.
- Fingerprint changes for ports, exclusions, profile, Xray config, and source
  changes.
- JSON round-trip.
- Schema/version rejection.
- Malformed/truncated JSON handling.
- Atomic-write temporary-file cleanup.
- Backup fallback when the primary checkpoint is invalid.
- Finite cursor validation and clamping/rejection.
- Deterministic shuffle reproduction.
- PRNG state round-trip and sequence continuation.
- Duplicate-tail policy.

Use temporary directories and avoid real network or Xray processes.

### Integration tests (`tests/CFScanner.IntegrationTests`)

Add tests for:

- File + range + ASN effective configuration fingerprinting.
- Finite loader resumed from a non-zero cursor.
- Exclusions and deduplication remaining identical after resume.
- Infinite generator producing the same next sequence after restore.
- Checkpoint publication while pipeline workers run.
- Ctrl+C/cancellation producing a recoverable checkpoint.
- Normal finite completion removing the checkpoint.
- Changed input/config refusing silent continuation.
- Existing result file being reused on continuation.
- Concurrent session lock behavior.

Keep tests deterministic, short, and free of external network dependencies.

### End-to-end tests (`tests/CFScanner.EndToEndTests`)

Keep opt-in behind `CFSCANNER_RUN_E2E=1`. If added, use a local deterministic
source and a test-specific resume directory; never depend on public internet
scanning or a real production Xray installation.

## 13. Safety and failure policy

- Resume is best-effort durability, not a transactional database.
- Never skip unacknowledged finite targets.
- Repeating a bounded tail is acceptable.
- Checkpoint errors must be visible. The scanner may continue scanning, but
  must clearly warn that recovery is unavailable.
- Permission, disk-full, serialization, and lock errors must not be swallowed.
- Avoid storing sensitive configuration values.
- Keep all file operations asynchronous where they are part of the network
  pipeline; do not introduce blocking waits into workers.

## 14. Definition of done

The feature is complete when:

1. `--resume` is documented and opt-in.
2. Finite and infinite scans resume deterministically.
3. Abrupt termination cannot leave a partially accepted checkpoint.
4. Ctrl+C remains cooperative and all workers/Xray processes are cleaned up.
5. Configuration mismatches never silently continue.
6. Checkpoint write frequency is bounded and documented.
7. Unit and integration tests cover persistence, compatibility, cursors,
   generator state, cancellation, and finalization.
8. Full solution build and required test commands pass.
9. Both READMEs and CLI help describe the final behavior.
