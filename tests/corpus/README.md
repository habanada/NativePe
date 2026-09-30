# NativePe Corpus Differential Harness v6

The corpus runner performs static PE validation in an isolated worker process for every input file. PE entry points and TLS callbacks are never executed.

## Corpus scope

For the standard corpus layout only these top-level directories are scanned:

- `System32`
- `SysWOW64`
- `bintests-master`
- `pocs-master`

If none of these roots exist, the supplied root is scanned recursively. Hidden directories and reparse-point directories are not traversed.

## Processing stages

For recognized PE files the worker performs:

- bounded NT/header parsing
- section header and raw-range validation
- RAW to virtual mapping without execution
- data-directory discovery
- normal import presence, validation and collection
- delay-import presence, validation and descriptor counting
- export presence and name enumeration
- TLS presence, callback enumeration, full-sequence digest, bounded callback preview, AddressOfIndex and RawData range without execution
- resource presence and parsing
- relocation presence, validation and processed relocation-field count
- exception-directory presence, entry count and deterministic entry digest without runtime registration
- LoadConfig presence, declared size/version and SecurityCookie RVA
- .NET detection
- virtual to RAW conversion
- reconstructed RAW-size capture
- byte comparison of PE headers and every declared raw section

The JSON and CSV reports use the same structured fields as the libpeconv v6 harness. TLS callback sequences are represented by `tlsCallbacksValid`, `tlsCallbacksInvalid`, `tlsCallbackDigest`, `tlsCallbackPreview`, `tlsCallbackTruncated`, `tlsCallbackFirstValidRva`, and `tlsCallbackLastValidRva`. The preview contains at most the first 64 normalized entries; the digest covers every callback in order. `tlsIndexRva`, `tlsRawData`, `relocFields`, exception fields, LoadConfig fields, and `securityCookieRva` remain semantically comparable across both harnesses.

`REJECT` means the input was safely rejected by a validation or reconstruction stage. `FAIL`, `CRASH`, and `TIMEOUT` are hard failures and produce exit code 1.

## Timing model

Schema v6 records four independent high-resolution timings in microseconds:

- `libraryElapsedUs`: starts immediately before RAW-to-virtual mapping and ends immediately after virtual-to-RAW returns. It covers mapping, structured feature traversal and reconstruction, but excludes file I/O, raw-layout preflight, roundtrip byte comparison, buffer cleanup, result serialization and process startup.
- `coreElapsedUs`: starts immediately after the input file has been read and ends after PE mapping/parsing/roundtrip work. It excludes file I/O, raw-input deallocation, result serialization and process startup.
- `workerElapsedUs`: starts at worker entry and ends after input-buffer cleanup. Result serialization and process startup are excluded.
- `wallElapsedUs`: measured by the supervisor from immediately before `CreateProcess` until the worker has exited. It includes process startup, file I/O, PE work, result serialization and process teardown.

`elapsedMs` remains for compatibility and is `workerElapsedUs div 1000`.

The NativePe versus libpeconv benchmark uses only `libraryElapsedUs`. `coreElapsedUs`, `workerElapsedUs` and `wallElapsedUs` remain diagnostic measurements. Both v6 harnesses use identical timing boundaries.

## Build

Open:

`tests\corpus\NativePeCorpusTest.dproj`

For robustness/debugging runs use Win64 Debug.

For performance comparison use Win64 Release with optimization enabled. The report records `buildConfig` and `optimized`; the v6 comparison script refuses to include samples in the benchmark unless both reports are optimized v6 reports with the same timing model.

The EXE is normally written to:

`bin\Win64\Release\NativePeCorpusTest.exe`

or:

`bin\Win64\Debug\NativePeCorpusTest.exe`

## Run

Default corpus:

`scripts\run-nativepe-corpus.bat Debug`

Standard corpus:

`scripts\run-nativepe-corpus.bat Debug "E:\PE-Corpus"`

Benchmark-quality NativePe report:

`scripts\run-nativepe-corpus.bat Release "E:\PE-Corpus"`

For the fair NativePe versus libpeconv comparison, use `run-fair-comparison.bat` from the libpeconv differential package. For performance results use its repeated `run-benchmark-rounds.bat` workflow; it creates one common manifest, warms both implementations, alternates execution order and aggregates per-file median `libraryElapsedUs` values across measured rounds.

## Exact file-list mode

The runner accepts a UTF-8 file list relative to the corpus root:

`NativePeCorpusTest.exe --root "E:\PE-Corpus" --list "E:\PE-Corpus\corpus-files.txt" --results "E:\Projects\NativePe\test-results\corpus" --timeout-ms 15000 --max-mb 512`

The batch wrapper accepts the list as its third argument:

`scripts\run-nativepe-corpus.bat Release "E:\PE-Corpus" "E:\PE-Corpus\corpus-files.txt"`

Entries outside the four standard corpus roots are ignored when the standard layout is present. Duplicate paths are removed.

## Result files

Every run creates:

- `NativePeCorpus-YYYYMMDD-HHNNSS-ZZZ.log`
- `NativePeCorpus-YYYYMMDD-HHNNSS-ZZZ.csv`
- `NativePeCorpus-YYYYMMDD-HHNNSS-ZZZ.json`

The JSON schema version is `6`.

TLS callback addresses, TLS `AddressOfIndex`, TLS raw-data bounds, and the LoadConfig security cookie are reported through the same deterministic address normalization in both harnesses: preferred image base first, mapped image base second, then an already-normalized RVA. The differential report therefore compares PE-relative addresses rather than library-specific VA/RVA heuristics.

TLS callback digest tokens use the same encoding in both harnesses: one validity byte followed by a 32-bit little-endian normalized RVA. Invalid entries use validity `0` and RVA `0`; valid entries use validity `1`. Two independent 64-bit rotating accumulators produce the 32-hex-character `tlsCallbackDigest`. This keeps the complete ordered callback sequence comparable without materializing multi-megabyte callback strings.

## Worker isolation

Every file is processed by a fresh worker process. Default timeout is 15 seconds and default maximum file size is 512 MB. A crash or hang in one sample does not terminate the complete corpus run.
