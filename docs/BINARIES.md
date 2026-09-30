# Binaries and Command Line Usage

This document describes the compiled NativePe demos, test runners, corpus tools, process dumper, and real-world test helpers.

The examples below assume:

- NativePe repository: `E:\NativePe\`
- PE corpus: `E:\PE-Corpus\`

Replace `E:\NativePe\` if your repository is stored somewhere else.

## Build layout

NativePe binaries are separated by platform and build configuration:

```text
bin\
  Win32\
    Debug\
    Release\
  Win64\
    Debug\
    Release\
```

Additional tools are placed below the selected build directory:

```text
bin\Win64\Release\Tools\
bin\Win64\Release\RealWorld\
```

The same layout is used for Win32 and Debug builds where supported.

## Important safety note

`NativePeCorpusTest.exe` performs static PE processing in isolated worker processes and does not intentionally execute PE entry points or TLS callbacks.

`NativePeDemo.exe` is different: it manually loads the supplied PE, resolves imports, runs TLS callbacks, and calls the PE entry point. Do not use `NativePeDemo.exe` with untrusted or malware corpus files.

---

# Recommended launchers

The regular scripts under `scripts\` are the supported entry points. They replace the older menu/select helper scripts; no separate launcher BAT is required.

All three launchers can be used interactively. If started without parameters, they ask for the required platform and build configuration.

| Launcher | Purpose | Interactive start |
|---|---|---|
| `run-nativepe-corpus.bat` | Run the NativePe corpus harness. Selects Win32/Win64, Debug/Release, corpus root, optional file list, timeout, and file-size limit. | `E:\NativePe\scripts\run-nativepe-corpus.bat` |
| `run-nativepe-dunitx.bat` | Run all DUnitX tests or select a predefined/custom subset. libpeconv fixture hashes are verified automatically when required. | `E:\NativePe\scripts\run-nativepe-dunitx.bat` |
| `run-nativepe-dunitx-all.bat` | Run the complete DUnitX suite in Debug and then Release for one selected platform. | `E:\NativePe\scripts\run-nativepe-dunitx-all.bat` |

## `run-nativepe-corpus.bat`

### Interactive mode

```bat
E:\NativePe\scripts\run-nativepe-corpus.bat
```

The launcher asks for:

1. Win32 or Win64
2. Debug or Release
3. corpus root, default `E:\PE-Corpus\`
4. optional file-list manifest
5. per-file timeout, default `15000` ms
6. maximum file size, default `512` MB

If no file list is supplied, the launcher recursively scans all subdirectories below the corpus root.

### Command-line syntax

```text
run-nativepe-corpus.bat <Win32|Win64> <Debug|Release> [corpus-root] [file-list] [timeout-ms] [max-mb]
```

| Position | Value | Default | Description |
|---|---|---|---|
| 1 | `Win32`, `Win64`, `32`, or `64` | Interactive | Binary platform to execute. |
| 2 | `Debug` or `Release` | Interactive | Build configuration. |
| 3 | Corpus root | `E:\PE-Corpus\` | Root containing the PE files. |
| 4 | File-list manifest | None | Optional exact list of files. If omitted, every subdirectory is scanned recursively. |
| 5 | Timeout in ms | `15000` | Worker timeout per input file. |
| 6 | Maximum MB | `512` | Maximum accepted input-file size. |

Examples:

```bat
E:\NativePe\scripts\run-nativepe-corpus.bat Win64 Release "E:\PE-Corpus\"
E:\NativePe\scripts\run-nativepe-corpus.bat Win32 Debug "E:\PE-Corpus\" "E:\PE-Corpus\corpus-files.txt" 30000 512
```

Existing Win64 calls using the former short form remain accepted:

```bat
E:\NativePe\scripts\run-nativepe-corpus.bat Release "E:\PE-Corpus\"
```

Results are written below:

```text
E:\NativePe\test-results\corpus\<Platform>\<Config>\
```

## `run-nativepe-dunitx.bat`

### Interactive mode

```bat
E:\NativePe\scripts\run-nativepe-dunitx.bat
```

The launcher asks for platform, configuration, and the test selection. It can run the complete suite, a predefined area, a custom fixture/test name, a run-list file, or raw DUnitX arguments.

### Command-line syntax

```text
run-nativepe-dunitx.bat <Win32|Win64> <Debug|Release> [preset-or-test] [additional DUnitX arguments...]
```

| Preset / value | Description |
|---|---|
| `all` | Run the complete registered DUnitX suite. |
| `core` | Run `NativePe.Core`. |
| `coverage` | Run `NativePe.Coverage`. |
| `pe` | Run `NativePe.Pe`. |
| `robustness` | Run `NativePe.Robustness`. |
| `windows` | Run `NativePe.Windows`. |
| `libpeconv` | Run `NativePe.LibPeConv` and verify the pinned libpeconv fixture hashes first. |
| `<fixture-or-test-name>` | Passed as a DUnitX `--run:` filter. |
| `runlist:<path>` | Run tests listed in the specified DUnitX run-list file. |
| `raw:<arguments>` | Pass raw DUnitX arguments as the test-selection expression. |
| `help` | Show DUnitX command-line help. |

Examples:

```bat
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Release all
E:\NativePe\scripts\run-nativepe-dunitx.bat Win32 Debug robustness
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Release libpeconv
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Debug TExceptionDirectoryRobustnessTests
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Debug TExceptionDirectoryRobustnessTests.TruncatedPdataRejected
```

When `all` or `libpeconv` is selected, the launcher verifies the SHA-256 hashes of the pinned files under:

```text
E:\NativePe\tests\dunitx\fixtures\libpeconv\
```

No separate fixture-verification BAT is required for the normal DUnitX workflow.

DUnitX XML and console-log output are written below:

```text
E:\NativePe\test-results\dunitx\<Platform>\<Config>\
```

## `run-nativepe-dunitx-all.bat`

### Syntax

```text
run-nativepe-dunitx-all.bat [Win32|Win64|32|64]
```

Without a parameter, the launcher asks for the platform. It then runs:

```text
<Platform> Debug   -> all tests
<Platform> Release -> all tests
```

The Release run starts only if the Debug run succeeds.

Examples:

```bat
E:\NativePe\scripts\run-nativepe-dunitx-all.bat Win32
E:\NativePe\scripts\run-nativepe-dunitx-all.bat Win64
```

---

# Executables with parameters

## `NativePeDemo.exe`

Loads a PE through NativePe and transfers execution to the loaded image.

### Syntax

```text
NativePeDemo.exe <pe-file>
```

| Parameter | Required | Description |
|---|---:|---|
| `<pe-file>` | Yes | Path to the PE file to load and execute. |

### Example

```bat
E:\NativePe\bin\Win64\Debug\NativePeDemo.exe "E:\PE-Corpus\trusted-sample.exe"
```

Use only trusted test files. This program executes code from the supplied PE.

---

## `NativePeCorpusTest.exe`

Runs the NativePe differential corpus harness. Each input file is processed in a separate worker process.

### Syntax

```text
NativePeCorpusTest.exe --root <dir> [--list <file>] [--results <dir>] [--timeout-ms <ms>] [--max-mb <mb>] [--all-subdirs]
```

| Parameter | Required | Default | Description |
|---|---:|---|---|
| `--root <dir>` | No | Built-in sample path relative to the EXE | Corpus root directory. For normal use, set this explicitly. |
| `--results <dir>` | No | `test-results\corpus` relative to the repository layout | Directory for `.log`, `.csv`, and `.json` reports. |
| `--list <file>` | No | None | UTF-8 file list. Entries are relative to `--root`. Only listed files are processed. |
| `--timeout-ms <ms>` | No | `15000` | Maximum worker time per file in milliseconds. |
| `--max-mb <mb>` | No | `512` | Maximum input file size in MB. |
| `--all-subdirs` | No | Off | Recursively scans every subdirectory below `--root`. Without it, the standard corpus-root selection is used. |
| `--worker <input> <result>` | Internal | - | Internal supervisor/worker protocol. Do not use manually. |

### Full corpus example

```bat
E:\NativePe\bin\Win64\Release\NativePeCorpusTest.exe --root "E:\PE-Corpus\" --results "E:\PE-Corpus\NativePeResults" --timeout-ms 15000 --max-mb 512 --all-subdirs
```

### Debug corpus example

```bat
E:\NativePe\bin\Win64\Debug\NativePeCorpusTest.exe --root "E:\PE-Corpus\" --results "E:\PE-Corpus\NativePeResults-Debug" --timeout-ms 15000 --max-mb 512 --all-subdirs
```

### Exact file-list example

Create for example:

```text
E:\PE-Corpus\corpus-files.txt
```

with paths relative to `E:\PE-Corpus\`, then run:

```bat
E:\NativePe\bin\Win64\Release\NativePeCorpusTest.exe --root "E:\PE-Corpus\" --list "E:\PE-Corpus\corpus-files.txt" --results "E:\PE-Corpus\NativePeResults-Exact" --timeout-ms 15000 --max-mb 512
```

Use Release for performance comparisons. Use Debug when investigating range checks, overflow checks, assertions, or malformed-input behavior.

---

## `NativePeDUnitX.exe`

Runs the NativePe DUnitX suite. With no arguments, all registered tests run.

### Basic syntax

```text
NativePeDUnitX.exe [DUnitX options]
```

| Parameter | Short form | Description |
|---|---|---|
| `--run:<name>` | `-r:<name>` | Run tests matching a fixture/test name. May be supplied more than once; comma-separated names are also accepted. |
| `--runlist:<file>` | `-rl:<file>` | Read the tests to run from a file. |
| `--include:<categories>` | `-i:<categories>` | Include DUnitX categories. NativePe currently relies mainly on name filtering rather than categories. |
| `--exclude:<categories>` | `-e:<categories>` | Exclude DUnitX categories. |
| `--dontshowignored` | `-dsi` | Do not show ignored tests. |
| `--loglevel:<level>` | `-l:<level>` | DUnitX logging level: `Information`, `Warning`, or `Error`. |
| `--hidebanner` | `-b` | Hide the DUnitX banner. |
| `--options:<file>` | `-opt:<file>` | Load DUnitX options from an options file. |
| `--h` | `-?` | Show DUnitX command-line help. |

The standard DUnitX options `--xmlfile`, `--consolemode`, and `--exitbehavior` are parsed by DUnitX, but this NativePe runner creates its own console/XML loggers. For NativePe, set the XML path through `NATIVEPE_DUNITX_XML` and redirect console output if a dedicated log file is required.

### Run all tests

```bat
E:\NativePe\bin\Win64\Release\NativePeDUnitX.exe
```

### Store XML results on drive E

```bat
set NATIVEPE_DUNITX_XML=E:\PE-Corpus\TestResults\NativePeDUnitX-Win64-Release.xml
E:\NativePe\bin\Win64\Release\NativePeDUnitX.exe
```

### Run robustness tests

```bat
E:\NativePe\bin\Win64\Debug\NativePeDUnitX.exe --run:NativePe.Robustness
```

### Run one robustness fixture

```bat
E:\NativePe\bin\Win64\Debug\NativePeDUnitX.exe --run:TExceptionDirectoryRobustnessTests
```

### Run one exact test

```bat
E:\NativePe\bin\Win64\Debug\NativePeDUnitX.exe --run:TExceptionDirectoryRobustnessTests.TruncatedPdataRejected
```

### Run the libpeconv-related DUnitX tests

The libpeconv fidelity tests use the fixture directory under the repository. `run-nativepe-dunitx.bat` sets this automatically. For direct EXE use:

```bat
set NATIVEPE_LIBPECONV_FIXTURES=E:\NativePe\tests\dunitx\fixtures\libpeconv
E:\NativePe\bin\Win64\Release\NativePeDUnitX.exe --run:NativePe.LibPeConv
```

For the hash-pinned workflow, use the regular launcher:

```bat
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Release libpeconv
```

The launcher verifies the reference fixture hashes before running the libpeconv-related DUnitX tests.

---

## `Tools\NativePeProcessDump.exe`

Dumps the main executable or a selected loaded module from a running process.

### Syntax

```text
NativePeProcessDump.exe --pid <pid> [--module <name>] [--out <path>] [--verbose]
```

| Parameter | Required | Description |
|---|---:|---|
| `--pid <pid>` | Yes | Windows process ID of the target process. |
| `--module <name>` | No | Dump a specific loaded module, for example `kernel32.dll`. If omitted, the main executable is dumped. |
| `--out <path>` | No | Output PE path. If omitted, a timestamped `NativePeDump-PID...exe` file is created in the current directory. |
| `--verbose` | No | Enable NativePe debug logging. |
| `--help` / `/?` | No | Show usage. |

### Simple PE dump by PID

First find the PID. You can use Task Manager -> Details, or from a command prompt:

```bat
tasklist
```

If the process PID is `1234`, dump its main executable:

```bat
E:\NativePe\bin\Win64\Release\Tools\NativePeProcessDump.exe --pid 1234 --out "E:\PE-Corpus\Dumps\PID-1234.exe"
```

With verbose logging:

```bat
E:\NativePe\bin\Win64\Release\Tools\NativePeProcessDump.exe --pid 1234 --out "E:\PE-Corpus\Dumps\PID-1234.exe" --verbose
```

Dump only a loaded DLL:

```bat
E:\NativePe\bin\Win64\Release\Tools\NativePeProcessDump.exe --pid 1234 --module kernel32.dll --out "E:\PE-Corpus\Dumps\kernel32-from-1234.dll" --verbose
```

### Win32 vs Win64

Use the build matching the target process architecture:

```text
32-bit target -> bin\Win32\Release\Tools\NativePeProcessDump.exe
64-bit target -> bin\Win64\Release\Tools\NativePeProcessDump.exe
```

The tool explicitly rejects incompatible cross-bitness module enumeration.

### Easy controlled dump test

Start the real-world target:

```bat
E:\NativePe\bin\Win64\Release\RealWorld\NativePeProcessDumpTarget.exe
```

It prints something like:

```text
PID=1234
BITS=64
COM=0
```

Keep that window open and use the printed PID:

```bat
E:\NativePe\bin\Win64\Release\Tools\NativePeProcessDump.exe --pid 1234 --out "E:\PE-Corpus\Dumps\NativePeProcessDumpTarget.exe" --verbose
```

The target intentionally stays alive until it is terminated.

---

## `RealWorld\NativePeRealWorldRunner.exe`

Runs opt-in real-world loading, exception, recycler, and dump-validation tests.

### Syntax

```text
NativePeRealWorldRunner.exe loader <fixture.dll>
NativePeRealWorldRunner.exe exceptions <fixture.dll>
NativePeRealWorldRunner.exe recycler <fixture.dll>
NativePeRealWorldRunner.exe verify-dump <dump.exe> <32|64>
```

| Mode | Parameters | Description |
|---|---|---|
| `loader` | `<fixture.dll>` | Compares NativePe loading/relocation behavior with the Windows loader. |
| `exceptions` | `<fixture.dll>` | Manually loads the fixture, sets up exception metadata, and executes the exception test. |
| `recycler` | `<fixture.dll>` | Injects into a code cave, converts back to RAW, reloads, and verifies the recycled image. |
| `verify-dump` | `<dump.exe> <32|64>` | Parses and validates a produced process dump for the expected architecture. |

### Examples

```bat
E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe loader "E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldFixture.dll"
```

```bat
E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe exceptions "E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldFixture.dll"
```

```bat
E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe recycler "E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldFixture.dll"
```

```bat
E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe verify-dump "E:\PE-Corpus\Dumps\PID-1234.exe" 64
```

Use the Win32 runner/fixture pair for 32-bit real-world tests and the Win64 pair for 64-bit tests.

---

# Start-only executables

The following executables do not require command-line parameters. Start them directly from the matching `Win32/Win64` and `Debug/Release` directory.

| Executable | Purpose |
|---|---|
| `TestDirectoryEntry.exe` | PE data-directory helper checks. |
| `TestExportsMapperForwarders.exe` | Export-forwarder mapping checks using Windows DLLs. |
| `TestFixDotNet.exe` | .NET entry-point/fixup checks. |
| `TestFormatDetect.exe` | RAW/virtual PE format detection checks. |
| `TestFoundBase.exe` | PE/module-base discovery checks. |
| `TestHookingLocal.exe` | Local hook, backup, and restore checks inside the test process. |
| `TestIsBadReadPointer.exe` | Pointer/readability validation checks. |
| `TestIsWantedModule.exe` | Module-selection/filtering checks. |
| `TestLde.exe` | Instruction-length decoder and trampoline-size checks. |
| `TestLoading.exe` | PE load/unmap/roundtrip checks. |
| `TestMalformedPe.exe` | Malformed PE validation and bounds-check regressions. |
| `TestPebLookup.exe` | PEB module lookup and module-size checks. |
| `TestThreadSafeHooks.exe` | Thread suspension/resume and thread-safe hooking checks. |
| `RealWorld\NativePeProcessDumpTarget.exe` | Controlled long-running dump target. Prints its PID and architecture, then waits. |

Example:

```bat
E:\NativePe\bin\Win64\Debug\TestMalformedPe.exe
```

---

# libpeconv differential tests

The libpeconv differential harness is built separately from the Delphi `bin` tree. The executable is normally located at:

```text
E:\NativePe\tools\LibPeConvCorpusDiff\build\Release\LibPeConvCorpus.exe
```

## `LibPeConvCorpus.exe`

### Syntax

```text
LibPeConvCorpus.exe --root <corpus-root> [--list <relative-file-list>] [--results <dir>] [--timeout-ms <ms>] [--max-mb <mb>] [--include-root <name>]...
```

| Parameter | Required | Default | Description |
|---|---:|---|---|
| `--root <dir>` | Yes | - | Corpus root. |
| `--list <file>` | No | None | Exact relative file list. Recommended for NativePe/libpeconv parity runs. |
| `--results <dir>` | No | `results` below the current working directory | Output directory. |
| `--timeout-ms <ms>` | No | `15000` | Maximum worker time per file. |
| `--max-mb <mb>` | No | `512` | Maximum file size in MB. |
| `--include-root <name>` | No | `System32`, `SysWOW64`, `bintests-master`, `pocs-master` | Top-level corpus root to include. May be repeated. Supplying any custom value replaces the default root set. |
| `--worker <input> <result>` | Internal | - | Internal worker protocol. Do not use manually. |

### Standard corpus example

```bat
E:\NativePe\tools\LibPeConvCorpusDiff\build\Release\LibPeConvCorpus.exe --root "E:\PE-Corpus\" --results "E:\PE-Corpus\LibPeConvResults" --timeout-ms 15000 --max-mb 512
```

### Exact manifest example

```bat
E:\NativePe\tools\LibPeConvCorpusDiff\build\Release\LibPeConvCorpus.exe --root "E:\PE-Corpus\" --list "E:\PE-Corpus\corpus-files.txt" --results "E:\PE-Corpus\LibPeConvResults-Exact" --timeout-ms 15000 --max-mb 512
```

### Custom top-level roots

```bat
E:\NativePe\tools\LibPeConvCorpusDiff\build\Release\LibPeConvCorpus.exe --root "E:\PE-Corpus\" --include-root System32 --include-root SysWOW64 --results "E:\PE-Corpus\LibPeConvResults"
```

For a strict NativePe-vs-libpeconv comparison, use the same `--list` manifest for both executables.

---

# Original libpeconv fixture comparison

The repository contains hash-pinned libpeconv reference fixtures. The supplied batch file stages the PE fixtures, runs the NativePe corpus harness, runs the libpeconv corpus harness, and compares the reports.

### Syntax

```text
run-libpeconv-fixtures.bat <NativePe-root> [results-dir] [Debug|Release]
```

| Parameter | Required | Example | Description |
|---|---:|---|---|
| `<NativePe-root>` | Yes | `E:\NativePe` | Repository root containing `bin`, `tests`, and `scripts`. |
| `[results-dir]` | No | `E:\PE-Corpus\libpeconv-fixture-results` | Directory for staged corpus and comparison results. |
| `[Debug|Release]` | No | `Release` | NativePe corpus build configuration. Default is Release. |

### Recommended fixture comparison

```bat
E:\NativePe\tools\LibPeConvCorpusDiff\run-libpeconv-fixtures.bat "E:\NativePe" "E:\PE-Corpus\libpeconv-fixture-results" Release
```

This workflow verifies the reference fixture hashes and uses these PE fixtures:

```text
greek_to_me.bin
payload.dll
test_case3_32.exe
test_case3_64.exe
```

The raw shellcode fixtures are intentionally not passed to the corpus runners because they are not PE images.

---

# Comparing existing NativePe and libpeconv JSON reports

The comparison script accepts one NativePe schema-v6 JSON report and one libpeconv schema-v6 JSON report:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File "E:\NativePe\tools\LibPeConvCorpusDiff\Compare-NativePe.ps1" -NativePeJson "E:\PE-Corpus\NativePeResults\NativePeCorpus-YYYYMMDD-HHNNSS-ZZZ.json" -LibPeConvJson "E:\PE-Corpus\LibPeConvResults\LibPeConvCorpus-YYYYMMDD-HHNNSS-ZZZ.json" -OutputDir "E:\PE-Corpus\Comparison"
```

For reproducible comparisons, generate one exact relative file list and pass it to both corpus executables.

---

# Typical workflows

## 1. Run the complete NativePe corpus interactively

```bat
E:\NativePe\scripts\run-nativepe-corpus.bat
```

For a direct Win64 Release run over every subdirectory of `E:\PE-Corpus\`:

```bat
E:\NativePe\scripts\run-nativepe-corpus.bat Win64 Release "E:\PE-Corpus\"
```

## 2. Run all DUnitX tests interactively

```bat
E:\NativePe\scripts\run-nativepe-dunitx.bat
```

## 3. Run the complete DUnitX suite in Debug and Release

```bat
E:\NativePe\scripts\run-nativepe-dunitx-all.bat Win64
```

## 4. Run only robustness tests

```bat
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Debug robustness
```

## 5. Run only libpeconv-related DUnitX tests

```bat
E:\NativePe\scripts\run-nativepe-dunitx.bat Win64 Release libpeconv
```

The launcher performs the pinned fixture-hash verification automatically.

## 6. Dump a running 64-bit process

Find the PID first:

```bat
tasklist
```

Then dump the main executable, for example PID `1234`:

```bat
E:\NativePe\bin\Win64\Release\Tools\NativePeProcessDump.exe --pid 1234 --out "E:\PE-Corpus\Dumps\PID-1234.exe" --verbose
```

## 7. Validate the produced dump

```bat
E:\NativePe\bin\Win64\Release\RealWorld\NativePeRealWorldRunner.exe verify-dump "E:\PE-Corpus\Dumps\PID-1234.exe" 64
```

## 8. Run the original libpeconv fixture comparison

```bat
E:\NativePe\tools\LibPeConvCorpusDiff\run-libpeconv-fixtures.bat "E:\NativePe" "E:\PE-Corpus\libpeconv-fixture-results" Release
```

---

# Quick platform guide

| Target / task | Recommended binary |
|---|---|
| 32-bit DUnitX | `bin\Win32\<Config>\NativePeDUnitX.exe` |
| 64-bit DUnitX | `bin\Win64\<Config>\NativePeDUnitX.exe` |
| 32-bit corpus runner | `bin\Win32\<Config>\NativePeCorpusTest.exe` |
| 64-bit corpus runner | `bin\Win64\<Config>\NativePeCorpusTest.exe` |
| Dump 32-bit process | `bin\Win32\<Config>\Tools\NativePeProcessDump.exe` |
| Dump 64-bit process | `bin\Win64\<Config>\Tools\NativePeProcessDump.exe` |
| 32-bit real-world tests | `bin\Win32\<Config>\RealWorld\...` |
| 64-bit real-world tests | `bin\Win64\<Config>\RealWorld\...` |
| Performance corpus comparison | Prefer `Win64\Release` |
| Debugging malformed inputs | Prefer `Debug` |

