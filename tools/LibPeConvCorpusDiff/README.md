# LibPeConv Corpus Differential Harness

This tool runs PE files through libpeconv and produces reports that can be compared with NativePe corpus results.

It is a test and research tool. It does not execute PE entry points or TLS callbacks.

## Reference libpeconv version

The NativePe comparison uses this exact libpeconv revision:

- Project: https://github.com/hasherezade/libpeconv
- Commit: `0fc25f680e03699d33ef3b2034a6724365f3d1a4`
- Commit page: https://github.com/hasherezade/libpeconv/commit/0fc25f680e03699d33ef3b2034a6724365f3d1a4

libpeconv is not included here. Clone it separately and check out the commit above.

## Requirements

The harness is Windows-only and builds as x64 C++17.

Required:

- Git
- CMake 3.20 or newer
- Microsoft C++ Build Tools with the Desktop C++ workload
- Windows SDK
- PowerShell

A full Visual Studio IDE is not required.

## Install the tools with winget

Open an elevated Command Prompt or PowerShell window:

```bat
winget install -e --id Git.Git
winget install -e --id Kitware.CMake
winget install -e --id Microsoft.VisualStudio.BuildTools --override "--passive --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

Open a new terminal after installation and verify:

```bat
git --version
cmake --version
```

If Visual Studio with Desktop development with C++ is already installed, the separate Build Tools installation is not needed.

## Get the pinned libpeconv revision

The default CMake setup expects both directories next to each other:

```text
PE-Tools\
  libpeconv\
  LibPeConvCorpusDiff\
```

Clone libpeconv and pin the reference revision:

```bat
cd /d E:\PE-Tools
git clone https://github.com/hasherezade/libpeconv.git
cd libpeconv
git checkout 0fc25f680e03699d33ef3b2034a6724365f3d1a4
git rev-parse HEAD
```

The last command should print:

```text
0fc25f680e03699d33ef3b2034a6724365f3d1a4
```

## Build

From the `LibPeConvCorpusDiff` directory:

```bat
build.bat
```

The batch file runs:

```bat
cmake -S . -B build -A x64
cmake --build build --config Release
```

Output:

```text
build\Release\LibPeConvCorpus.exe
build\Release\LibPeConvProcessDump.exe
```

If libpeconv is stored somewhere else:

```bat
cmake -S . -B build -A x64 -DLIBPECONV_DIR="D:\Source\libpeconv"
cmake --build build --config Release
```

## Run a corpus scan

Basic example:

```bat
build\Release\LibPeConvCorpus.exe --root "E:\PE-Corpus" --results "results" --timeout-ms 15000 --max-mb 512
```

By default the scanner looks below these directories inside the corpus root:

```text
System32
SysWOW64
bintests-master
pocs-master
```

Use one or more `--include-root` options for other corpus directories:

```bat
build\Release\LibPeConvCorpus.exe --root "E:\PE-Corpus" --include-root "samples" --include-root "malformed" --results "results"
```

For reproducible NativePe comparisons, use an explicit file list containing paths relative to the corpus root:

```bat
build\Release\LibPeConvCorpus.exe --root "E:\PE-Corpus" --list "E:\PE-Corpus\corpus-files.txt" --results "results" --timeout-ms 15000 --max-mb 512
```

Each run creates:

```text
LibPeConvCorpus-<timestamp>.json
LibPeConvCorpus-<timestamp>.csv
LibPeConvCorpus-<timestamp>.log
```

Each PE is processed in a separate worker process. A crash or timeout is recorded without stopping the complete corpus run.

## Compare with NativePe

Run NativePe and libpeconv against the same corpus and preferably the same explicit file list. Keep both JSON reports.

Then run:

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File .\Compare-NativePe.ps1 ^
  -NativePeJson "E:\Results\NativePeCorpus.json" ^
  -LibPeConvJson "E:\Results\LibPeConvCorpus.json" ^
  -OutputDir ".\results\comparison"
```

The comparison creates:

```text
NativePe-vs-libpeconv-<timestamp>.csv
NativePe-vs-libpeconv-<timestamp>.log
```

A reported difference is something to investigate. It does not automatically mean that either implementation is wrong.

## NativePe libpeconv fixtures

To run the pinned NativePe libpeconv fixtures through both implementations:

```bat
run-libpeconv-fixtures.bat "E:\Projects\NativePe"
```

Optional result directory and NativePe build configuration:

```bat
run-libpeconv-fixtures.bat "E:\Projects\NativePe" "E:\Results\libpeconv-fixtures" Release
```

The script verifies the fixture hashes, runs both corpus workers and invokes `Compare-NativePe.ps1`.

## Process dump reference tool

Run against the main module of a process:

```bat
run-processdump.bat 1234
```

Or dump a specific module:

```bat
build\Release\LibPeConvProcessDump.exe --pid 1234 --module kernel32.dll --out "kernel32-dump.bin"
```

The supplied build is x64. Use an x64 target process when module enumeration is required.

## Scope

The corpus reports cover the PE properties used by the NativePe differential tests, including headers, architecture, image base, entry point, sections, mapping, imports, delay imports, exports, TLS, resources, relocations, exception data, LoadConfig, security cookie information, .NET detection and virtual-to-raw conversion.
