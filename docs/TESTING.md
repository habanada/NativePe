# Testing

NativePe uses DUnitX tests, controlled real-world tests, and a corpus runner. Each layer covers different failure modes and execution conditions.

## DUnitX

The main DUnitX project is `tests\dunitx\NativePeDUnitX.dproj`.

The suite covers:

- core PE parsing and loading behavior
- malformed input and regression cases
- Windows integration
- WinAPI and NTAPI memory providers
- the Win64 direct syscall memory provider
- libpeconv fidelity and reference behavior

libpeconv-specific cases are classified in `tests\dunitx\LIBPECONV-TEST-MATRIX.md`.

## Real-world tests

`tests\realworld\NativePeRealWorld.groupproj` contains controlled integration projects for manual loading, exception handling, PE recycling, and process dumping.

These tests are separate from DUnitX where they require process-wide state, executable mappings, or child processes.

See [REALWORLD-TESTS.md](REALWORLD-TESTS.md) for the covered scenarios.

## Corpus testing

The corpus project is `tests\corpus\NativePeCorpusTest.dproj`.

`NativePeCorpusTest.exe` processes each input file in a separate worker process. For recognized PE files it performs bounded parsing, mapping, directory inspection, and virtual to RAW reconstruction without intentionally executing PE entry points or TLS callbacks.

A worker crash or timeout does not stop the complete corpus run. The runner writes log, CSV, and JSON reports.

Detailed corpus behavior and report formats are documented in [the corpus harness README](../tests/corpus/README.md).

See [CORPUS-RESULTS.md](CORPUS-RESULTS.md) for the corpus sources and recorded differential result set.

## libpeconv comparison

NativePe's PE-processing core is an Object Pascal port/reimplementation of libpeconv's core. libpeconv is therefore used as an upstream behavioral reference for fidelity, regression, and differential testing rather than as an independent implementation.

Recorded differential results are kept in [CORPUS-RESULTS.md](CORPUS-RESULTS.md). See [PROVENANCE.md](PROVENANCE.md) and [LIBPECONV-COMPARISON.md](LIBPECONV-COMPARISON.md) for the source relationship and documented differences.

## Limits

Passing the current tests does not prove complete PE compatibility. New compiler versions, Windows versions, unusual linkers, packers, malformed files, and hostile files can expose additional cases.
