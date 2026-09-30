# Documentation

NativePe keeps the root README short and stores detailed technical material in this directory.

## Project documentation

- [PROVENANCE.md](PROVENANCE.md) - source-level relationship to libpeconv and NativePe-specific extensions
- [FEATURES.md](FEATURES.md) - implemented PE and Windows functionality
- [MEMORY-PROVIDERS.md](MEMORY-PROVIDERS.md) - WinAPI, NTAPI, and Win64 syscall memory providers
- [TESTING.md](TESTING.md) - test layers, corpus scope, and testing limitations
- [REALWORLD-TESTS.md](REALWORLD-TESTS.md) - controlled Windows loader, exception, recycler, and process-dump tests
- [BINARIES.md](BINARIES.md) - binaries, launchers, and command line usage
- [CORPUS-RESULTS.md](CORPUS-RESULTS.md) - recorded corpus result snapshot
- [LIBPECONV-COMPARISON.md](LIBPECONV-COMPARISON.md) - differential comparison with the pinned libpeconv upstream reference
- [../THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) - source attribution and third-party licenses

## Component documentation

Detailed harness-specific instructions remain next to the corresponding source:

- [../tests/corpus/README.md](../tests/corpus/README.md) - NativePe corpus harness schema and timing model
- [../tests/dunitx/README.md](../tests/dunitx/README.md) - DUnitX suite and libpeconv fidelity fixtures
- [../tools/LibPeConvCorpusDiff/README.md](../tools/LibPeConvCorpusDiff/README.md) - libpeconv corpus differential harness
