# Features

NativePe is split into small Object Pascal units. Applications can use only the parts they need.

## PE parsing and layout

NativePe provides helpers for:

- DOS and NT header validation
- PE32 and PE32+ optional headers
- section tables
- data directories
- entry point and image base handling
- RAW and virtual layout detection
- RAW to virtual mapping
- virtual to RAW reconstruction
- base relocation processing

Relevant units include `NativePe.Types`, `NativePe.PeHdrsHelper`, `NativePe.PeModeDetector`, `NativePe.PeRawToVirtual`, `NativePe.PeVirtualToRaw`, and `NativePe.Relocate`.

## Imports and exports

The library supports:

- normal import resolution
- delay-load import resolution
- custom function resolvers
- export lookup by name and ordinal
- export mapping across modules
- import reconstruction helpers
- import repair helpers

Relevant units include `NativePe.FunctionResolver`, `NativePe.ImportsLoader`, `NativePe.DelayedImports`, `NativePe.ExportsLookup`, `NativePe.ExportsMapper`, `NativePe.ImportsUneraser`, and `NativePe.FixImports`.

## Loader related functionality

NativePe includes:

- manual PE loading
- PEB based module lookup
- optional main module registration in the PEB
- TLS parsing and callback handling
- exception directory handling
- Load Config parsing
- optional API Set resolution
- optional security cookie initialization

Relevant units include `NativePe.PeLoader`, `NativePe.PebLookup`, `NativePe.TlsParser`, `NativePe.ExceptionsParser`, `NativePe.LoadConfig`, `NativePe.ApiSet`, and `NativePe.SecurityCookie`.

## Resources and .NET helpers

The library includes resource directory parsing and a helper for .NET entry point handling.

Relevant units include `NativePe.ResourceUtil`, `NativePe.ResourceParser`, and `NativePe.DotNetEpFixer`.

## Remote process and dumping support

NativePe can read mapped PE images from another process and reconstruct PE files from memory.

Relevant units include `NativePe.RemotePeReader` and `NativePe.PeDumper`.

The repository also contains `NativePeProcessDump.exe` as a practical process dump tool.

## Hooking and patching

`NativePe.Hooks` provides import redirection and local code patching helpers. Patch backup and restore support is included, together with optional thread suspension for patch operations.

`NativePe.Lde` provides the instruction length decoding used to avoid splitting instructions when a local patch is created.

## Memory providers

`NativePe.MemoryProvider` separates selected memory operations from the PE algorithms that use them.

Built-in backends:

- WinAPI through `TWinApiMemoryProvider`
- NTAPI through `TNtApiMemoryProvider`
- direct Win64 syscalls through `TSyscallMemoryProvider`

The default hook backend keeps the existing NTDLL based protection path and the optional `UseSyscalls` compatibility switch.

See [MEMORY-PROVIDERS.md](MEMORY-PROVIDERS.md).

## PE recycling helpers

`NativePe.Caves` and `NativePe.PeRecycler` contain helpers for finding suitable code caves and modifying PE images while preserving a valid PE layout where possible.

## Scope

NativePe is a research library, not a replacement for the Windows loader and not a guarantee that every valid or malformed PE will be handled correctly.
