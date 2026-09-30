# Source Provenance

This document describes the source-level relationship between NativePe and libpeconv based on the current NativePe source tree and the pinned libpeconv revision used by the differential harness.

## Classification

NativePe's PE-processing core is a Delphi/Object Pascal port and reimplementation of libpeconv's core library.

It is not accurately described as:

- a clean-room implementation
- an independently designed implementation of the same PE functionality
- a project that was only inspired by libpeconv at a high level

It is also not a literal text conversion of C++ syntax into Pascal. The source was rewritten for Object Pascal and contains additional checks, changed policies, Delphi-specific types and classes, and NativePe-specific functionality. The correct description is a source-informed port/reimplementation with extensions and deliberate divergences.

## Pinned upstream revision

The current differential harness pins libpeconv to:

- Project: `hasherezade/libpeconv`
- Commit: `0fc25f680e03699d33ef3b2034a6724365f3d1a4`

At this revision, libpeconv's `libpeconv/CMakeLists.txt` lists 29 core C++ source modules. NativePe contains a direct Object Pascal counterpart for every one of them.

## One-to-one core module mapping

| libpeconv source | NativePe unit |
| --- | --- |
| `pe_hdrs_helper.cpp` | `NativePe.PeHdrsHelper.pas` |
| `pe_mode_detector.cpp` | `NativePe.PeModeDetector.pas` |
| `pe_raw_to_virtual.cpp` | `NativePe.PeRawToVirtual.pas` |
| `pe_virtual_to_raw.cpp` | `NativePe.PeVirtualToRaw.pas` |
| `relocate.cpp` | `NativePe.Relocate.pas` |
| `buffer_util.cpp` | `NativePe.BufferUtil.pas` |
| `remote_pe_reader.cpp` | `NativePe.RemotePeReader.pas` |
| `imports_loader.cpp` | `NativePe.ImportsLoader.pas` |
| `delayed_imports_loader.cpp` | `NativePe.DelayedImports.pas` |
| `fix_imports.cpp` | `NativePe.FixImports.pas` |
| `pe_loader.cpp` | `NativePe.PeLoader.pas` |
| `pe_dumper.cpp` | `NativePe.PeDumper.pas` |
| `exports_lookup.cpp` | `NativePe.ExportsLookup.pas` |
| `function_resolver.cpp` | `NativePe.FunctionResolver.pas` |
| `hooks.cpp` | `NativePe.Hooks.pas` |
| `exported_func.cpp` | `NativePe.ExportedFunc.pas` |
| `exports_mapper.cpp` | `NativePe.ExportsMapper.pas` |
| `resource_parser.cpp` | `NativePe.ResourceParser.pas` |
| `file_util.cpp` | `NativePe.FileUtil.pas` |
| `resource_util.cpp` | `NativePe.ResourceUtil.pas` |
| `imports_uneraser.cpp` | `NativePe.ImportsUneraser.pas` |
| `load_config_util.cpp` | `NativePe.LoadConfig.pas` |
| `caves.cpp` | `NativePe.Caves.pas` |
| `util.cpp` | `NativePe.Util.pas` |
| `fix_dot_net_ep.cpp` | `NativePe.DotNetEpFixer.pas` |
| `find_base.cpp` | `NativePe.FindBase.pas` |
| `peb_lookup.cpp` | `NativePe.PebLookup.pas` |
| `tls_parser.cpp` | `NativePe.TlsParser.pas` |
| `exceptions_parser.cpp` | `NativePe.ExceptionsParser.pas` |

The mapping is not only a similarity of filenames. Representative source review shows the same internal operation split and closely matching control flow.

For example, `NativePe.PeLoader.LoadPeModule` follows libpeconv `load_pe_module` through the same sequence: validate NT headers, handle sectionless images, force the preferred base when relocation is requested but no relocation table exists, map RAW data to a virtual image, relocate it, free the image on relocation failure, and return the mapped image. Several comments and diagnostics in this path are preserved from the upstream source.

The RAW/virtual conversion, relocation, import, export, resource, and dumping paths show the same source-level relationship. Pascal syntax and types differ, but the algorithms and operation ordering are recognizably ported from the corresponding libpeconv implementation.

## NativePe-specific code and divergences

The current NativePe tree contains additional units and behavior beyond the one-to-one libpeconv core mapping. Examples include:

- `NativePe.ApiSet`
- `NativePe.HookMemoryProvider`
- `NativePe.MemoryProvider`
- `NativePe.NtApi`
- `NativePe.NtMemoryProvider`
- `NativePe.PeRecycler`
- `NativePe.SecurityCookie`
- `NativePe.Syscall`
- `NativePe.SyscallMemoryProvider`

`NativePe.Logger` and `NativePe.Types` are NativePe-side infrastructure rather than one-to-one `.cpp` ports. `NativePe.Lde` is separately derived from hde64 and is documented in `THIRD-PARTY-NOTICES.md`.

NativePe also deliberately differs from the pinned libpeconv behavior in several core paths. Examples visible in the current tree include stricter or safer malformed-input handling, additional bounds checks, configurable import-directory validation, exception registration, security-cookie initialization, and bounded TLS processing.

These changes make the current NativePe implementation behaviorally distinct from libpeconv, but they do not make the libpeconv-derived core independently designed.

## Tests and differential harness

The DUnitX suite explicitly contains exact libpeconv fixtures, exact byte oracles, direct behavioral ports, and source-faithful synthetic cases. This is fidelity and regression testing against the upstream source behavior.

The corpus harness compares NativePe with the pinned libpeconv revision on the same input set. Because libpeconv is the source basis for much of NativePe's core, this differential run is not independent cross-validation in the clean-room sense. Its purpose is to detect regressions, deliberate policy differences, robustness differences, and places where the Pascal port has diverged from the pinned C++ reference.

## Short description

For public documentation, the technically accurate short description is:

`NativePe is an Object Pascal port/reimplementation of libpeconv's PE-processing core, extended with additional Delphi- and Windows-specific functionality.`
