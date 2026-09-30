# libpeconv -> NativePe DUnitX fidelity matrix

`libpeconv-master-TESTS.rar` is the reference oracle for this layer.
The matrix distinguishes exact fixture fidelity from behavioral equivalents. A test is not called exact unless the original binary, byte array, RVA, ordinal, or expected value from the libpeconv reference material is used directly.

## Fidelity levels

- `EXACT FIXTURE`: the original file from the libpeconv test archive is packaged unchanged and verified by SHA-256 before the DUnitX run.
- `EXACT BYTES`: the expected byte array is copied from the original libpeconv source and compared byte-for-byte.
- `DIRECT PORT`: the same input values and success condition are used against the NativePe API.
- `SOURCE-FAITHFUL SYNTHETIC`: the compiled original fixture is absent from the archive, so the source-level contract is reproduced with a deterministic NativePe fixture.
- `OPT-IN`: executing the original payload or mutating process-wide state is intentionally separated from the ordinary CI-safe suite.

## Original fixture identity

| file | exact size | SHA-256 |
|---|---:|---|
| `greek_to_me.bin` | 2048 | `a3eb21f603efb6731d3493be3427a33982a427f1b630214136531aba1746e540` |
| `payload.dll` | 105984 | `2fbca35e033a0bd34b43ebbbb023bb98e6ac4063f9bb7800dd0f45b8bfe9a3e0` |
| `test_case3_32.exe` | 181248 | `fe71c9d21eaa67f9aad31df6ca60e5c6c99f77494ac7c15b9963ba954983c459` |
| `test_case3_64.exe` | 215040 | `8994981a704ff7647470080798142fa44a89049ce67706f6bd73ad10ae8c38cf` |
| `shellc32.bin` from `shellc32.h` | 1080 | `8a36e3d8fad5933d5877f962296f3970fb9304355f643dd6caa7c5579da0ce98` |
| `shellc64.bin` from `shellc64.h` | 1536 | `6c1ca77e7f94ad5e83b4515be597a7ef166ccce38905ae230e059a995adc6d15` |

`scripts\verify-libpeconv-fixtures.bat` checks all six hashes before `NativePeDUnitX.exe` is launched.

## Exact oracle coverage

| libpeconv reference | NativePe DUnitX coverage | Fidelity |
|---|---|---|
| `shellc32.h` | `Shellcode32MatchesOriginalHeaderByteForByte` compares all 1080 bytes | EXACT BYTES |
| `shellc64.h` | `Shellcode64MatchesOriginalHeaderByteForByte` compares all 1536 bytes | EXACT BYTES |
| `test_fix_dotnet.cpp` | jump pattern `FF 25 00 20 40 00`, image base `$400000`, thunk `$2000`, offsets start/end/end-30 | DIRECT PORT + EXACT BYTES |
| `test_crackme_f4_3.cpp` / `greek_to_me.bin` | exact PE32 header, section table, import/IAT directories, WS2_32 ordinal list, bytes at RVA `$107C` and checksum function RVA `$11E6` | EXACT FIXTURE + EXACT BYTES |
| `test_crackme_f4_6.cpp` / `payload.dll` | exact PE64 header, seven sections, export `EntryPoint` at `$5C00`, only KERNEL32/USER32 imports, exact machine-code prefixes at `$4710`, `$5C00`, `$5D30`, `$664C`, `$6824`, `$78D4`, `$7900` | EXACT FIXTURE + EXACT BYTES |
| `test_replacing_func.cpp` / `test_case3_32.exe` | exact PE header/sections, call bytes at `$2A4C`, checksum bytes at `$2AB0`, and verification that CALL rel32 targets `$2AB0` | EXACT FIXTURE + EXACT BYTES |
| `test_replacing_func.cpp` / `test_case3_64.exe` | exact PE header/sections and checksum-function bytes at `$2B10` | EXACT FIXTURE + EXACT BYTES |
| `test_loading.cpp` | self RAW -> virtual -> RAW and `memcmp`-equivalent comparison | DIRECT PORT |
| `test_loading_imps.cpp` | `LoadPeExecutable` maps, relocates and resolves name+ordinal imports in one deterministic synthetic image; entry point execution remains in isolated RealWorld coverage | SOURCE-FAITHFUL SYNTHETIC / OPT-IN split |
| `test_imp_list.cpp` | self import collection is non-empty/in-bounds plus exact synthetic name+ordinal import metadata | DIRECT PORT / SOURCE-FAITHFUL SYNTHETIC |
| `test_format_detect.cpp` | raw file must be RAW; mapped image must be virtual | DIRECT PORT |
| `test_found_base.cpp` | found base must equal mapped base | DIRECT PORT |
| `test_peb_lookup.cpp` | self/ntdll/kernel32/user32/advapi32/ws2_32 address and image-size parity plus missing module | DIRECT PORT |
| `test_load_ntdll.cpp` | real ntdll mapping and export-RVA parity are in ordinary suite; original MessageBox shellcode execution is not | DIRECT PORT / OPT-IN split |
| `test_hooking_local.cpp` | resolver and patch/restore behavior use deterministic executable memory rather than patching real process APIs | SOURCE-FAITHFUL SYNTHETIC |
| `test_hooking_imps.cpp` | synthetic IAT is actually patched through `THookingFuncResolver` | SOURCE-FAITHFUL SYNTHETIC |
| `test_delayed_imps.cpp` | name+ordinal delayed imports and exact IAT writes | SOURCE-FAITHFUL SYNTHETIC |
| `test_imports_mix.cpp` | normal and delayed imports resolved together in one image | SOURCE-FAITHFUL SYNTHETIC |
| `test_tls_callbacks.cpp` | real executable synthetic TLS callbacks with observable side effects; one-callback and two-callback order/list coverage | SOURCE-FAITHFUL SYNTHETIC |
| `test_exceptions.cpp` | excluded from ordinary runner because it mutates process-wide exception metadata | OPT-IN |

## Original values retained for future opt-in execution tests

These are recorded from the libpeconv tests and are not silently replaced with easier values:

- `greek_to_me.bin`: data RVA `$107C`, checksum RVA `$11E6`, buffer length `$79`, transform `(xor xor byte) + $22`, expected checksum `$FB5E`, expected brute-force byte `$A2`.
- `test_case3_32.exe`: call RVA `$2A4C`, original checksum RVA `$2AB0`, `calc_checksum("my_test_password", true) = $9E5619E7`, replacement return `$1F561E6A`.
- `test_case3_64.exe`: replacement target RVA `$2B10`, replacement return `$1F561E6A`.
- Flare-On-6 `payload.dll`: expected flag `wuuut-exp0rts@flare-on.com`, modifying function `$5D30`, `srand` `$7900`, `rand` `$78D4`, index function `$4710`, CRT init `$664C`, CRT uninit `$6824`.
- `test_case5` source oracle: exported checksum results `$F96316C1`, `$EC0C46D5`, `$90C9026E`, `$67F58277`, `$C29CC69E`; total `$A0CAA919`.
- `test_case6` TLS source oracle: two TLS callbacks construct `NR7YcqGFUn0`.

The archive does not contain compiled `test_case5` or `test_case6` binaries, so tests for those binaries cannot honestly be labelled exact-fixture tests until matching binaries are available or rebuilt with the matching toolchain.

## CorpusDiff reuse of original PE fixtures

The four original PE fixtures `greek_to_me.bin`, `payload.dll`, `test_case3_32.exe`, and `test_case3_64.exe` are also intended for direct NativePe-versus-libpeconv CorpusDiff runs. `LibPeConvCorpusDif2f\run-libpeconv-fixtures.bat` verifies the fixture hashes, stages exactly those four PEs under an allowed corpus root, runs both corpus workers against the same file list, and invokes the semantic comparison report. The shellcode `.bin` fixtures stay in the DUnitX byte-oracle layer because they are not PE images.

The ordinary DUnitX suite now contains 272 `[Test]` methods. The TLS fidelity layer includes a two-callback executable synthetic case matching the `test_case6` source contract that two TLS callbacks exist, without claiming exact binary fidelity for the unavailable compiled fixture.

## NativePe robustness beyond the upstream test set

The dedicated robustness layer adds 46 deterministic tests beyond the direct libpeconv fidelity cases. It covers malformed `.pdata` bounds, section-layout asymmetries and overlaps, multi-root resource traversal, export holes and malformed name ordinals/forwarders, malformed header/table boundaries, and PE32/PE32+ semantic roundtrips. These tests use libpeconv behavior as a reference where it defines a useful contract, but malformed-input expectations prefer bounded, controlled rejection over reproducing unsafe or ambiguous upstream behavior.

## CI safety boundary

The ordinary DUnitX runner parses, maps and patches isolated allocated test buffers, but it does not automatically execute the reference payloads, display shellcode MessageBoxes, or modify Windows' process-wide exception tables. Those operations need a separate opt-in integration executable so a crash or global side effect cannot invalidate the rest of the regression report.
