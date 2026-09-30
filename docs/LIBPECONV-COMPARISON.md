# NativePe and libpeconv Comparison

libpeconv is both an upstream source basis for much of NativePe's PE-processing core and the pinned behavioral reference used by the differential harness. The comparison is therefore a port-fidelity, regression, robustness, and divergence check; it is not independent cross-validation between unrelated implementations.

See [PROVENANCE.md](PROVENANCE.md) for the source-level relationship.

## Reference revision

The differential harness is pinned to:

- Project: `hasherezade/libpeconv`
- Commit: `0fc25f680e03699d33ef3b2034a6724365f3d1a4`

The comparison below records one corpus run from September 25, 2026. It describes observed behavior for that run only.

## Run summary

Both harnesses processed the same 30,159 relative paths. At outcome level, 30,147 paths matched and 12 differed.

| Comparison | Paths |
| --- | ---: |
| PASS / PASS | 25,769 |
| REJECT / REJECT | 1,089 |
| FAIL / FAIL | 8 |
| SKIP / SKIP | 3,281 |
| NativePe PASS / libpeconv REJECT | 6 |
| NativePe PASS / libpeconv CRASH | 4 |
| NativePe REJECT / libpeconv CRASH | 2 |

NativePe recorded no worker crash in this run. The libpeconv harness recorded six worker crashes with process exit code `3221225477`, which is Windows status `0xC0000005` (access violation). This is a result for these inputs and this harness configuration, not a general statement about libpeconv.

## Outcome mismatches

The 12 mismatching paths are duplicated Corkami samples present under both `bintests-master\misc\corkami` and `pocs-master`. They represent six sample names.

| Sample | NativePe | libpeconv | Observed libpeconv stage or message |
| --- | --- | --- | --- |
| `lfanew_relocW7.exe` | REJECT | CRASH | worker terminated during TLS processing |
| `tinyW7.exe` | PASS | CRASH | worker terminated during TLS processing |
| `tinyW7x64.exe` | PASS | CRASH | worker terminated during TLS processing |
| `no_dd.exe` | PASS | REJECT | import directory reported malformed |
| `tinynet.exe` | PASS | REJECT | relocation directory reported malformed |
| `tinyW7_3264.exe` | PASS | REJECT | delay imports, exceptions, resources, relocations, and roundtrip diagnostics reported malformed or unavailable |

These mismatches are candidates for deterministic regression fixtures. A PASS/REJECT difference can reflect a validation-policy difference and does not automatically identify a defect.

## Shared FAIL results

Both harnesses reported FAIL for the same eight paths. Each pair reported the same section and first differing raw offset during RAW roundtrip comparison. The message strings differ only because libpeconv prints the offset with additional leading hexadecimal zeroes.

This shows that the port and the pinned upstream reference locate the same roundtrip byte differences in those eight cases.

## PASS/PASS semantic differences

Fifteen paths had structured field differences while both harnesses returned PASS.

Fourteen paths are seven Corkami samples duplicated under two corpus roots:

- `ibrelocW7.exe`
- `mini.exe`
- `nosectionW7.exe`
- `nothing.dll`
- `pdf.exe`
- `pdf_zip_pe.exe`
- `tinydll.dll`

For these paths NativePe reported `roundTripChecked=true` and `roundTripEqual=true`, while the libpeconv harness reported the roundtrip comparison as unavailable because the original layout was unavailable during comparison. This is primarily a harness/roundtrip-availability difference and is not evidence of a parser disagreement by itself.

## TLS callback case requiring manual validation

One PASS/PASS path has a substantive TLS callback enumeration difference:

`intewild\Virussign.2026.09.15\virussign.com_e5d134bada8ed31c0b5b1a7bd44e2961.vir`

| Field | NativePe | libpeconv |
| --- | ---: | ---: |
| `tlsCallbacks` | 0 | 104,811 |
| `tlsCallbacksValid` | 0 | 44 |
| `tlsCallbacksInvalid` | 0 | 104,767 |
| `tlsCallbackTruncated` | false | true |
| `tlsCallbackFirstValidRva` | empty | `0x0000B848` |
| `tlsCallbackLastValidRva` | empty | `0x0000F024` |

The reports alone do not establish which interpretation is correct. The sample should be checked manually against `IMAGE_TLS_DIRECTORY`, `AddressOfCallBacks`, VA-to-RVA normalization, mapped-image bounds, and callback termination. The resulting case should be converted into a deterministic fixture if redistribution and licensing permit it; otherwise an equivalent synthetic fixture should be created.

## Performance

No performance conclusion is recorded from this run. The NativePe input is a Win64 Debug report, and the libpeconv report was not marked as optimized. The corpus harness documentation requires optimized comparable runs for benchmark use.

A performance comparison should use the same explicit manifest, optimized Win64 Release builds, identical schema/timing boundaries, warmup, alternating execution order, and repeated rounds.

## Scope and limitations

The corpus comparison is intended to find concrete behavioral differences between NativePe and the pinned upstream implementation. It does not establish general superiority, complete PE compatibility, or correctness for every malformed input. Differences should be reduced to deterministic fixtures and checked against PE format rules and the intended NativePe validation policy before code changes are made.
