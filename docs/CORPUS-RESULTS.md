# Corpus Results

This file records the differential corpus snapshot analyzed on September 25, 2026. It is a result record, not a claim of complete PE compatibility.

## Inputs

NativePe report:

`NativePeCorpus-20260925-083917-179`

libpeconv report:

`LibPeConvCorpus-20260925-084847-502`

Both reports contained the same 30,159 relative corpus paths. There were no NativePe-only or libpeconv-only paths.

The NativePe report came from `Win64\Debug`. The libpeconv report identifies schema version 6 and was not marked as optimized. Timing values from this run are therefore diagnostic only and are not used as a performance benchmark.

## Corpus sources

The development corpus used files from several public and local sources:

- local Windows `System32` files
- local Windows `SysWOW64` files
- corkami pocs: https://github.com/corkami/pocs
- aftermathlabs bintests: https://github.com/aftermathlabs/bintests
- CubicleSoft php-winpefile: https://github.com/cubiclesoft/php-winpefile
- Windows PE Artifact Library: https://github.com/cubiclesoft/windows-pe-artifact-library
- selected samples from VX-Underground: https://vx-underground.org/Samples/
- project-specific malformed and synthetic PE fixtures

The external corpora are not distributed with NativePe. They can be obtained from the original projects and used as input for the NativePe corpus runner.

VX-Underground files were used only as test inputs. They are not distributed with NativePe and should only be handled in an appropriate isolated research environment.

The exact contents of a newly assembled corpus can differ from this September 25, 2026 snapshot because local Windows files and external repositories may change over time.

## Outcome totals

| Outcome | NativePe | libpeconv |
| --- | ---: | ---: |
| PASS | 25,779 | 25,769 |
| REJECT | 1,091 | 1,095 |
| FAIL | 8 | 8 |
| CRASH | 0 | 6 |
| SKIP | 3,281 | 3,281 |
| Total | 30,159 | 30,159 |

## Outcome matrix

| NativePe | libpeconv | Paths |
| --- | --- | ---: |
| PASS | PASS | 25,769 |
| REJECT | REJECT | 1,089 |
| FAIL | FAIL | 8 |
| SKIP | SKIP | 3,281 |
| PASS | REJECT | 6 |
| PASS | CRASH | 4 |
| REJECT | CRASH | 2 |

The two harnesses therefore reported the same outcome for 30,147 of 30,159 paths. The remaining 12 paths require case-by-case interpretation; an outcome mismatch does not by itself establish which implementation is correct.

## Field-level comparison

Across all outcomes, 43 paths had at least one structured field difference and 288 individual field values differed. These counts include consequences of earlier outcome differences, roundtrip availability differences, and one notable TLS callback enumeration difference. They must not be interpreted as 288 independent parser defects.

Among the 25,769 PASS/PASS paths, 15 paths had structured differences:

- 14 paths were seven duplicated Corkami samples where NativePe completed the RAW roundtrip comparison and the libpeconv harness reported the roundtrip comparison as unavailable.
- 1 path had a TLS callback enumeration difference and is documented in [LIBPECONV-COMPARISON.md](LIBPECONV-COMPARISON.md).

## Shared hard failures

Both harnesses reported FAIL for the same eight paths. In all eight cases the reported first differing section/raw offset matched; the message text differed only in hexadecimal zero padding.

## Interpretation

This snapshot is useful for regression tracking and differential validation against the pinned upstream implementation. Because NativePe's core is a port/reimplementation of libpeconv, this result must not be described as independent cross-validation between unrelated PE libraries.

The remaining differences still matter: they identify places where NativePe has diverged from the pinned upstream behavior through validation policy, robustness changes, implementation changes, or harness behavior.

See [PROVENANCE.md](PROVENANCE.md) for the source relationship and [LIBPECONV-COMPARISON.md](LIBPECONV-COMPARISON.md) for the concrete mismatches.
