# Third-Party Notices

This file records source provenance and third-party license notices used by NativePe.

## libpeconv

- Project: https://github.com/hasherezade/libpeconv
- Author: hasherezade
- License: BSD 2-Clause License
- Copyright (c) 2017-2026, hasherezade
- Pinned reference commit: `0fc25f680e03699d33ef3b2034a6724365f3d1a4`

NativePe's core PE implementation is a source-level Object Pascal port/reimplementation of libpeconv. It is not a clean-room or independently designed implementation of that core.

At the pinned revision, libpeconv lists 29 C++ source modules for its PE library. The current NativePe tree contains direct Object Pascal counterparts for all 29 of those modules. Representative core paths such as PE loading, RAW-to-virtual mapping, virtual-to-RAW reconstruction, relocations, imports, exports, resources, dumping, TLS handling, and related helpers retain the same operation split and closely follow the upstream control flow. Some paths preserve upstream diagnostic text and source comments as well.

NativePe also changes upstream behavior where required for bounded parsing, validation, Delphi integration, or project-specific policy, and it contains additional functionality with no direct libpeconv source-module counterpart. See `docs/PROVENANCE.md` for the detailed mapping.

The libpeconv-derived portions are redistributed subject to the BSD 2-Clause terms below. NativePe's original additions are released under the repository MIT license; the MIT license does not remove the upstream BSD notice and redistribution conditions from libpeconv-derived material.

```
BSD 2-Clause License

Copyright (c) 2017-2026, hasherezade
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

## hde64

- Project: Hacker Disassembler Engine 64 (hde64)
- Author: Vyacheslav Patkov
- License: BSD 2-Clause License
- Copyright (c) 2008-2009, Vyacheslav Patkov

`src/NativePe.Lde.pas` contains a direct Object Pascal port of hde64's instruction-length table and the core table-driven decoding algorithm used for instruction length calculation. NativePe adds its own result structure and integration around that port and intentionally omits hde64 validation paths that do not affect the computed instruction length.

The hde64-derived portion remains subject to the BSD 2-Clause notice and conditions below. NativePe-specific additions around it are released under the repository MIT license.

```
Copyright (c) 2008-2009, Vyacheslav Patkov.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```
