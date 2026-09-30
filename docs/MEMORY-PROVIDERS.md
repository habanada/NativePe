# Memory Providers

NativePe uses `TNativePeMemoryProvider` to separate PE logic from selected operating system memory operations.

This keeps callers source compatible while allowing a different backend to be supplied where needed.

## Provider contract

The provider covers the memory operations currently required by NativePe:

- local allocation
- local free
- process memory query
- process memory read
- process memory protection
- local memory protection
- instruction cache flush

## WinAPI backend

`TWinApiMemoryProvider` is the normal WinAPI implementation.

It uses the same Windows memory APIs that NativePe used before the provider layer was introduced. Existing overloads continue to use this behavior by default.

Use `GetWinApiMemoryProvider` when a provider instance is required explicitly.

## NTAPI backend

`TNtApiMemoryProvider` implements the same contract through NTDLL Native API functions:

- `NtAllocateVirtualMemory`
- `NtFreeVirtualMemory`
- `NtQueryVirtualMemory`
- `NtReadVirtualMemory`
- `NtProtectVirtualMemory`
- `NtFlushInstructionCache`

NTSTATUS failures are converted to Win32 error codes before leaving the provider.

Use `GetNtApiMemoryProvider` with provider-aware overloads to select the NTAPI backend explicitly.

## Direct syscall backend

`TSyscallMemoryProvider` implements the same contract with direct Win64 system calls for the memory operations used by NativePe.

It uses the existing SSN resolver in `NativePe.Syscall` and creates each syscall stub only when that operation is first used. The stub bootstrap keeps the same PEB/export lookup and executable stub allocation approach as the earlier direct `NtProtectVirtualMemory` path.

The provider supports:

- `NtAllocateVirtualMemory`
- `NtFreeVirtualMemory`
- `NtQueryVirtualMemory`
- `NtReadVirtualMemory`
- `NtProtectVirtualMemory`
- `NtFlushInstructionCache`

Use `GetSyscallMemoryProvider` with provider-aware overloads to select it explicitly. The provider is Win64-only. On Win32 its operations return `ERROR_NOT_SUPPORTED`.

The `UseSyscalls` flag is not required when this provider is selected explicitly. That flag remains for compatibility with the default hook backend.

## Hook memory backend

`NativePe.HookMemoryProvider` keeps the established hook protection behavior separate from the general WinAPI provider.

Normal mode resolves `NtProtectVirtualMemory` through NTDLL. On Win64, the existing optional direct syscall protection path can still be selected through `NativePe.Syscall.UseSyscalls`.

## Custom backends

A custom backend can derive from `TNativePeMemoryProvider` and implement the complete contract.

A backend can also derive from `TWinApiMemoryProvider` when only selected operations need different behavior.

NativePe does not install custom providers globally. A custom provider is passed explicitly to provider-aware operations, which avoids changing unrelated callers or threads.
