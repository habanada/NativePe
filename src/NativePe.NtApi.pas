{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.NtApi;

interface

uses
  Winapi.Windows;

const
  NTDLL_NAME = 'ntdll.dll';
  NT_MEMORY_BASIC_INFORMATION = 0;

type
  TNtStatus = LongInt;

function NtSuccess(Status: TNtStatus): Boolean; inline;
function NtStatusToWin32Error(Status: TNtStatus): DWORD;
function NtCurrentProcess: THandle; inline;

function NtAllocateVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; ZeroBits: NativeUInt;
  var RegionSize: NativeUInt; AllocationType, Protect: DWORD): TNtStatus; stdcall; external NTDLL_NAME;
function NtFreeVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
  FreeType: DWORD): TNtStatus; stdcall; external NTDLL_NAME;
function NtReadVirtualMemory(ProcessHandle: THandle; BaseAddress, Buffer: Pointer; BufferSize: NativeUInt;
  NumberOfBytesRead: PNativeUInt): TNtStatus; stdcall; external NTDLL_NAME;
function NtProtectVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
  NewProtect: DWORD; out OldProtect: DWORD): TNtStatus; stdcall; external NTDLL_NAME;
function NtQueryVirtualMemory(ProcessHandle: THandle; BaseAddress: Pointer; MemoryInformationClass: DWORD;
  MemoryInformation: Pointer; MemoryInformationLength: NativeUInt; ReturnLength: PNativeUInt): TNtStatus; stdcall;
  external NTDLL_NAME;
function NtFlushInstructionCache(ProcessHandle: THandle; BaseAddress: Pointer; Length: NativeUInt): TNtStatus; stdcall;
  external NTDLL_NAME;
function RtlNtStatusToDosError(Status: TNtStatus): DWORD; stdcall; external NTDLL_NAME;

implementation

function NtSuccess(Status: TNtStatus): Boolean;
begin
  Result := Status >= 0;
end;

function NtStatusToWin32Error(Status: TNtStatus): DWORD;
begin
  if NtSuccess(Status) then
    Exit(ERROR_SUCCESS);
  Result := RtlNtStatusToDosError(Status);
end;

function NtCurrentProcess: THandle;
begin
  Result := THandle(NativeInt(-1));
end;

end.
