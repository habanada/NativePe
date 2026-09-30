{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.NtMemoryProvider;

interface

uses
  Winapi.Windows,
  NativePe.MemoryProvider;

type
  TNtApiMemoryProvider = class(TNativePeMemoryProvider)
  public
    function AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType, Protect: DWORD;
      out ErrorCode: DWORD): Pointer; override;
    function FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD; out ErrorCode: DWORD): Boolean; override;
    function QueryProcess(ProcessHandle: THandle; Address: Pointer; out MemoryInfo: TMemoryBasicInformation;
      out ErrorCode: DWORD): Boolean; override;
    function ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
      out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean; override;
    function ProtectProcess(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
      out OldProtect: DWORD; out ErrorCode: DWORD): Boolean; override;
    function ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD; OldProtect: PDWORD;
      out ErrorCode: DWORD): Boolean; override;
    function FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt;
      out ErrorCode: DWORD): Boolean; override;
  end;

function GetNtApiMemoryProvider: TNativePeMemoryProvider;

implementation

uses
  NativePe.NtApi;

var
  GNtApiMemoryProvider: TNtApiMemoryProvider;

function TNtApiMemoryProvider.AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType, Protect: DWORD;
  out ErrorCode: DWORD): Pointer;
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
  Status: TNtStatus;
begin
  BaseAddress := DesiredBase;
  RegionSize := Size;
  Status := NtAllocateVirtualMemory(NtCurrentProcess, BaseAddress, 0, RegionSize, AllocationType, Protect);
  ErrorCode := NtStatusToWin32Error(Status);
  if not NtSuccess(Status) then
    Exit(nil);
  Result := BaseAddress;
end;

function TNtApiMemoryProvider.FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD;
  out ErrorCode: DWORD): Boolean;
var
  Address: Pointer;
  RegionSize: NativeUInt;
  Status: TNtStatus;
begin
  Address := BaseAddress;
  RegionSize := Size;
  Status := NtFreeVirtualMemory(NtCurrentProcess, Address, RegionSize, FreeType);
  ErrorCode := NtStatusToWin32Error(Status);
  Result := NtSuccess(Status);
end;

function TNtApiMemoryProvider.QueryProcess(ProcessHandle: THandle; Address: Pointer;
  out MemoryInfo: TMemoryBasicInformation; out ErrorCode: DWORD): Boolean;
var
  ReturnLength: NativeUInt;
  Status: TNtStatus;
begin
  FillChar(MemoryInfo, SizeOf(MemoryInfo), 0);
  ReturnLength := 0;
  Status := NtQueryVirtualMemory(ProcessHandle, Address, NT_MEMORY_BASIC_INFORMATION, @MemoryInfo, SizeOf(MemoryInfo),
    @ReturnLength);
  ErrorCode := NtStatusToWin32Error(Status);
  Result := NtSuccess(Status);
end;

function TNtApiMemoryProvider.ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
  out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean;
var
  Status: TNtStatus;
begin
  BytesRead := 0;
  Status := NtReadVirtualMemory(ProcessHandle, Address, Buffer, Size, @BytesRead);
  ErrorCode := NtStatusToWin32Error(Status);
  Result := NtSuccess(Status);
end;

function TNtApiMemoryProvider.ProtectProcess(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt;
  NewProtect: DWORD; out OldProtect: DWORD; out ErrorCode: DWORD): Boolean;
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
  Status: TNtStatus;
begin
  BaseAddress := Address;
  RegionSize := Size;
  OldProtect := 0;
  Status := NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
  ErrorCode := NtStatusToWin32Error(Status);
  Result := NtSuccess(Status);
end;

function TNtApiMemoryProvider.ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
  OldProtect: PDWORD; out ErrorCode: DWORD): Boolean;
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
  PreviousProtect: DWORD;
  Status: TNtStatus;
begin
  if OldProtect = nil then
  begin
    ErrorCode := ERROR_INVALID_PARAMETER;
    Exit(False);
  end;
  BaseAddress := Address;
  RegionSize := Size;
  PreviousProtect := 0;
  Status := NtProtectVirtualMemory(NtCurrentProcess, BaseAddress, RegionSize, NewProtect, PreviousProtect);
  ErrorCode := NtStatusToWin32Error(Status);
  Result := NtSuccess(Status);
  if Result then
    OldProtect^ := PreviousProtect;
end;

function TNtApiMemoryProvider.FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer;
  Size: NativeUInt; out ErrorCode: DWORD): Boolean;
var
  Status: TNtStatus;
begin
  Status := NtFlushInstructionCache(ProcessHandle, Address, Size);
  ErrorCode := NtStatusToWin32Error(Status);
  Result := NtSuccess(Status);
end;

function GetNtApiMemoryProvider: TNativePeMemoryProvider;
begin
  Result := GNtApiMemoryProvider;
end;

initialization
  GNtApiMemoryProvider := TNtApiMemoryProvider.Create;

finalization
  GNtApiMemoryProvider.Free;
  GNtApiMemoryProvider := nil;

end.
