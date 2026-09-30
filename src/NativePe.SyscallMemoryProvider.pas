{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.SyscallMemoryProvider;

interface

uses
  Winapi.Windows,
  NativePe.MemoryProvider;

type
  TSyscallMemoryProvider = class(TNativePeMemoryProvider)
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

function GetSyscallMemoryProvider: TNativePeMemoryProvider;

implementation

{$IFDEF WIN64}
uses
  NativePe.Syscall,
  NativePe.PebLookup,
  NativePe.ExportsLookup;
{$ENDIF}

var
  GSyscallMemoryProvider: TSyscallMemoryProvider;

{$IFDEF WIN64}
type
  TRtlNtStatusToDosError = function(Status: LongInt): DWORD; stdcall;

function CurrentProcessHandle: THandle; inline;
begin
  Result := THandle(NativeInt(-1));
end;

function StatusToWin32Error(Status: LongInt): DWORD;
var
  NtdllBase: HMODULE;
  Proc: FARPROC;
  ConvertStatus: TRtlNtStatusToDosError;
begin
  if Status >= 0 then
    Exit(ERROR_SUCCESS);
  NtdllBase := GetModuleViaPeb(PWideChar('ntdll.dll'));
  if NtdllBase = 0 then
    Exit(ERROR_GEN_FAILURE);
  Proc := GetExportedFunc(Pointer(NtdllBase), 'RtlNtStatusToDosError');
  if not Assigned(Proc) then
    Exit(ERROR_GEN_FAILURE);
  ConvertStatus := TRtlNtStatusToDosError(Proc);
  Result := ConvertStatus(Status);
end;
{$ENDIF}

function TSyscallMemoryProvider.AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType, Protect: DWORD;
  out ErrorCode: DWORD): Pointer;
{$IFDEF WIN64}
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
  Status: LongInt;
{$ENDIF}
begin
{$IFDEF WIN64}
  BaseAddress := DesiredBase;
  RegionSize := Size;
  Status := DirectNtAllocateVirtualMemory(CurrentProcessHandle, BaseAddress, 0, RegionSize, AllocationType, Protect);
  ErrorCode := StatusToWin32Error(Status);
  if Status < 0 then
    Exit(nil);
  Result := BaseAddress;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := nil;
{$ENDIF}
end;

function TSyscallMemoryProvider.FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD;
  out ErrorCode: DWORD): Boolean;
{$IFDEF WIN64}
var
  Address: Pointer;
  RegionSize: NativeUInt;
  Status: LongInt;
{$ENDIF}
begin
{$IFDEF WIN64}
  Address := BaseAddress;
  RegionSize := Size;
  Status := DirectNtFreeVirtualMemory(CurrentProcessHandle, Address, RegionSize, FreeType);
  ErrorCode := StatusToWin32Error(Status);
  Result := Status >= 0;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := False;
{$ENDIF}
end;

function TSyscallMemoryProvider.QueryProcess(ProcessHandle: THandle; Address: Pointer;
  out MemoryInfo: TMemoryBasicInformation; out ErrorCode: DWORD): Boolean;
{$IFDEF WIN64}
var
  ReturnLength: NativeUInt;
  Status: LongInt;
{$ENDIF}
begin
  FillChar(MemoryInfo, SizeOf(MemoryInfo), 0);
{$IFDEF WIN64}
  ReturnLength := 0;
  Status := DirectNtQueryVirtualMemory(ProcessHandle, Address, 0, @MemoryInfo,
    SizeOf(MemoryInfo), @ReturnLength);
  ErrorCode := StatusToWin32Error(Status);
  Result := Status >= 0;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := False;
{$ENDIF}
end;

function TSyscallMemoryProvider.ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
  out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean;
{$IFDEF WIN64}
var
  Status: LongInt;
{$ENDIF}
begin
  BytesRead := 0;
{$IFDEF WIN64}
  Status := DirectNtReadVirtualMemory(ProcessHandle, Address, Buffer, Size, @BytesRead);
  ErrorCode := StatusToWin32Error(Status);
  Result := Status >= 0;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := False;
{$ENDIF}
end;

function TSyscallMemoryProvider.ProtectProcess(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt;
  NewProtect: DWORD; out OldProtect: DWORD; out ErrorCode: DWORD): Boolean;
{$IFDEF WIN64}
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
  Status: LongInt;
{$ENDIF}
begin
  OldProtect := 0;
{$IFDEF WIN64}
  BaseAddress := Address;
  RegionSize := Size;
  Status := DirectNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, @OldProtect);
  ErrorCode := StatusToWin32Error(Status);
  Result := Status >= 0;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := False;
{$ENDIF}
end;

function TSyscallMemoryProvider.ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
  OldProtect: PDWORD; out ErrorCode: DWORD): Boolean;
{$IFDEF WIN64}
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
  PreviousProtect: DWORD;
  Status: LongInt;
{$ENDIF}
begin
  if OldProtect = nil then
  begin
    ErrorCode := ERROR_INVALID_PARAMETER;
    Exit(False);
  end;
{$IFDEF WIN64}
  BaseAddress := Address;
  RegionSize := Size;
  PreviousProtect := 0;
  Status := DirectNtProtectVirtualMemory(CurrentProcessHandle, BaseAddress, RegionSize, NewProtect, @PreviousProtect);
  ErrorCode := StatusToWin32Error(Status);
  Result := Status >= 0;
  if Result then
    OldProtect^ := PreviousProtect;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := False;
{$ENDIF}
end;

function TSyscallMemoryProvider.FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer;
  Size: NativeUInt; out ErrorCode: DWORD): Boolean;
{$IFDEF WIN64}
var
  Status: LongInt;
{$ENDIF}
begin
{$IFDEF WIN64}
  Status := DirectNtFlushInstructionCache(ProcessHandle, Address, Size);
  ErrorCode := StatusToWin32Error(Status);
  Result := Status >= 0;
{$ELSE}
  ErrorCode := ERROR_NOT_SUPPORTED;
  Result := False;
{$ENDIF}
end;

function GetSyscallMemoryProvider: TNativePeMemoryProvider;
begin
  Result := GSyscallMemoryProvider;
end;

initialization
  GSyscallMemoryProvider := TSyscallMemoryProvider.Create;

finalization
  GSyscallMemoryProvider.Free;
  GSyscallMemoryProvider := nil;

end.
