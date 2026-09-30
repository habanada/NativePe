{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.HookMemoryProvider;

interface

uses
  Winapi.Windows,
  NativePe.MemoryProvider;

type
  TDefaultHookMemoryProvider = class(TWinApiMemoryProvider)
  public
    function ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD; OldProtect: PDWORD;
      out ErrorCode: DWORD): Boolean; override;
  end;

function GetDefaultHookMemoryProvider: TNativePeMemoryProvider;

implementation

uses
  NativePe.PebLookup,
  NativePe.ExportsLookup,
  NativePe.Syscall;

type
  TNtProtectVirtualMemory = function(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
    NewProtect: DWORD; OldProtect: PDWORD): LongInt; stdcall;

var
  GDefaultHookMemoryProvider: TDefaultHookMemoryProvider;

function TDefaultHookMemoryProvider.ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
  OldProtect: PDWORD; out ErrorCode: DWORD): Boolean;
var
  Proc: FARPROC;
  NtProtectVirtualMemory: TNtProtectVirtualMemory;
  Status: LongInt;
  ProtectSize: NativeUInt;
  BaseAddress: Pointer;
begin
  ErrorCode := ERROR_SUCCESS;
  Result := False;
{$IFDEF WIN64}
  if UseSyscalls then
  begin
    Result := DirectNtProtect(Address, Size, NewProtect, OldProtect);
    if not Result then
      ErrorCode := ERROR_GEN_FAILURE;
    Exit;
  end;
{$ENDIF}
  Proc := GetExportedFunc(Pointer(GetModuleViaPeb(PWideChar('ntdll.dll'))), 'NtProtectVirtualMemory');
  if not Assigned(Proc) then
  begin
    ErrorCode := ERROR_PROC_NOT_FOUND;
    Exit;
  end;
  NtProtectVirtualMemory := TNtProtectVirtualMemory(Proc);
  ProtectSize := Size;
  BaseAddress := Address;
  Status := NtProtectVirtualMemory(GetCurrentProcess, BaseAddress, ProtectSize, NewProtect, OldProtect);
  Result := Status = 0;
  if not Result then
    ErrorCode := ERROR_GEN_FAILURE;
end;

function GetDefaultHookMemoryProvider: TNativePeMemoryProvider;
begin
  Result := GDefaultHookMemoryProvider;
end;

initialization
  GDefaultHookMemoryProvider := TDefaultHookMemoryProvider.Create;

finalization
  GDefaultHookMemoryProvider.Free;
  GDefaultHookMemoryProvider := nil;

end.
