{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.MemoryProvider;

interface

uses
  Winapi.Windows;

type
  TNativePeMemoryProvider = class abstract
  public
    function AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType, Protect: DWORD;
      out ErrorCode: DWORD): Pointer; virtual; abstract;
    function FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD; out ErrorCode: DWORD): Boolean; virtual; abstract;
    function QueryProcess(ProcessHandle: THandle; Address: Pointer; out MemoryInfo: TMemoryBasicInformation;
      out ErrorCode: DWORD): Boolean; virtual; abstract;
    function ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
      out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean; virtual; abstract;
    function ProtectProcess(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
      out OldProtect: DWORD; out ErrorCode: DWORD): Boolean; virtual; abstract;
    function ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD; OldProtect: PDWORD;
      out ErrorCode: DWORD): Boolean; virtual; abstract;
    function FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt;
      out ErrorCode: DWORD): Boolean; virtual; abstract;
  end;

  TWinApiMemoryProvider = class(TNativePeMemoryProvider)
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

function GetWinApiMemoryProvider: TNativePeMemoryProvider;

implementation

var
  GWinApiMemoryProvider: TWinApiMemoryProvider;

function TWinApiMemoryProvider.AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType,
  Protect: DWORD; out ErrorCode: DWORD): Pointer;
begin
  ErrorCode := ERROR_SUCCESS;
  Result := VirtualAlloc(DesiredBase, Size, AllocationType, Protect);
  if Result = nil then
    ErrorCode := GetLastError;
end;

function TWinApiMemoryProvider.FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD;
  out ErrorCode: DWORD): Boolean;
begin
  ErrorCode := ERROR_SUCCESS;
  Result := VirtualFree(BaseAddress, Size, FreeType);
  if not Result then
    ErrorCode := GetLastError;
end;

function TWinApiMemoryProvider.QueryProcess(ProcessHandle: THandle; Address: Pointer;
  out MemoryInfo: TMemoryBasicInformation; out ErrorCode: DWORD): Boolean;
var
  Res: NativeUInt;
begin
  ErrorCode := ERROR_SUCCESS;
  FillChar(MemoryInfo, SizeOf(MemoryInfo), 0);
  Res := VirtualQueryEx(ProcessHandle, Address, MemoryInfo, SizeOf(MemoryInfo));
  Result := Res = NativeUInt(SizeOf(MemoryInfo));
  if not Result then
    ErrorCode := GetLastError;
end;

function TWinApiMemoryProvider.ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
  out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean;
begin
  ErrorCode := ERROR_SUCCESS;
  BytesRead := 0;
  Result := ReadProcessMemory(ProcessHandle, Address, Buffer, Size, BytesRead);
  if not Result then
    ErrorCode := GetLastError;
end;

function TWinApiMemoryProvider.ProtectProcess(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt;
  NewProtect: DWORD; out OldProtect: DWORD; out ErrorCode: DWORD): Boolean;
begin
  ErrorCode := ERROR_SUCCESS;
  OldProtect := 0;
  Result := VirtualProtectEx(ProcessHandle, Address, Size, NewProtect, OldProtect);
  if not Result then
    ErrorCode := GetLastError;
end;

function TWinApiMemoryProvider.ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
  OldProtect: PDWORD; out ErrorCode: DWORD): Boolean;
begin
  ErrorCode := ERROR_SUCCESS;
  if OldProtect = nil then
  begin
    ErrorCode := ERROR_INVALID_PARAMETER;
    Exit(False);
  end;
  Result := VirtualProtect(Address, Size, NewProtect, OldProtect^);
  if not Result then
    ErrorCode := GetLastError;
end;

function TWinApiMemoryProvider.FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer;
  Size: NativeUInt; out ErrorCode: DWORD): Boolean;
begin
  ErrorCode := ERROR_SUCCESS;
  Result := Winapi.Windows.FlushInstructionCache(ProcessHandle, Address, Size);
  if not Result then
    ErrorCode := GetLastError;
end;

function GetWinApiMemoryProvider: TNativePeMemoryProvider;
begin
  Result := GWinApiMemoryProvider;
end;

initialization
  GWinApiMemoryProvider := TWinApiMemoryProvider.Create;

finalization
  GWinApiMemoryProvider.Free;
  GWinApiMemoryProvider := nil;

end.
