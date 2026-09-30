{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/resource_util.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ResourceUtil;

interface

uses
  Winapi.Windows,
  NativePe.BufferUtil;

const
  RT_RCDATA_A: PAnsiChar = PAnsiChar(10);

function LoadResourceData(var OutSize: NativeUInt; ResId: Integer; ResType: PAnsiChar = nil;
  HInstance: HMODULE = 0): TAlignedBuf;
procedure FreeResourceData(Buffer: TAlignedBuf);
function GetCurrentModuleHandle: HMODULE;

implementation

uses
  NativePe.Logger;

const
  GMH_EX_UNCHANGED_REFCOUNT = $00000002;
  GMH_EX_FROM_ADDRESS = $00000004;

function NativeGetModuleHandleExW(dwFlags: DWORD; lpModuleName: PWideChar; var phModule: HMODULE): BOOL; stdcall;
  external 'kernel32.dll' name 'GetModuleHandleExW';

function GetCurrentModuleHandle: HMODULE;
begin
  Result := 0;
  NativeGetModuleHandleExW(GMH_EX_FROM_ADDRESS or GMH_EX_UNCHANGED_REFCOUNT,
    PWideChar(@GetCurrentModuleHandle), Result);
end;

function LoadResourceData(var OutSize: NativeUInt; ResId: Integer; ResType: PAnsiChar; HInstance: HMODULE): TAlignedBuf;
var
  Res: HRSRC;
  ResHandle: HGLOBAL;
  ResData: PByte;
  RSize: NativeUInt;
  OutBuf: TAlignedBuf;
begin
  Result := nil;
  if ResType = nil then
    ResType := RT_RCDATA_A;
  if HInstance = 0 then
    HInstance := GetModuleHandleA(nil);
  Res := FindResourceA(HInstance, PAnsiChar(NativeUInt(ResId)), ResType);
  if Res = 0 then
  begin
    LogError('Cannot find resource.');
    Exit;
  end;
  ResHandle := LoadResource(HInstance, Res);
  if ResHandle = 0 then
  begin
    LogError('Cannot get resource handle.');
    Exit;
  end;
  ResData := PByte(LockResource(ResHandle));
  RSize := SizeofResource(HInstance, Res);
  if (OutSize <> 0) and (OutSize <= RSize) then
    RSize := OutSize;

  OutBuf := AllocAligned(RSize, PAGE_READWRITE);
  if OutBuf <> nil then
  begin
    Move(ResData^, OutBuf^, RSize);
    OutSize := RSize;
  end
  else
    OutSize := 0;
  FreeResource(ResHandle);
  Result := OutBuf;
end;

procedure FreeResourceData(Buffer: TAlignedBuf);
begin
  FreeAligned(Buffer);
end;

end.
