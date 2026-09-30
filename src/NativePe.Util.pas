{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/util.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.Util;

interface

uses
  Winapi.Windows;

function IsPadding(CavePtr: PByte; CaveSize: NativeUInt; PaddingChar: Byte): Boolean;
function GetProcessIdOf(HProcess: THandle): DWORD;
function IsMemAccessible(AreaStart: Pointer; AreaSize: NativeUInt; AccessRights: DWORD): Boolean;
function IsBadReadPointer(AreaStart: Pointer; AreaSize: NativeUInt): Boolean;
function IsValidStringA(ModulePtr: Pointer; ModuleSize: NativeUInt; NamePtr: PAnsiChar; MaxLen: NativeUInt = 260): Boolean;
function IsValidStringW(ModulePtr: Pointer; ModuleSize: NativeUInt; NamePtr: PWideChar; MaxLen: NativeUInt = 260): Boolean;

implementation

uses
  NativePe.BufferUtil;

type
  TProcessBasicInfoLocal = record
    Reserved1: Pointer;
    PebBaseAddress: Pointer;
    Reserved2: array [0 .. 1] of Pointer;
    UniqueProcessId: NativeUInt;
    Reserved3: Pointer;
  end;

function NtQueryInformationProcess(ProcessHandle: THandle; ProcessInformationClass: DWORD;
  ProcessInformation: Pointer; ProcessInformationLength: DWORD; ReturnLength: PDWORD): LongInt; stdcall;
  external 'ntdll.dll';

function NtdllGetProcessId(HProcess: THandle): DWORD;
var
  Pbi: TProcessBasicInfoLocal;
  Status: LongInt;
begin
  Result := 0;
  FillChar(Pbi, SizeOf(Pbi), 0);
  Status := NtQueryInformationProcess(HProcess, 0, @Pbi, SizeOf(Pbi), nil);
  if Status >= 0 then
    Result := DWORD(Pbi.UniqueProcessId);
end;

function GetProcessIdOf(HProcess: THandle): DWORD;
begin
  Result := Winapi.Windows.GetProcessId(HProcess);
  if Result = 0 then
    Result := NtdllGetProcessId(HProcess);
end;

function IsPadding(CavePtr: PByte; CaveSize: NativeUInt; PaddingChar: Byte): Boolean;
var
  I: NativeUInt;
begin
  I := 0;
  while I < CaveSize do
  begin
    if CavePtr[I] <> PaddingChar then
      Exit(False);
    Inc(I);
  end;
  Result := True;
end;

function IsMemAccessible(AreaStart: Pointer; AreaSize: NativeUInt; AccessRights: DWORD): Boolean;
const
  ForbiddenArea = PAGE_GUARD or PAGE_NOACCESS;
var
  Mbi: TMemoryBasicInformation;
  SizeToCheck: NativeUInt;
  AreaPtr: Pointer;
  Offset, QueriedSize: NativeUInt;
  IsOk: Boolean;
begin
  if AreaSize = 0 then
    Exit(False);

  SizeToCheck := AreaSize;
  AreaPtr := AreaStart;

  while SizeToCheck > 0 do
  begin
    FillChar(Mbi, SizeOf(Mbi), 0);
    if VirtualQuery(AreaPtr, Mbi, SizeOf(Mbi)) <> SizeOf(Mbi) then
      Exit(False);

    IsOk := (Mbi.State and MEM_COMMIT <> 0) and (Mbi.Protect and ForbiddenArea = 0) and
      (Mbi.Protect and AccessRights <> 0);
    if not IsOk then
      Exit(False);

    Offset := NativeUInt(AreaPtr) - NativeUInt(Mbi.BaseAddress);
    QueriedSize := Mbi.RegionSize - Offset;
    if QueriedSize >= SizeToCheck then
      Exit(True);

    Dec(SizeToCheck, QueriedSize);
    AreaPtr := Pointer(NativeUInt(AreaPtr) + QueriedSize);
  end;
  Result := False;
end;

function IsBadReadPointer(AreaStart: Pointer; AreaSize: NativeUInt): Boolean;
const
  ReadableMask = PAGE_READONLY or PAGE_READWRITE or PAGE_WRITECOPY or
    PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
begin
  Result := not IsMemAccessible(AreaStart, AreaSize, ReadableMask);
end;

function IsValidStringA(ModulePtr: Pointer; ModuleSize: NativeUInt; NamePtr: PAnsiChar; MaxLen: NativeUInt): Boolean;
var
  I: NativeUInt;
  IsTerminated: Boolean;
begin
  IsTerminated := False;
  I := 0;
  while I < MaxLen do
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, @NamePtr[I], SizeOf(AnsiChar)) then
      Exit(False);
    if NamePtr[I] = #0 then
    begin
      IsTerminated := True;
      Break;
    end;
    Inc(I);
  end;
  Result := IsTerminated and (I <> 0);
end;

function IsValidStringW(ModulePtr: Pointer; ModuleSize: NativeUInt; NamePtr: PWideChar; MaxLen: NativeUInt): Boolean;
var
  I: NativeUInt;
  IsTerminated: Boolean;
begin
  IsTerminated := False;
  I := 0;
  while I < MaxLen do
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, @NamePtr[I], SizeOf(WideChar)) then
      Exit(False);
    if NamePtr[I] = #0 then
    begin
      IsTerminated := True;
      Break;
    end;
    Inc(I);
  end;
  Result := IsTerminated and (I <> 0);
end;

end.
