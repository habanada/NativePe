{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/peb_lookup.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PebLookup;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function GetModuleViaPeb(ModuleName: PWideChar = nil): HMODULE;
function GetModuleSizeViaPeb(HModule: HMODULE = 0): NativeUInt;
function SetMainModuleInPeb(HModule: HMODULE): Boolean;
function GetMainModuleViaPeb: HMODULE;
function GetCurrentPeb: PPeb;

implementation

const
  ProcessBasicInformation = 0;

function NtQueryInformationProcess(ProcessHandle: THandle; ProcessInformationClass: DWORD;
  ProcessInformation: Pointer; ProcessInformationLength: DWORD; ReturnLength: PDWORD): LongInt; stdcall;
  external 'ntdll.dll';

function GetPeb: PPeb;
var
  Pbi: TProcessBasicInformation;
  Status: LongInt;
begin
  Result := nil;
  FillChar(Pbi, SizeOf(Pbi), 0);
  Status := NtQueryInformationProcess(GetCurrentProcess, ProcessBasicInformation, @Pbi, SizeOf(Pbi), nil);
  if Status < 0 then
    Exit;
  Result := Pbi.PebBaseAddress;
end;

function ToLowerWide(C: WideChar): WideChar;
begin
  if (C >= 'A') and (C <= 'Z') then
    Result := WideChar(Ord(C) - Ord('A') + Ord('a'))
  else
    Result := C;
end;

function IsWantedModule(CurrName, WantedName: PWideChar): Boolean;
var
  CurrEndPtr, WantedEndPtr: PWideChar;
begin
  Result := False;
  if (WantedName = nil) or (CurrName = nil) then
    Exit;

  CurrEndPtr := CurrName;
  while CurrEndPtr^ <> #0 do
    Inc(CurrEndPtr);
  if CurrEndPtr = CurrName then
    Exit;

  WantedEndPtr := WantedName;
  while WantedEndPtr^ <> #0 do
    Inc(WantedEndPtr);
  if WantedEndPtr = WantedName then
    Exit;

  Dec(CurrEndPtr);
  Dec(WantedEndPtr);
  while True do
  begin
    if ToLowerWide(CurrEndPtr^) <> ToLowerWide(WantedEndPtr^) then
      Exit(False);
    if WantedEndPtr = WantedName then
      Break;
    if CurrEndPtr = CurrName then
      Exit(False);
    Dec(CurrEndPtr);
    Dec(WantedEndPtr);
  end;
  if CurrEndPtr = CurrName then
    Exit(True);
  Dec(CurrEndPtr);
  Result := (CurrEndPtr^ = '\') or (CurrEndPtr^ = '/');
end;

function GetModuleViaPeb(ModuleName: PWideChar): HMODULE;
var
  Peb: PPeb;
  FirstModule, CurrModule: PLdrDataTableEntry;
begin
  Result := 0;
  Peb := GetPeb;
  if Peb = nil then
    Exit;
  EnterCriticalSection(Peb.LoaderLock^);
  try
    FirstModule := PLdrDataTableEntry(Peb.Ldr.InLoadOrderModuleList.Flink);
    CurrModule := FirstModule;
    if ModuleName = nil then
    begin
      Result := HMODULE(CurrModule.DllBase);
      Exit;
    end;

    repeat
      if (CurrModule = nil) or (CurrModule.DllBase = nil) then
        Break;
      if IsWantedModule(CurrModule.BaseDllName.Buffer, ModuleName) then
      begin
        Result := HMODULE(CurrModule.DllBase);
        Exit;
      end;
      CurrModule := PLdrDataTableEntry(CurrModule.InLoadOrderLinks.Flink);
    until CurrModule = FirstModule;
    Result := 0;
  finally
    LeaveCriticalSection(Peb.LoaderLock^);
  end;
end;

function GetModuleSizeViaPeb(HModule: HMODULE): NativeUInt;
var
  Peb: PPeb;
  FirstModule, CurrModule: PLdrDataTableEntry;
begin
  Result := 0;
  Peb := GetPeb;
  if Peb = nil then
    Exit;
  EnterCriticalSection(Peb.LoaderLock^);
  try
    FirstModule := PLdrDataTableEntry(Peb.Ldr.InLoadOrderModuleList.Flink);
    CurrModule := FirstModule;
    if HModule = 0 then
    begin
      Result := CurrModule.SizeOfImage;
      Exit;
    end;

    repeat
      if (CurrModule = nil) or (CurrModule.DllBase = nil) then
        Break;
      if HModule = Winapi.Windows.HMODULE(CurrModule.DllBase) then
      begin
        Result := CurrModule.SizeOfImage;
        Exit;
      end;
      CurrModule := PLdrDataTableEntry(CurrModule.InLoadOrderLinks.Flink);
    until CurrModule = FirstModule;
    Result := 0;
  finally
    LeaveCriticalSection(Peb.LoaderLock^);
  end;
end;

function SetMainModuleInPeb(HModule: HMODULE): Boolean;
var
  Peb: PPeb;
begin
  Result := False;
  Peb := GetPeb;
  if Peb = nil then
    Exit;
  EnterCriticalSection(Peb.FastPebLock^);
  try
    Peb.ImageBaseAddress := Pointer(HModule);
    Result := True;
  finally
    LeaveCriticalSection(Peb.FastPebLock^);
  end;
end;

function GetMainModuleViaPeb: HMODULE;
var
  Peb: PPeb;
begin
  Result := 0;
  Peb := GetPeb;
  if Peb = nil then
    Exit;
  EnterCriticalSection(Peb.FastPebLock^);
  try
    Result := HMODULE(Peb.ImageBaseAddress);
  finally
    LeaveCriticalSection(Peb.FastPebLock^);
  end;
end;

function GetCurrentPeb: PPeb;
begin
  Result := GetPeb;
end;

end.
