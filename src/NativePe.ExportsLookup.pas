{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/exports_lookup.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ExportsLookup;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.Types,
  NativePe.FunctionResolver;

function GetExportedFunc(ModulePtr: Pointer; WantedName: PAnsiChar): FARPROC;
function GetExportedNames(ModulePtr: Pointer; NamesList: TList<string>): NativeUInt;
function ReadDllName(ModulePtr: Pointer): PAnsiChar;

type
  TExportBasedResolver = class(TDefaultFuncResolver)
  public
    function ResolveFunc(LibName, FuncName: PAnsiChar): FARPROC; override;
  end;

implementation

uses
  System.SysUtils,
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.ExportedFunc,
  NativePe.Logger;

function ToLowerAnsi(C: AnsiChar): AnsiChar;
begin
  if (C >= 'A') and (C <= 'Z') then
    Result := AnsiChar(Ord(C) - Ord('A') + Ord('a'))
  else
    Result := C;
end;

function IsWantedFunc(CurrName, WantedName: PAnsiChar): Boolean;
var
  WantedLen, CurrLen, I: NativeUInt;
  C1, C2: AnsiChar;
begin
  Result := False;
  if (CurrName = nil) or (WantedName = nil) then
    Exit;
  WantedLen := StrLen(WantedName);
  CurrLen := StrLen(CurrName);
  if CurrLen <> WantedLen then
    Exit;
  I := 0;
  while I < WantedLen do
  begin
    C1 := ToLowerAnsi(CurrName[I]);
    C2 := ToLowerAnsi(WantedName[I]);
    if C1 <> C2 then
      Exit(False);
    Inc(I);
  end;
  Result := True;
end;

function IsOrdinalPtr(Exp: PImageExportDirectory; FuncName: PAnsiChar): Boolean;
var
  Base, MaxOrd, NamePtrVal: UInt64;
begin
  Base := Exp.Base;
  MaxOrd := Base + Exp.NumberOfFunctions;
  NamePtrVal := UInt64(NativeUInt(FuncName));
  Result := (NamePtrVal >= Base) and (NamePtrVal < MaxOrd);
end;

function IsForwarderRva(ModulePtr: PByte; Rva: DWORD): Boolean;
var
  Dir: PImageDataDirectory;
  EndRva: UInt64;
begin
  Result := False;
  Dir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if Dir = nil then
    Exit;
  EndRva := UInt64(Dir.VirtualAddress) + UInt64(Dir.Size);
  Result := (Rva >= Dir.VirtualAddress) and (UInt64(Rva) < EndRva);
end;

function GetExportByOrd(ModulePtr: Pointer; Exp: PImageExportDirectory; WantedOrdinal: DWORD): FARPROC;
var
  FunctCount: NativeUInt;
  FuncsListRva, OrdBase: DWORD;
  ModSize: NativeUInt;
  I: DWORD;
  Ordinal: DWORD;
  FuncRva: PDWORD;
  FPtr: PByte;
begin
  Result := nil;
  FunctCount := Exp.NumberOfFunctions;
  FuncsListRva := Exp.AddressOfFunctions;
  OrdBase := Exp.Base;
  ModSize := GetImageSize(PByte(ModulePtr));
  I := 0;
  while I < FunctCount do
  begin
    Ordinal := OrdBase + I;
    if Ordinal = WantedOrdinal then
    begin
      FuncRva := PDWORD(NativeUInt(FuncsListRva) + NativeUInt(ModulePtr) + NativeUInt(I) * SizeOf(DWORD));
      if not ValidatePtr(ModulePtr, ModSize, FuncRva, SizeOf(DWORD)) then
      begin
        LogError('Invalid RVA of exported function');
        Exit(nil);
      end;
      if FuncRva^ = 0 then
        Exit(nil);
      FPtr := PByte(ModulePtr) + FuncRva^;
      if not ValidatePtr(ModulePtr, ModSize, FPtr, 1) then
      begin
        LogError('Invalid pointer to exported function');
        Exit(nil);
      end;
      if IsForwarderRva(PByte(ModulePtr), FuncRva^) then
      begin
        if not IsValidStringA(ModulePtr, ModSize, PAnsiChar(FPtr)) or (ForwarderNameLen(PAnsiChar(FPtr)) <= 1) then
        begin
          LogError('Invalid forwarded function.');
          Exit(nil);
        end;
        LogWarning('Forwarded function: [%u -> 0x%x] cannot be resolved.', [WantedOrdinal, NativeUInt(FPtr)]);
        Exit(nil);
      end;
      Exit(FARPROC(FPtr));
    end;
    Inc(I);
  end;
end;

function GetExportedNames(ModulePtr: Pointer; NamesList: TList<string>): NativeUInt;
var
  ModSize: NativeUInt;
  Exp: PImageExportDirectory;
  NamesCount: NativeUInt;
  FuncNamesListRva: DWORD;
  NameRva: DWORD;
  NameRvaPtr: PDWORD;
  NamePtr: PAnsiChar;
  I: NativeUInt;
begin
  Result := 0;
  ModSize := GetImageSize(PByte(ModulePtr));
  if ModSize = 0 then
    Exit;
  Exp := GetExportDirectory(ModulePtr);
  if (Exp = nil) or (not ValidatePtr(ModulePtr, ModSize, Exp, SizeOf(TImageExportDirectory))) then
    Exit;
  NamesCount := Exp.NumberOfNames;
  FuncNamesListRva := Exp.AddressOfNames;
  I := 0;
  while I < NamesCount do
  begin
    NameRvaPtr := PDWORD(NativeUInt(FuncNamesListRva) + NativeUInt(ModulePtr) + I * SizeOf(DWORD));
    if not ValidatePtr(ModulePtr, ModSize, NameRvaPtr, SizeOf(DWORD)) then
      Break;
    NameRva := NameRvaPtr^;
    if NameRva = 0 then
    begin
      Inc(I);
      Continue;
    end;
    NamePtr := PAnsiChar(NativeUInt(NameRva) + NativeUInt(ModulePtr));
    if not IsValidStringA(ModulePtr, ModSize, NamePtr) then
      Break;
    NamesList.Add(string(AnsiString(NamePtr)));
    Inc(I);
  end;
  Result := I;
end;

function GetExportedFunc(ModulePtr: Pointer; WantedName: PAnsiChar): FARPROC;
var
  ModSize: NativeUInt;
  Exp: PImageExportDirectory;
  NamesCount: NativeUInt;
  FuncsListRva, FuncNamesListRva, NamesOrdsListRva: DWORD;
  I: NativeUInt;
  NameRvaPtr: PDWORD;
  NameIndexPtr: PWord;
  FuncRvaPtr: PDWORD;
  NamePtr: PAnsiChar;
  FPtr: PByte;
  WantedOrdinal: DWORD;
begin
  Result := nil;
  ModSize := GetImageSize(PByte(ModulePtr));
  if ModSize = 0 then
    Exit;
  Exp := GetExportDirectory(ModulePtr);
  if (Exp = nil) or (not ValidatePtr(ModulePtr, ModSize, Exp, SizeOf(TImageExportDirectory))) then
    Exit;

  NamesCount := Exp.NumberOfNames;
  FuncsListRva := Exp.AddressOfFunctions;
  FuncNamesListRva := Exp.AddressOfNames;
  NamesOrdsListRva := Exp.AddressOfNameOrdinals;

  if IsOrdinalPtr(Exp, WantedName) then
  begin
    LogDebug('Getting function by ordinal.');
    WantedOrdinal := MaskToDword(NativeUInt(WantedName));
    Exit(GetExportByOrd(ModulePtr, Exp, WantedOrdinal));
  end;
  if IsBadReadPointer(WantedName, 1) then
  begin
    LogError('Invalid pointer to the name.');
    Exit(nil);
  end;
  I := 0;
  while I < NamesCount do
  begin
    NameRvaPtr := PDWORD(NativeUInt(FuncNamesListRva) + NativeUInt(ModulePtr) + I * SizeOf(DWORD));
    NameIndexPtr := PWord(NativeUInt(NamesOrdsListRva) + NativeUInt(ModulePtr) + I * SizeOf(Word));
    if (not ValidatePtr(ModulePtr, ModSize, NameRvaPtr, SizeOf(DWORD))) or
      (not ValidatePtr(ModulePtr, ModSize, NameIndexPtr, SizeOf(Word))) then
    begin
      LogError('Invalid pointer to exported name RVA or index');
      Exit(nil);
    end;
    if NameIndexPtr^ >= Exp.NumberOfFunctions then
    begin
      LogError('Invalid exported function index');
      Exit(nil);
    end;
    FuncRvaPtr := PDWORD(NativeUInt(FuncsListRva) + NativeUInt(ModulePtr) + NativeUInt(NameIndexPtr^) * SizeOf(DWORD));
    if not ValidatePtr(ModulePtr, ModSize, FuncRvaPtr, SizeOf(DWORD)) then
    begin
      LogError('Invalid pointer to exported function RVA');
      Exit(nil);
    end;
    NamePtr := PAnsiChar(NativeUInt(NameRvaPtr^) + NativeUInt(ModulePtr));
    if not IsValidStringA(ModulePtr, ModSize, NamePtr) then
    begin
      LogError('Invalid pointer to exported function name');
      Exit(nil);
    end;
    if not IsWantedFunc(NamePtr, WantedName) then
    begin
      Inc(I);
      Continue;
    end;
    if FuncRvaPtr^ = 0 then
      Exit(nil);
    FPtr := PByte(ModulePtr) + FuncRvaPtr^;
    if not ValidatePtr(ModulePtr, ModSize, FPtr, 1) then
    begin
      LogError('Invalid pointer to exported function');
      Exit(nil);
    end;
    if IsForwarderRva(PByte(ModulePtr), FuncRvaPtr^) then
    begin
      if not IsValidStringA(ModulePtr, ModSize, PAnsiChar(FPtr)) or (ForwarderNameLen(PAnsiChar(FPtr)) <= 1) then
      begin
        LogError('Invalid forwarded function.');
        Exit(nil);
      end;
      LogWarning('Forwarded function: [%s -> 0x%x] cannot be resolved.', [string(AnsiString(NamePtr)), NativeUInt(FPtr)]);
      Exit(nil);
    end;
    Exit(FARPROC(FPtr));
  end;
  LogWarning('Function not found.');
  Result := nil;
end;

function TExportBasedResolver.ResolveFunc(LibName, FuncName: PAnsiChar): FARPROC;
var
  LibBasePtr: HMODULE;
begin
  LibBasePtr := LoadLibraryByName(LibName);
  if LibBasePtr = 0 then
  begin
    LogError('Could not load the library.');
    Exit(nil);
  end;
  Result := GetExportedFunc(Pointer(LibBasePtr), FuncName);
  if not Assigned(Result) then
  begin
    LogWarning('Could could not get function from exports. Falling back to the default resolver.');
    Result := inherited ResolveFunc(LibName, FuncName);
    if not Assigned(Result) then
      LogError('Loading function from %s failed.', [string(AnsiString(LibName))]);
  end;
end;

function ReadDllName(ModulePtr: Pointer): PAnsiChar;
var
  ModSize: NativeUInt;
  Exp: PImageExportDirectory;
  ModuleName: PAnsiChar;
begin
  Result := nil;
  ModSize := GetImageSize(PByte(ModulePtr));
  if ModSize = 0 then
    Exit;
  Exp := GetExportDirectory(ModulePtr);
  if (Exp = nil) or (not ValidatePtr(ModulePtr, ModSize, Exp, SizeOf(TImageExportDirectory))) then
    Exit;
  ModuleName := PAnsiChar(NativeUInt(ModulePtr) + Exp.Name);
  if IsValidStringA(ModulePtr, ModSize, ModuleName) and (ForwarderNameLen(ModuleName) > 1) then
    Result := ModuleName;
end;

end.
