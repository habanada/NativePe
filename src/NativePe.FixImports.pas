{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/fix_imports.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.FixImports;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.Types,
  NativePe.ExportsMapper,
  NativePe.ImportsUneraser;

function FixImports(ModulePtr: Pointer; ModuleSize: NativeUInt; ExportsMap: TExportsMapper;
  NotCovered: TImpsNotCovered = nil): Boolean;

implementation

uses
  System.SysUtils,
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.ExportedFunc,
  NativePe.Logger;

function FindAddressesToFill32(CallVia, ThunkAddr: DWORD; ModulePtr: Pointer; ModuleSize: NativeUInt;
  ExportsMap: TExportsMapper; Addresses: TList<UInt64>): NativeUInt;
var
  ThunkPtr, CallViaPtr: Pointer;
  CallViaVal: PDWORD;
  SearchedAddr: UInt64;
begin
  Result := 0;
  if (ModulePtr = nil) or (CallVia = 0) then
    Exit;

  repeat
    if ThunkAddr <> 0 then
    begin
      ThunkPtr := Pointer(NativeUInt(ModulePtr) + ThunkAddr);
      if not ValidatePtr(ModulePtr, ModuleSize, ThunkPtr, SizeOf(DWORD)) then
        Break;
    end;

    CallViaPtr := Pointer(NativeUInt(ModulePtr) + CallVia);
    if not ValidatePtr(ModulePtr, ModuleSize, CallViaPtr, SizeOf(DWORD)) then
      Break;

    CallViaVal := PDWORD(CallViaPtr);
    if CallViaVal^ = 0 then
      Break;

    SearchedAddr := UInt64(CallViaVal^);
    if ExportsMap.FindExportByVa(SearchedAddr) <> nil then
    begin
      if not Addresses.Contains(SearchedAddr) then
        Addresses.Add(SearchedAddr);
      Inc(Result);
    end;

    Inc(CallVia, SizeOf(DWORD));
    if ThunkAddr <> 0 then
      Inc(ThunkAddr, SizeOf(DWORD));
  until False;
end;

function FindAddressesToFill64(CallVia, ThunkAddr: UInt64; ModulePtr: Pointer; ModuleSize: NativeUInt;
  ExportsMap: TExportsMapper; Addresses: TList<UInt64>): NativeUInt;
var
  ThunkPtr, CallViaPtr: Pointer;
  CallViaVal: PUInt64;
  SearchedAddr: UInt64;
begin
  Result := 0;
  if (ModulePtr = nil) or (CallVia = 0) then
    Exit;

  repeat
    if ThunkAddr <> 0 then
    begin
      ThunkPtr := Pointer(NativeUInt(ModulePtr) + ThunkAddr);
      if not ValidatePtr(ModulePtr, ModuleSize, ThunkPtr, SizeOf(UInt64)) then
        Break;
    end;

    CallViaPtr := Pointer(NativeUInt(ModulePtr) + CallVia);
    if not ValidatePtr(ModulePtr, ModuleSize, CallViaPtr, SizeOf(UInt64)) then
      Break;

    CallViaVal := PUInt64(CallViaPtr);
    if CallViaVal^ = 0 then
      Break;

    SearchedAddr := CallViaVal^;
    if ExportsMap.FindExportByVa(SearchedAddr) <> nil then
    begin
      if not Addresses.Contains(SearchedAddr) then
        Addresses.Add(SearchedAddr);
      Inc(Result);
    end;

    Inc(CallVia, SizeOf(UInt64));
    if ThunkAddr <> 0 then
      Inc(ThunkAddr, SizeOf(UInt64));
  until False;
end;

function FixImports(ModulePtr: Pointer; ModuleSize: NativeUInt; ExportsMap: TExportsMapper;
  NotCovered: TImpsNotCovered): Boolean;
const
  SkipBound = False;
var
  ImportsDir: PImageDataDirectory;
  Is64: Boolean;
  MaxSize, ImpAddr: DWORD;
  LibDesc: PImageImportDescriptor;
  ParsedSize: DWORD;
  IsBound: Boolean;
  LibName, NamePtr: PAnsiChar;
  LibNameStr: string;
  CallVia, ThunkAddr: DWORD;
  CallVia64, ThunkAddr64: UInt64;
  Addresses: TList<UInt64>;
  DllCoverage: TImportedDllCoverage;
  IsAllCovered, IsLibErased: Boolean;
  Uneraser: TImportsUneraser;
  DllWithExt: string;
begin
  Result := True;
  ImportsDir := GetDirectoryEntry(PByte(ModulePtr), IMAGE_DIRECTORY_ENTRY_IMPORT);
  if ImportsDir = nil then
    Exit(True);

  Is64 := Is64Bit(PByte(ModulePtr));
  MaxSize := ImportsDir.Size;
  ImpAddr := ImportsDir.VirtualAddress;

  ParsedSize := 0;
  LogDebug('---IMP---');

  while ParsedSize < MaxSize do
  begin
    LibDesc := PImageImportDescriptor(NativeUInt(ImpAddr) + ParsedSize + NativeUInt(ModulePtr));
    if not ValidatePtr(ModulePtr, ModuleSize, LibDesc, SizeOf(TImageImportDescriptor)) then
    begin
      LogError('Invalid import descriptor pointer.');
      Exit(False);
    end;
    Inc(ParsedSize, SizeOf(TImageImportDescriptor));
    if (LibDesc.OriginalFirstThunk = 0) and (LibDesc.FirstThunk = 0) then
      Break;

    IsBound := LibDesc.TimeDateStamp = DWORD(-1);
    if IsBound and SkipBound then
      Continue;

    LogDebug('Imported Lib: %x : %x : %x', [LibDesc.FirstThunk, LibDesc.OriginalFirstThunk, LibDesc.Name]);

    LibNameStr := '';
    if LibDesc.Name <> 0 then
    begin
      NamePtr := PAnsiChar(NativeUInt(ModulePtr) + LibDesc.Name);
      if IsValidStringA(ModulePtr, ModuleSize, NamePtr) then
        LibNameStr := string(AnsiString(NamePtr));
    end;

    Addresses := TList<UInt64>.Create;
    try
      if not Is64 then
      begin
        CallVia := LibDesc.FirstThunk;
        ThunkAddr := LibDesc.OriginalFirstThunk;
        FindAddressesToFill32(CallVia, ThunkAddr, ModulePtr, ModuleSize, ExportsMap, Addresses);
      end
      else
      begin
        CallVia64 := UInt64(LibDesc.FirstThunk);
        ThunkAddr64 := UInt64(LibDesc.OriginalFirstThunk);
        FindAddressesToFill64(CallVia64, ThunkAddr64, ModulePtr, ModuleSize, ExportsMap, Addresses);
      end;

      DllCoverage := TImportedDllCoverage.Create(Addresses, ExportsMap);
      try
        IsAllCovered := DllCoverage.FindCoveringDll;
        IsLibErased := False;

        LibNameStr := GetDllShortName(LibNameStr);

        if LibNameStr = '' then
        begin
          IsLibErased := True;
          if IsAllCovered then
            LibNameStr := DllCoverage.DllName;
        end;
        if LibNameStr = '' then
          Continue;

        LogDebug('Lib: %s.', [LibNameStr]);
        if DllCoverage.MapAddressesToFunctions(LibNameStr) = 0 then
          Continue;

        Uneraser := TImportsUneraser.Create(ModulePtr, ModuleSize);
        try
          if not Uneraser.UneraseDllImports(LibDesc, DllCoverage, NotCovered) then
            Exit(False);
          if IsLibErased then
          begin
            DllWithExt := ExportsMap.GetDllFullName(DllCoverage.DllName);
            Uneraser.UneraseDllName(LibDesc, AnsiString(DllWithExt));
          end;
        finally
          Uneraser.Free;
        end;
      finally
        DllCoverage.Free;
      end;
    finally
      Addresses.Free;
    end;
  end;
  LogDebug('---------');
  Result := True;
end;

end.
