{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/resource_parser.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ResourceParser;

interface

uses
  Winapi.Windows,
  NativePe.Types;

type
  TOnResEntryFound = function(ModulePtr: PByte; RootDir: PImageResourceDirectoryEntry;
    CurrEntry: PImageResourceDataEntry): Boolean;

function ParseResources(ModulePtr: PByte; OnEntry: TOnResEntryFound): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.Logger;

function ParseResourceDir(ModulePtr: PByte; ModuleSize: NativeUInt; RootDir: PImageResourceDirectoryEntry;
  UpperDir: PImageResourceDirectory; CurrDir: PImageResourceDirectory; OnEntry: TOnResEntryFound;
  Depth: NativeUInt = 0): Boolean; forward;

function ParseResourceEntry(ModulePtr: PByte; ModuleSize: NativeUInt; RootDir: PImageResourceDirectoryEntry;
  UpperDir: PImageResourceDirectory; Entry: PImageResourceDirectoryEntry; OnEntry: TOnResEntryFound;
  Depth: NativeUInt): Boolean;
var
  Offset: DWORD;
  DataEntry: PImageResourceDataEntry;
  DataPtr: PByte;
  NextDir: PImageResourceDirectory;
begin
  Result := False;
  if not Entry.DataIsDirectory then
  begin
    LogDebug('Entry is NOT a directory.');
    Offset := Entry.OffsetToData;
    LogDebug('Offset: %u.', [Offset]);
    DataEntry := PImageResourceDataEntry(NativeUInt(Offset) + NativeUInt(UpperDir));
    if not ValidatePtr(ModulePtr, ModuleSize, DataEntry, SizeOf(TImageResourceDataEntry)) then
      Exit;
    LogDebug('Data Offset: %u : %u.', [DataEntry.OffsetToData, DataEntry.Size]);
    DataPtr := PByte(NativeUInt(ModulePtr) + NativeUInt(DataEntry.OffsetToData));
    if not ValidatePtr(ModulePtr, ModuleSize, DataPtr, DataEntry.Size) then
      Exit;
    if not Assigned(OnEntry) then
    begin
      LogWarning('Missing on entry callback.');
      Exit;
    end;
    Exit(OnEntry(ModulePtr, RootDir, DataEntry));
  end;
  LogDebug('Entry is a directory.');
  Offset := Entry.OffsetToDirectory;
  LogDebug('Offset: 0x%x.', [Offset]);
  NextDir := PImageResourceDirectory(NativeUInt(Offset) + NativeUInt(UpperDir));
  if not ValidatePtr(ModulePtr, ModuleSize, NextDir, SizeOf(TImageResourceDirectory)) then
    Exit;
  Result := ParseResourceDir(ModulePtr, ModuleSize, RootDir, UpperDir, NextDir, OnEntry, Depth);
end;

function ParseResourceDir(ModulePtr: PByte; ModuleSize: NativeUInt; RootDir: PImageResourceDirectoryEntry;
  UpperDir: PImageResourceDirectory; CurrDir: PImageResourceDirectory; OnEntry: TOnResEntryFound;
  Depth: NativeUInt): Boolean;
var
  TotalEntries: NativeUInt;
  FirstEntry: PImageResourceDirectoryEntry;
  I: NativeUInt;
  Entry, EntryRoot: PImageResourceDirectoryEntry;
begin
  Result := False;
  if Depth > 8 then
  begin
    LogError('Maximum depth exceeded: %u', [Depth]);
    Exit;
  end;
  TotalEntries := NativeUInt(CurrDir.NumberOfIdEntries) + NativeUInt(CurrDir.NumberOfNamedEntries);
  FirstEntry := PImageResourceDirectoryEntry(NativeUInt(CurrDir) + SizeOf(TImageResourceDirectory));
  I := 0;
  while I < TotalEntries do
  begin
    Entry := PImageResourceDirectoryEntry(NativeUInt(FirstEntry) + I * SizeOf(TImageResourceDirectoryEntry));
    if not ValidatePtr(ModulePtr, ModuleSize, Entry, SizeOf(TImageResourceDirectoryEntry)) then
    begin
      LogError('Invalid resource entry pointer');
      Exit;
    end;
    LogDebug('Entry: 0x%x ; Id: %u ; dataOffset: %u.', [I, Entry.Id, Entry.OffsetToData]);
    EntryRoot := RootDir;
    if EntryRoot = nil then
      EntryRoot := Entry;
    if not ParseResourceEntry(ModulePtr, ModuleSize, EntryRoot, UpperDir, Entry, OnEntry, Depth + 1) then
    begin
      LogError('Parsing resource entry failed.');
      Exit;
    end;
    Inc(I);
  end;
  Result := True;
end;

function ParseResources(ModulePtr: PByte; OnEntry: TOnResEntryFound): Boolean;
var
  ModuleSize: NativeUInt;
  Dir: PImageDataDirectory;
  ResDir: PImageResourceDirectory;
begin
  Result := False;
  ModuleSize := GetImageSize(ModulePtr);
  Dir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_RESOURCE);
  if (Dir = nil) or (Dir.VirtualAddress = 0) or (Dir.Size = 0) then
    Exit;
  ResDir := PImageResourceDirectory(NativeUInt(Dir.VirtualAddress) + NativeUInt(ModulePtr));
  if not ValidatePtr(ModulePtr, ModuleSize, ResDir, SizeOf(TImageResourceDirectory)) then
    Exit;
  Result := ParseResourceDir(ModulePtr, ModuleSize, nil, ResDir, ResDir, OnEntry);
end;

end.
