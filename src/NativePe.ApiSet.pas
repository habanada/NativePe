{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.ApiSet;

interface

uses
  Winapi.Windows,
  NativePe.Types;

var
  UseApiSetResolution: Boolean = False;

function ResolveApiSetSchema(const DllName: string): string;

implementation

uses
  System.SysUtils,
  NativePe.PebLookup;

const
  API_SET_SCHEMA_MIN_VERSION = 6;

type
  TApiSetNamespace = packed record
    Version: DWORD;
    Size: DWORD;
    Flags: DWORD;
    Count: DWORD;
    EntryOffset: DWORD;
    HashOffset: DWORD;
    HashFactor: DWORD;
  end;
  PApiSetNamespace = ^TApiSetNamespace;

  TApiSetNamespaceEntry = packed record
    Flags: DWORD;
    NameOffset: DWORD;
    NameLength: DWORD;
    HashedLength: DWORD;
    ValueOffset: DWORD;
    ValueCount: DWORD;
  end;
  PApiSetNamespaceEntry = ^TApiSetNamespaceEntry;

  TApiSetValueEntry = packed record
    Flags: DWORD;
    NameOffset: DWORD;
    NameLength: DWORD;
    ValueOffset: DWORD;
    ValueLength: DWORD;
  end;
  PApiSetValueEntry = ^TApiSetValueEntry;

function ResolveApiSetSchema(const DllName: string): string;
var
  LookupName: string;
  Peb: PPeb;
  Schema: PApiSetNamespace;
  Entry: PApiSetNamespaceEntry;
  ValueEntry: PApiSetValueEntry;
  I: DWORD;
  HashPos: Integer;
  EntryName, HostName: string;
  SchemaBase, EntriesBase, CurrentEntryPtr, NamePtr, ValueEntryPtr, HostNamePtr: PByte;
begin
  Result := DllName;
  if DllName = '' then
    Exit;
  if not (DllName.StartsWith('api-', True) or DllName.StartsWith('ext-', True)) then
    Exit;

  LookupName := DllName;
  if LookupName.EndsWith('.dll', True) then
    LookupName := LookupName.Substring(0, LookupName.Length - 4);
  HashPos := LastDelimiter('-', LookupName);
  if HashPos <= 1 then
    Exit;
  LookupName := Copy(LookupName, 1, HashPos - 1);

  Peb := GetCurrentPeb;
  if (Peb = nil) or (Peb.ApiSetMap = nil) then
    Exit;

  SchemaBase := PByte(Peb.ApiSetMap);
  Schema := PApiSetNamespace(SchemaBase);
  if Schema.Version < API_SET_SCHEMA_MIN_VERSION then
    Exit;

  EntriesBase := SchemaBase + Schema.EntryOffset;

  I := 0;
  while I < Schema.Count do
  begin
    CurrentEntryPtr := EntriesBase + (I * SizeOf(TApiSetNamespaceEntry));
    Entry := PApiSetNamespaceEntry(CurrentEntryPtr);
    NamePtr := SchemaBase + Entry.NameOffset;
    SetString(EntryName, PWideChar(NamePtr), Entry.HashedLength div 2);

    if (EntryName <> '') and (CompareText(LookupName, EntryName) = 0) then
    begin
      if Entry.ValueCount > 0 then
      begin
        ValueEntryPtr := SchemaBase + Entry.ValueOffset;
        ValueEntry := PApiSetValueEntry(ValueEntryPtr);
        if ValueEntry.ValueLength > 0 then
        begin
          HostNamePtr := SchemaBase + ValueEntry.ValueOffset;
          SetString(HostName, PWideChar(HostNamePtr), ValueEntry.ValueLength div 2);
          Exit(HostName);
        end;
      end;
    end;
    Inc(I);
  end;
end;

end.
