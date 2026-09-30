{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/relocate.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.Relocate;

interface

uses
  Winapi.Windows,
  NativePe.Types;

type
  TRelocBlockCallback = class abstract
  protected
    FIs64Bit: Boolean;
  public
    constructor Create(AIs64Bit: Boolean);
    function ProcessRelocField(RelocField: NativeUInt): Boolean; virtual; abstract;
  end;

function ProcessRelocationTable(ModulePtr: Pointer; ModuleSize: NativeUInt; Callback: TRelocBlockCallback): Boolean;
function RelocateModule(ModulePtr: PByte; ModuleSize: NativeUInt; NewBase: UInt64; OldBase: UInt64 = 0): Boolean;
function HasValidRelocationTable(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.Logger;

const
  RELOC_32BIT_FIELD = 3;
  RELOC_64BIT_FIELD = $A;

type
  TApplyRelocCallback = class(TRelocBlockCallback)
  private
    FOldBase, FNewBase: UInt64;
  public
    constructor Create(AIs64Bit: Boolean; AOldBase, ANewBase: UInt64);
    function ProcessRelocField(RelocField: NativeUInt): Boolean; override;
  end;

constructor TRelocBlockCallback.Create(AIs64Bit: Boolean);
begin
  inherited Create;
  FIs64Bit := AIs64Bit;
end;

constructor TApplyRelocCallback.Create(AIs64Bit: Boolean; AOldBase, ANewBase: UInt64);
begin
  inherited Create(AIs64Bit);
  FOldBase := AOldBase;
  FNewBase := ANewBase;
end;

function TApplyRelocCallback.ProcessRelocField(RelocField: NativeUInt): Boolean;
var
  Rva: UInt64;
  P64: PUInt64;
  P32: PDWORD;
begin
  if FIs64Bit then
  begin
    P64 := PUInt64(RelocField);
    Rva := P64^ - FOldBase;
    P64^ := Rva + FNewBase;
  end
  else
  begin
    P32 := PDWORD(RelocField);
    Rva := UInt64(P32^) - FOldBase;
    P32^ := DWORD(Rva + FNewBase);
  end;
  Result := True;
end;

function IsEmptyRelocBlock(Block: PBaseRelocationEntry; EntriesNum: NativeUInt; Page: DWORD; ModulePtr: Pointer;
  ModuleSize: NativeUInt): Boolean;
var
  Entry: PBaseRelocationEntry;
  I: NativeUInt;
begin
  if EntriesNum = 0 then
    Exit(True);
  Entry := Block;
  for I := 0 to EntriesNum - 1 do
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, Entry, SizeOf(TBaseRelocationEntry)) then
      Exit(False);
    if Entry.RelocType <> 0 then
      Exit(False);
    Entry := PBaseRelocationEntry(NativeUInt(Entry) + SizeOf(Word));
  end;
  Result := True;
end;

function ValidateRelocField(ModulePtr: Pointer; ModuleSize: NativeUInt; AIs64Bit: Boolean; RelocField: DWORD): Boolean;
var
  FieldWidth: NativeUInt;
  RelocPtr: NativeUInt;
begin
  if AIs64Bit then
    FieldWidth := SizeOf(UInt64)
  else
    FieldWidth := SizeOf(DWORD);
  RelocPtr := NativeUInt(ModulePtr) + RelocField;
  Result := ValidatePtr(ModulePtr, ModuleSize, Pointer(RelocPtr), FieldWidth);
end;

function ProcessRelocBlock(Block: PBaseRelocationEntry; EntriesNum: NativeUInt; Page: DWORD; ModulePtr: Pointer;
  ModuleSize: NativeUInt; AIs64Bit: Boolean; Callback: TRelocBlockCallback): Boolean;
var
  Entry: PBaseRelocationEntry;
  I: NativeUInt;
  Offset, RelocType, RelocField: DWORD;
  IsOk: Boolean;
begin
  if EntriesNum = 0 then
    Exit(True);
  Entry := Block;
  I := 0;
  while I < EntriesNum do
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, Entry, SizeOf(TBaseRelocationEntry)) then
      Break;
    Offset := Entry.Offset;
    RelocType := Entry.RelocType;
    if RelocType = 0 then
    begin
      Entry := PBaseRelocationEntry(NativeUInt(Entry) + SizeOf(Word));
      Inc(I);
      Continue;
    end;
    if (RelocType <> RELOC_32BIT_FIELD) and (RelocType <> RELOC_64BIT_FIELD) then
    begin
      if Assigned(Callback) then
        LogError('Not supported relocation format at %d: %d.', [I, RelocType]);
      Exit(False);
    end;
    RelocField := Page + Offset;
    if not ValidateRelocField(ModulePtr, ModuleSize, AIs64Bit, RelocField) then
    begin
      if Assigned(Callback) then
        LogError('Malformed reloc field: 0x%x.', [RelocField]);
      Exit(False);
    end;
    if Assigned(Callback) then
    begin
      IsOk := Callback.ProcessRelocField(NativeUInt(ModulePtr) + RelocField);
      if not IsOk then
      begin
        LogError('Failed processing reloc field at: 0x%x.', [RelocField]);
        Exit(False);
      end;
    end;
    Entry := PBaseRelocationEntry(NativeUInt(Entry) + SizeOf(Word));
    Inc(I);
  end;
  Result := I <> 0;
end;

function ProcessRelocationTable(ModulePtr: Pointer; ModuleSize: NativeUInt; Callback: TRelocBlockCallback): Boolean;
var
  RelocDir: PImageDataDirectory;
  MaxSize, RelocAddr: DWORD;
  Is64B: Boolean;
  Reloc: PImageBaseRelocation;
  ParsedSize, NewParsedSize: DWORD;
  EntriesNum: NativeUInt;
  Page: DWORD;
  Block: PBaseRelocationEntry;
begin
  Result := False;
  RelocDir := GetDirectoryEntry(PByte(ModulePtr), IMAGE_DIRECTORY_ENTRY_BASERELOC);
  if RelocDir = nil then
  begin
    LogDebug('No relocation table found.');
    Exit;
  end;
  if not ValidatePtr(ModulePtr, ModuleSize, RelocDir, SizeOf(TImageDataDirectory)) then
  begin
    LogError('Invalid relocDir pointer.');
    Exit;
  end;
  MaxSize := RelocDir.Size;
  RelocAddr := RelocDir.VirtualAddress;
  Is64B := Is64Bit(PByte(ModulePtr));

  ParsedSize := 0;
  while ParsedSize < MaxSize do
  begin
    Reloc := PImageBaseRelocation(NativeUInt(RelocAddr) + ParsedSize + NativeUInt(ModulePtr));
    if not ValidatePtr(ModulePtr, ModuleSize, Reloc, SizeOf(TImageBaseRelocation)) then
    begin
      LogError('Invalid address of relocations.');
      Exit;
    end;
    if Reloc.SizeOfBlock < (2 * SizeOf(DWORD)) then
    begin
      LogError('Malformed relocation block: SizeOfBlock too small.');
      Exit;
    end;
    EntriesNum := (Reloc.SizeOfBlock - 2 * SizeOf(DWORD)) div SizeOf(Word);
    Page := Reloc.VirtualAddress;
    Block := PBaseRelocationEntry(NativeUInt(Reloc) + 2 * SizeOf(DWORD));
    if not ValidatePtr(ModulePtr, ModuleSize, Block, SizeOf(TBaseRelocationEntry)) then
    begin
      LogError('Invalid address of relocations block.');
      Exit;
    end;
    if not IsEmptyRelocBlock(Block, EntriesNum, Page, ModulePtr, ModuleSize) then
    begin
      if not ProcessRelocBlock(Block, EntriesNum, Page, ModulePtr, ModuleSize, Is64B, Callback) then
        Exit;
    end;
    NewParsedSize := ParsedSize + Reloc.SizeOfBlock;
    if NewParsedSize < ParsedSize then
    begin
      LogError('Invalid SizeOfBlock: DWORD overflow.');
      Exit;
    end;
    ParsedSize := NewParsedSize;
  end;
  Result := True;
end;

function ApplyRelocations(ModulePtr: Pointer; ModuleSize: NativeUInt; NewBase, OldBase: UInt64): Boolean;
var
  Is64B: Boolean;
  Callback: TApplyRelocCallback;
begin
  Is64B := Is64Bit(PByte(ModulePtr));
  Callback := TApplyRelocCallback.Create(Is64B, OldBase, NewBase);
  try
    Result := ProcessRelocationTable(ModulePtr, ModuleSize, Callback);
  finally
    Callback.Free;
  end;
end;

function RelocateModule(ModulePtr: PByte; ModuleSize: NativeUInt; NewBase: UInt64; OldBase: UInt64): Boolean;
begin
  Result := False;
  if (ModulePtr = nil) or (ModuleSize = 0) then
    Exit;
  if OldBase = 0 then
    OldBase := GetImageBase(ModulePtr);
  LogDebug('New Base: 0x%x Old Base: 0x%x.', [NewBase, OldBase]);
  if NewBase = OldBase then
  begin
    LogDebug('Nothing to relocate: oldBase equals newBase.');
    Exit(True);
  end;
  if ApplyRelocations(ModulePtr, ModuleSize, NewBase, OldBase) then
    Exit(True);
  LogError('Could not relocate the module.');
  Result := False;
end;

function HasValidRelocationTable(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;
begin
  Result := ProcessRelocationTable(ModulePtr, ModuleSize, nil);
end;

end.
