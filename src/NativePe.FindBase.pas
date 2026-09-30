{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/find_base.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.FindBase;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function FindBaseCandidate(ModulePtr: PByte; ModuleSize: NativeUInt): UInt64;

implementation

uses
  System.Generics.Collections,
  NativePe.PeHdrsHelper,
  NativePe.Relocate;

type
  TCollectCodeRelocs = class(TRelocBlockCallback)
  private
    FRelocs: TList<UInt64>;
    FPeBuffer: PByte;
    FBufferSize: NativeUInt;
    FCodeSec: PImageSectionHeader;
  public
    constructor Create(APeBuffer: PByte; ABufferSize: NativeUInt; AIs64Bit: Boolean; ARelocs: TList<UInt64>);
    function ProcessRelocField(RelocField: NativeUInt): Boolean; override;
    class function GetCodeSection(PeBuffer: PByte; BufferSize: NativeUInt): PImageSectionHeader;
  end;

constructor TCollectCodeRelocs.Create(APeBuffer: PByte; ABufferSize: NativeUInt; AIs64Bit: Boolean; ARelocs: TList<UInt64>);
begin
  inherited Create(AIs64Bit);
  FRelocs := ARelocs;
  FPeBuffer := APeBuffer;
  FBufferSize := ABufferSize;
  FCodeSec := GetCodeSection(FPeBuffer, FBufferSize);
end;

class function TCollectCodeRelocs.GetCodeSection(PeBuffer: PByte; BufferSize: NativeUInt): PImageSectionHeader;
var
  SecCount, I: NativeUInt;
  Hdr: PImageSectionHeader;
begin
  Result := nil;
  SecCount := GetSectionsCount(PeBuffer, BufferSize);
  I := 0;
  while I < SecCount do
  begin
    Hdr := GetSectionHdr(PeBuffer, BufferSize, I);
    if Hdr = nil then
      Break;
    if (Hdr.VirtualAddress <> 0) and (Hdr.SizeOfRawData <> 0) then
      if (Hdr.Characteristics and IMAGE_SCN_MEM_EXECUTE) <> 0 then
        Exit(Hdr);
    Inc(I);
  end;
end;

function TCollectCodeRelocs.ProcessRelocField(RelocField: NativeUInt): Boolean;
var
  RelocAddr: UInt64;
  CodeStart, CodeEnd: UInt64;
  IsInCode: Boolean;
  Rva: UInt64;
begin
  if FCodeSec = nil then
    Exit(False);
  RelocAddr := RelocField - NativeUInt(FPeBuffer);
  CodeStart := FCodeSec.VirtualAddress;
  CodeEnd := CodeStart + FCodeSec.Misc.VirtualSize;
  IsInCode := (RelocAddr >= CodeStart) and (RelocAddr < CodeEnd);
  if (not FIs64Bit) and (not IsInCode) then
    Exit(True);
  if FIs64Bit then
    Rva := PUInt64(RelocField)^
  else
    Rva := UInt64(PDWORD(RelocField)^);
  FRelocs.Add(Rva);
  Result := True;
end;

function FindBaseCandidate(ModulePtr: PByte; ModuleSize: NativeUInt): UInt64;
var
  Is64: Boolean;
  Relocs: TList<UInt64>;
  Callback: TCollectCodeRelocs;
  Hdr: PImageSectionHeader;
  Mask: UInt64;
  Keys: TList<UInt64>;
  Counts: TList<NativeUInt>;
  I: Integer;
  GuessedBase: UInt64;
  MostFrequent: UInt64;
  MaxFreq: NativeUInt;
  FirstBase, Delta: UInt64;
begin
  Result := 0;
  if ModuleSize = 0 then
    ModuleSize := GetImageSize(ModulePtr);
  if ModuleSize = 0 then
    Exit;

  Is64 := Is64Bit(ModulePtr);
  Relocs := TList<UInt64>.Create;
  Keys := TList<UInt64>.Create;
  Counts := TList<NativeUInt>.Create;
  try
    Callback := TCollectCodeRelocs.Create(ModulePtr, ModuleSize, Is64, Relocs);
    try
      if not ProcessRelocationTable(ModulePtr, ModuleSize, Callback) then
        Exit(0);
    finally
      Callback.Free;
    end;
    if Relocs.Count = 0 then
      Exit(0);
    Relocs.Sort;

    Hdr := TCollectCodeRelocs.GetCodeSection(ModulePtr, ModuleSize);
    if Hdr = nil then
      Exit(0);

    Mask := not UInt64($FFFF);
    for I := 0 to Relocs.Count - 1 do
    begin
      GuessedBase := Relocs[I] and Mask;
      if (Keys.Count = 0) or (Keys[Keys.Count - 1] <> GuessedBase) then
      begin
        Keys.Add(GuessedBase);
        Counts.Add(1);
      end
      else
        Counts[Counts.Count - 1] := Counts[Counts.Count - 1] + 1;
    end;

    MostFrequent := 0;
    MaxFreq := 0;
    for I := 0 to Keys.Count - 1 do
      if Counts[I] >= MaxFreq then
      begin
        MostFrequent := Keys[I];
        MaxFreq := Counts[I];
      end;

    for I := 0 to Relocs.Count - 1 do
    begin
      FirstBase := Relocs[I] and Mask;
      if FirstBase > MostFrequent then
        Break;
      Delta := MostFrequent - FirstBase;
      if Delta < ModuleSize then
        Exit(FirstBase);
    end;
    Result := 0;
  finally
    Counts.Free;
    Keys.Free;
    Relocs.Free;
  end;
end;

end.
