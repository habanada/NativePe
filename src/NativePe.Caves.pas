{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/caves.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.	
}
unit NativePe.Caves;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function FindEndingCave(ModulePtr: PByte; ModuleSize: NativeUInt; CaveSize: DWORD;
  ReqCharact: DWORD = IMAGE_SCN_MEM_READ; Reserve: Boolean = True): PByte;
function FindAlignmentCave(ModulePtr: PByte; ModuleSize: NativeUInt; CaveSize: DWORD;
  ReqCharact: DWORD = IMAGE_SCN_MEM_READ; Reserve: Boolean = True): PByte;
function FindPaddingCave(ModulePtr: PByte; ModuleSize: NativeUInt; MinimalSize: NativeUInt;
  ReqCharact: DWORD = IMAGE_SCN_MEM_READ): PByte;

implementation

uses
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.Logger;

function FindEndingCave(ModulePtr: PByte; ModuleSize: NativeUInt; CaveSize: DWORD; ReqCharact: DWORD;
  Reserve: Boolean): PByte;
var
  SecCount, LastSec: NativeUInt;
  SectionHdr: PImageSectionHeader;
  RawSize, VirtualSize, TheCaveSize: DWORD;
  CavePtr: PByte;
begin
  Result := nil;
  SecCount := GetSectionsCount(ModulePtr, ModuleSize);
  if SecCount = 0 then
    Exit;

  LastSec := SecCount - 1;
  SectionHdr := GetSectionHdr(ModulePtr, ModuleSize, LastSec);
  if SectionHdr = nil then
    Exit;
  if (SectionHdr.Characteristics and ReqCharact) = 0 then
    Exit;

  RawSize := SectionHdr.SizeOfRawData;
  VirtualSize := DWORD(ModuleSize) - SectionHdr.VirtualAddress;

  if RawSize >= VirtualSize then
  begin
    LogInfo('Last section''s raw_size: 0x%x >= virtual_size: 0x%x', [RawSize, VirtualSize]);
    Exit;
  end;
  TheCaveSize := VirtualSize - RawSize;
  if TheCaveSize < CaveSize then
  begin
    LogInfo('Cave is too small.');
    Exit;
  end;
  CavePtr := PByte(NativeUInt(ModulePtr) + SectionHdr.VirtualAddress + SectionHdr.SizeOfRawData);
  if not ValidatePtr(ModulePtr, ModuleSize, CavePtr, CaveSize) then
  begin
    LogInfo('Invalid cave pointer.');
    Exit;
  end;
  if Reserve then
    SectionHdr.SizeOfRawData := SectionHdr.SizeOfRawData + CaveSize;
  Result := CavePtr;
end;

function FindAlignmentCave(ModulePtr: PByte; ModuleSize: NativeUInt; CaveSize: DWORD; ReqCharact: DWORD;
  Reserve: Boolean): PByte;
var
  Alignment: DWORD;
  SecCount, I: NativeUInt;
  SectionHdr: PImageSectionHeader;
  Rem, Div_, NewSize, TheCaveSize: DWORD;
  SecStart, SecEnd: DWORD;
  CavePtr: PByte;
begin
  Result := nil;
  Alignment := GetSecAlignment(ModulePtr, True);
  if Alignment = 0 then
    Exit;

  SecCount := GetSectionsCount(ModulePtr, ModuleSize);
  I := 0;
  while I < SecCount do
  begin
    SectionHdr := GetSectionHdr(ModulePtr, ModuleSize, I);
    if SectionHdr = nil then
    begin
      Inc(I);
      Continue;
    end;
    if (SectionHdr.Characteristics and ReqCharact) = 0 then
    begin
      Inc(I);
      Continue;
    end;

    Rem := SectionHdr.SizeOfRawData mod Alignment;
    if Rem = 0 then
    begin
      Inc(I);
      Continue;
    end;

    Div_ := (SectionHdr.SizeOfRawData div Alignment) + 1;
    NewSize := Div_ * Alignment;
    TheCaveSize := NewSize - SectionHdr.SizeOfRawData;
    if TheCaveSize < CaveSize then
    begin
      LogInfo('Cave is too small.');
      Inc(I);
      Continue;
    end;
    SecStart := SectionHdr.PointerToRawData;
    if SecStart = 0 then
    begin
      Inc(I);
      Continue;
    end;

    SecEnd := SecStart + SectionHdr.SizeOfRawData;
    LogInfo('Section: 0x%x : 0x%x', [SecStart, SecEnd]);
    CavePtr := PByte(NativeUInt(ModulePtr) + SecEnd);
    if not ValidatePtr(ModulePtr, ModuleSize, CavePtr, CaveSize) then
    begin
      LogInfo('Invalid cave pointer.');
      Inc(I);
      Continue;
    end;
    if Reserve then
      SectionHdr.SizeOfRawData := SectionHdr.SizeOfRawData + CaveSize;
    Exit(CavePtr);
  end;
  LogInfo('Cave not found.');
end;

function FindPaddingCave(ModulePtr: PByte; ModuleSize: NativeUInt; MinimalSize: NativeUInt; ReqCharact: DWORD): PByte;
var
  SecCount, I: NativeUInt;
  SectionHdr: PImageSectionHeader;
  SecStart, SecEnd: DWORD;
  CaveOffset: NativeUInt;
  CavePtr: PByte;
  Found: Boolean;
begin
  Result := nil;
  SecCount := GetSectionsCount(ModulePtr, ModuleSize);
  I := 0;
  while I < SecCount do
  begin
    SectionHdr := GetSectionHdr(ModulePtr, ModuleSize, I);
    if SectionHdr = nil then
    begin
      Inc(I);
      Continue;
    end;
    if (SectionHdr.Characteristics and ReqCharact) = 0 then
    begin
      Inc(I);
      Continue;
    end;

    if SectionHdr.SizeOfRawData < MinimalSize then
    begin
      Inc(I);
      Continue;
    end;

    SecStart := SectionHdr.VirtualAddress;
    if SecStart = 0 then
    begin
      Inc(I);
      Continue;
    end;

    SecEnd := SecStart + SectionHdr.SizeOfRawData;
    LogInfo('Section: 0x%x : 0x%x', [SecStart, SecEnd]);
    CaveOffset := SectionHdr.SizeOfRawData - MinimalSize;
    CavePtr := PByte(NativeUInt(ModulePtr) + NativeUInt(SecStart) + CaveOffset);
    if not ValidatePtr(ModulePtr, ModuleSize, CavePtr, MinimalSize) then
    begin
      LogInfo('Invalid cave pointer.');
      Inc(I);
      Continue;
    end;
    Found := False;
    if IsPadding(CavePtr, MinimalSize, 0) then
      Found := True;
    if (SectionHdr.Characteristics and IMAGE_SCN_MEM_EXECUTE) <> 0 then
      if IsPadding(CavePtr, MinimalSize, $CC) then
        Found := True;
    if Found then
      Exit(CavePtr);
    Inc(I);
  end;
  LogInfo('Cave not found.');
end;

end.
