{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/pe_mode_detector.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PeModeDetector;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function IsPeRaw(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
function IsPeRawEqVirtual(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
function IsPeExpanded(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
function IsSectionExpanded(PeBuffer: PByte; PeSize: NativeUInt; Sec: PImageSectionHeader): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.ImportsLoader,
  NativePe.Relocate,
  NativePe.Logger;

function IsVirtualPadding(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
var
  RAlign: NativeUInt;
  SectionsCount, I: NativeUInt;
  Sec1, Sec2: PImageSectionHeader;
  Sec1EndOffset: DWORD;
  Diff: NativeUInt;
  Sec1EndPtr: PByte;
  IsValidPadding: Boolean;
begin
  RAlign := GetSecAlignment(PeBuffer, True);
  if RAlign = 0 then
    Exit(False);
  SectionsCount := GetSectionsCount(PeBuffer, PeSize);
  if SectionsCount < 2 then
    Exit(False);
  IsValidPadding := False;
  I := 1;
  while I < SectionsCount do
  begin
    Sec1 := GetSectionHdr(PeBuffer, PeSize, I - 1);
    Sec2 := GetSectionHdr(PeBuffer, PeSize, I);
    if (Sec1 = nil) or (Sec2 = nil) then
    begin
      Inc(I);
      Continue;
    end;
    if Sec1.SizeOfRawData = 0 then
    begin
      Inc(I);
      Continue;
    end;
    Sec1EndOffset := Sec1.VirtualAddress + Sec1.SizeOfRawData;
    if Sec2.VirtualAddress = Sec1EndOffset then
    begin
      Inc(I);
      Continue;
    end;
    if Sec2.VirtualAddress < Sec1EndOffset then
      Exit(False);
    Diff := Sec2.VirtualAddress - Sec1EndOffset;
    if Diff < RAlign then
    begin
      Inc(I);
      Continue;
    end;
    Sec1EndPtr := PeBuffer + Sec1EndOffset;
    if not ValidatePtr(PeBuffer, PeSize, Sec1EndPtr, Diff) then
      Exit(False);
    if IsPadding(Sec1EndPtr, Diff, 0) then
      IsValidPadding := True
    else
      Exit(False);
    Inc(I);
  end;
  Result := IsValidPadding;
end;

function IsHdrVirtualAlign(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
var
  VAlign: NativeUInt;
  SectionsCount, I: NativeUInt;
  Sec: PImageSectionHeader;
  Diff: NativeUInt;
  SecRawPtr: PByte;
begin
  Result := False;
  VAlign := GetSecAlignment(PeBuffer, False);
  if GetHdrsSize(PeBuffer) >= VAlign then
    Exit;
  SectionsCount := GetSectionsCount(PeBuffer, PeSize);
  if SectionsCount = 0 then
    Exit;
  for I := 0 to SectionsCount - 1 do
  begin
    Sec := GetSectionHdr(PeBuffer, PeSize, I);
    if (Sec = nil) or (Sec.PointerToRawData = 0) or (Sec.SizeOfRawData = 0) then
      Continue;
    if Sec.PointerToRawData >= VAlign then
      Continue;
    Diff := VAlign - Sec.PointerToRawData;
    SecRawPtr := PeBuffer + Sec.PointerToRawData;
    if not ValidatePtr(PeBuffer, PeSize, SecRawPtr, Diff) then
      Exit(False);
    if IsPadding(SecRawPtr, Diff, 0) then
      Exit(True);
  end;
end;

function IsSecHdrsErased(PeBuffer: PByte; PeSize: NativeUInt; IsRaw: Boolean): Boolean;
var
  Count, I: NativeUInt;
  Hdr: PImageSectionHeader;
begin
  Count := GetSectionsCount(PeBuffer, PeSize);
  I := 0;
  while I < Count do
  begin
    Hdr := GetSectionHdr(PeBuffer, PeSize, I);
    if Hdr = nil then
    begin
      Inc(I);
      Continue;
    end;
    if IsRaw then
    begin
      if Hdr.PointerToRawData <> 0 then
        Exit(False);
    end
    else if Hdr.VirtualAddress <> 0 then
      Exit(False);
    Inc(I);
  end;
  Result := True;
end;

function IsPeRawEqVirtual(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
var
  Count, I: NativeUInt;
  Hdr: PImageSectionHeader;
begin
  Count := GetSectionsCount(PeBuffer, PeSize);
  I := 0;
  while I < Count do
  begin
    Hdr := GetSectionHdr(PeBuffer, PeSize, I);
    if Hdr = nil then
    begin
      Inc(I);
      Continue;
    end;
    if Hdr.VirtualAddress <> Hdr.PointerToRawData then
      Exit(False);
    Inc(I);
  end;
  Result := True;
end;

function IsPeMapped(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
var
  VScore: NativeUInt;
begin
  VScore := 0;
  if HasValidImportTable(PeBuffer, PeSize) then
  begin
    LogInfo('Valid Import Table found.');
    Inc(VScore);
  end;
  if HasValidRelocationTable(PeBuffer, PeSize) then
  begin
    LogInfo('Valid Relocations Table found.');
    Inc(VScore);
  end;
  if IsHdrVirtualAlign(PeBuffer, PeSize) then
  begin
    LogInfo('Header virtual alignment OK.');
    Inc(VScore);
  end;
  LogInfo('TOTAL v_score: %d.', [VScore]);
  Result := VScore > 0;
end;

function IsPeRaw(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
begin
  if GetSectionsCount(PeBuffer, PeSize) = 0 then
    Exit(True);
  if IsPeMapped(PeBuffer, PeSize) then
    Exit(False);
  if IsSecHdrsErased(PeBuffer, PeSize, True) then
  begin
    LogInfo('Raw alignment is erased.');
    Exit(False);
  end;
  Result := True;
end;

function IsSectionExpanded(PeBuffer: PByte; PeSize: NativeUInt; Sec: PImageSectionHeader): Boolean;
var
  SecVSize, SecRSize, Diff: NativeUInt;
  SecRawEndPtr: PByte;
begin
  Result := False;
  if Sec = nil then
    Exit;
  SecVSize := GetVirtualSecSize(PeBuffer, Sec, True);
  SecRSize := Sec.SizeOfRawData;
  if SecRSize >= SecVSize then
    Exit;
  Diff := SecVSize - SecRSize;
  SecRawEndPtr := PeBuffer + Sec.VirtualAddress + SecRSize;
  if not ValidatePtr(PeBuffer, PeSize, SecRawEndPtr, Diff) then
    Exit;
  Result := not IsPadding(SecRawEndPtr, Diff, 0);
end;

function IsPeExpanded(PeBuffer: PByte; PeSize: NativeUInt): Boolean;
var
  SectionsCount, I: NativeUInt;
  Sec: PImageSectionHeader;
begin
  Result := False;
  SectionsCount := GetSectionsCount(PeBuffer, PeSize);
  I := 0;
  while I < SectionsCount do
  begin
    Sec := GetSectionHdr(PeBuffer, PeSize, I);
    if IsSectionExpanded(PeBuffer, PeSize, Sec) then
      Exit(True);
    Inc(I);
  end;
end;

end.
