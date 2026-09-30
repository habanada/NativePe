{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/pe_virtual_to_raw.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PeVirtualToRaw;

interface

uses
  Winapi.Windows,
  NativePe.Types,
  NativePe.BufferUtil;

function PeVirtualToRaw(Payload: PByte; InSize: NativeUInt; LoadBase: UInt64; out OutputSize: NativeUInt;
  Rebuffer: Boolean = True): TAlignedBuf;
function PeRealignRawToVirtual(Payload: PByte; InSize: NativeUInt; LoadBase: UInt64; out OutputSize: NativeUInt): TAlignedBuf;

implementation

uses
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.Relocate,
  NativePe.Logger;

function SectionsVirtualToRaw(Payload: PByte; PayloadSize: NativeUInt; DestAddress: PByte; out RawSize: NativeUInt): Boolean;
var
  PayloadNtHdr: PByte;
  Is64B: Boolean;
  FileHdr: PImageFileHeader;
  HdrsSize: DWORD;
  SecPtr: Pointer;
  FirstRaw: DWORD;
  RawEnd: NativeUInt;
  SectionsCount, I: NativeUInt;
  NextSec: PImageSectionHeader;
  SectionMapped, SectionRawPtr: PByte;
  SecSize, NewEnd: NativeUInt;
begin
  Result := False;
  RawSize := 0;
  if (Payload = nil) or (DestAddress = nil) then
    Exit;
  PayloadNtHdr := GetNtHdrs(Payload, PayloadSize);
  if PayloadNtHdr = nil then
  begin
    LogError('Invalid PE at 0x%x.', [NativeUInt(Payload)]);
    Exit;
  end;
  Is64B := Is64Bit(Payload);
  if Is64B then
  begin
    FileHdr := @PImageNtHeaders64(PayloadNtHdr).FileHeader;
    HdrsSize := PImageNtHeaders64(PayloadNtHdr).OptionalHeader.SizeOfHeaders;
    SecPtr := Pointer(NativeUInt(@PImageNtHeaders64(PayloadNtHdr).OptionalHeader) + FileHdr.SizeOfOptionalHeader);
  end
  else
  begin
    FileHdr := @PImageNtHeaders32(PayloadNtHdr).FileHeader;
    HdrsSize := PImageNtHeaders32(PayloadNtHdr).OptionalHeader.SizeOfHeaders;
    SecPtr := Pointer(NativeUInt(@PImageNtHeaders32(PayloadNtHdr).OptionalHeader) + FileHdr.SizeOfOptionalHeader);
  end;

  LogDebug('Copying sections.');
  FirstRaw := 0;
  RawEnd := HdrsSize;
  SectionsCount := FileHdr.NumberOfSections;
  I := 0;
  while I < SectionsCount do
  begin
    NextSec := PImageSectionHeader(NativeUInt(SecPtr) + NativeUInt(IMAGE_SIZEOF_SECTION_HEADER) * I);
    if not ValidatePtr(Payload, PayloadSize, NextSec, IMAGE_SIZEOF_SECTION_HEADER) then
      Exit(False);

    SectionMapped := Payload + NextSec.VirtualAddress;
    SectionRawPtr := DestAddress + NextSec.PointerToRawData;
    SecSize := NextSec.SizeOfRawData;

    NewEnd := SecSize + NextSec.PointerToRawData;
    if NewEnd > RawEnd then
      RawEnd := NewEnd;



    if (NativeUInt(NextSec.VirtualAddress) + SecSize) > PayloadSize then
    begin
      if PayloadSize > NextSec.VirtualAddress then
        SecSize := PayloadSize - NextSec.VirtualAddress
      else
        SecSize := 0;
      LogWarning('Section %u: virtual size exceeds buffer, truncating to 0x%x.', [I, SecSize]);
    end;
    if (NativeUInt(NextSec.VirtualAddress) > PayloadSize) and (SecSize <> 0) then
    begin
      LogError('Section %u: VirtualAddress 0x%x is out of bounds.', [I, NextSec.VirtualAddress]);
      Exit(False);
    end;
    if (NativeUInt(NextSec.PointerToRawData) + SecSize) > PayloadSize then
    begin
      LogError('Section %u: raw data exceeds buffer (size: 0x%x).', [I, SecSize]);
      Exit(False);
    end;
    LogDebug('Section %u: copying to raw offset 0x%x.', [I, NativeUInt(SectionRawPtr)]);
    if not ValidatePtr(Payload, PayloadSize, SectionMapped, SecSize) then
    begin
      LogWarning('Section %u: source out of bounds, skipping.', [I]);
      Inc(I);
      Continue;
    end;
    if not ValidatePtr(DestAddress, PayloadSize, SectionRawPtr, SecSize) then
    begin
      LogWarning('Section %u: destination out of bounds, skipping.', [I]);
      Inc(I);
      Continue;
    end;
    Move(SectionMapped^, SectionRawPtr^, SecSize);
    if (FirstRaw = 0) or (NextSec.PointerToRawData < FirstRaw) then
      FirstRaw := NextSec.PointerToRawData;
    Inc(I);
  end;
  if RawEnd > PayloadSize then
    RawEnd := PayloadSize;
  RawSize := RawEnd;

  if HdrsSize = 0 then
  begin
    HdrsSize := FirstRaw;
    LogDebug('SizeOfHeaders not set, using first section raw offset as fallback: 0x%x.', [HdrsSize]);
  end;
  if not ValidatePtr(Payload, PayloadSize, Payload, HdrsSize) then
    Exit(False);
  Move(Payload^, DestAddress^, HdrsSize);
  Result := True;
end;

function PeVirtualToRaw(Payload: PByte; InSize: NativeUInt; LoadBase: UInt64; out OutputSize: NativeUInt;
  Rebuffer: Boolean): TAlignedBuf;
var
  OutBuf, InBuf: TAlignedBuf;
  OldBase: UInt64;
  IsOk: Boolean;
  RawSize: NativeUInt;
begin
  Result := nil;
  OutputSize := 0;
  OutBuf := AllocPeBuffer(InSize, PAGE_READWRITE);
  if OutBuf = nil then
    Exit;

  InBuf := Payload;
  if Rebuffer then
  begin
    InBuf := AllocPeBuffer(InSize, PAGE_READWRITE);
    if InBuf = nil then
    begin
      FreePeBuffer(OutBuf, InSize);
      Exit;
    end;
    Move(Payload^, InBuf^, InSize);
  end;

  OldBase := GetImageBase(InBuf);
  IsOk := True;
  if not RelocateModule(InBuf, InSize, OldBase, LoadBase) then
  begin
    if not UpdateImageBase(InBuf, LoadBase) then
    begin
      LogError('Failed relocating the module.');
      IsOk := False;
    end
    else
      LogWarning('The module could not be relocated, so the ImageBase has been changed instead.');
  end;
  RawSize := 0;
  if IsOk then
    if not SectionsVirtualToRaw(InBuf, InSize, OutBuf, RawSize) then
      IsOk := False;

  if Rebuffer and (InBuf <> nil) then
  begin
    FreePeBuffer(InBuf, InSize);
    InBuf := nil;
  end;
  if not IsOk then
  begin
    FreePeBuffer(OutBuf, InSize);
    OutBuf := nil;
    RawSize := 0;
  end;
  OutputSize := RawSize;
  Result := OutBuf;
end;

function PeRealignRawToVirtual(Payload: PByte; InSize: NativeUInt; LoadBase: UInt64; out OutputSize: NativeUInt): TAlignedBuf;
var
  OutBuf: TAlignedBuf;
  OldBase: UInt64;
  IsOk: Boolean;
  VAlignment: DWORD;
  SectionsCount, I: NativeUInt;
  Sec: PImageSectionHeader;
begin
  Result := nil;
  OutputSize := InSize;
  OutBuf := AllocPeBuffer(OutputSize, PAGE_READWRITE);
  if OutBuf = nil then
  begin
    OutputSize := 0;
    Exit;
  end;
  Move(Payload^, OutBuf^, InSize);

  OldBase := GetImageBase(OutBuf);
  IsOk := True;
  if not RelocateModule(OutBuf, OutputSize, OldBase, LoadBase) then
  begin
    if not UpdateImageBase(OutBuf, LoadBase) then
    begin
      LogError('Failed relocating the module.');
      IsOk := False;
    end
    else
      LogWarning('The module could not be relocated, so the ImageBase has been changed instead.');
  end;

  VAlignment := GetSecAlignment(Payload, False);
  if not SetSecAlignment(OutBuf, True, VAlignment) then
    IsOk := False;

  SectionsCount := GetSectionsCount(OutBuf, OutputSize);
  I := 0;
  while I < SectionsCount do
  begin
    Sec := GetSectionHdr(OutBuf, OutputSize, I);
    if Sec = nil then
      Break;
    Sec.Misc.VirtualSize := GetVirtualSecSize(OutBuf, Sec, True);
    Sec.SizeOfRawData := Sec.Misc.VirtualSize;
    Sec.PointerToRawData := Sec.VirtualAddress;
    Inc(I);
  end;

  if not IsOk then
  begin
    FreePeBuffer(OutBuf);
    OutBuf := nil;
    OutputSize := 0;
  end;
  Result := OutBuf;
end;

end.
