{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/pe_raw_to_virtual.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PeRawToVirtual;

interface

uses
  Winapi.Windows,
  NativePe.Types,
  NativePe.BufferUtil;

function PeRawToVirtual(RawPeBuffer: PByte; RawPeSize: NativeUInt; out OutputSize: NativeUInt; Executable: Boolean = True;
  DesiredBase: NativeUInt = 0): TAlignedBuf;

implementation

uses
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.Logger;

function SectionsRawToVirtual(Payload: PByte; PayloadSize: NativeUInt; DestBuffer: PByte; DestBufferSize: NativeUInt): Boolean;
var
  PayloadNtHdr: PByte;
  Is64B: Boolean;
  FileHdr: PImageFileHeader;
  HdrsSize: DWORD;
  SecPtr: Pointer;
  SectionsCount, I: NativeUInt;
  NextSec: PImageSectionHeader;
  NextSecDest: PByte;
  SectionMapped, SectionRawPtr: PByte;
  SecSize: NativeUInt;
  FirstRaw: DWORD;
begin
  Result := False;
  if (Payload = nil) or (DestBuffer = nil) then
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
  FirstRaw := 0;
  SectionsCount := FileHdr.NumberOfSections;
  I := 0;
  while I < SectionsCount do
  begin
    NextSec := PImageSectionHeader(NativeUInt(SecPtr) + NativeUInt(IMAGE_SIZEOF_SECTION_HEADER) * I);
    if not ValidatePtr(Payload, PayloadSize, NextSec, IMAGE_SIZEOF_SECTION_HEADER) then
      Exit(False);
    NextSecDest := DestBuffer + (NativeUInt(NextSec) - NativeUInt(Payload));
    if not ValidatePtr(DestBuffer, DestBufferSize, NextSecDest, IMAGE_SIZEOF_SECTION_HEADER) then
      Exit(False);
    if (NextSec.PointerToRawData = 0) or (NextSec.SizeOfRawData = 0) then
    begin
      Inc(I);
      Continue;
    end;
    SectionMapped := DestBuffer + NextSec.VirtualAddress;
    SectionRawPtr := Payload + NextSec.PointerToRawData;
    SecSize := NextSec.SizeOfRawData;

    if (NativeUInt(NextSec.VirtualAddress) + SecSize) > DestBufferSize then
    begin
      if DestBufferSize > NextSec.VirtualAddress then
        SecSize := DestBufferSize - NextSec.VirtualAddress
      else
        SecSize := 0;
      LogWarning('Section %u: virtual size exceeds buffer, truncating to 0x%x (buffer: 0x%x).',
        [I, SecSize, DestBufferSize]);
    end;
    if (NativeUInt(NextSec.VirtualAddress) >= DestBufferSize) and (SecSize <> 0) then
    begin
      LogError('Section %u: VirtualAddress 0x%x is out of bounds.', [I, NextSec.VirtualAddress]);
      Exit(False);
    end;
    if not ValidatePtr(Payload, PayloadSize, SectionRawPtr, SecSize) then
    begin
      if NextSec.PointerToRawData > PayloadSize then
      begin
        LogWarning('Section %u: PointerToRawData out of bounds, skipping.', [I]);
        Inc(I);
        Continue;
      end;
      SecSize := PayloadSize - NextSec.PointerToRawData;
    end;
    if not ValidatePtr(DestBuffer, DestBufferSize, SectionMapped, SecSize) then
    begin
      LogWarning('Section %u: destination out of bounds, skipping.', [I]);
      Inc(I);
      Continue;
    end;
    Move(SectionRawPtr^, SectionMapped^, SecSize);
    if (FirstRaw = 0) or (NextSec.PointerToRawData < FirstRaw) then
      FirstRaw := NextSec.PointerToRawData;
    Inc(I);
  end;

  if HdrsSize = 0 then
  begin
    HdrsSize := FirstRaw;
    LogInfo('SizeOfHeaders not set, using first section raw offset as fallback: 0x%x.', [HdrsSize]);
  end;
  if not ValidatePtr(Payload, PayloadSize, Payload, HdrsSize) then
    Exit(False);
  if HdrsSize > DestBufferSize then
    Exit(False);
  Move(Payload^, DestBuffer^, HdrsSize);
  Result := True;
end;

function PeRawToVirtual(RawPeBuffer: PByte; RawPeSize: NativeUInt; out OutputSize: NativeUInt; Executable: Boolean;
  DesiredBase: NativeUInt): TAlignedBuf;
var
  NtHdr: PByte;
  PayloadImageSize: DWORD;
  Is64: Boolean;
  Protect: DWORD;
  LocalCopyAddress: TAlignedBuf;
begin
  Result := nil;
  OutputSize := 0;
  NtHdr := GetNtHdrs(RawPeBuffer, RawPeSize);
  if NtHdr = nil then
  begin
    LogError('Invalid PE at 0x%x.', [NativeUInt(RawPeBuffer)]);
    Exit;
  end;
  Is64 := Is64Bit(RawPeBuffer);
  if Is64 then
    PayloadImageSize := PImageNtHeaders64(NtHdr).OptionalHeader.SizeOfImage
  else
    PayloadImageSize := PImageNtHeaders32(NtHdr).OptionalHeader.SizeOfImage;
  PayloadImageSize := RoundUpToUnitD(PayloadImageSize, PE_PAGE_SIZE);

  if Executable then
    Protect := PAGE_EXECUTE_READWRITE
  else
    Protect := PAGE_READWRITE;
  LocalCopyAddress := AllocPeBuffer(PayloadImageSize, Protect, Pointer(DesiredBase));
  if LocalCopyAddress = nil then
  begin
    LogError('Could not allocate memory in the current process.');
    Exit;
  end;
  LogDebug('Allocated local memory: 0x%x size: %x', [NativeUInt(LocalCopyAddress), PayloadImageSize]);
  if not SectionsRawToVirtual(RawPeBuffer, RawPeSize, LocalCopyAddress, PayloadImageSize) then
  begin
    LogError('Could not copy PE file into virtual buffer.');
    FreePeBuffer(LocalCopyAddress);
    Exit;
  end;
  OutputSize := PayloadImageSize;
  Result := LocalCopyAddress;
end;

end.
