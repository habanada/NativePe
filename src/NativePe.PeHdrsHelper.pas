{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/pe_hdrs_helper.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PeHdrsHelper;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function RoundUpToUnitD(Size, AUnit: DWORD): DWORD;
function RoundUpToUnitU(Size, AUnit: NativeUInt): NativeUInt;

function GetImageSize(Payload: PByte): DWORD;
function UpdateImageSize(Payload: PByte; NewImgSize: DWORD): Boolean;
function GetNtHdrArchitecture(PeBuffer: PByte): Word;
function Is64Bit(PeBuffer: PByte): Boolean;
function GetNtHdrs(PeBuffer: PByte; BufferSize: NativeUInt = 0; MaxPeOffset: LongInt = PE_PAGE_SIZE): PByte;
function GetNtHdrs32(Payload: PByte): PImageNtHeaders32;
function GetNtHdrs64(Payload: PByte): PImageNtHeaders64;
function GetOptionalHdr(Payload: PByte; BufferSize: NativeUInt): Pointer;
function GetFileHdr(Payload: PByte; BufferSize: NativeUInt): PImageFileHeader;
function GetHdrsSize(PeBuffer: PByte): DWORD;
function GetDirectoryEntry(PeBuffer: PByte; DirId: DWORD; AllowEmpty: Boolean = False): PImageDataDirectory;
function GetTypeDirectoryPtr(ModulePtr: Pointer; DirId: DWORD): Pointer;
function GetExportDirectory(ModulePtr: Pointer): PImageExportDirectory;
function GetImageBase(PeBuffer: PByte): UInt64;
function UpdateImageBase(Payload: PByte; DestImageBase: UInt64): Boolean;
function GetEntryPointRva(PeBuffer: PByte): DWORD;
function UpdateEntryPointRva(PeBuffer: PByte; Ep: DWORD): Boolean;
function GetSectionsCount(Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
function IsValidSectionsHdrOffset(Buffer: PByte; BufferSize: NativeUInt): Boolean;
function GetSectionHdr(PeBuffer: PByte; BufferSize: NativeUInt; SectionNum: NativeUInt): PImageSectionHeader;
function GetFileCharacteristics(Payload: PByte): Word;
function IsModuleDll(Payload: PByte): Boolean;
function IsDotNet(PeBuffer: PByte; PeBufferSize: NativeUInt): Boolean;
function GetDllCharacteristics(Payload: PByte): Word;
function SetSubsystem(Payload: PByte; Subsystem: Word): Boolean;
function GetSubsystem(Payload: PByte): Word;
function HasRelocations(PeBuffer: PByte): Boolean;
function GetDotNetHdr(Module: PByte; ModuleSize: NativeUInt; DotNetDir: PImageDataDirectory): PImageCor20Header;
function GetSecAlignment(ModulePtr: PByte; IsRaw: Boolean): DWORD;
function SetSecAlignment(ModulePtr: PByte; IsRaw: Boolean; NewAlignment: DWORD): Boolean;
function GetVirtualSecSize(PeHdr: PByte; SecHdr: PImageSectionHeader; Rounded: Boolean): DWORD;
function GetLastSection(PeBuffer: PByte; PeSize: NativeUInt; IsRaw: Boolean): PImageSectionHeader;
function CalcPeSize(PeBuffer: PByte; PeSize: NativeUInt; IsRaw: Boolean): DWORD;
function IsValidSectionsAlignment(Payload: PByte; PayloadSize: NativeUInt; IsRaw: Boolean): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.Logger;

function RoundUpToUnitD(Size, AUnit: DWORD): DWORD;
var
  Rem, Addend: DWORD;
begin
  if AUnit = 0 then
    Exit(Size);
  Rem := Size mod AUnit;
  if Rem = 0 then
    Exit(Size);
  Addend := AUnit - Rem;
  if Size > High(DWORD) - Addend then
    Exit(Size);
  Result := Size + Addend;
end;

function RoundUpToUnitU(Size, AUnit: NativeUInt): NativeUInt;
var
  Rem, Addend: NativeUInt;
begin
  if AUnit = 0 then
    Exit(Size);
  Rem := Size mod AUnit;
  if Rem = 0 then
    Exit(Size);
  Addend := AUnit - Rem;
  if Size > High(NativeUInt) - Addend then
    Exit(Size);
  Result := Size + Addend;
end;

function GetNtHdrs(PeBuffer: PByte; BufferSize: NativeUInt; MaxPeOffset: LongInt): PByte;
var
  Idh: PImageDosHeader;
  PeOffset: LongInt;
  Inh: PImageNtHeaders32;
begin
  Result := nil;
  if PeBuffer = nil then
    Exit;
  Idh := PImageDosHeader(PeBuffer);
  if BufferSize <> 0 then
  begin
    if not ValidatePtr(PeBuffer, BufferSize, Idh, SizeOf(TImageDosHeader)) then
      Exit;
  end
  else if IsBadReadPointer(Idh, SizeOf(TImageDosHeader)) then
    Exit;

  if Idh.e_magic <> IMAGE_DOS_SIGNATURE then
    Exit;

  PeOffset := Idh.e_lfanew;
  if (PeOffset < 0) or (PeOffset > MaxPeOffset) then
    Exit;

  Inh := PImageNtHeaders32(PeBuffer + PeOffset);
  if BufferSize <> 0 then
  begin
    if not ValidatePtr(PeBuffer, BufferSize, Inh, SizeOf(TImageNtHeaders32)) then
      Exit;
  end
  else if IsBadReadPointer(Inh, SizeOf(TImageNtHeaders32)) then
    Exit;

  if Inh.Signature <> IMAGE_NT_SIGNATURE then
    Exit;

  Result := PByte(Inh);
end;

function GetNtHdrs32(Payload: PByte): PImageNtHeaders32;
var
  Ptr: PByte;
begin
  Result := nil;
  if Payload = nil then
    Exit;
  Ptr := GetNtHdrs(Payload);
  if Ptr = nil then
    Exit;
  if not Is64Bit(Payload) then
    Result := PImageNtHeaders32(Ptr);
end;

function GetNtHdrs64(Payload: PByte): PImageNtHeaders64;
var
  Ptr: PByte;
begin
  Result := nil;
  if Payload = nil then
    Exit;
  Ptr := GetNtHdrs(Payload);
  if Ptr = nil then
    Exit;
  if Is64Bit(Payload) then
    Result := PImageNtHeaders64(Ptr);
end;

function GetImageSize(Payload: PByte): DWORD;
begin
  Result := 0;
  if GetNtHdrs(Payload) = nil then
    Exit;
  if Is64Bit(Payload) then
    Result := GetNtHdrs64(Payload).OptionalHeader.SizeOfImage
  else
    Result := GetNtHdrs32(Payload).OptionalHeader.SizeOfImage;
end;

function UpdateImageSize(Payload: PByte; NewImgSize: DWORD): Boolean;
begin
  Result := False;
  if GetNtHdrs(Payload) = nil then
    Exit;
  if Is64Bit(Payload) then
    GetNtHdrs64(Payload).OptionalHeader.SizeOfImage := NewImgSize
  else
    GetNtHdrs32(Payload).OptionalHeader.SizeOfImage := NewImgSize;
  Result := True;
end;

function GetNtHdrArchitecture(PeBuffer: PByte): Word;
var
  Ptr: PByte;
  Inh: PImageNtHeaders32;
begin
  Result := 0;
  Ptr := GetNtHdrs(PeBuffer);
  if Ptr = nil then
    Exit;
  Inh := PImageNtHeaders32(Ptr);
  if IsBadReadPointer(Inh, SizeOf(TImageNtHeaders32)) then
    Exit;
  Result := Inh.OptionalHeader.Magic;
end;

function Is64Bit(PeBuffer: PByte): Boolean;
begin
  Result := GetNtHdrArchitecture(PeBuffer) = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
end;

function GetDirectoryEntry(PeBuffer: PByte; DirId: DWORD; AllowEmpty: Boolean): PImageDataDirectory;
var
  NtHeaders: PByte;
  PeDir: PImageDataDirectory;
  NumDirs: DWORD;
begin
  Result := nil;
  if DirId >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES then
    Exit;
  NtHeaders := GetNtHdrs(PeBuffer);
  if NtHeaders = nil then
    Exit;
  if Is64Bit(PeBuffer) then
  begin
    NumDirs := PImageNtHeaders64(NtHeaders).OptionalHeader.NumberOfRvaAndSizes;
    if NumDirs > IMAGE_NUMBEROF_DIRECTORY_ENTRIES then
      NumDirs := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    if DirId >= NumDirs then
      Exit;
    PeDir := @PImageNtHeaders64(NtHeaders).OptionalHeader.DataDirectory[DirId];
  end
  else
  begin
    NumDirs := PImageNtHeaders32(NtHeaders).OptionalHeader.NumberOfRvaAndSizes;
    if NumDirs > IMAGE_NUMBEROF_DIRECTORY_ENTRIES then
      NumDirs := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    if DirId >= NumDirs then
      Exit;
    PeDir := @PImageNtHeaders32(NtHeaders).OptionalHeader.DataDirectory[DirId];
  end;
  if (not AllowEmpty) and (PeDir.VirtualAddress = 0) then
    Exit;
  Result := PeDir;
end;

function GetTypeDirectoryPtr(ModulePtr: Pointer; DirId: DWORD): Pointer;
var
  MyDir: PImageDataDirectory;
  DirAddr: DWORD;
begin
  Result := nil;
  MyDir := GetDirectoryEntry(PByte(ModulePtr), DirId);
  if MyDir = nil then
    Exit;
  DirAddr := MyDir.VirtualAddress;
  if DirAddr = 0 then
    Exit;
  Result := Pointer(NativeUInt(DirAddr) + NativeUInt(ModulePtr));
end;

function GetExportDirectory(ModulePtr: Pointer): PImageExportDirectory;
begin
  Result := PImageExportDirectory(GetTypeDirectoryPtr(ModulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT));
end;

function GetImageBase(PeBuffer: PByte): UInt64;
var
  Is64B: Boolean;
  Hdr: PByte;
begin
  Result := 0;
  Is64B := Is64Bit(PeBuffer);
  Hdr := GetNtHdrs(PeBuffer);
  if Hdr = nil then
    Exit;
  if Is64B then
    Result := PImageNtHeaders64(Hdr).OptionalHeader.ImageBase
  else
    Result := UInt64(PImageNtHeaders32(Hdr).OptionalHeader.ImageBase);
end;

function UpdateImageBase(Payload: PByte; DestImageBase: UInt64): Boolean;
var
  Hdr: PByte;
begin
  Result := False;
  Hdr := GetNtHdrs(Payload);
  if Hdr = nil then
    Exit;
  if Is64Bit(Payload) then
    PImageNtHeaders64(Hdr).OptionalHeader.ImageBase := DestImageBase
  else
    PImageNtHeaders32(Hdr).OptionalHeader.ImageBase := DWORD(DestImageBase);
  Result := True;
end;

function GetEntryPointRva(PeBuffer: PByte): DWORD;
var
  Hdr: PByte;
begin
  Result := 0;
  Hdr := GetNtHdrs(PeBuffer);
  if Hdr = nil then
    Exit;
  if Is64Bit(PeBuffer) then
    Result := PImageNtHeaders64(Hdr).OptionalHeader.AddressOfEntryPoint
  else
    Result := PImageNtHeaders32(Hdr).OptionalHeader.AddressOfEntryPoint;
end;

function UpdateEntryPointRva(PeBuffer: PByte; Ep: DWORD): Boolean;
var
  Hdr: PByte;
begin
  Result := False;
  Hdr := GetNtHdrs(PeBuffer);
  if Hdr = nil then
    Exit;
  if Is64Bit(PeBuffer) then
    PImageNtHeaders64(Hdr).OptionalHeader.AddressOfEntryPoint := Ep
  else
    PImageNtHeaders32(Hdr).OptionalHeader.AddressOfEntryPoint := Ep;
  Result := True;
end;

function GetHdrsSize(PeBuffer: PByte): DWORD;
var
  Hdr: PByte;
begin
  Result := 0;
  Hdr := GetNtHdrs(PeBuffer);
  if Hdr = nil then
    Exit;
  if Is64Bit(PeBuffer) then
    Result := PImageNtHeaders64(Hdr).OptionalHeader.SizeOfHeaders
  else
    Result := PImageNtHeaders32(Hdr).OptionalHeader.SizeOfHeaders;
end;

function InternalFileHdrPtr(Payload: PByte; BufferSize: NativeUInt; NtHdr: PByte): PImageFileHeader;
var
  FileHdr: PImageFileHeader;
begin
  Result := nil;
  if (Payload = nil) or (NtHdr = nil) then
    Exit;
  FileHdr := PImageFileHeader(NtHdr + SizeOf(DWORD));
  if not ValidatePtr(Payload, BufferSize, FileHdr, SizeOf(TImageFileHeader)) then
    Exit;
  Result := FileHdr;
end;

function GetFileHdr(Payload: PByte; BufferSize: NativeUInt): PImageFileHeader;
var
  NtHdr: PByte;
begin
  Result := nil;
  if Payload = nil then
    Exit;
  NtHdr := GetNtHdrs(Payload, BufferSize);
  if NtHdr = nil then
    Exit;
  Result := InternalFileHdrPtr(Payload, BufferSize, NtHdr);
end;

function InternalOptHdrPtr(Payload: PByte; BufferSize: NativeUInt; NtHdr: PByte): Pointer;
var
  FileHdr: PImageFileHeader;
  OptHdr: Pointer;
  OptSize: NativeUInt;
begin
  Result := nil;
  if Payload = nil then
    Exit;
  FileHdr := InternalFileHdrPtr(Payload, BufferSize, NtHdr);
  if FileHdr = nil then
    Exit;
  OptHdr := Pointer(NtHdr + SizeOf(DWORD) + SizeOf(TImageFileHeader));
  OptSize := FileHdr.SizeOfOptionalHeader;
  if not ValidatePtr(Payload, BufferSize, OptHdr, OptSize) then
    Exit;
  Result := OptHdr;
end;

function GetOptionalHdr(Payload: PByte; BufferSize: NativeUInt): Pointer;
var
  NtHdr: PByte;
  FileHdr: PImageFileHeader;
begin
  Result := nil;
  if Payload = nil then
    Exit;
  NtHdr := GetNtHdrs(Payload, BufferSize);
  FileHdr := GetFileHdr(Payload, BufferSize);
  if (NtHdr = nil) or (FileHdr = nil) then
    Exit;
  Result := InternalOptHdrPtr(Payload, BufferSize, NtHdr);
end;

function InternalSectionHdrsPtr(Payload: PByte; BufferSize: NativeUInt; NtHdr: PByte): Pointer;
var
  FileHdr: PImageFileHeader;
  OptHdr: PByte;
  OptSize: NativeUInt;
begin
  Result := nil;
  FileHdr := InternalFileHdrPtr(Payload, BufferSize, NtHdr);
  if FileHdr = nil then
    Exit;
  OptSize := FileHdr.SizeOfOptionalHeader;
  OptHdr := PByte(InternalOptHdrPtr(Payload, BufferSize, NtHdr));
  if not ValidatePtr(Payload, BufferSize, OptHdr, OptSize) then
    Exit;
  Result := OptHdr + OptSize;
end;

function GetSectionsCount(Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
var
  FileHdr: PImageFileHeader;
begin
  Result := 0;
  FileHdr := GetFileHdr(Buffer, BufferSize);
  if FileHdr = nil then
    Exit;
  Result := FileHdr.NumberOfSections;
end;

function IsValidSectionsHdrOffset(Buffer: PByte; BufferSize: NativeUInt): Boolean;
var
  SecCount: NativeUInt;
  LastHdr: PImageSectionHeader;
begin
  Result := False;
  SecCount := GetSectionsCount(Buffer, BufferSize);
  if SecCount = 0 then
    Exit;
  LastHdr := GetSectionHdr(Buffer, BufferSize, SecCount - 1);
  if LastHdr = nil then
    Exit;
  Result := True;
end;

function GetSectionHdr(PeBuffer: PByte; BufferSize: NativeUInt; SectionNum: NativeUInt): PImageSectionHeader;
var
  SectionsCount: NativeUInt;
  NtHdrs: PByte;
  SecPtr: Pointer;
  NextSec: PImageSectionHeader;
begin
  Result := nil;
  if PeBuffer = nil then
    Exit;
  SectionsCount := GetSectionsCount(PeBuffer, BufferSize);
  if SectionNum >= SectionsCount then
    Exit;
  NtHdrs := GetNtHdrs(PeBuffer, BufferSize);
  if NtHdrs = nil then
    Exit;
  SecPtr := InternalSectionHdrsPtr(PeBuffer, BufferSize, NtHdrs);
  NextSec := PImageSectionHeader(NativeUInt(SecPtr) + IMAGE_SIZEOF_SECTION_HEADER * SectionNum);
  if not ValidatePtr(PeBuffer, BufferSize, NextSec, SizeOf(TImageSectionHeader)) then
    Exit;
  Result := NextSec;
end;

function GetFileCharacteristics(Payload: PByte): Word;
var
  Is64B: Boolean;
  Hdr: PByte;
  FileHdr: PImageFileHeader;
begin
  Result := 0;
  if Payload = nil then
    Exit;
  Is64B := Is64Bit(Payload);
  Hdr := GetNtHdrs(Payload);
  if Hdr = nil then
    Exit;
  if Is64B then
    FileHdr := @PImageNtHeaders64(Hdr).FileHeader
  else
    FileHdr := @PImageNtHeaders32(Hdr).FileHeader;
  Result := FileHdr.Characteristics;
end;

function IsModuleDll(Payload: PByte): Boolean;
begin
  if Payload = nil then
    Exit(False);
  Result := (GetFileCharacteristics(Payload) and IMAGE_FILE_DLL) <> 0;
end;

function GetDotNetHdr(Module: PByte; ModuleSize: NativeUInt; DotNetDir: PImageDataDirectory): PImageCor20Header;
var
  Rva, HdrSize: DWORD;
  DnetHdr: PImageCor20Header;
  SignaturePtr: PDWORD;
begin
  Result := nil;
  Rva := DotNetDir.VirtualAddress;
  HdrSize := DotNetDir.Size;
  if not ValidatePtr(Module, ModuleSize, Module + Rva, HdrSize) then
    Exit;
  DnetHdr := PImageCor20Header(Module + Rva);
  if not ValidatePtr(Module, ModuleSize, Module + DnetHdr.MetaData.VirtualAddress, DnetHdr.MetaData.Size) then
    Exit;
  SignaturePtr := PDWORD(Module + DnetHdr.MetaData.VirtualAddress);
  if SignaturePtr^ <> DOTNET_METADATA_SIGNATURE then
    Exit;
  Result := DnetHdr;
end;

function IsDotNet(PeBuffer: PByte; PeBufferSize: NativeUInt): Boolean;
var
  DotnetPtr: PImageDataDirectory;
begin
  Result := False;
  if PeBuffer = nil then
    Exit;
  DotnetPtr := GetDirectoryEntry(PeBuffer, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, False);
  if DotnetPtr = nil then
    Exit;
  Result := GetDotNetHdr(PeBuffer, PeBufferSize, DotnetPtr) <> nil;
end;

function GetDllCharacteristics(Payload: PByte): Word;
var
  Is64B: Boolean;
  Hdr: PByte;
begin
  Result := 0;
  if Payload = nil then
    Exit;
  Is64B := Is64Bit(Payload);
  Hdr := GetNtHdrs(Payload);
  if Hdr = nil then
    Exit;
  if Is64B then
    Result := PImageNtHeaders64(Hdr).OptionalHeader.DllCharacteristics
  else
    Result := PImageNtHeaders32(Hdr).OptionalHeader.DllCharacteristics;
end;

function SetSubsystem(Payload: PByte; Subsystem: Word): Boolean;
var
  Is64B: Boolean;
  Hdr: PByte;
begin
  Result := False;
  if Payload = nil then
    Exit;
  Is64B := Is64Bit(Payload);
  Hdr := GetNtHdrs(Payload);
  if Hdr = nil then
    Exit;
  if Is64B then
    PImageNtHeaders64(Hdr).OptionalHeader.Subsystem := Subsystem
  else
    PImageNtHeaders32(Hdr).OptionalHeader.Subsystem := Subsystem;
  Result := True;
end;

function GetSubsystem(Payload: PByte): Word;
var
  Hdr: PByte;
begin
  Result := 0;
  if Payload = nil then
    Exit;
  Hdr := GetNtHdrs(Payload);
  if Hdr = nil then
    Exit;
  if Is64Bit(Payload) then
    Result := PImageNtHeaders64(Hdr).OptionalHeader.Subsystem
  else
    Result := PImageNtHeaders32(Hdr).OptionalHeader.Subsystem;
end;

function HasRelocations(PeBuffer: PByte): Boolean;
begin
  Result := GetDirectoryEntry(PeBuffer, IMAGE_DIRECTORY_ENTRY_BASERELOC) <> nil;
end;

function InternalSecAlignmentPtr32(ModulePtr: PByte; IsRaw: Boolean): PDWORD;
var
  Hdrs: PImageNtHeaders32;
begin
  Result := nil;
  Hdrs := PImageNtHeaders32(GetNtHdrs(ModulePtr));
  if Hdrs = nil then
    Exit;
  if IsRaw then
    Result := @Hdrs.OptionalHeader.FileAlignment
  else
    Result := @Hdrs.OptionalHeader.SectionAlignment;
end;

function InternalSecAlignmentPtr64(ModulePtr: PByte; IsRaw: Boolean): PDWORD;
var
  Hdrs: PImageNtHeaders64;
begin
  Result := nil;
  Hdrs := PImageNtHeaders64(GetNtHdrs(ModulePtr));
  if Hdrs = nil then
    Exit;
  if IsRaw then
    Result := @Hdrs.OptionalHeader.FileAlignment
  else
    Result := @Hdrs.OptionalHeader.SectionAlignment;
end;

function GetSecAlignment(ModulePtr: PByte; IsRaw: Boolean): DWORD;
var
  Alignment: PDWORD;
begin
  if Is64Bit(ModulePtr) then
    Alignment := InternalSecAlignmentPtr64(ModulePtr, IsRaw)
  else
    Alignment := InternalSecAlignmentPtr32(ModulePtr, IsRaw);
  if Alignment = nil then
    Exit(0);
  Result := Alignment^;
end;

function SetSecAlignment(ModulePtr: PByte; IsRaw: Boolean; NewAlignment: DWORD): Boolean;
var
  Alignment: PDWORD;
begin
  if Is64Bit(ModulePtr) then
    Alignment := InternalSecAlignmentPtr64(ModulePtr, IsRaw)
  else
    Alignment := InternalSecAlignmentPtr32(ModulePtr, IsRaw);
  if Alignment = nil then
    Exit(False);
  Alignment^ := NewAlignment;
  Result := True;
end;

function GetVirtualSecSize(PeHdr: PByte; SecHdr: PImageSectionHeader; Rounded: Boolean): DWORD;
var
  Alignment, Vsize, ImageSize: DWORD;
begin
  Result := 0;
  if (PeHdr = nil) or (SecHdr = nil) then
    Exit;
  if not Rounded then
    Exit(SecHdr.Misc.VirtualSize);
  Alignment := GetSecAlignment(PeHdr, False);
  Vsize := RoundUpToUnitD(SecHdr.Misc.VirtualSize, Alignment);
  ImageSize := GetImageSize(PeHdr);
  if (SecHdr.VirtualAddress + Vsize) > ImageSize then
    Vsize := SecHdr.Misc.VirtualSize;
  Result := Vsize;
end;

function GetLastSection(PeBuffer: PByte; PeSize: NativeUInt; IsRaw: Boolean): PImageSectionHeader;
var
  ModuleEnd: NativeUInt;
  SectionsCount: NativeUInt;
  I: NativeUInt;
  Sec: PImageSectionHeader;
  RawEnd, VirtEnd, NewEnd: NativeUInt;
begin
  Result := nil;
  ModuleEnd := GetHdrsSize(PeBuffer);
  SectionsCount := GetSectionsCount(PeBuffer, PeSize);
  if SectionsCount = 0 then
    Exit;
  for I := 0 to SectionsCount - 1 do
  begin
    Sec := GetSectionHdr(PeBuffer, PeSize, I);
    if Sec = nil then
      Break;
    RawEnd := NativeUInt(Sec.PointerToRawData) + Sec.SizeOfRawData;
    VirtEnd := NativeUInt(Sec.VirtualAddress) + Sec.Misc.VirtualSize;
    if (RawEnd < Sec.PointerToRawData) or (VirtEnd < Sec.VirtualAddress) then
    begin
      LogWarning('Wrap on section [%d] size: exceeding DWORD value', [I]);
      Continue;
    end;
    if IsRaw then
      NewEnd := RawEnd
    else
      NewEnd := VirtEnd;
    if NewEnd > ModuleEnd then
    begin
      ModuleEnd := NewEnd;
      Result := Sec;
    end;
  end;
end;

function CalcPeSize(PeBuffer: PByte; PeSize: NativeUInt; IsRaw: Boolean): DWORD;
var
  ModuleEnd: DWORD;
  SectionsCount: NativeUInt;
  I: NativeUInt;
  Sec: PImageSectionHeader;
  RawEnd, VirtEnd, NewEnd: UInt64;
begin
  ModuleEnd := GetHdrsSize(PeBuffer);
  SectionsCount := GetSectionsCount(PeBuffer, PeSize);
  if SectionsCount = 0 then
    Exit(ModuleEnd);
  for I := 0 to SectionsCount - 1 do
  begin
    Sec := GetSectionHdr(PeBuffer, PeSize, I);
    if Sec = nil then
      Break;
    RawEnd := UInt64(Sec.PointerToRawData) + UInt64(Sec.SizeOfRawData);
    VirtEnd := UInt64(Sec.VirtualAddress) + UInt64(Sec.Misc.VirtualSize);
    if (RawEnd > High(DWORD)) or (VirtEnd > High(DWORD)) then
    begin
      LogWarning('Wrap on section [%d] size: exceeding DWORD value', [I]);
      Continue;
    end;
    if IsRaw then
      NewEnd := RawEnd
    else
      NewEnd := VirtEnd;
    if NewEnd > ModuleEnd then
      ModuleEnd := DWORD(NewEnd);
  end;
  Result := ModuleEnd;
end;

function IsValidSectionsAlignment(Payload: PByte; PayloadSize: NativeUInt; IsRaw: Boolean): Boolean;
var
  MyAlign: DWORD;
  SectionsCount: NativeUInt;
  I: NativeUInt;
  NextSec: PImageSectionHeader;
  NextSecAddr: DWORD;
  SecSize: NativeUInt;
begin
  Result := False;
  if Payload = nil then
    Exit;
  MyAlign := GetSecAlignment(Payload, IsRaw);
  if MyAlign = 0 then
  begin
    LogDebug('Section alignment cannot be 0.');
    Exit;
  end;
  SectionsCount := GetSectionsCount(Payload, PayloadSize);
  if SectionsCount = 0 then
    Exit;
  for I := 0 to SectionsCount - 1 do
  begin
    NextSec := GetSectionHdr(Payload, PayloadSize, I);
    if NextSec = nil then
      Exit(False);
    if IsRaw then
      NextSecAddr := NextSec.PointerToRawData
    else
      NextSecAddr := NextSec.VirtualAddress;
    if IsRaw then
      SecSize := NextSec.SizeOfRawData
    else
      SecSize := NextSec.Misc.VirtualSize;
    if SecSize = 0 then
      Continue;
    if NextSec.Misc.VirtualSize = 0 then
      Continue;
    if NextSecAddr = 0 then
      Exit(False);
    if NextSecAddr mod MyAlign <> 0 then
    begin
      LogDebug('Section is misaligned.');
      Exit(False);
    end;
  end;
  Result := True;
end;

end.
