{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/remote_pe_reader.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.RemotePeReader;

interface

uses
  Winapi.Windows,
  NativePe.BufferUtil,
  NativePe.MemoryProvider,
  NativePe.PeDumper,
  NativePe.ExportsMapper;

const
  MAX_HEADER_SIZE = $1000;

function FetchRegionInfo(ProcessHandle: THandle; StartAddr: Pointer; out PageInfo: TMemoryBasicInformation): Boolean; overload;
function FetchRegionInfo(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer;
  out PageInfo: TMemoryBasicInformation): Boolean; overload;
function FetchRegionSize(ProcessHandle: THandle; StartAddr: Pointer): NativeUInt; overload;
function FetchRegionSize(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer): NativeUInt; overload;
function FetchAllocBase(ProcessHandle: THandle; StartAddr: Pointer): UInt64; overload;
function FetchAllocBase(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer): UInt64; overload;
function ReadRemoteMemory(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  MinimalSize: NativeUInt = $100): NativeUInt; overload;
function ReadRemoteMemory(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; MinimalSize: NativeUInt = $100): NativeUInt; overload;
function ReadRemoteRegion(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  ForceAccess: Boolean; MinimalSize: NativeUInt = $100): NativeUInt; overload;
function ReadRemoteRegion(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; ForceAccess: Boolean; MinimalSize: NativeUInt = $100): NativeUInt; overload;
function ReadRemoteArea(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  ForceAccess: Boolean; MinimalSize: NativeUInt = $100): NativeUInt; overload;
function ReadRemoteArea(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; ForceAccess: Boolean; MinimalSize: NativeUInt = $100): NativeUInt; overload;
function ReadRemotePeHeader(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  ForceAccess: Boolean = False): Boolean; overload;
function ReadRemotePeHeader(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; ForceAccess: Boolean = False): Boolean; overload;
function GetRemotePeSection(ProcessHandle: THandle; StartAddr: Pointer; SectionNum: NativeUInt;
  out SectionSize: NativeUInt; Roundup: Boolean; ForceAccess: Boolean = False): TUnalignedBuf; overload;
function GetRemotePeSection(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer;
  SectionNum: NativeUInt; out SectionSize: NativeUInt; Roundup: Boolean; ForceAccess: Boolean = False): TUnalignedBuf; overload;
function ReadRemotePe(ProcessHandle: THandle; StartAddr: Pointer; ModSize: NativeUInt; Buffer: PByte;
  BufferSize: NativeUInt): NativeUInt; overload;
function ReadRemotePe(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; ModSize: NativeUInt;
  Buffer: PByte; BufferSize: NativeUInt): NativeUInt; overload;
function GetRemoteImageSize(ProcessHandle: THandle; StartAddr: Pointer): DWORD; overload;
function GetRemoteImageSize(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer): DWORD; overload;
function DumpRemotePe(const OutPath: string; ProcessHandle: THandle; StartAddr: Pointer;
  var DumpMode: TPeDumpMode; ExportsMap: TExportsMapper = nil): Boolean; overload;
function DumpRemotePe(Provider: TNativePeMemoryProvider; const OutPath: string; ProcessHandle: THandle; StartAddr: Pointer;
  var DumpMode: TPeDumpMode; ExportsMap: TExportsMapper = nil): Boolean; overload;

implementation

uses
  NativePe.Types,
  NativePe.PeHdrsHelper,
  NativePe.Logger;

function FetchRegionInfo(ProcessHandle: THandle; StartAddr: Pointer; out PageInfo: TMemoryBasicInformation): Boolean;
begin
  Result := FetchRegionInfo(GetWinApiMemoryProvider, ProcessHandle, StartAddr, PageInfo);
end;

function FetchRegionInfo(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer;
  out PageInfo: TMemoryBasicInformation): Boolean;
var
  ErrorCode: DWORD;
begin
  FillChar(PageInfo, SizeOf(PageInfo), 0);
  if Provider = nil then
    Exit(False);
  Result := Provider.QueryProcess(ProcessHandle, StartAddr, PageInfo, ErrorCode);
  if not Result then
    SetLastError(ErrorCode);
end;

function InternalFetchRegionSize(const PageInfo: TMemoryBasicInformation; StartAddr: Pointer): NativeUInt;
var
  Offset: NativeUInt;
begin
  Result := 0;
 if PageInfo.Type_9  = 0 then
    Exit;
  if NativeUInt(PageInfo.BaseAddress) > NativeUInt(StartAddr) then
    Exit;
  Offset := NativeUInt(StartAddr) - NativeUInt(PageInfo.BaseAddress);
  if PageInfo.RegionSize < Offset then
    Exit;
  Result := PageInfo.RegionSize - Offset;
end;

function FetchRegionSize(ProcessHandle: THandle; StartAddr: Pointer): NativeUInt;
begin
  Result := FetchRegionSize(GetWinApiMemoryProvider, ProcessHandle, StartAddr);
end;

function FetchRegionSize(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer): NativeUInt;
var
  PageInfo: TMemoryBasicInformation;
begin
  Result := 0;
  if not FetchRegionInfo(Provider, ProcessHandle, StartAddr, PageInfo) then
    Exit;
  Result := InternalFetchRegionSize(PageInfo, StartAddr);
end;

function FetchAllocBase(ProcessHandle: THandle; StartAddr: Pointer): UInt64;
begin
  Result := FetchAllocBase(GetWinApiMemoryProvider, ProcessHandle, StartAddr);
end;

function FetchAllocBase(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer): UInt64;
var
  PageInfo: TMemoryBasicInformation;
begin
  Result := 0;
  if not FetchRegionInfo(Provider, ProcessHandle, StartAddr, PageInfo) then
    Exit;
  if PageInfo.Type_9  = 0 then
    Exit;
  Result := UInt64(NativeUInt(PageInfo.AllocationBase));
end;

function SearchReadableSize(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; MinimalSize: NativeUInt): NativeUInt;
var
  LastFailedSize, LastSuccessSize, TestReadSize, ReadSize, ToReadSize, Delta: NativeUInt;
  ErrorCode: DWORD;
begin
  Result := 0;
  if (Buffer = nil) or (BufferSize = 0) then
    Exit;
  if (BufferSize < MinimalSize) or (MinimalSize = 0) then
    Exit;

  LastFailedSize := BufferSize;
  LastSuccessSize := 0;

  TestReadSize := 0;
  if not Provider.ReadProcess(ProcessHandle, StartAddr, Buffer, MinimalSize, TestReadSize, ErrorCode) then
    Exit(TestReadSize);
  LastSuccessSize := MinimalSize;

  ReadSize := 0;
  ToReadSize := BufferSize div 2;

  while (ToReadSize > MinimalSize) and (ToReadSize < BufferSize) do
  begin
    ReadSize := 0;
    if Provider.ReadProcess(ProcessHandle, StartAddr, Buffer, ToReadSize, ReadSize, ErrorCode) then
      LastSuccessSize := ToReadSize
    else
      LastFailedSize := ToReadSize;
    Delta := (LastFailedSize - LastSuccessSize) div 2;
    if Delta = 0 then
      Break;
    ToReadSize := LastSuccessSize + Delta;
  end;

  if LastSuccessSize <> 0 then
  begin
    ReadSize := 0;
    FillChar(Buffer^, BufferSize, 0);
    if Provider.ReadProcess(ProcessHandle, StartAddr, Buffer, LastSuccessSize, ReadSize, ErrorCode) then
      Exit(ReadSize);
  end;
  Result := 0;
end;

function ReadRemoteMemory(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  MinimalSize: NativeUInt): NativeUInt;
begin
  Result := ReadRemoteMemory(GetWinApiMemoryProvider, ProcessHandle, StartAddr, Buffer, BufferSize, MinimalSize);
end;

function ReadRemoteMemory(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; MinimalSize: NativeUInt): NativeUInt;
var
  LastError: DWORD;
  ReadSize: NativeUInt;
begin
  Result := 0;
  if (Provider = nil) or (Buffer = nil) or (BufferSize = 0) then
    Exit;
  FillChar(Buffer^, BufferSize, 0);
  LastError := 0;

  ReadSize := 0;
  if not Provider.ReadProcess(ProcessHandle, StartAddr, Buffer, BufferSize, ReadSize, LastError) then
  begin
    SetLastError(LastError);
    if LastError = ERROR_PARTIAL_COPY then
    begin
      ReadSize := SearchReadableSize(Provider, ProcessHandle, StartAddr, Buffer, BufferSize, MinimalSize);
      LogDebug('search_readable_size res: 0x%x.', [ReadSize]);
    end;
  end;

  if ReadSize = 0 then
    LogWarning('Cannot read memory. Last Error: %u.', [LastError])
  else if ReadSize < BufferSize then
    LogWarning('Read size: 0x%x is smaller than requested: 0x%x. Last Error: %u.', [ReadSize, BufferSize, LastError]);

  Result := ReadSize;
end;

function ReadRemoteRegion(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  ForceAccess: Boolean; MinimalSize: NativeUInt): NativeUInt;
begin
  Result := ReadRemoteRegion(GetWinApiMemoryProvider, ProcessHandle, StartAddr, Buffer, BufferSize, ForceAccess, MinimalSize);
end;

function ReadRemoteRegion(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; ForceAccess: Boolean; MinimalSize: NativeUInt): NativeUInt;
var
  PageInfo: TMemoryBasicInformation;
  RegionSize, SizeToRead: NativeUInt;
  IsAccessible, AccessChanged: Boolean;
  OldProtect, RestoreProtect: DWORD;
  SizeRead: NativeUInt;
  Err: DWORD;
begin
  Result := 0;
  if (Provider = nil) or (Buffer = nil) or (BufferSize = 0) then
    Exit;
  if not FetchRegionInfo(Provider, ProcessHandle, StartAddr, PageInfo) then
    Exit;
  if (PageInfo.State and MEM_COMMIT) = 0 then
    Exit;
  RegionSize := InternalFetchRegionSize(PageInfo, StartAddr);
  if RegionSize = 0 then
    Exit;

  if RegionSize > BufferSize then
    SizeToRead := BufferSize
  else
    SizeToRead := RegionSize;

  IsAccessible := (PageInfo.Protect and PAGE_NOACCESS) = 0;
  AccessChanged := False;
  OldProtect := 0;

  if ForceAccess and (not IsAccessible) then
  begin
    AccessChanged := Provider.ProtectProcess(ProcessHandle, StartAddr, RegionSize, PAGE_READONLY, OldProtect, Err);
    if not AccessChanged then
    begin
      SetLastError(Err);
      if Err <> ERROR_ACCESS_DENIED then
        LogWarning('0x%x : 0x%x inaccessible area, changing page access failed: %u.',
          [NativeUInt(StartAddr), RegionSize, Err]);
    end;
  end;

  SizeRead := 0;
  if IsAccessible or AccessChanged then
  begin
    SizeRead := ReadRemoteMemory(Provider, ProcessHandle, StartAddr, Buffer, SizeToRead, MinimalSize);
    if (SizeRead = 0) and ((PageInfo.Protect and PAGE_GUARD) <> 0) then
    begin
      LogDebug('Guarded page, trying to read again.');
      SizeRead := ReadRemoteMemory(Provider, ProcessHandle, StartAddr, Buffer, SizeToRead, MinimalSize);
    end;
  end;

  if AccessChanged then
  begin
    if not Provider.ProtectProcess(ProcessHandle, StartAddr, RegionSize, OldProtect, RestoreProtect, Err) then
      LogWarning('Failed to restore protection of region: 0x%x.', [NativeUInt(StartAddr)]);
  end;

  Result := SizeRead;
end;

function ReadRemoteArea(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  ForceAccess: Boolean; MinimalSize: NativeUInt): NativeUInt;
begin
  Result := ReadRemoteArea(GetWinApiMemoryProvider, ProcessHandle, StartAddr, Buffer, BufferSize, ForceAccess, MinimalSize);
end;

function ReadRemoteArea(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; ForceAccess: Boolean; MinimalSize: NativeUInt): NativeUInt;
var
  RealRead, LastValid, BufIndex: NativeUInt;
  RemoteChunk: Pointer;
  PageInfo: TMemoryBasicInformation;
  RegionSize, ReadChunk: NativeUInt;
begin
  Result := 0;
  if (Provider = nil) or (Buffer = nil) or (StartAddr = nil) or (BufferSize = 0) then
    Exit;
  FillChar(Buffer^, BufferSize, 0);

  RealRead := 0;
  LastValid := 0;
  BufIndex := 0;

  while BufIndex < BufferSize do
  begin
    RemoteChunk := Pointer(NativeUInt(StartAddr) + BufIndex);

    if not FetchRegionInfo(Provider, ProcessHandle, RemoteChunk, PageInfo) then
      Break;
    RegionSize := InternalFetchRegionSize(PageInfo, RemoteChunk);
    if RegionSize = 0 then
      Break;

    ReadChunk := ReadRemoteRegion(Provider, ProcessHandle, RemoteChunk, PByte(NativeUInt(Buffer) + BufIndex),
      BufferSize - BufIndex, ForceAccess, MinimalSize);
    if ReadChunk = 0 then
    begin
      Inc(BufIndex, RegionSize);
      Continue;
    end;
    Inc(BufIndex, ReadChunk);
    Inc(RealRead, ReadChunk);
    LastValid := BufIndex;
  end;
  if RealRead = 0 then
    Exit(0);
  Result := LastValid;
end;

function ReadRemotePeHeader(ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte; BufferSize: NativeUInt;
  ForceAccess: Boolean): Boolean;
begin
  Result := ReadRemotePeHeader(GetWinApiMemoryProvider, ProcessHandle, StartAddr, Buffer, BufferSize, ForceAccess);
end;

function ReadRemotePeHeader(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; Buffer: PByte;
  BufferSize: NativeUInt; ForceAccess: Boolean): Boolean;
var
  ReadSize: NativeUInt;
  NtPtr: PByte;
  NtOffset, NtSize, MinSize: NativeUInt;
begin
  Result := False;
  if (Provider = nil) or (Buffer = nil) then
    Exit;
  ReadSize := ReadRemoteArea(Provider, ProcessHandle, StartAddr, Buffer, BufferSize, ForceAccess);
  if ReadSize = 0 then
    Exit;
  NtPtr := GetNtHdrs(Buffer, BufferSize);
  if NtPtr = nil then
    Exit;
  NtOffset := NativeUInt(NtPtr) - NativeUInt(Buffer);
  if Is64Bit(Buffer) then
    NtSize := SizeOf(TImageNtHeaders64)
  else
    NtSize := SizeOf(TImageNtHeaders32);
  MinSize := NtOffset + NtSize;

  if ReadSize < MinSize then
  begin
    LogError('[PID %u][0x%x] Read size: 0x%x is smaller than the minimal size: 0x%x.',
      [GetProcessId(ProcessHandle), NativeUInt(StartAddr), ReadSize, GetHdrsSize(Buffer)]);
    Exit;
  end;
  Result := True;
end;

function GetRemotePeSection(ProcessHandle: THandle; StartAddr: Pointer; SectionNum: NativeUInt;
  out SectionSize: NativeUInt; Roundup: Boolean; ForceAccess: Boolean): TUnalignedBuf;
begin
  Result := GetRemotePeSection(GetWinApiMemoryProvider, ProcessHandle, StartAddr, SectionNum, SectionSize, Roundup, ForceAccess);
end;

function GetRemotePeSection(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer;
  SectionNum: NativeUInt; out SectionSize: NativeUInt; Roundup: Boolean; ForceAccess: Boolean): TUnalignedBuf;
var
  HeaderBuffer: array [0 .. MAX_HEADER_SIZE - 1] of Byte;
  SectionHdr: PImageSectionHeader;
  BufferSize: NativeUInt;
  Va: DWORD;
  ModuleCode: TUnalignedBuf;
  ReadSize: NativeUInt;
begin
  Result := nil;
  SectionSize := 0;
  if Provider = nil then
    Exit;
  FillChar(HeaderBuffer, SizeOf(HeaderBuffer), 0);

  if not ReadRemotePeHeader(Provider, ProcessHandle, StartAddr, @HeaderBuffer[0], MAX_HEADER_SIZE, ForceAccess) then
    Exit;
  SectionHdr := GetSectionHdr(@HeaderBuffer[0], MAX_HEADER_SIZE, SectionNum);
  if (SectionHdr = nil) or (SectionHdr.Misc.VirtualSize = 0) then
    Exit;

  BufferSize := SectionHdr.Misc.VirtualSize;
  if Roundup then
  begin
    Va := GetSecAlignment(@HeaderBuffer[0], False);
    if Va = 0 then
      Va := PE_PAGE_SIZE;
    BufferSize := RoundUpToUnitU(SectionHdr.Misc.VirtualSize, Va);
  end;

  ModuleCode := AllocUnaligned(BufferSize);
  if ModuleCode = nil then
    Exit;

  ReadSize := ReadRemoteMemory(Provider, ProcessHandle, Pointer(NativeUInt(StartAddr) + SectionHdr.VirtualAddress), ModuleCode,
    BufferSize);
  if ReadSize = 0 then
    ReadSize := ReadRemoteArea(Provider, ProcessHandle, Pointer(NativeUInt(StartAddr) + SectionHdr.VirtualAddress), ModuleCode,
      BufferSize, ForceAccess);
  if ReadSize = 0 then
  begin
    FreeUnaligned(ModuleCode);
    Exit;
  end;

  SectionSize := BufferSize;
  Result := ModuleCode;
end;

function ReadRemotePe(ProcessHandle: THandle; StartAddr: Pointer; ModSize: NativeUInt; Buffer: PByte;
  BufferSize: NativeUInt): NativeUInt;
begin
  Result := ReadRemotePe(GetWinApiMemoryProvider, ProcessHandle, StartAddr, ModSize, Buffer, BufferSize);
end;

function ReadRemotePe(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer; ModSize: NativeUInt;
  Buffer: PByte; BufferSize: NativeUInt): NativeUInt;
var
  HdrBuffer: PByte;
  SectionsCount, I: NativeUInt;
  Hdr: PImageSectionHeader;
  SecVa, SecVSize: DWORD;
  ReadSize, NewEnd, DummySize: NativeUInt;
begin
  Result := 0;
  if Provider = nil then
    Exit;
  if Buffer = nil then
  begin
    LogError('Invalid output buffer: NULL pointer.');
    Exit;
  end;
  if (BufferSize < ModSize) or (BufferSize < NativeUInt(MAX_HEADER_SIZE)) then
  begin
    LogError('Invalid output buffer: size too small.');
    Exit;
  end;

  HdrBuffer := Buffer;
  if not ReadRemotePeHeader(Provider, ProcessHandle, StartAddr, HdrBuffer, MAX_HEADER_SIZE, False) then
  begin
    LogError('Failed to read the module header.');
    Exit;
  end;
  if not IsValidSectionsHdrOffset(HdrBuffer, MAX_HEADER_SIZE) then
  begin
    LogError('Section headers are invalid or atypically aligned.');
    Exit;
  end;
  SectionsCount := GetSectionsCount(HdrBuffer, MAX_HEADER_SIZE);
  LogDebug('Sections: %u.', [SectionsCount]);
  ReadSize := MAX_HEADER_SIZE;

  I := 0;
  while I < SectionsCount do
  begin
    Hdr := GetSectionHdr(HdrBuffer, MAX_HEADER_SIZE, I);
    if Hdr = nil then
    begin
      LogError('Failed to read the header of section: %u.', [I]);
      Break;
    end;
    SecVa := Hdr.VirtualAddress;
    SecVSize := GetVirtualSecSize(HdrBuffer, Hdr, True);
    if (NativeUInt(SecVa) + NativeUInt(SecVSize)) > BufferSize then
    begin
      LogError('No more space in the buffer.');
      Break;
    end;
    if SecVSize > 0 then
    begin
      DummySize := ReadRemoteMemory(Provider, ProcessHandle, Pointer(NativeUInt(StartAddr) + SecVa),
        PByte(NativeUInt(Buffer) + SecVa), SecVSize);
      if DummySize = 0 then
        LogWarning('Failed to read module section %u at 0x%x.', [I, NativeUInt(StartAddr) + SecVa]);
    end;
    NewEnd := NativeUInt(SecVa) + NativeUInt(SecVSize);
    if NewEnd > ReadSize then
      ReadSize := NewEnd;
    Inc(I);
  end;
  LogDebug('Total read size: %u.', [ReadSize]);
  Result := ReadSize;
end;

function GetRemoteImageSize(ProcessHandle: THandle; StartAddr: Pointer): DWORD;
begin
  Result := GetRemoteImageSize(GetWinApiMemoryProvider, ProcessHandle, StartAddr);
end;

function GetRemoteImageSize(Provider: TNativePeMemoryProvider; ProcessHandle: THandle; StartAddr: Pointer): DWORD;
var
  HdrBuffer: array [0 .. MAX_HEADER_SIZE - 1] of Byte;
begin
  Result := 0;
  if Provider = nil then
    Exit;
  FillChar(HdrBuffer, SizeOf(HdrBuffer), 0);
  if not ReadRemotePeHeader(Provider, ProcessHandle, StartAddr, @HdrBuffer[0], MAX_HEADER_SIZE, False) then
    Exit;
  Result := GetImageSize(@HdrBuffer[0]);
end;

function DumpRemotePe(const OutPath: string; ProcessHandle: THandle; StartAddr: Pointer;
  var DumpMode: TPeDumpMode; ExportsMap: TExportsMapper): Boolean;
begin
  Result := DumpRemotePe(GetWinApiMemoryProvider, OutPath, ProcessHandle, StartAddr, DumpMode, ExportsMap);
end;

function DumpRemotePe(Provider: TNativePeMemoryProvider; const OutPath: string; ProcessHandle: THandle; StartAddr: Pointer;
  var DumpMode: TPeDumpMode; ExportsMap: TExportsMapper): Boolean;
var
  ModSize: DWORD;
  Buffer: TAlignedBuf;
  ReadSize: NativeUInt;
  IsDumped: Boolean;
begin
  Result := False;
  if Provider = nil then
    Exit;
  ModSize := GetRemoteImageSize(Provider, ProcessHandle, StartAddr);
  LogDebug('Module size: %u.', [ModSize]);
  if ModSize = 0 then
    Exit;

  Buffer := AllocPeBuffer(Provider, ModSize, PAGE_READWRITE);
  if Buffer = nil then
  begin
    LogError('Failed allocating buffer. Error: %u.', [GetLastError]);
    Exit;
  end;

  ReadSize := ReadRemotePe(Provider, ProcessHandle, StartAddr, ModSize, Buffer, ModSize);
  if ReadSize = 0 then
  begin
    LogError('Failed reading module. Error: %u.', [GetLastError]);
    FreePeBuffer(Provider, Buffer, ModSize);
    Exit;
  end;

  IsDumped := DumpPe(OutPath, Buffer, ModSize, UInt64(NativeUInt(StartAddr)), DumpMode, ExportsMap);

  FreePeBuffer(Provider, Buffer, ModSize);
  Result := IsDumped;
end;

end.
