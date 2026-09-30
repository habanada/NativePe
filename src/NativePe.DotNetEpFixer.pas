{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/fix_dot_net_ep.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.	
}
unit NativePe.DotNetEpFixer;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function FixDotNetEp(PeBuffer: PByte; PeBufferSize: NativeUInt): Boolean;
function SearchJump(Buf: PByte; BufSize: NativeUInt; CorExeMainThunk: DWORD; ImgBase: UInt64): PByte;

implementation

uses
  System.SysUtils,
  System.Generics.Collections,
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.ImportsLoader,
  NativePe.Logger;

type
  TListImportNames = class(TImportThunksCallback)
  private
    FNameToAddr: TDictionary<string, DWORD>;
  public
    constructor Create(AModulePtr: PByte; AModuleSize: NativeUInt; ANameToAddr: TDictionary<string, DWORD>);
    function ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr: NativeUInt; FirstThunkPtr: NativeUInt): Boolean; override;
  end;

constructor TListImportNames.Create(AModulePtr: PByte; AModuleSize: NativeUInt; ANameToAddr: TDictionary<string, DWORD>);
begin
  inherited Create(AModulePtr, AModuleSize);
  FNameToAddr := ANameToAddr;
end;

function TListImportNames.ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr: NativeUInt;
  FirstThunkPtr: NativeUInt): Boolean;
var
  CallViaRva: DWORD;
  IsByOrd: Boolean;
  ByName: PImageImportByName;
  FuncName: PAnsiChar;
  Desc32: PImageThunkData32;
  Desc64: PImageThunkData64;
begin
  Result := True;
  CallViaRva := DWORD(FirstThunkPtr - NativeUInt(FModulePtr));
  LogDebug('via RVA: 0x%x', [CallViaRva]);

  if FIs64B then
  begin
    Desc64 := PImageThunkData64(OrigFirstThunkPtr);
    IsByOrd := (Desc64.Ordinal and IMAGE_ORDINAL_FLAG64) <> 0;
    if IsByOrd then
      Exit;
    ByName := PImageImportByName(NativeUInt(FModulePtr) + Desc64.AddressOfData);
  end
  else
  begin
    Desc32 := PImageThunkData32(OrigFirstThunkPtr);
    IsByOrd := (Desc32.Ordinal and IMAGE_ORDINAL_FLAG32) <> 0;
    if IsByOrd then
      Exit;
    ByName := PImageImportByName(NativeUInt(FModulePtr) + Desc32.AddressOfData);
  end;

  if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
  begin
    LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME');
    Exit(False);
  end;
  FuncName := PAnsiChar(@ByName.Name[0]);
  if not IsValidStringA(FModulePtr, FModuleSize, FuncName) then
  begin
    LogError('Invalid pointer to function name');
    Exit(False);
  end;
  LogDebug('name: %s', [string(AnsiString(FuncName))]);
  FNameToAddr.AddOrSetValue(string(AnsiString(FuncName)), CallViaRva);
end;

function FindCorExeMain(Buf: PByte; BufSize: NativeUInt): DWORD;
var
  NameToAddr: TDictionary<string, DWORD>;
  Callback: TListImportNames;
  Found: DWORD;
begin
  Result := 0;
  NameToAddr := TDictionary<string, DWORD>.Create;
  try
    Callback := TListImportNames.Create(Buf, BufSize, NameToAddr);
    try
      if not ProcessImportTable(Buf, BufSize, Callback) then
        Exit(0);
    finally
      Callback.Free;
    end;
    if NameToAddr.TryGetValue('_CorExeMain', Found) then
      Exit(Found);
    if NameToAddr.TryGetValue('_CorDllMain', Found) then
      Exit(Found);
    Result := 0;
  finally
    NameToAddr.Free;
  end;
end;

function SearchJump(Buf: PByte; BufSize: NativeUInt; CorExeMainThunk: DWORD; ImgBase: UInt64): PByte;
const
  JmpSize = 2;
  JmpPattern: array [0 .. 1] of Byte = ($FF, $25);
var
  ArgSize, EndOffset, I: NativeUInt;
  Addr: PDWORD;
  Rva: DWORD;
begin
  Result := nil;
  ArgSize := SizeOf(DWORD);
  if (NativeUInt(JmpSize) + ArgSize) > BufSize then
    Exit;
  EndOffset := BufSize - (NativeUInt(JmpSize) + ArgSize);

  I := EndOffset;
  while True do
  begin
    if (Buf[I] = JmpPattern[0]) and (Buf[I + 1] = JmpPattern[1]) then
    begin
      Addr := PDWORD(@Buf[I + JmpSize]);
      Rva := DWORD(UInt64(Addr^) - ImgBase);
      if Rva = CorExeMainThunk then
      begin
        LogDebug('Found call to _CorExeMain.');
        Exit(@Buf[I]);
      end
      else
        LogWarning('Mismatch: 0x%x vs _CorExeMain: 0x%x', [Rva, CorExeMainThunk]);
    end;
    if I = 0 then
      Break;
    Dec(I);
  end;
end;

function FixDotNetEp(PeBuffer: PByte; PeBufferSize: NativeUInt): Boolean;
var
  EpRva: DWORD;
  SecHdr: PImageSectionHeader;
  SecPtr: PByte;
  ImgBase: UInt64;
  CorExeMainThunk: DWORD;
  JumpPtr: PByte;
  Offset: NativeUInt;
  IsUpdated: Boolean;
begin
  Result := False;
  if PeBuffer = nil then
    Exit;

  if Is64Bit(PeBuffer) then
    Exit(UpdateEntryPointRva(PeBuffer, 0));

  EpRva := GetEntryPointRva(PeBuffer);
  LogInfo('.NET payload may require Entry Point correction. Current EP: 0x%x', [EpRva]);
  SecHdr := GetSectionHdr(PeBuffer, PeBufferSize, 0);
  if SecHdr = nil then
    Exit;
  SecPtr := PByte(NativeUInt(PeBuffer) + SecHdr.VirtualAddress);
  if not ValidatePtr(PeBuffer, PeBufferSize, SecPtr, SecHdr.SizeOfRawData) then
    Exit;
  ImgBase := GetImageBase(PeBuffer);
  CorExeMainThunk := FindCorExeMain(PeBuffer, PeBufferSize);
  if CorExeMainThunk = 0 then
    Exit;
  JumpPtr := SearchJump(SecPtr, SecHdr.SizeOfRawData, CorExeMainThunk, ImgBase);
  if JumpPtr = nil then
    Exit;
  Offset := NativeUInt(JumpPtr) - NativeUInt(PeBuffer);
  IsUpdated := UpdateEntryPointRva(PeBuffer, DWORD(Offset));
  LogInfo('Found possible Entry Point: 0x%x', [DWORD(Offset)]);
  Result := IsUpdated;
end;

end.
