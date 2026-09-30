{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/buffer_util.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
	
}
unit NativePe.BufferUtil;

interface

uses
  Winapi.Windows,
  NativePe.MemoryProvider;

const
  MAX_DWORD = DWORD($FFFFFFFF);
  MAX_WORD = Word($FFFF);

type
  TUnalignedBuf = PByte;
  TAlignedBuf = PByte;

function MaskToDword(Val: UInt64): DWORD;
function MaskToWord(Val: UInt64): Word;

function ValidatePtr(BufferBgn: Pointer; BufferSize: NativeUInt; FieldBgn: Pointer; FieldSize: NativeUInt): Boolean;

function AllocUnaligned(BufSize: NativeUInt): TUnalignedBuf;
procedure FreeUnaligned(SectionBuffer: TUnalignedBuf);

function AllocAligned(BufferSize: NativeUInt; Protect: DWORD; DesiredBase: Pointer = nil): TAlignedBuf; overload;
function AllocAligned(Provider: TNativePeMemoryProvider; BufferSize: NativeUInt; Protect: DWORD;
  DesiredBase: Pointer = nil): TAlignedBuf; overload;
function FreeAligned(Buffer: TAlignedBuf; BufferSize: NativeUInt = 0): Boolean; overload;
function FreeAligned(Provider: TNativePeMemoryProvider; Buffer: TAlignedBuf; BufferSize: NativeUInt = 0): Boolean; overload;

function AllocPeBuffer(BufferSize: NativeUInt; Protect: DWORD; DesiredBase: Pointer = nil): TAlignedBuf; overload;
function AllocPeBuffer(Provider: TNativePeMemoryProvider; BufferSize: NativeUInt; Protect: DWORD;
  DesiredBase: Pointer = nil): TAlignedBuf; overload;
function FreePeBuffer(Buffer: TAlignedBuf; BufferSize: NativeUInt = 0): Boolean; overload;
function FreePeBuffer(Provider: TNativePeMemoryProvider; Buffer: TAlignedBuf; BufferSize: NativeUInt = 0): Boolean; overload;

implementation

uses
  NativePe.Logger;

function MaskToDword(Val: UInt64): DWORD;
begin
  if Val < MAX_DWORD then
    Result := DWORD(Val and MAX_DWORD)
  else
    Result := MAX_DWORD;
end;

function MaskToWord(Val: UInt64): Word;
begin
  if Val < MAX_WORD then
    Result := Word(Val and MAX_WORD)
  else
    Result := MAX_WORD;
end;

function ValidatePtr(BufferBgn: Pointer; BufferSize: NativeUInt; FieldBgn: Pointer; FieldSize: NativeUInt): Boolean;
var
  StartDelta, AreaSize: NativeUInt;
begin
  if (BufferBgn = nil) or (FieldBgn = nil) then
    Exit(False);
  if NativeUInt(FieldBgn) < NativeUInt(BufferBgn) then
    Exit(False);
  StartDelta := NativeUInt(FieldBgn) - NativeUInt(BufferBgn);

  if FieldSize > High(NativeUInt) - StartDelta then
  begin
    LogWarning('Integer Overflow, limit exceeded! start_delta: %u field_size: %u',
      [StartDelta, FieldSize]);
    Exit(False);
  end;

  AreaSize := StartDelta + FieldSize;
  if AreaSize > BufferSize then
    Exit(False);

  Result := True;
end;

function AllocUnaligned(BufSize: NativeUInt): TUnalignedBuf;
begin
  if BufSize = 0 then
    Exit(nil);
  Result := TUnalignedBuf(AllocMem(BufSize));
end;

procedure FreeUnaligned(SectionBuffer: TUnalignedBuf);
begin
  if SectionBuffer <> nil then
    FreeMem(SectionBuffer);
end;

function AllocAligned(BufferSize: NativeUInt; Protect: DWORD; DesiredBase: Pointer): TAlignedBuf;
begin
  Result := AllocAligned(GetWinApiMemoryProvider, BufferSize, Protect, DesiredBase);
end;

function AllocAligned(Provider: TNativePeMemoryProvider; BufferSize: NativeUInt; Protect: DWORD;
  DesiredBase: Pointer): TAlignedBuf;
var
  ErrorCode: DWORD;
begin
  Result := nil;
  if (Provider = nil) or (BufferSize = 0) then
    Exit;
  Result := TAlignedBuf(Provider.AllocLocal(DesiredBase, BufferSize, MEM_COMMIT or MEM_RESERVE, Protect, ErrorCode));
  if Result = nil then
    SetLastError(ErrorCode);
end;

function FreeAligned(Buffer: TAlignedBuf; BufferSize: NativeUInt): Boolean;
begin
  Result := FreeAligned(GetWinApiMemoryProvider, Buffer, BufferSize);
end;

function FreeAligned(Provider: TNativePeMemoryProvider; Buffer: TAlignedBuf; BufferSize: NativeUInt): Boolean;
var
  ErrorCode: DWORD;
begin
  if Buffer = nil then
    Exit(True);
  if Provider = nil then
    Exit(False);
  if not Provider.FreeLocal(Buffer, 0, MEM_RELEASE, ErrorCode) then
  begin
    SetLastError(ErrorCode);
    LogError('VirtualFree failed.');
    Exit(False);
  end;
  Result := True;
end;

function AllocPeBuffer(BufferSize: NativeUInt; Protect: DWORD; DesiredBase: Pointer): TAlignedBuf;
begin
  Result := AllocAligned(BufferSize, Protect, DesiredBase);
end;

function AllocPeBuffer(Provider: TNativePeMemoryProvider; BufferSize: NativeUInt; Protect: DWORD;
  DesiredBase: Pointer): TAlignedBuf;
begin
  Result := AllocAligned(Provider, BufferSize, Protect, DesiredBase);
end;

function FreePeBuffer(Buffer: TAlignedBuf; BufferSize: NativeUInt): Boolean;
begin
  Result := FreeAligned(Buffer, BufferSize);
end;

function FreePeBuffer(Provider: TNativePeMemoryProvider; Buffer: TAlignedBuf; BufferSize: NativeUInt): Boolean;
begin
  Result := FreeAligned(Provider, Buffer, BufferSize);
end;

end.
