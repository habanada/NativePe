{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/file_util.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.FileUtil;

interface

uses
  Winapi.Windows,
  NativePe.BufferUtil;

function LoadFile(const FileName: string; var ReadSize: NativeUInt): TUnalignedBuf;
function ReadFromFile(const InPath: string; var ReadSize: NativeUInt): TUnalignedBuf;
function DumpToFile(const OutPath: string; DumpData: PByte; DumpSize: NativeUInt): Boolean;
procedure FreeFile(Buffer: TUnalignedBuf);

function GetFileNamePart(const FullPath: string): string;
function GetDirectoryNamePart(const FullPath: string): string;
function FindExtensionPos(const S: string): Integer;

implementation

uses
  System.SysUtils,
  NativePe.Util,
  NativePe.Logger;

function LoadFile(const FileName: string; var ReadSize: NativeUInt): TUnalignedBuf;
var
  HFile, HMapping: THandle;
  DllRawData: PByte;
  RSize: NativeUInt;
  LocalCopy: TUnalignedBuf;
begin
  Result := nil;
  HFile := CreateFile(PChar(FileName), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if HFile = INVALID_HANDLE_VALUE then
  begin
    LogError('Could not open file.');
    Exit;
  end;
  HMapping := CreateFileMapping(HFile, nil, PAGE_READONLY, 0, 0, nil);
  if HMapping = 0 then
  begin
    LogError('Could not create file mapping.');
    CloseHandle(HFile);
    Exit;
  end;
  DllRawData := MapViewOfFile(HMapping, FILE_MAP_READ, 0, 0, 0);
  if DllRawData = nil then
  begin
    LogError('Could not map view of file.');
    CloseHandle(HMapping);
    CloseHandle(HFile);
    Exit;
  end;
  RSize := GetFileSize(HFile, nil);
  if RSize = INVALID_FILE_SIZE then
  begin
    LogError('Cannot retrieve file size.');
    UnmapViewOfFile(DllRawData);
    CloseHandle(HMapping);
    CloseHandle(HFile);
    Exit;
  end;
  if (ReadSize <> 0) and (ReadSize <= RSize) then
    RSize := ReadSize;
  if IsBadReadPointer(DllRawData, RSize) then
  begin
    LogError('Mapping is invalid.');
    UnmapViewOfFile(DllRawData);
    CloseHandle(HMapping);
    CloseHandle(HFile);
    Exit;
  end;
  LocalCopy := AllocUnaligned(RSize);
  if LocalCopy <> nil then
  begin
    Move(DllRawData^, LocalCopy^, RSize);
    ReadSize := RSize;
  end
  else
  begin
    ReadSize := 0;
    LogError('Could not allocate memory in the current process.');
  end;
  UnmapViewOfFile(DllRawData);
  CloseHandle(HMapping);
  CloseHandle(HFile);
  Result := LocalCopy;
end;

function ReadFromFile(const InPath: string; var ReadSize: NativeUInt): TUnalignedBuf;
var
  HFile: THandle;
  RSize: DWORD;
  Buffer: TUnalignedBuf;
  OutSize: DWORD;
begin
  Result := nil;
  HFile := CreateFile(PChar(InPath), GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if HFile = INVALID_HANDLE_VALUE then
  begin
    LogError('Cannot open the file for reading.');
    Exit;
  end;
  RSize := GetFileSize(HFile, nil);
  if RSize = INVALID_FILE_SIZE then
  begin
    LogError('Cannot retrieve file size.');
    CloseHandle(HFile);
    Exit;
  end;
  if (ReadSize <> 0) and (ReadSize <= RSize) then
    RSize := MaskToDword(ReadSize);
  Buffer := AllocUnaligned(RSize);
  if Buffer = nil then
  begin
    CloseHandle(HFile);
    LogError('Buffer allocation failed.');
    Exit;
  end;
  OutSize := 0;
  if not Winapi.Windows.ReadFile(HFile, Buffer^, RSize, OutSize, nil) then
  begin
    LogError('ReadFile failed.');
    FreeFile(Buffer);
    Buffer := nil;
    ReadSize := 0;
  end
  else
    ReadSize := OutSize;
  CloseHandle(HFile);
  Result := Buffer;
end;

function DumpToFile(const OutPath: string; DumpData: PByte; DumpSize: NativeUInt): Boolean;
var
  HFile: THandle;
  WrittenSize: DWORD;
  IsDumped: Boolean;
begin
  Result := False;
  if (OutPath = '') or (DumpData = nil) or (DumpSize = 0) then
    Exit;
  HFile := CreateFile(PChar(OutPath), GENERIC_WRITE, FILE_SHARE_WRITE, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if HFile = INVALID_HANDLE_VALUE then
  begin
    LogError('Cannot open the file for writing.');
    Exit;
  end;
  if DumpSize > MAX_DWORD then
    LogWarning('Dump size exceeds DWORD range and will be truncated.');
  WrittenSize := 0;
  IsDumped := False;
  if Winapi.Windows.WriteFile(HFile, DumpData^, MaskToDword(DumpSize), WrittenSize, nil) then
  begin
    if WrittenSize <> DumpSize then
      LogWarning('The written size %u is different than the requested size: %u.', [WrittenSize, DumpSize]);
    if WrittenSize <> 0 then
      IsDumped := True;
  end
  else
    LogError('Failed to write to the file.');
  CloseHandle(HFile);
  Result := IsDumped;
end;

procedure FreeFile(Buffer: TUnalignedBuf);
begin
  FreeUnaligned(Buffer);
end;

function GetFileNamePart(const FullPath: string): string;
var
  P: Integer;
begin
  P := LastDelimiter('/\', FullPath);
  if P = 0 then
    Result := FullPath
  else
    Result := Copy(FullPath, P + 1, MaxInt);
end;

function GetDirectoryNamePart(const FullPath: string): string;
var
  P: Integer;
begin
  P := LastDelimiter('/\', FullPath);
  if P = 0 then
    Result := ''
  else
    Result := Copy(FullPath, 1, P - 1);
end;

function FindExtensionPos(const S: string): Integer;
var
  I: Integer;
begin
  Result := Length(S) + 1;
  for I := Length(S) downto 1 do
  begin
    if S[I] = '.' then
    begin
      Result := I;
      Break;
    end;
  end;
end;

end.
