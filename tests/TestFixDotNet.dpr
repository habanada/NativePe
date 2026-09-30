{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program TestFixDotNet;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas',
  NativePe.PeHdrsHelper in '..\src\NativePe.PeHdrsHelper.pas',
  NativePe.ExportedFunc in '..\src\NativePe.ExportedFunc.pas',
  NativePe.FunctionResolver in '..\src\NativePe.FunctionResolver.pas',
  NativePe.ImportsLoader in '..\src\NativePe.ImportsLoader.pas',
  NativePe.DotNetEpFixer in '..\src\NativePe.DotNetEpFixer.pas';

const
  ImgBase: UInt64 = $400000;
  CorExeMainThunk: DWORD = $2000;

function TestFindingOffset(Buf: PByte; BufSize: NativeUInt; PatternOffset: NativeUInt;
  DirectionStart: Boolean): Boolean;
const
  JmpPattern: array [0 .. 5] of Byte = ($FF, $25, $00, $20, $40, $00);
var
  Found: PByte;
  Diff: NativeUInt;
begin
  Result := False;
  FillChar(Buf^, BufSize, 0);

  if not DirectionStart then
    PatternOffset := (BufSize - SizeOf(JmpPattern)) - PatternOffset;

  if (BufSize < SizeOf(JmpPattern)) or ((PatternOffset + SizeOf(JmpPattern)) > BufSize) then
  begin
    Writeln('Incorrect test data!');
    Exit;
  end;
  Move(JmpPattern[0], Buf[PatternOffset], SizeOf(JmpPattern));

  Found := SearchJump(Buf, BufSize, CorExeMainThunk, ImgBase);
  if Found = nil then
  begin
    Writeln('Not found!');
    Exit;
  end;
  Diff := NativeUInt(Found) - NativeUInt(Buf);
  Writeln('Found at offset: 0x', IntToHex(Diff, 1));
  Result := Diff = PatternOffset;
end;

var
  Buf: array [0 .. $FF] of Byte;
  IsOk: Boolean;
  AllPassed: Boolean;

begin
  try
    AllPassed := True;

    IsOk := TestFindingOffset(@Buf[0], SizeOf(Buf), 0, True);
    if IsOk then
      Writeln('Test 1 passed!')
    else
    begin
      Writeln('Test 1 failed!');
      AllPassed := False;
    end;

    IsOk := TestFindingOffset(@Buf[0], SizeOf(Buf), 0, False);
    if IsOk then
      Writeln('Test 2 passed!')
    else
    begin
      Writeln('Test 2 failed!');
      AllPassed := False;
    end;

    IsOk := TestFindingOffset(@Buf[0], SizeOf(Buf), 30, False);
    if IsOk then
      Writeln('Test 3 passed!')
    else
    begin
      Writeln('Test 3 failed!');
      AllPassed := False;
    end;

    if AllPassed then
    begin
      Writeln('PASSED.');
      Halt(0);
    end
    else
    begin
      Writeln('FAILED.');
      Halt(1);
    end;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
