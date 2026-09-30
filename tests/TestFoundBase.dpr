{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program TestFoundBase;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas',
  NativePe.FileUtil in '..\src\NativePe.FileUtil.pas',
  NativePe.PeHdrsHelper in '..\src\NativePe.PeHdrsHelper.pas',
  NativePe.Relocate in '..\src\NativePe.Relocate.pas',
  NativePe.ExportedFunc in '..\src\NativePe.ExportedFunc.pas',
  NativePe.FunctionResolver in '..\src\NativePe.FunctionResolver.pas',
  NativePe.ImportsLoader in '..\src\NativePe.ImportsLoader.pas',
  NativePe.PeModeDetector in '..\src\NativePe.PeModeDetector.pas',
  NativePe.FindBase in '..\src\NativePe.FindBase.pas',
  NativePe.PeRawToVirtual in '..\src\NativePe.PeRawToVirtual.pas',
  NativePe.PeVirtualToRaw in '..\src\NativePe.PeVirtualToRaw.pas',
  NativePe.ExportsLookup in '..\src\NativePe.ExportsLookup.pas',
  NativePe.TlsParser in '..\src\NativePe.TlsParser.pas',
  NativePe.PebLookup in '..\src\NativePe.PebLookup.pas',
  NativePe.PeLoader in '..\src\NativePe.PeLoader.pas',
  NativePe.DelayedImports in '..\src\NativePe.DelayedImports.pas';

function LoadAndCheckBase(const Path: string): Integer;
var
  VSize: NativeUInt;
  Pe: TAlignedBuf;
  FoundBase: UInt64;
begin
  if Path = '' then
    Exit(-1);

  VSize := 0;
  Pe := LoadPeModule(Path, VSize, False, True);
  if Pe = nil then
    Exit(-2);

  Writeln('Loaded at: 0x', IntToHex(NativeUInt(Pe), 1));
  FoundBase := FindBaseCandidate(Pe, VSize);

  Writeln('Load Base: 0x', IntToHex(NativeUInt(Pe), 1));
  Writeln('Found Base: 0x', IntToHex(FoundBase, 1));

  FreePeBuffer(Pe, VSize);

  if FoundBase = UInt64(NativeUInt(Pe)) then
  begin
    Writeln('[+] Success! Correct base found!');
    Result := 0;
  end
  else
    Result := 1;
end;

var
  PathBuf: array [0 .. MAX_PATH - 1] of Char;
  MyPath: string;
  Res: Integer;

begin
  try
    FillChar(PathBuf, SizeOf(PathBuf), 0);
    GetModuleFileName(0, PathBuf, MAX_PATH);
    MyPath := PathBuf;
    Writeln('Module: ', MyPath);

    Res := LoadAndCheckBase(MyPath);
    if Res = 0 then
      Writeln('PASSED.')
    else
      Writeln('FAILED.');
    Halt(Res);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
