{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program TestFormatDetect;

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

procedure PrintFormat(IsRaw: Boolean);
begin
  if IsRaw then
    Writeln('PE is in the RAW format')
  else
    Writeln('PE is in the VIRTUAL format');
end;

var
  PathBuf: array [0 .. MAX_PATH - 1] of Char;
  MyPath: string;
  PeSize: NativeUInt;
  LoadedRaw: TUnalignedBuf;
  IsRaw, IsRaw2: Boolean;
  VSize: NativeUInt;
  VirtualPe: TAlignedBuf;

begin
  IsRaw2 := False;
  try
    FillChar(PathBuf, SizeOf(PathBuf), 0);
    GetModuleFileName(0, PathBuf, MAX_PATH);
    MyPath := PathBuf;
    Writeln('Module: ', MyPath);

    PeSize := 0;
    LoadedRaw := LoadFile(MyPath, PeSize);
    if LoadedRaw = nil then
    begin
      Writeln('Loading failed!');
      Halt(1);
    end;

    IsRaw := IsPeRaw(LoadedRaw, PeSize);
    if IsRaw then
    begin
      VSize := 0;
      VirtualPe := LoadPeModule(MyPath, VSize, False, False);
      if VirtualPe = nil then
      begin
        Writeln('Mapping failed!');
        FreeFile(LoadedRaw);
        Halt(1);
      end;
      IsRaw2 := IsPeRaw(VirtualPe, VSize);
      FreePeBuffer(VirtualPe, VSize);
    end;
    FreeFile(LoadedRaw);

    Writeln('Test 1:');
    PrintFormat(IsRaw);
    Writeln('Test 2:');
    PrintFormat(IsRaw2);

    if IsRaw and (not IsRaw2) then
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
