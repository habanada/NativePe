{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program TestLoading;

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

var
  PathBuf: array [0 .. MAX_PATH - 1] of Char;
  MyPath: string;
  VSize: NativeUInt;
  LoadedPe: TAlignedBuf;
  RawSize: NativeUInt;
  Unmapped: TAlignedBuf;
  ReadSize: NativeUInt;
  FileContent: TUnalignedBuf;
  SmallerSize: NativeUInt;
  Matches: Boolean;
  ExitStatus: Integer;

begin
  ExitStatus := 1;
  try
    FillChar(PathBuf, SizeOf(PathBuf), 0);
    GetModuleFileName(0, PathBuf, MAX_PATH);
    MyPath := PathBuf;
    Writeln('Module: ', MyPath);

    VSize := 0;
    LoadedPe := LoadPeModule(MyPath, VSize, True, True);
    if LoadedPe = nil then
    begin
      Writeln('Loading failed!');
      Halt(1);
    end;
    Writeln('Loaded at: 0x' + IntToHex(NativeUInt(LoadedPe), 1));

    RawSize := 0;
    Unmapped := PeVirtualToRaw(LoadedPe, VSize, UInt64(NativeUInt(LoadedPe)), RawSize, True);
    if (Unmapped = nil) or (RawSize = 0) then
    begin
      Writeln('Unmapping failed!');
      FreePeBuffer(LoadedPe, VSize);
      Halt(1);
    end;
    Writeln('Unmapped at: 0x' + IntToHex(NativeUInt(Unmapped), 1));

    ReadSize := 0;
    FileContent := LoadFile(MyPath, ReadSize);
    if FileContent = nil then
    begin
      Writeln('Reading file failed!');
      FreePeBuffer(LoadedPe, VSize);
      FreePeBuffer(Unmapped, RawSize);
      Halt(1);
    end;
    Writeln('Read size: ', ReadSize);
    Writeln('Unmapped size: ', RawSize);

    if RawSize < ReadSize then
      SmallerSize := RawSize
    else
      SmallerSize := ReadSize;

    Matches := CompareMem(Unmapped, FileContent, NativeInt(SmallerSize));

    FreePeBuffer(LoadedPe, VSize);
    FreePeBuffer(Unmapped, RawSize);
    FreeFile(FileContent);
    Writeln('Unloaded!');

    if Matches then
    begin
      Writeln('PASSED: unmapped module matches the original file.');
      ExitStatus := 0;
    end
    else
      Writeln('FAILED: unmapped module is NOT the same as the original!');

    Halt(ExitStatus);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
