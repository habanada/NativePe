{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program TestPebLookup;

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

function CompareModulesAndSizes(ModuleName: PWideChar): Boolean;
var
  Mod1, Mod2: HMODULE;
  Size1, Size2: NativeUInt;
begin
  Write('[*] Test: ');
  if ModuleName = nil then
    Writeln('self')
  else
  begin
    Writeln(ModuleName);
    LoadLibraryW(ModuleName);
  end;

  Mod1 := GetModuleViaPeb(ModuleName);
  Mod2 := GetModuleHandleW(ModuleName);
  Writeln('GetModuleViaPeb:   0x', IntToHex(NativeUInt(Mod1), 1));
  Writeln('GetModuleHandleW:  0x', IntToHex(NativeUInt(Mod2), 1));
  if Mod1 <> Mod2 then
    Exit(False);

  Size1 := GetImageSize(PByte(Mod1));
  Size2 := GetModuleSizeViaPeb(Mod2);
  Writeln('GetImageSize:         0x', IntToHex(Size1, 1));
  Writeln('GetModuleSizeViaPeb:  0x', IntToHex(Size2, 1));
  Result := Size1 = Size2;
end;

function CheckUnexistingModule: Boolean;
var
  ModuleName: PWideChar;
  Mod1, Mod2: HMODULE;
begin
  Writeln('[*] Test: unexisting module');
  ModuleName := 'unexisting_module';
  Mod1 := GetModuleViaPeb(ModuleName);
  Mod2 := GetModuleHandleW(ModuleName);
  Writeln('GetModuleViaPeb:  0x', IntToHex(NativeUInt(Mod1), 1));
  Writeln('GetModuleHandleW: 0x', IntToHex(NativeUInt(Mod2), 1));
  Result := Mod1 = Mod2;
end;

var
  AllPassed: Boolean;

begin
  try
    AllPassed := True;

    if not CompareModulesAndSizes(nil) then AllPassed := False;
    if not CompareModulesAndSizes('ntdll.dll') then AllPassed := False;
    if not CompareModulesAndSizes('kernel32.dll') then AllPassed := False;
    if not CompareModulesAndSizes('user32.dll') then AllPassed := False;
    if not CompareModulesAndSizes('advapi32.dll') then AllPassed := False;
    if not CompareModulesAndSizes('ws2_32.dll') then AllPassed := False;
    if not CheckUnexistingModule then AllPassed := False;

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
