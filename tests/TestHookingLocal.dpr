{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

program TestHookingLocal;

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
  NativePe.DelayedImports in '..\src\NativePe.DelayedImports.pas',
  NativePe.Hooks in '..\src\NativePe.Hooks.pas';

const
  FAKE_NAME: AnsiString = 'fake_module_name';

function My_MessageBoxA(HWndParam: HWND; LpText, LpCaption: LPCSTR; UType: UINT): Integer; stdcall;
begin
  Writeln('TITLE: [', string(AnsiString(LpCaption)), ']');
  Writeln('MESSAGE: [', string(AnsiString(LpText)), ']');
  Result := 1337;
end;

function My_GetModuleFileNameA(HModuleParam: HMODULE; LpFilename: LPSTR; NSize: DWORD): DWORD; stdcall;
var
  ToCopy: NativeUInt;
begin
  ToCopy := Length(FAKE_NAME);
  if (NSize = 0) then
    Exit(0);
  if DWORD(ToCopy) >= NSize then
    ToCopy := NSize - 1;
  Move(FAKE_NAME[1], LpFilename^, ToCopy);
  LpFilename[ToCopy] := #0;
  Result := DWORD(ToCopy);
end;

function My_Rand: Integer; cdecl;
begin
  Result := 44;
end;

type
  TSrandProc = procedure(Seed: Cardinal); cdecl;
  TRandFunc = function: Integer; cdecl;

var
  NormalName, ModuleName: array [0 .. MAX_PATH - 1] of AnsiChar;
  User32Lib, Kernel32Lib, MsvcrtLib: HMODULE;
  Backup: TPatchBackup;
  RandPtr: Pointer;
  SrandPtr: Pointer;
  RandVal: Integer;
  AllPassed: Boolean;

begin
  AllPassed := True;
  Backup := TPatchBackup.Create;
  try
    try
      FillChar(NormalName, SizeOf(NormalName), 0);
      GetModuleFileNameA(0, NormalName, MAX_PATH);

      User32Lib := LoadLibraryA('user32.dll');
      Kernel32Lib := LoadLibraryA('kernel32.dll');
      MsvcrtLib := LoadLibraryA('msvcrt.dll');
      if (User32Lib = 0) or (Kernel32Lib = 0) or (MsvcrtLib = 0) then
      begin
        Writeln('Failed to load a required system DLL!');
        Halt(1);
      end;

      RedirectToLocal(GetProcAddress(User32Lib, 'MessageBoxA'), @My_MessageBoxA);
      RedirectToLocal(GetProcAddress(Kernel32Lib, 'GetModuleFileNameA'), @My_GetModuleFileNameA, Backup);

      RandPtr := GetProcAddress(MsvcrtLib, 'rand');
      SrandPtr := GetProcAddress(MsvcrtLib, 'srand');
      RedirectToLocal(RandPtr, @My_Rand);

      FillChar(ModuleName, SizeOf(ModuleName), 0);
      GetModuleFileNameA(0, ModuleName, MAX_PATH);
      MessageBoxA(0, ModuleName, 'Module Name', MB_OK);

      if AnsiString(ModuleName) <> FAKE_NAME then
      begin
        Writeln('FAILED: hooked GetModuleFileNameA did not run.');
        AllPassed := False;
      end;

      TSrandProc(SrandPtr)(10000);
      RandVal := TRandFunc(RandPtr)();
      if RandVal <> 44 then
      begin
        Writeln('FAILED: hooked rand() returned ', RandVal, ' instead of 44.');
        AllPassed := False;
      end;

      if not Backup.ApplyBackup then
      begin
        Writeln('FAILED: could not apply backup.');
        AllPassed := False;
      end;

      FillChar(ModuleName, SizeOf(ModuleName), 0);
      GetModuleFileNameA(0, ModuleName, MAX_PATH);
      MessageBoxA(0, ModuleName, 'Module Name', MB_OK);

      if AnsiString(ModuleName) <> AnsiString(NormalName) then
      begin
        Writeln('FAILED: GetModuleFileNameA was not restored after ApplyBackup.');
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
  finally
    Backup.Free;
  end;
end.
