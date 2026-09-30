program TestExportsMapperForwarders;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas',
  NativePe.FileUtil in '..\src\NativePe.FileUtil.pas',
  NativePe.PeHdrsHelper in '..\src\NativePe.PeHdrsHelper.pas',
  NativePe.ExportedFunc in '..\src\NativePe.ExportedFunc.pas',
  NativePe.ExportsMapper in '..\src\NativePe.ExportsMapper.pas';

function CheckForwarderMerge(FirstDll, SecondDll: string; FirstMod, SecondMod: HMODULE;
  KernelBaseMod: HMODULE): Boolean;
var
  Mapper: TExportsMapper;
  RealVa: UInt64;
  ExpSet: TExportedFuncSet;
  Pair: TPair<string, TExportedFunc>;
  FoundForwarderAlias: Boolean;
begin
  Result := False;
  RealVa := UInt64(NativeUInt(GetProcAddress(KernelBaseMod, 'CreateFileW')));
  if RealVa = 0 then
  begin
    Writeln('  Could not resolve the real CreateFileW export -- skipping.');
    Exit;
  end;

  Mapper := TExportsMapper.Create;
  try
    Mapper.AddToLookup(FirstDll, FirstMod);
    Mapper.AddToLookup(SecondDll, SecondMod);

    ExpSet := Mapper.FindExportsByVa(RealVa);
    if ExpSet = nil then
    begin
      Writeln('  FindExportsByVa returned no entries at all for the real VA.');
      Exit;
    end;

    FoundForwarderAlias := False;
    for Pair in ExpSet do
      if SameText(Pair.Value.LibName, 'kernel32') and SameText(Pair.Value.FuncName, 'CreateFileW') then
        FoundForwarderAlias := True;

    if FoundForwarderAlias then
    begin
      Writeln('  kernel32.CreateFileW forwarder was correctly merged with the real export.');
      Result := True;
    end
    else
      Writeln('  kernel32.CreateFileW forwarder was NOT merged -- bug is present.');
  finally
    Mapper.Free;
  end;
end;

procedure PrintPlatformNote;
begin
{$IFDEF WIN64}
  Writeln;
  Writeln('NOTE: This test depends on the export layout of the installed Windows system DLLs.');
  Writeln('On current Win64 builds, kernel32!CreateFileW may use code or an API-set path');
  Writeln('instead of a classic PE export forwarder to KERNELBASE.CreateFileW.');
  Writeln('In that case this test cannot validate the forwarder merge reliably.');
  Writeln('Use TestExportsMapperForwarderFixture.exe for deterministic validation.');
{$ENDIF}
end;

var
  Kernel32Lib, KernelBaseLib: HMODULE;
  AllPassed: Boolean;

begin
  try
    Kernel32Lib := LoadLibraryA('kernel32.dll');
    KernelBaseLib := LoadLibraryA('kernelbase.dll');
    if (Kernel32Lib = 0) or (KernelBaseLib = 0) then
    begin
      Writeln('Failed to load kernel32.dll / kernelbase.dll!');
      Halt(1);
    end;

    Writeln('[*] Test 1: forwarder DLL (kernel32) added before the real target (kernelbase)');
    AllPassed := CheckForwarderMerge('kernel32.dll', 'kernelbase.dll', Kernel32Lib, KernelBaseLib, KernelBaseLib);

    Writeln('[*] Test 2: real target (kernelbase) added before the forwarder DLL (kernel32)');
    if not CheckForwarderMerge('kernelbase.dll', 'kernel32.dll', KernelBaseLib, Kernel32Lib, KernelBaseLib) then
      AllPassed := False;

    if AllPassed then
    begin
      Writeln('PASSED.');
      PrintPlatformNote;
      Halt(0);
    end
    else
    begin
      Writeln('FAILED.');
      PrintPlatformNote;
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
