program TestIsWantedModule;

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

function Check(const Label_: string; Got: Boolean; Expected: Boolean): Boolean;
begin
  Result := Got = Expected;
  if Result then
    Writeln('[PASS] ', Label_)
  else
    Writeln('[FAIL] ', Label_, ' -- expected ', Expected, ', got ', Got);
end;

var
  AllPassed: Boolean;
  RealNtdll, WrongFirst, WrongSuffix, ShortName: HMODULE;

begin
  try
    AllPassed := True;

    LoadLibraryW('ntdll.dll');

    RealNtdll := GetModuleViaPeb(PWideChar('ntdll.dll'));
    if not Check('ntdll.dll finds ntdll', RealNtdll <> 0, True) then
      AllPassed := False;

    WrongFirst := GetModuleViaPeb(PWideChar('atdll.dll'));
    if not Check('atdll.dll must not find ntdll.dll', WrongFirst = 0, True) then
      AllPassed := False;

    WrongSuffix := GetModuleViaPeb(PWideChar('ntdll.dlx'));
    if not Check('ntdll.dlx must not find ntdll.dll', WrongSuffix = 0, True) then
      AllPassed := False;

    LoadLibraryW('kernel32.dll');
    ShortName := GetModuleViaPeb(PWideChar('kernel32.dll'));
    if not Check('kernel32.dll short-name suffix match', ShortName <> 0, True) then
      AllPassed := False;

    if not Check('unexisting_module returns 0',
        GetModuleViaPeb(PWideChar('unexisting_module')) = 0, True) then
      AllPassed := False;

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
