program NativePeDUnitX;

{$APPTYPE CONSOLE}
{$STRONGLINKTYPES ON}

uses
  System.SysUtils,
  DUnitX.Loggers.Console,
  DUnitX.Loggers.Xml.NUnit,
  DUnitX.TestFramework,
  NativePe.TestFixtures in 'NativePe.TestFixtures.pas',
  NativePe.Core.Tests in 'NativePe.Core.Tests.pas',
  NativePe.Pe.Tests in 'NativePe.Pe.Tests.pas',
  NativePe.Robustness.Tests in 'NativePe.Robustness.Tests.pas',
  NativePe.Windows.Tests in 'NativePe.Windows.Tests.pas',
  NativePe.Coverage.Tests in 'NativePe.Coverage.Tests.pas',
  NativePe.LibPeConv.Tests in 'NativePe.LibPeConv.Tests.pas',
  NativePe.LibPeConv.ReferenceData in 'NativePe.LibPeConv.ReferenceData.pas',
  NativePe.LibPeConv.Fidelity.Tests in 'NativePe.LibPeConv.Fidelity.Tests.pas';

var
  Runner: ITestRunner;
  Results: IRunResults;
  ConsoleLogger: ITestLogger;
  XmlLogger: ITestLogger;
  OutputFile, OutputDir: string;
begin
  ReportMemoryLeaksOnShutdown := True;
  try
    TDUnitX.CheckCommandLine;
    Runner := TDUnitX.CreateRunner;
    Runner.UseRTTI := True;
    Runner.FailsOnNoAsserts := True;
    ConsoleLogger := TDUnitXConsoleLogger.Create(False);
    Runner.AddLogger(ConsoleLogger);
    OutputFile := GetEnvironmentVariable('NATIVEPE_DUNITX_XML');
    if OutputFile = '' then
      OutputFile := IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0))) + 'NativePeDUnitX-results.xml';
    OutputDir := ExtractFileDir(OutputFile);
    if OutputDir <> '' then
      ForceDirectories(OutputDir);
    XmlLogger := TDUnitXXMLNUnitFileLogger.Create(OutputFile);
    Runner.AddLogger(XmlLogger);
    Results := Runner.Execute;
    if not Results.AllPassed then
      System.ExitCode := EXIT_ERRORS;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName + ': ' + E.Message);
      System.ExitCode := EXIT_ERRORS;
    end;
  end;
end.
