program NativePeCorpusTest;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  NativePe.Corpus.Runner in 'NativePe.Corpus.Runner.pas';

begin
  if (ParamCount >= 1) and SameText(ParamStr(1), '--worker') then
    System.ExitCode := RunCorpusApplication
  else
  begin
    try
      System.ExitCode := RunCorpusApplication;
    except
      on E: Exception do
      begin
        Writeln(E.ClassName + ': ' + E.Message);
        System.ExitCode := 2;
      end;
    end;
  end;
end.
