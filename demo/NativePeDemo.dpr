program NativePeDemo;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,  Winapi.Windows,
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

type
  TNewMain = function: Integer; stdcall;

var
  PePath: string;
  BufSize: NativeUInt;
  Buffer: TUnalignedBuf;
  VSize: NativeUInt;
  MyPe: TAlignedBuf;
  EpRva: DWORD;
  EpVa: NativeUInt;
  NewMain: TNewMain;

begin
  try
    if ParamCount < 1 then
    begin
      Writeln('Args: <path to the exe>');
      Halt(0);
    end;
    PePath := ParamStr(1);

    BufSize := 0;
    Buffer := LoadFile(PePath, BufSize);
    if Buffer = nil then
    begin
      System.ExitCode := -1;
      Halt;
    end;

    VSize := 0;
    MyPe := LoadPeExecutable(Buffer, BufSize, VSize);
    FreeFile(Buffer);
    if MyPe = nil then
    begin
      System.ExitCode := -1;
      Halt;
    end;

    SetMainModuleInPeb(HMODULE(MyPe));

    LoadDelayedImports(MyPe, UInt64(NativeUInt(MyPe)));

    RunTlsCallbacks(MyPe, VSize);

    EpRva := GetEntryPointRva(MyPe);
    if EpRva = DWORD(0) then
    begin
      System.ExitCode := -2;
      Halt;
    end;

    EpVa := NativeUInt(EpRva) + NativeUInt(MyPe);
    NewMain := TNewMain(EpVa);

    Halt(NewMain());
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
