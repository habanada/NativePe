program TestExportsMapperForwarderFixture;

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

const
  FIXTURE_SIZE = $1000;
  NT_HEADERS_RVA = $80;
  EXPORT_DIRECTORY_RVA = $300;
  FUNCTIONS_RVA = $380;
  NAMES_RVA = $390;
  ORDINALS_RVA = $3A0;
  DLL_NAME_RVA = $400;
  EXPORT_NAME_RVA = $420;
  FORWARDER_RVA = $440;
  CODE_RVA = $800;

procedure WriteAnsiZ(Base: PByte; Rva: DWORD; const Value: AnsiString);
begin
  if Value <> '' then
    Move(PAnsiChar(Value)^, (Base + Rva)^, Length(Value));
  (Base + Rva + Length(Value))^ := 0;
end;

procedure BuildFixture(const DllName, ExportName: AnsiString; OrdinalBase: DWORD; const Forwarder: AnsiString;
  out Buffer: TBytes);
var
  Base: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeaders32;
  Exp: PImageExportDirectory;
  FunctionRva: DWORD;
begin
  SetLength(Buffer, FIXTURE_SIZE);
  FillChar(Buffer[0], Length(Buffer), 0);
  Base := @Buffer[0];

  Dos := PImageDosHeader(Base);
  Dos^.e_magic := IMAGE_DOS_SIGNATURE;
  Dos^.e_lfanew := NT_HEADERS_RVA;

  Nt := PImageNtHeaders32(Base + NT_HEADERS_RVA);
  Nt^.Signature := IMAGE_NT_SIGNATURE;
  Nt^.FileHeader.Machine := IMAGE_FILE_MACHINE_I386;
  Nt^.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
  Nt^.FileHeader.Characteristics := IMAGE_FILE_DLL;
  Nt^.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  Nt^.OptionalHeader.SizeOfImage := FIXTURE_SIZE;
  Nt^.OptionalHeader.SizeOfHeaders := $200;
  Nt^.OptionalHeader.NumberOfRvaAndSizes := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  Nt^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress := EXPORT_DIRECTORY_RVA;
  Nt^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size := $200;

  Exp := PImageExportDirectory(Base + EXPORT_DIRECTORY_RVA);
  Exp^.Name := DLL_NAME_RVA;
  Exp^.Base := OrdinalBase;
  Exp^.NumberOfFunctions := 1;
  Exp^.NumberOfNames := 1;
  Exp^.AddressOfFunctions := FUNCTIONS_RVA;
  Exp^.AddressOfNames := NAMES_RVA;
  Exp^.AddressOfNameOrdinals := ORDINALS_RVA;

  if Forwarder <> '' then
    FunctionRva := FORWARDER_RVA
  else
    FunctionRva := CODE_RVA;

  PDWORD(Base + FUNCTIONS_RVA)^ := FunctionRva;
  PDWORD(Base + NAMES_RVA)^ := EXPORT_NAME_RVA;
  PWord(Base + ORDINALS_RVA)^ := 0;

  WriteAnsiZ(Base, DLL_NAME_RVA, DllName);
  WriteAnsiZ(Base, EXPORT_NAME_RVA, ExportName);
  if Forwarder <> '' then
    WriteAnsiZ(Base, FORWARDER_RVA, Forwarder)
  else
    (Base + CODE_RVA)^ := $C3;

end;

function ContainsExport(FuncSet: TExportedFuncSet; const LibName, FuncName: string): Boolean;
var
  Pair: TPair<string, TExportedFunc>;
begin
  Result := False;
  if FuncSet = nil then
    Exit;
  for Pair in FuncSet do
    if SameText(Pair.Value.LibName, LibName) and SameText(Pair.Value.FuncName, FuncName) then
      Exit(True);
end;

function RunCase(ForwarderFirst: Boolean): Boolean;
var
  ForwarderBuffer, TargetBuffer: TBytes;
  TargetVa: UInt64;
  Mapper: TExportsMapper;
  FuncSet: TExportedFuncSet;
begin
  Result := False;
  BuildFixture('forwarder.dll', 'TestFunc', 3, 'target.TestFunc', ForwarderBuffer);
  BuildFixture('target.dll', 'TestFunc', 7, '', TargetBuffer);
  TargetVa := UInt64(NativeUInt(@TargetBuffer[0]) + CODE_RVA);

  Mapper := TExportsMapper.Create;
  try
    if ForwarderFirst then
    begin
      Mapper.AddToLookup('forwarder.dll', HMODULE(NativeUInt(@ForwarderBuffer[0])), Length(ForwarderBuffer), UInt64(NativeUInt(@ForwarderBuffer[0])));
      Mapper.AddToLookup('target.dll', HMODULE(NativeUInt(@TargetBuffer[0])), Length(TargetBuffer), UInt64(NativeUInt(@TargetBuffer[0])));
    end
    else
    begin
      Mapper.AddToLookup('target.dll', HMODULE(NativeUInt(@TargetBuffer[0])), Length(TargetBuffer), UInt64(NativeUInt(@TargetBuffer[0])));
      Mapper.AddToLookup('forwarder.dll', HMODULE(NativeUInt(@ForwarderBuffer[0])), Length(ForwarderBuffer), UInt64(NativeUInt(@ForwarderBuffer[0])));
    end;

    FuncSet := Mapper.FindExportsByVa(TargetVa);
    Result := ContainsExport(FuncSet, 'target', 'TestFunc') and ContainsExport(FuncSet, 'forwarder', 'TestFunc');
  finally
    Mapper.Free;
  end;
end;

var
  AllPassed: Boolean;

begin
  try
    Writeln('[*] Test 1: synthetic forwarder added before synthetic target');
    AllPassed := RunCase(True);
    if AllPassed then
      Writeln('  PASS')
    else
      Writeln('  FAIL');

    Writeln('[*] Test 2: synthetic target added before synthetic forwarder');
    if RunCase(False) then
      Writeln('  PASS')
    else
    begin
      Writeln('  FAIL');
      AllPassed := False;
    end;

    if AllPassed then
    begin
      Writeln('PASSED.');
      Halt(0);
    end;

    Writeln('FAILED.');
    Halt(1);
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
