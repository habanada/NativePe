program TestMalformedPe;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.PeHdrsHelper in '..\src\NativePe.PeHdrsHelper.pas',
  NativePe.PeRawToVirtual in '..\src\NativePe.PeRawToVirtual.pas',
  NativePe.TlsParser in '..\src\NativePe.TlsParser.pas',
  NativePe.ExportedFunc in '..\src\NativePe.ExportedFunc.pas',
  NativePe.FunctionResolver in '..\src\NativePe.FunctionResolver.pas',
  NativePe.ImportsLoader in '..\src\NativePe.ImportsLoader.pas';

var
  FailCount: Integer;

procedure Check(const Name: string; Pass: Boolean);
begin
  if Pass then
    Writeln(Format('  OK   %s', [Name]))
  else
  begin
    Writeln(Format('  FAIL %s', [Name]));
    Inc(FailCount);
  end;
end;

procedure TestValidatePtrWraparound;
var
  Buf: array [0 .. 63] of Byte;
begin
  Writeln('-- ValidatePtr: overflow/wraparound guards --');
  Check('in-bounds field accepted', ValidatePtr(@Buf[0], SizeOf(Buf), @Buf[10], 8));
  Check('field exceeding buffer end rejected', not ValidatePtr(@Buf[0], SizeOf(Buf), @Buf[60], 8));
  Check('field starting before buffer rejected', not ValidatePtr(@Buf[8], SizeOf(Buf) - 8, @Buf[0], 8));
  Check('field size causing StartDelta+FieldSize to wrap past NativeUInt''s range is rejected',
    not ValidatePtr(Pointer(NativeUInt($1000)), 100, Pointer(NativeUInt($1000) + 10), NativeUInt(-5)));
  Check('nil field pointer rejected', not ValidatePtr(@Buf[0], SizeOf(Buf), nil, 8));
end;

procedure TestIsValidStringA;
var
  Buf: array [0 .. 15] of AnsiChar;
begin
  Writeln('-- IsValidStringA: the primitive fixes #3/#4 now use --');
  FillChar(Buf, SizeOf(Buf), Ord('A'));
  Check('unterminated string filling the whole buffer rejected',
    not IsValidStringA(@Buf[0], SizeOf(Buf), @Buf[0]));
  Buf[5] := #0;
  Check('string terminated within bounds accepted', IsValidStringA(@Buf[0], SizeOf(Buf), @Buf[0]));
  Buf[0] := #0;
  Check('empty string (immediate terminator) rejected', not IsValidStringA(@Buf[0], SizeOf(Buf), @Buf[0]));
end;

procedure WriteMinimalNtHeaders(Buf: PByte; NtOffset: Integer; SizeOfImageVal: DWORD);
var
  Dos: PImageDosHeader;
  Nt: PImageNtHeaders64;
begin
  Dos := PImageDosHeader(Buf);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := NtOffset;
  Nt := PImageNtHeaders64(Buf + NtOffset);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := $8664;
  Nt.FileHeader.NumberOfSections := 0;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64);
  Nt.FileHeader.Characteristics := 0;
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt.OptionalHeader.SizeOfImage := SizeOfImageVal;
  Nt.OptionalHeader.SizeOfHeaders := NtOffset + SizeOf(TImageNtHeaders64);
  Nt.OptionalHeader.NumberOfRvaAndSizes := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
end;

procedure TestPeRawToVirtualHeaderCopyBug;
const
  NtOffset = 64;
  PayloadSize = 512;
var
  RawBuf: PByte;
  Nt: PImageNtHeaders64;
  OutSize: NativeUInt;
  Mapped: TAlignedBuf;
begin
  Writeln('-- NativePe.PeRawToVirtual: header copy bounds --');
  GetMem(RawBuf, PayloadSize);
  try
    FillChar(RawBuf^, PayloadSize, 0);
    WriteMinimalNtHeaders(RawBuf, NtOffset, $2000);
    Nt := PImageNtHeaders64(RawBuf + NtOffset);
    Nt.OptionalHeader.SizeOfHeaders := 600; // > PayloadSize (512), simulating a corrupted/hostile file
    OutSize := 0;
    Mapped := PeRawToVirtual(RawBuf, PayloadSize, OutSize, False);
    Check('SizeOfHeaders exceeding the raw file size is rejected instead of ' +
      'copying past the source buffer', Mapped = nil);
    if Mapped <> nil then
      FreePeBuffer(Mapped);
  finally
    FreeMem(RawBuf);
  end;
end;

procedure TestTlsDirectoryTruncated;
const
  ModuleSize = 500;
  RealAlloc = 2048;
  NtOffset = 64;
  TlsRva = 470; // 470 + SizeOf(TImageTlsDirectory64)=40 = 510 > ModuleSize: truncated at the buffer end
  FakeCallbacksListRva = 420;
var
  Buf: PByte;
  P64: PUInt64;
  Callbacks: TList<UInt64>;
  Found: NativeUInt;
begin
  Writeln('-- NativePe.TlsParser: TLS directory bounds --');
  GetMem(Buf, RealAlloc);
  try
    FillChar(Buf^, RealAlloc, 0);
    WriteMinimalNtHeaders(Buf, NtOffset, RealAlloc);
    PImageNtHeaders64(Buf + NtOffset).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress := TlsRva;
    PImageNtHeaders64(Buf + NtOffset).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size :=
      SizeOf(TImageTlsDirectory64);

    P64 := PUInt64(Buf + TlsRva + 24);
    P64^ := NativeUInt(Buf) + FakeCallbacksListRva;

    P64 := PUInt64(Buf + FakeCallbacksListRva);
    P64^ := $0000000140001234; // a plausible-looking, but fake, callback address
    P64 := PUInt64(Buf + FakeCallbacksListRva + 8);
    P64^ := 0; // terminator

    Callbacks := TList<UInt64>.Create;
    try
      Found := ListTlsCallbacks(Buf, ModuleSize, Callbacks);
      Check('truncated TLS directory yields zero callbacks instead of ' +
        'trusting an unvalidated AddressOfCallBacks field', (Found = 0) and (Callbacks.Count = 0));
    finally
      Callbacks.Free;
    end;
  finally
    FreeMem(Buf);
  end;
end;

type
  TNoOpImportCallback = class(TImportThunksCallback)
  public
    function ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, FirstThunkPtr: NativeUInt): Boolean; override;
  end;

function TNoOpImportCallback.ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, FirstThunkPtr: NativeUInt): Boolean;
begin
  Result := True;
end;

procedure BuildModuleWithTruncatedImportThunk(out Buf: PByte; out ModuleSize: NativeUInt);
const
  RealAlloc = 2048;
  NtOffset = 64;
  ImportRva = 300;
  DllNameRva = 350;
  ThunkRva = 495; // ThunkRva + SizeOf(TImageThunkData64)=8 = 503 > ModuleSize (500): truncated
var
  Desc: PImageImportDescriptor;
  DllName: PAnsiChar;
begin
  ModuleSize := 500;
  GetMem(Buf, RealAlloc);
  FillChar(Buf^, RealAlloc, 0);
  WriteMinimalNtHeaders(Buf, NtOffset, RealAlloc);
  PImageNtHeaders64(Buf + NtOffset).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress :=
    ImportRva;
  PImageNtHeaders64(Buf + NtOffset).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size :=
    SizeOf(TImageImportDescriptor);

  Desc := PImageImportDescriptor(Buf + ImportRva);
  Desc.OriginalFirstThunk := 0;
  Desc.TimeDateStamp := 0;
  Desc.ForwarderChain := 0;
  Desc.Name := DllNameRva;
  Desc.FirstThunk := ThunkRva;

  DllName := PAnsiChar(Buf + DllNameRva);
  DllName[0] := 'a';
  DllName[1] := '.';
  DllName[2] := 'd';
  DllName[3] := 'l';
  DllName[4] := 'l';
  DllName[5] := #0;

end;

procedure TestImportThunkTableTruncated;
var
  Buf: PByte;
  ModuleSize: NativeUInt;
  Callback: TNoOpImportCallback;
  ThunkRvas: TList<DWORD>;
  Ok: Boolean;
begin
  Writeln('-- NativePe.ImportsLoader: truncated thunk table --');
  BuildModuleWithTruncatedImportThunk(Buf, ModuleSize);
  try
    Callback := TNoOpImportCallback.Create(Buf, ModuleSize);
    try
      Ok := ProcessImportTable(Buf, ModuleSize, Callback);
      Check('ProcessImportTable reports failure instead of silently ' +
        'stopping at the truncated thunk', not Ok);
    finally
      Callback.Free;
    end;

    ThunkRvas := TList<DWORD>.Create;
    try
      Ok := CollectThunks(Buf, ModuleSize, ThunkRvas);
      Check('CollectThunks (used by higher-level callers) also reports failure',
        not Ok);
    finally
      ThunkRvas.Free;
    end;
  finally
    FreeMem(Buf);
  end;
end;

procedure TestHasValidImportTableDistinguishesAbsentFromCorrupt;
var
  Buf: PByte;
  ModuleSize: NativeUInt;
  NtOffset: Integer;
begin
  Writeln('-- HasValidImportTable / GetDirectoryEntry: building blocks for the ' +
    'PeLoader.ValidateAndLoadImports --');
  NtOffset := 64;

  BuildModuleWithTruncatedImportThunk(Buf, ModuleSize);
  try
    Check('import directory present but corrupted: GetDirectoryEntry still finds it',
      GetDirectoryEntry(Buf, IMAGE_DIRECTORY_ENTRY_IMPORT) <> nil);
    Check('import directory present but corrupted: HasValidImportTable correctly says invalid',
      not HasValidImportTable(Buf, ModuleSize));
  finally
    FreeMem(Buf);
  end;

  GetMem(Buf, 2048);
  try
    FillChar(Buf^, 2048, 0);
    WriteMinimalNtHeaders(Buf, NtOffset, 2048);
    Check('no import directory at all: GetDirectoryEntry correctly returns nil',
      GetDirectoryEntry(Buf, IMAGE_DIRECTORY_ENTRY_IMPORT) = nil);
  finally
    FreeMem(Buf);
  end;

  Writeln('  Missing and corrupted import directories are handled as distinct cases.');
end;

begin
  try
    FailCount := 0;

    TestValidatePtrWraparound;
    TestIsValidStringA;
    TestPeRawToVirtualHeaderCopyBug;
    TestTlsDirectoryTruncated;
    TestImportThunkTableTruncated;
    TestHasValidImportTableDistinguishesAbsentFromCorrupt;

    if FailCount = 0 then
    begin
      Writeln('PASSED.');
      Halt(0);
    end
    else
    begin
      Writeln(Format('FAILED (%d check(s)).', [FailCount]));
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
