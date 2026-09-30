unit NativePe.Core.Tests;

interface

uses
  System.SysUtils,
  System.Classes,
  Winapi.Windows,
  DUnitX.TestFramework,
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.FileUtil,
  NativePe.ExportedFunc,
  NativePe.TlsParser,
  NativePe.Lde;

type
  {$M+}

  [TestFixture]
  TBufferUtilTests = class
  public
    [Test] procedure MaskToDwordBoundaries;
    [Test] procedure MaskToWordBoundaries;
    [Test] procedure ValidatePtrAcceptsInBounds;
    [Test] procedure ValidatePtrRejectsPastEnd;
    [Test] procedure ValidatePtrRejectsBeforeStart;
    [Test] procedure ValidatePtrRejectsOverflow;
    [Test] procedure ValidatePtrRejectsNil;
    [Test] procedure IsValidStringARequiresTerminator;
    [Test] procedure IsValidStringWRequiresTerminator;
  end;

  [TestFixture]
  TFileUtilTests = class
  public
    [Test] procedure PathPartsWindows;
    [Test] procedure PathPartsUnixStyle;
    [Test] procedure PathPartsBareFile;
    [Test] procedure ExtensionPositionUsesLastDot;
    [Test] procedure ExtensionPositionAbsentReturnsLengthPlusOne;
    [Test] procedure DumpReadRoundTrip;
    [Test] procedure LoadFileHonorsRequestedSize;
  end;

  [TestFixture]
  TExportedFuncTests = class
  public
    [Test] procedure DllShortNameNormalizesPathCaseAndExtension;
    [Test] procedure ExportedFunctionPartUsesLastDot;
    [Test] procedure OrdinalStringRoundTrip;
    [Test] procedure ForwarderNameRequiresDot;
    [Test] procedure ForwarderNameAcceptsCommonCharacters;
    [Test] procedure NamedForwarderParses;
    [Test] procedure OrdinalForwarderParses;
    [Test] procedure NamedMapKeyIgnoresOrdinal;
    [Test] procedure DllIdentityIgnoresModuleExtension;
    [Test] procedure CopyConstructorPreservesFields;
  end;

  [TestFixture]
  TTlsAddressTests = class
  public
    [Test] procedure VirtualAddressConvertsToRva;
    [Test] procedure ExistingRvaPassesThrough;
    [Test] procedure ZeroAddressRejected;
    [Test] procedure ImageEndRejected;
    [Test] procedure OutsideImageRejected;
  end;

  [TestFixture]
  TLdeTests = class
  public
    [Test] procedure NopLength;
    [Test] procedure CallRel32Detected;
    [Test] procedure JccRel32Detected;
    [Test] procedure RipRelativeMovDetected;
    [Test] procedure RipRelativeIndirectCallDetected;
    [Test] procedure MovImm64Length;
    [Test] procedure F7TestImmediateLength;
    [Test] procedure F6TestImmediateLength;
    [Test] procedure SibNoBaseDisp32Length;
    [Test] procedure MultiByteNopLength;
    [Test] procedure TrampolineStopsOnInstructionBoundary;
  end;

implementation

function BytesOf(const Values: array of Byte): TBytes;
var
  I: Integer;
begin
  SetLength(Result, Length(Values));
  for I := 0 to High(Values) do
    Result[I] := Values[I];
end;

procedure AssertUInt64(Expected, Actual: UInt64; const Name: string);
begin
  Assert.IsTrue(Expected = Actual, Format('%s: expected %s, actual %s', [Name, UIntToStr(Expected), UIntToStr(Actual)]));
end;

procedure CheckInstruction(const Bytes: array of Byte; ExpectedLength: Integer; ExpectedRip, ExpectedRel: Boolean; const Name: string);
var
  Buf: array [0 .. 31] of Byte;
  Instr: TLdeInstruction;
  I, Got: Integer;
begin
  FillChar(Buf, SizeOf(Buf), $90);
  for I := 0 to High(Bytes) do
    Buf[I] := Bytes[I];
  Got := LdeDisasm(@Buf[0], True, Instr);
  Assert.IsTrue(Got = ExpectedLength, Format('%s length: expected %d, actual %d', [Name, ExpectedLength, Got]));
  Assert.IsTrue(Instr.IsRipRelative = ExpectedRip, Name + ': unexpected RIP-relative flag');
  Assert.IsTrue(Instr.IsRelativeBranch = ExpectedRel, Name + ': unexpected relative-branch flag');
end;

function TempFileName: string;
var
  Buf: array [0 .. MAX_PATH] of Char;
  N: DWORD;
begin
  N := GetTempPath(MAX_PATH, @Buf[0]);
  if N = 0 then
    Result := ExtractFilePath(ParamStr(0))
  else
    Result := string(PChar(@Buf[0]));
  Result := IncludeTrailingPathDelimiter(Result) + 'NativePeDUnitX-' + IntToStr(GetCurrentProcessId) + '.bin';
end;

procedure TBufferUtilTests.MaskToDwordBoundaries;
begin
  AssertUInt64($12345678, MaskToDword($12345678), 'DWORD normal');
  AssertUInt64($FFFFFFFF, MaskToDword($FFFFFFFF), 'DWORD max');
  AssertUInt64($FFFFFFFF, MaskToDword(UInt64($FFFFFFFF) + 1), 'DWORD saturates');
end;

procedure TBufferUtilTests.MaskToWordBoundaries;
begin
  AssertUInt64($1234, MaskToWord($1234), 'WORD normal');
  AssertUInt64($FFFF, MaskToWord($FFFF), 'WORD max');
  AssertUInt64($FFFF, MaskToWord($10000), 'WORD saturates');
end;

procedure TBufferUtilTests.ValidatePtrAcceptsInBounds;
var
  Buf: array [0 .. 63] of Byte;
begin
  Assert.IsTrue(ValidatePtr(@Buf[0], SizeOf(Buf), @Buf[10], 8));
  Assert.IsTrue(ValidatePtr(@Buf[0], SizeOf(Buf), @Buf[56], 8));
end;

procedure TBufferUtilTests.ValidatePtrRejectsPastEnd;
var
  Buf: array [0 .. 63] of Byte;
begin
  Assert.IsFalse(ValidatePtr(@Buf[0], SizeOf(Buf), @Buf[60], 8));
end;

procedure TBufferUtilTests.ValidatePtrRejectsBeforeStart;
var
  Buf: array [0 .. 63] of Byte;
begin
  Assert.IsFalse(ValidatePtr(@Buf[8], SizeOf(Buf) - 8, @Buf[0], 8));
end;

procedure TBufferUtilTests.ValidatePtrRejectsOverflow;
var
  FieldSize: NativeUInt;
begin
  FieldSize := High(NativeUInt) - 4;
  Assert.IsFalse(ValidatePtr(Pointer(NativeUInt($1000)), 100, Pointer(NativeUInt($100A)), FieldSize));
end;

procedure TBufferUtilTests.ValidatePtrRejectsNil;
var
  Buf: array [0 .. 15] of Byte;
begin
  Assert.IsFalse(ValidatePtr(nil, SizeOf(Buf), @Buf[0], 1));
  Assert.IsFalse(ValidatePtr(@Buf[0], SizeOf(Buf), nil, 1));
end;

procedure TBufferUtilTests.IsValidStringARequiresTerminator;
var
  Buf: array [0 .. 15] of AnsiChar;
begin
  FillChar(Buf, SizeOf(Buf), Ord('A'));
  Assert.IsFalse(IsValidStringA(@Buf[0], SizeOf(Buf), @Buf[0]));
  Buf[5] := #0;
  Assert.IsTrue(IsValidStringA(@Buf[0], SizeOf(Buf), @Buf[0]));
  Buf[0] := #0;
  Assert.IsFalse(IsValidStringA(@Buf[0], SizeOf(Buf), @Buf[0]));
end;

procedure TBufferUtilTests.IsValidStringWRequiresTerminator;
var
  Buf: array [0 .. 7] of WideChar;
  I: Integer;
begin
  for I := 0 to High(Buf) do
    Buf[I] := 'A';
  Assert.IsFalse(IsValidStringW(@Buf[0], SizeOf(Buf), @Buf[0]));
  Buf[3] := #0;
  Assert.IsTrue(IsValidStringW(@Buf[0], SizeOf(Buf), @Buf[0]));
  Buf[0] := #0;
  Assert.IsFalse(IsValidStringW(@Buf[0], SizeOf(Buf), @Buf[0]));
end;

procedure TFileUtilTests.PathPartsWindows;
begin
  Assert.IsTrue(GetFileNamePart('C:\Windows\System32\ntdll.dll') = 'ntdll.dll');
  Assert.IsTrue(GetDirectoryNamePart('C:\Windows\System32\ntdll.dll') = 'C:\Windows\System32');
end;

procedure TFileUtilTests.PathPartsUnixStyle;
begin
  Assert.IsTrue(GetFileNamePart('a/b/c.bin') = 'c.bin');
  Assert.IsTrue(GetDirectoryNamePart('a/b/c.bin') = 'a/b');
end;

procedure TFileUtilTests.PathPartsBareFile;
begin
  Assert.IsTrue(GetFileNamePart('test.bin') = 'test.bin');
  Assert.IsTrue(GetDirectoryNamePart('test.bin') = '');
end;

procedure TFileUtilTests.ExtensionPositionUsesLastDot;
begin
  Assert.IsTrue(FindExtensionPos('archive.part.bin') = 13);
end;

procedure TFileUtilTests.ExtensionPositionAbsentReturnsLengthPlusOne;
const
  S = 'filename';
begin
  Assert.IsTrue(FindExtensionPos(S) = Length(S) + 1);
end;

procedure TFileUtilTests.DumpReadRoundTrip;
var
  Path: string;
  Data: TBytes;
  ReadSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Path := TempFileName;
  Data := BytesOf([$10, $20, $30, $40, $50]);
  System.SysUtils.DeleteFile(Path);
  try
    Assert.IsTrue(DumpToFile(Path, @Data[0], Length(Data)), 'DumpToFile failed');
    ReadSize := 0;
    Buf := ReadFromFile(Path, ReadSize);
    try
      Assert.IsTrue(Buf <> nil, 'ReadFromFile returned nil');
      Assert.IsTrue(ReadSize = NativeUInt(Length(Data)), 'Read size mismatch');
      Assert.IsTrue(CompareMem(Buf, @Data[0], Length(Data)), 'Round-trip bytes differ');
    finally
      FreeFile(Buf);
    end;
  finally
    System.SysUtils.DeleteFile(Path);
  end;
end;

procedure TFileUtilTests.LoadFileHonorsRequestedSize;
var
  Path: string;
  Data: TBytes;
  ReadSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Path := TempFileName;
  Data := BytesOf([$11, $22, $33, $44, $55, $66]);
  System.SysUtils.DeleteFile(Path);
  try
    Assert.IsTrue(DumpToFile(Path, @Data[0], Length(Data)), 'DumpToFile failed');
    ReadSize := 3;
    Buf := LoadFile(Path, ReadSize);
    try
      Assert.IsTrue(Buf <> nil, 'LoadFile returned nil');
      Assert.IsTrue(ReadSize = 3, 'Requested partial size was not honored');
      Assert.IsTrue(CompareMem(Buf, @Data[0], 3), 'Partial bytes differ');
    finally
      FreeFile(Buf);
    end;
  finally
    System.SysUtils.DeleteFile(Path);
  end;
end;

procedure TExportedFuncTests.DllShortNameNormalizesPathCaseAndExtension;
begin
  Assert.IsTrue(GetDllShortName('C:\Windows\System32\KERNEL32.DLL') = 'kernel32');
  Assert.IsTrue(GetDllShortName('NTDLL') = 'ntdll');
end;

procedure TExportedFuncTests.ExportedFunctionPartUsesLastDot;
begin
  Assert.IsTrue(GetExportedFuncNamePart('KERNEL32.CreateFileW') = 'CreateFileW');
  Assert.IsTrue(GetExportedFuncNamePart('NoDot') = '');
end;

procedure TExportedFuncTests.OrdinalStringRoundTrip;
begin
  Assert.IsTrue(OrdinalToString(123) = '#123');
  Assert.IsTrue(IsOrdinalString('#123'));
  Assert.IsTrue(OrdinalStringToVal('#123') = 123);
  Assert.IsTrue(OrdinalStringToVal('#  +77') = 77);
end;

procedure TExportedFuncTests.ForwarderNameRequiresDot;
var
  A: AnsiString;
begin
  A := 'CreateFileW';
  Assert.IsTrue(ForwarderNameLen(PAnsiChar(A)) = 0);
end;

procedure TExportedFuncTests.ForwarderNameAcceptsCommonCharacters;
var
  A: AnsiString;
begin
  A := 'KERNELBASE.Api_Name@4-Impl';
  Assert.IsTrue(ForwarderNameLen(PAnsiChar(A)) = NativeUInt(Length(A)));
end;

procedure TExportedFuncTests.NamedForwarderParses;
var
  F: TExportedFunc;
begin
  F := TExportedFunc.CreateFromForwarder('KERNELBASE.CreateFileW');
  try
    Assert.IsTrue(F.LibName = 'kernelbase');
    Assert.IsTrue(F.FuncName = 'CreateFileW');
    Assert.IsFalse(F.IsByOrdinal);
    Assert.IsTrue(F.FuncOrdinal = 0);
    Assert.IsTrue(F.MapKey = 'kernelbase.CreateFileW');
  finally
    F.Free;
  end;
end;

procedure TExportedFuncTests.OrdinalForwarderParses;
var
  F: TExportedFunc;
begin
  F := TExportedFunc.CreateFromForwarder('NTDLL.#123');
  try
    Assert.IsTrue(F.LibName = 'ntdll');
    Assert.IsTrue(F.FuncName = '');
    Assert.IsTrue(F.IsByOrdinal);
    Assert.IsTrue(F.FuncOrdinal = 123);
    Assert.IsTrue(F.MapKey = 'ntdll.#123');
  finally
    F.Free;
  end;
end;

procedure TExportedFuncTests.NamedMapKeyIgnoresOrdinal;
var
  A, B: TExportedFunc;
begin
  A := TExportedFunc.Create('kernel32', 'CreateFileW', 1);
  B := TExportedFunc.Create('kernel32', 'CreateFileW', 999);
  try
    Assert.IsTrue(TExportedFunc.IsTheSameFuncName(A, B));
    Assert.IsTrue(A.MapKey = B.MapKey);
    Assert.IsFalse(A.ToStringFull = B.ToStringFull);
  finally
    B.Free;
    A.Free;
  end;
end;

procedure TExportedFuncTests.DllIdentityIgnoresModuleExtension;
var
  A, B: TExportedFunc;
begin
  A := TExportedFunc.Create('kernel32', 'X', 1);
  B := TExportedFunc.Create('kernel32.dll', 'X', 2);
  try
    Assert.IsTrue(TExportedFunc.IsTheSameDllName(A, B));
  finally
    B.Free;
    A.Free;
  end;
end;

procedure TExportedFuncTests.CopyConstructorPreservesFields;
var
  A, B: TExportedFunc;
begin
  A := TExportedFunc.Create('ntdll', 'NtClose', 15);
  B := TExportedFunc.Create(A);
  try
    Assert.IsTrue(A.LibName = B.LibName);
    Assert.IsTrue(A.FuncName = B.FuncName);
    Assert.IsTrue(A.FuncOrdinal = B.FuncOrdinal);
    Assert.IsTrue(A.IsByOrdinal = B.IsByOrdinal);
  finally
    B.Free;
    A.Free;
  end;
end;

procedure TTlsAddressTests.VirtualAddressConvertsToRva;
var
  Rva: DWORD;
begin
  Assert.IsTrue(VirtualAddrToRva($140000000, $4000, $140001234, Rva));
  Assert.IsTrue(Rva = $1234);
end;

procedure TTlsAddressTests.ExistingRvaPassesThrough;
var
  Rva: DWORD;
begin
  Assert.IsTrue(VirtualAddrToRva($140000000, $4000, $2345, Rva));
  Assert.IsTrue(Rva = $2345);
end;

procedure TTlsAddressTests.ZeroAddressRejected;
var
  Rva: DWORD;
begin
  Rva := $FFFFFFFF;
  Assert.IsFalse(VirtualAddrToRva($140000000, $4000, 0, Rva));
  Assert.IsTrue(Rva = 0);
end;

procedure TTlsAddressTests.ImageEndRejected;
var
  Rva: DWORD;
begin
  Assert.IsFalse(VirtualAddrToRva($140000000, $4000, $140004000, Rva));
end;

procedure TTlsAddressTests.OutsideImageRejected;
var
  Rva: DWORD;
begin
  Assert.IsFalse(VirtualAddrToRva($140000000, $4000, $5000, Rva));
end;

procedure TLdeTests.NopLength;
begin
  CheckInstruction([$90], 1, False, False, 'NOP');
end;

procedure TLdeTests.CallRel32Detected;
begin
  CheckInstruction([$E8, $11, $22, $33, $44], 5, False, True, 'CALL rel32');
end;

procedure TLdeTests.JccRel32Detected;
begin
  CheckInstruction([$0F, $84, $11, $22, $33, $44], 6, False, True, 'JZ rel32');
end;

procedure TLdeTests.RipRelativeMovDetected;
begin
  CheckInstruction([$48, $89, $05, $11, $22, $33, $44], 7, True, False, 'MOV RIP');
end;

procedure TLdeTests.RipRelativeIndirectCallDetected;
begin
  CheckInstruction([$FF, $15, $11, $22, $33, $44], 6, True, False, 'CALL RIP');
end;

procedure TLdeTests.MovImm64Length;
begin
  CheckInstruction([$48, $B8, 1, 2, 3, 4, 5, 6, 7, 8], 10, False, False, 'MOV imm64');
end;

procedure TLdeTests.F7TestImmediateLength;
begin
  CheckInstruction([$F7, $C0, $11, $22, $33, $44], 6, False, False, 'F7 TEST');
end;

procedure TLdeTests.F6TestImmediateLength;
begin
  CheckInstruction([$F6, $C0, $01], 3, False, False, 'F6 TEST');
end;

procedure TLdeTests.SibNoBaseDisp32Length;
begin
  CheckInstruction([$8B, $04, $85, 1, 2, 3, 4], 7, False, False, 'SIB disp32');
end;

procedure TLdeTests.MultiByteNopLength;
begin
  CheckInstruction([$0F, $1F, $00], 3, False, False, 'multi NOP');
end;

procedure TLdeTests.TrampolineStopsOnInstructionBoundary;
var
  Buf: array [0 .. 15] of Byte;
  N: Integer;
begin
  FillChar(Buf, SizeOf(Buf), $90);
  Buf[0] := $48;
  Buf[1] := $83;
  Buf[2] := $EC;
  Buf[3] := $20;
  Buf[4] := $E8;
  Buf[5] := $11;
  Buf[6] := $22;
  Buf[7] := $33;
  Buf[8] := $44;
  N := LdeGetTrampolineSize(@Buf[0], 6, True);
  Assert.IsTrue(N = 9, Format('Expected trampoline size 9, actual %d', [N]));
end;

initialization
  TDUnitX.RegisterTestFixture(TBufferUtilTests);
  TDUnitX.RegisterTestFixture(TFileUtilTests);
  TDUnitX.RegisterTestFixture(TExportedFuncTests);
  TDUnitX.RegisterTestFixture(TTlsAddressTests);
  TDUnitX.RegisterTestFixture(TLdeTests);

end.
