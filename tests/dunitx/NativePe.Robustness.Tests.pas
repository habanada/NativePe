unit NativePe.Robustness.Tests;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  DUnitX.TestFramework,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.PeRawToVirtual,
  NativePe.PeVirtualToRaw,
  NativePe.ExportsLookup,
  NativePe.ExportsMapper,
  NativePe.ResourceParser,
  NativePe.TlsParser,
  NativePe.Relocate,
  NativePe.ImportsLoader,
  NativePe.LoadConfig,
  NativePe.ExceptionsParser,
  NativePe.TestFixtures;

type
  {$M+}

  [TestFixture]
  TExceptionDirectoryRobustnessTests = class
  public
    [Test] procedure SetupExceptionsRejectsNilWithoutRegistration;
    [Test] procedure ExceptionDirectoryAbsentAccepted;
    [Test] procedure SingleRuntimeFunctionAccepted;
    [Test] procedure MultipleRuntimeFunctionsAccepted;
    [Test] procedure TruncatedPdataRejected;
    [Test] procedure ExceptionDirectoryOutsideImageRejected;
    [Test] procedure InvalidUnwindRvaRejected;
    [Test] procedure InvalidRuntimeFunctionRangeRejected;
    [Test] procedure ExceptionDirectorySizeOverflowRejected;
  end;

  [TestFixture]
  TSectionLayoutRobustnessTests = class
  public
    [Test] procedure VirtualSizeGreaterThanRawSizeZeroFillsTail;
    [Test] procedure RawSizeGreaterThanVirtualSizeCopiesRawBytes;
    [Test] procedure ZeroRawSizeLeavesVirtualSectionZeroed;
    [Test] procedure SectionGapRemainsZero;
    [Test] procedure TruncatedLastSectionCopiesAvailablePrefix;
    [Test] procedure InvalidRawOffsetIsSkippedSafely;
    [Test] procedure OverlappingSectionsUseSectionTableOrder;
    [Test] procedure LowSectionAlignmentAcceptedWhenConsistent;
    [Test] procedure UnusualFileAlignmentAcceptedWhenConsistent;
    [Test] procedure SectionSizeOverflowDoesNotWrap;
  end;

  [TestFixture]
  TResourceRobustnessTests = class
  public
    [Test] procedure MultipleRootEntriesKeepOwnRootIdentity;
    [Test] procedure NamedRootEntryTraverses;
    [Test] procedure MultipleLanguagesEnumerated;
    [Test] procedure InvalidResourceDirectoryOffsetRejected;
    [Test] procedure InvalidResourceDataRvaRejected;
    [Test] procedure ResourceCycleRejectedByDepthGuard;
    [Test] procedure OversizedResourceEntryCountRejected;
    [Test] procedure TruncatedResourceImageRejected;
  end;

  [TestFixture]
  TExportRobustnessTests = class
  public
    [Test] procedure OrdinalOnlyExportResolves;
    [Test] procedure ExportHoleByOrdinalReturnsNil;
    [Test] procedure NamedExportHoleReturnsNil;
    [Test] procedure HoleBeforeValidNamedExportDoesNotHideIt;
    [Test] procedure InvalidNameOrdinalIndexReturnsNil;
    [Test] procedure MapperRejectsInvalidNameOrdinalIndex;
    [Test] procedure MapperSkipsExportHole;
    [Test] procedure ForwarderChainResolvesToConcreteAddress;
    [Test] procedure InvalidForwarderDoesNotMapConcreteAddress;
    [Test] procedure StringLikeCodeOutsideExportDirectoryStillResolves;
    [Test] procedure ForwarderCycleDoesNotMapConcreteAddress;
  end;

  [TestFixture]
  TMalformedMatrixTests = class
  public
    [Test] procedure TruncatedDosHeaderRejected;
    [Test] procedure TruncatedNtHeaderRejected;
    [Test] procedure InvalidOptionalHeaderSizeRejectsSectionTable;
    [Test] procedure ExcessiveSectionCountRejectsSectionTable;
    [Test] procedure ExportNameOutsideImageRejected;
    [Test] procedure TlsCallbackTableOutsideImageRejected;
  end;

  [TestFixture]
  TFullRoundTripTests = class
  public
    [Test] procedure Pe64DirectoriesSurviveRawVirtualRawVirtual;
    [Test] procedure Pe32DirectoriesSurviveRawVirtualRawVirtual;
  end;

implementation

type
  PImageLoadConfigDir32W10Test = ^TImageLoadConfigDir32W10;
  PImageLoadConfigDir64W10Test = ^TImageLoadConfigDir64W10;

  TRuntimeFunctionEntryTest = packed record
    BeginAddress: DWORD;
    EndAddress: DWORD;
    UnwindInfoAddress: DWORD;
  end;
  PRuntimeFunctionEntryTest = ^TRuntimeFunctionEntryTest;

var
  GResCount: Integer;
  GResRoots: array [0 .. 7] of DWORD;
  GResRootNamed: array [0 .. 7] of Boolean;
  GResSizes: array [0 .. 7] of DWORD;

procedure PutAnsiZLocal(var Data: TBytes; Offset: NativeUInt; const S: AnsiString);
var
  N: Integer;
begin
  N := Length(S);
  if N > 0 then
    Move(S[1], Data[Offset], N);
  Data[Offset + NativeUInt(N)] := 0;
end;

procedure SetSectionNameLocal(Sec: PImageSectionHeader; const Name: AnsiString);
var
  N: Integer;
begin
  FillChar(Sec.Name, SizeOf(Sec.Name), 0);
  N := Length(Name);
  if N > SizeOf(Sec.Name) then
    N := SizeOf(Sec.Name);
  if N > 0 then
    Move(Name[1], Sec.Name[0], N);
end;

function ParseExceptionDirectoryForTest(ModulePtr: PByte; ModuleSize: NativeUInt; out Count: NativeUInt): Boolean;
var
  Dir: PImageDataDirectory;
  Entry: PRuntimeFunctionEntryTest;
  I: NativeUInt;
begin
  Result := False;
  Count := 0;
  if (ModulePtr = nil) or (ModuleSize = 0) then
    Exit;
  Dir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
  if Dir = nil then
    Exit(True);
  if (Dir.Size = 0) or ((Dir.Size mod SizeOf(TRuntimeFunctionEntryTest)) <> 0) then
    Exit;
  if not ValidatePtr(ModulePtr, ModuleSize, ModulePtr + Dir.VirtualAddress, Dir.Size) then
    Exit;
  Count := Dir.Size div SizeOf(TRuntimeFunctionEntryTest);
  I := 0;
  while I < Count do
  begin
    Entry := PRuntimeFunctionEntryTest(ModulePtr + Dir.VirtualAddress + I * SizeOf(TRuntimeFunctionEntryTest));
    if (Entry.BeginAddress >= Entry.EndAddress) or (Entry.EndAddress > ModuleSize) then
      Exit(False);
    if (Entry.UnwindInfoAddress = 0) or (not ValidatePtr(ModulePtr, ModuleSize, ModulePtr + Entry.UnwindInfoAddress, 1)) then
      Exit(False);
    Inc(I);
  end;
  Result := True;
end;

procedure AddExceptionDirectory64(var Data: TBytes; EntryCount: Integer);
var
  Nt: PImageNtHeaders64;
  Entry: PRuntimeFunctionEntryTest;
  I: Integer;
begin
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress := $2800;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size := EntryCount * SizeOf(TRuntimeFunctionEntryTest);
  for I := 0 to EntryCount - 1 do
  begin
    Entry := PRuntimeFunctionEntryTest(@Data[$2800 + I * SizeOf(TRuntimeFunctionEntryTest)]);
    Entry.BeginAddress := $1000 + DWORD(I) * $100;
    Entry.EndAddress := Entry.BeginAddress + $80;
    Entry.UnwindInfoAddress := $2B80 + DWORD(I) * $10;
    Data[Entry.UnwindInfoAddress] := 1;
  end;
end;

function CaptureComplexResource(ModulePtr: PByte; RootDir: PImageResourceDirectoryEntry;
  CurrEntry: PImageResourceDataEntry): Boolean;
begin
  if GResCount < Length(GResRoots) then
  begin
    GResRoots[GResCount] := RootDir.NameOrId;
    GResRootNamed[GResCount] := RootDir.NameIsString;
    GResSizes[GResCount] := CurrEntry.Size;
  end;
  Inc(GResCount);
  Result := True;
end;

procedure ResetResourceCapture;
begin
  GResCount := 0;
  FillChar(GResRoots, SizeOf(GResRoots), 0);
  FillChar(GResRootNamed, SizeOf(GResRootNamed), 0);
  FillChar(GResSizes, SizeOf(GResSizes), 0);
end;

function BuildResourceTree64: TBytes;
var
  P: PByte;
  Nt: PImageNtHeaders64;
  Dir: PImageResourceDirectory;
  Entry: PImageResourceDirectoryEntry;
  DataEntry: PImageResourceDataEntry;
begin
  Result := BuildRichVirtualPe64;
  P := @Result[0];
  FillChar(Result[$2300], $300, 0);
  Nt := PImageNtHeaders64(P + TEST_NT_OFFSET);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress := $2300;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size := $300;
  Dir := PImageResourceDirectory(P + $2300);
  Dir.NumberOfNamedEntries := 1;
  Dir.NumberOfIdEntries := 1;
  Entry := PImageResourceDirectoryEntry(P + $2310);
  Entry.NameOrId := $80000180;
  Entry.OffsetToDataOrDirectory := $80000080;
  Inc(Entry);
  Entry.NameOrId := 10;
  Entry.OffsetToDataOrDirectory := $80000040;
  PWord(P + $2480)^ := 5;
  PWideChar(P + $2482)[0] := 'N';
  PWideChar(P + $2482)[1] := 'A';
  PWideChar(P + $2482)[2] := 'M';
  PWideChar(P + $2482)[3] := 'E';
  PWideChar(P + $2482)[4] := 'D';

  Dir := PImageResourceDirectory(P + $2340);
  Dir.NumberOfIdEntries := 1;
  Entry := PImageResourceDirectoryEntry(P + $2350);
  Entry.NameOrId := 1;
  Entry.OffsetToDataOrDirectory := $800000A0;

  Dir := PImageResourceDirectory(P + $2380);
  Dir.NumberOfIdEntries := 1;
  Entry := PImageResourceDirectoryEntry(P + $2390);
  Entry.NameOrId := 2;
  Entry.OffsetToDataOrDirectory := $800000C0;

  Dir := PImageResourceDirectory(P + $23A0);
  Dir.NumberOfIdEntries := 2;
  Entry := PImageResourceDirectoryEntry(P + $23B0);
  Entry.NameOrId := 1033;
  Entry.OffsetToDataOrDirectory := $E0;
  Inc(Entry);
  Entry.NameOrId := 1031;
  Entry.OffsetToDataOrDirectory := $F0;

  Dir := PImageResourceDirectory(P + $23C0);
  Dir.NumberOfIdEntries := 1;
  Entry := PImageResourceDirectoryEntry(P + $23D0);
  Entry.NameOrId := 1033;
  Entry.OffsetToDataOrDirectory := $100;

  DataEntry := PImageResourceDataEntry(P + $23E0);
  DataEntry.OffsetToData := $2600;
  DataEntry.Size := 4;
  Inc(DataEntry);
  DataEntry.OffsetToData := $2610;
  DataEntry.Size := 5;
  Inc(DataEntry);
  DataEntry.OffsetToData := $2620;
  DataEntry.Size := 6;
end;

procedure ConfigureSingleExport64(var Data: TBytes; const DllName, FuncName: AnsiString; FuncRva: DWORD);
var
  P: PByte;
  Nt: PImageNtHeaders64;
  Exp: PImageExportDirectory;
begin
  P := @Data[0];
  FillChar(Data[$2100], $180, 0);
  Nt := PImageNtHeaders64(P + TEST_NT_OFFSET);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress := $2100;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size := $180;
  Exp := PImageExportDirectory(P + $2100);
  Exp.Name := $2180;
  Exp.Base := 1;
  Exp.NumberOfFunctions := 1;
  Exp.NumberOfNames := 1;
  Exp.AddressOfFunctions := $2200;
  Exp.AddressOfNames := $2220;
  Exp.AddressOfNameOrdinals := $2240;
  PDWORD(P + $2200)^ := FuncRva;
  PDWORD(P + $2220)^ := $2260;
  PWord(P + $2240)^ := 0;
  PutAnsiZLocal(Data, $2180, DllName);
  PutAnsiZLocal(Data, $2260, FuncName);
end;

function FixtureVirtualToRaw(const VirtualImage: TBytes): TBytes;
var
  P: PByte;
  I, Count: NativeUInt;
  Sec: PImageSectionHeader;
  RawSize: DWORD;
begin
  SetLength(Result, CalcPeSize(@VirtualImage[0], Length(VirtualImage), True));
  FillChar(Result[0], Length(Result), 0);
  P := @VirtualImage[0];
  RawSize := GetHdrsSize(P);
  if RawSize > Length(Result) then
    RawSize := Length(Result);
  if RawSize > 0 then
    Move(VirtualImage[0], Result[0], RawSize);
  Count := GetSectionsCount(P, Length(VirtualImage));
  I := 0;
  while I < Count do
  begin
    Sec := GetSectionHdr(P, Length(VirtualImage), I);
    if (Sec <> nil) and (Sec.SizeOfRawData <> 0) and
      (NativeUInt(Sec.VirtualAddress) + Sec.SizeOfRawData <= NativeUInt(Length(VirtualImage))) and
      (NativeUInt(Sec.PointerToRawData) + Sec.SizeOfRawData <= NativeUInt(Length(Result))) then
      Move(VirtualImage[Sec.VirtualAddress], Result[Sec.PointerToRawData], Sec.SizeOfRawData);
    Inc(I);
  end;
end;

function BuildRoundTripVirtual32: TBytes;
var
  P: PByte;
  Nt: PImageNtHeaders32;
  Sec: PImageSectionHeader;
  Exp: PImageExportDirectory;
  ResDir: PImageResourceDirectory;
  ResEntry: PImageResourceDirectoryEntry;
  ResData: PImageResourceDataEntry;
  Tls: PImageTlsDirectory32;
  Imp: PImageImportDescriptor;
  Thunk: PImageThunkData32;
  ByName: PImageImportByName;
  Reloc: PImageBaseRelocation;
  RelEntry: PWord;
  Lc: PImageLoadConfigDir32W10Test;
begin
  SetLength(Result, TEST_IMAGE_SIZE);
  FillChar(Result[0], Length(Result), 0);
  P := @Result[0];
  PImageDosHeader(P).e_magic := IMAGE_DOS_SIGNATURE;
  PImageDosHeader(P).e_lfanew := TEST_NT_OFFSET;
  Nt := PImageNtHeaders32(P + TEST_NT_OFFSET);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_I386;
  Nt.FileHeader.NumberOfSections := 3;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
  Nt.FileHeader.Characteristics := $0002 or IMAGE_FILE_DLL;
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  Nt.OptionalHeader.AddressOfEntryPoint := $1050;
  Nt.OptionalHeader.BaseOfCode := $1000;
  Nt.OptionalHeader.BaseOfData := $2000;
  Nt.OptionalHeader.ImageBase := TEST_IMAGE_BASE32;
  Nt.OptionalHeader.SectionAlignment := TEST_SECTION_ALIGNMENT;
  Nt.OptionalHeader.FileAlignment := TEST_FILE_ALIGNMENT;
  Nt.OptionalHeader.SizeOfImage := TEST_IMAGE_SIZE;
  Nt.OptionalHeader.SizeOfHeaders := TEST_HEADERS_SIZE;
  Nt.OptionalHeader.NumberOfRvaAndSizes := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  Sec := PImageSectionHeader(NativeUInt(@Nt.OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader);
  SetSectionNameLocal(Sec, '.text');
  Sec.Misc.VirtualSize := $400;
  Sec.VirtualAddress := $1000;
  Sec.SizeOfRawData := $400;
  Sec.PointerToRawData := $400;
  Sec.Characteristics := IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ;
  Inc(Sec);
  SetSectionNameLocal(Sec, '.rdata');
  Sec.Misc.VirtualSize := $1000;
  Sec.VirtualAddress := $2000;
  Sec.SizeOfRawData := $1000;
  Sec.PointerToRawData := $800;
  Sec.Characteristics := IMAGE_SCN_MEM_READ;
  Inc(Sec);
  SetSectionNameLocal(Sec, '.reloc');
  Sec.Misc.VirtualSize := $200;
  Sec.VirtualAddress := $3000;
  Sec.SizeOfRawData := $200;
  Sec.PointerToRawData := $1800;
  Sec.Characteristics := IMAGE_SCN_MEM_READ;
  Result[$1050] := $C3;
  PDWORD(P + $1020)^ := TEST_IMAGE_BASE32 + $1234;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress := $2100;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size := $180;
  Exp := PImageExportDirectory(P + $2100);
  Exp.Name := $2180;
  Exp.Base := 1;
  Exp.NumberOfFunctions := 1;
  Exp.NumberOfNames := 1;
  Exp.AddressOfFunctions := $2200;
  Exp.AddressOfNames := $2220;
  Exp.AddressOfNameOrdinals := $2240;
  PDWORD(P + $2200)^ := $1050;
  PDWORD(P + $2220)^ := $2260;
  PWord(P + $2240)^ := 0;
  PutAnsiZLocal(Result, $2180, 'round32.dll');
  PutAnsiZLocal(Result, $2260, 'Only32');

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress := $2300;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size := $80;
  ResDir := PImageResourceDirectory(P + $2300);
  ResDir.NumberOfIdEntries := 1;
  ResEntry := PImageResourceDirectoryEntry(P + $2310);
  ResEntry.NameOrId := 10;
  ResEntry.OffsetToDataOrDirectory := $20;
  ResData := PImageResourceDataEntry(P + $2320);
  ResData.OffsetToData := $2380;
  ResData.Size := 4;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress := $2400;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size := SizeOf(TImageTlsDirectory32);
  Tls := PImageTlsDirectory32(P + $2400);
  Tls.AddressOfCallBacks := $2450;
  PDWORD(P + $2450)^ := $11111111;
  PDWORD(P + $2454)^ := $22222222;
  PDWORD(P + $2458)^ := 0;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress := $2600;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size := 2 * SizeOf(TImageImportDescriptor);
  Imp := PImageImportDescriptor(P + $2600);
  Imp.OriginalFirstThunk := $2680;
  Imp.Name := $2640;
  Imp.FirstThunk := $26A0;
  PutAnsiZLocal(Result, $2640, 'fixturedep.dll');
  Thunk := PImageThunkData32(P + $2680);
  Thunk.AddressOfData := $26C0;
  Inc(Thunk);
  Thunk.Ordinal := IMAGE_ORDINAL_FLAG32 or 7;
  Inc(Thunk);
  Thunk.Func := 0;
  Thunk := PImageThunkData32(P + $26A0);
  Thunk.Func := $1111;
  Inc(Thunk);
  Thunk.Func := $2222;
  Inc(Thunk);
  Thunk.Func := 0;
  ByName := PImageImportByName(P + $26C0);
  ByName.Hint := 42;
  PutAnsiZLocal(Result, $26C2, 'NamedFunc');

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress := $2800;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size := SizeOf(TImageLoadConfigDir32W10);
  Lc := PImageLoadConfigDir32W10Test(P + $2800);
  Lc.Size := SizeOf(TImageLoadConfigDir32W10);
  Lc.SecurityCookie := TEST_IMAGE_BASE32 + $2F00;
  Lc.GuardFlags := $100;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress := $3000;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 12;
  Reloc := PImageBaseRelocation(P + $3000);
  Reloc.VirtualAddress := $1000;
  Reloc.SizeOfBlock := 12;
  RelEntry := PWord(P + $3008);
  RelEntry^ := Word((3 shl 12) or $20);
  Inc(RelEntry);
  RelEntry^ := 0;
end;

function BuildFullVirtual64: TBytes;
var
  Nt: PImageNtHeaders64;
  Lc: PImageLoadConfigDir64W10Test;
begin
  Result := BuildRichVirtualPe64;
  AddExceptionDirectory64(Result, 2);
  Nt := PImageNtHeaders64(@Result[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress := $2900;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size := SizeOf(TImageLoadConfigDir64W10);
  Lc := PImageLoadConfigDir64W10Test(@Result[$2900]);
  Lc.Size := SizeOf(TImageLoadConfigDir64W10);
  Lc.SecurityCookie := TEST_IMAGE_BASE64 + $2B00;
  Lc.GuardFlags := $100;
end;

procedure AssertDirectoryTableEqual(A, B: PByte);
var
  I: DWORD;
  DA, DB: PImageDataDirectory;
begin
  for I := 0 to IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1 do
  begin
    DA := GetDirectoryEntry(A, I, True);
    DB := GetDirectoryEntry(B, I, True);
    Assert.IsTrue((DA = nil) = (DB = nil));
    if (DA <> nil) and (DB <> nil) then
    begin
      Assert.IsTrue(DA.VirtualAddress = DB.VirtualAddress);
      Assert.IsTrue(DA.Size = DB.Size);
    end;
  end;
end;

procedure AssertCommonSemantics(A, B: PByte; SizeA, SizeB: NativeUInt; Is64: Boolean);
var
  I, Count, Span: NativeUInt;
  SA, SB: PImageSectionHeader;
  ImportsA, ImportsB: TImportsCollection;
  ExportNamesA, ExportNamesB: TList<string>;
  TlsA, TlsB: TList<UInt64>;
  LcA, LcB: PByte;
  ExcA, ExcB: NativeUInt;
begin
  Assert.IsTrue(Is64Bit(A) = Is64);
  Assert.IsTrue(Is64Bit(B) = Is64);
  Assert.IsTrue(GetImageBase(A) = GetImageBase(B));
  Assert.IsTrue(GetEntryPointRva(A) = GetEntryPointRva(B));
  Assert.IsTrue(GetSectionsCount(A, SizeA) = GetSectionsCount(B, SizeB));
  AssertDirectoryTableEqual(A, B);
  Count := GetSectionsCount(A, SizeA);
  I := 0;
  while I < Count do
  begin
    SA := GetSectionHdr(A, SizeA, I);
    SB := GetSectionHdr(B, SizeB, I);
    Assert.IsTrue((SA <> nil) and (SB <> nil));
    Assert.IsTrue(SA.VirtualAddress = SB.VirtualAddress);
    Assert.IsTrue(SA.Misc.VirtualSize = SB.Misc.VirtualSize);
    Assert.IsTrue(SA.SizeOfRawData = SB.SizeOfRawData);
    Span := SA.SizeOfRawData;
    if Span > 0 then
    begin
      Assert.IsTrue(NativeUInt(SA.VirtualAddress) + Span <= SizeA);
      Assert.IsTrue(NativeUInt(SB.VirtualAddress) + Span <= SizeB);
      Assert.IsTrue(CompareMem(A + SA.VirtualAddress, B + SB.VirtualAddress, NativeInt(Span)));
    end;
    Inc(I);
  end;
  ExportNamesA := TList<string>.Create;
  ExportNamesB := TList<string>.Create;
  try
    Assert.IsTrue(GetExportedNames(A, ExportNamesA) = GetExportedNames(B, ExportNamesB));
    Assert.IsTrue(ExportNamesA.Count = ExportNamesB.Count);
    I := 0;
    while I < NativeUInt(ExportNamesA.Count) do
    begin
      Assert.IsTrue(ExportNamesA[Integer(I)] = ExportNamesB[Integer(I)]);
      Inc(I);
    end;
  finally
    ExportNamesA.Free;
    ExportNamesB.Free;
  end;
  Assert.IsTrue(HasValidRelocationTable(A, SizeA));
  Assert.IsTrue(HasValidRelocationTable(B, SizeB));
  ImportsA := TImportsCollection.Create;
  ImportsB := TImportsCollection.Create;
  try
    Assert.IsTrue(CollectImports(A, SizeA, ImportsA));
    Assert.IsTrue(CollectImports(B, SizeB, ImportsB));
    Assert.IsTrue(ImportsA.ThunkToFunc.Count = ImportsB.ThunkToFunc.Count);
  finally
    ImportsA.Free;
    ImportsB.Free;
  end;
  TlsA := TList<UInt64>.Create;
  TlsB := TList<UInt64>.Create;
  try
    Assert.IsTrue(ListTlsCallbacks(A, SizeA, TlsA) = ListTlsCallbacks(B, SizeB, TlsB));
    Assert.IsTrue(TlsA.Count = TlsB.Count);
    I := 0;
    while I < NativeUInt(TlsA.Count) do
    begin
      Assert.IsTrue(TlsA[Integer(I)] = TlsB[Integer(I)]);
      Inc(I);
    end;
  finally
    TlsA.Free;
    TlsB.Free;
  end;
  ResetResourceCapture;
  Assert.IsTrue(ParseResources(A, CaptureComplexResource));
  Count := GResCount;
  ResetResourceCapture;
  Assert.IsTrue(ParseResources(B, CaptureComplexResource));
  Assert.IsTrue(Count = NativeUInt(GResCount));
  LcA := GetLoadConfigPtr(A, SizeA);
  LcB := GetLoadConfigPtr(B, SizeB);
  Assert.IsTrue((LcA = nil) = (LcB = nil));
  if (LcA <> nil) and (LcB <> nil) then
  begin
    Assert.IsTrue(GetLoadConfigVersion(A, SizeA, LcA) = GetLoadConfigVersion(B, SizeB, LcB));
    Assert.IsTrue(PDWORD(LcA)^ = PDWORD(LcB)^);
    if Is64 then
    begin
      Assert.IsTrue(PImageLoadConfigDir64W10Test(LcA).SecurityCookie = PImageLoadConfigDir64W10Test(LcB).SecurityCookie);
      Assert.IsTrue(PImageLoadConfigDir64W10Test(LcA).GuardFlags = PImageLoadConfigDir64W10Test(LcB).GuardFlags);
    end
    else
    begin
      Assert.IsTrue(PImageLoadConfigDir32W10Test(LcA).SecurityCookie = PImageLoadConfigDir32W10Test(LcB).SecurityCookie);
      Assert.IsTrue(PImageLoadConfigDir32W10Test(LcA).GuardFlags = PImageLoadConfigDir32W10Test(LcB).GuardFlags);
    end;
  end;
  Assert.IsTrue(ParseExceptionDirectoryForTest(A, SizeA, ExcA));
  Assert.IsTrue(ParseExceptionDirectoryForTest(B, SizeB, ExcB));
  Assert.IsTrue(ExcA = ExcB);
end;

procedure RunFullRoundTrip(const VirtualFixture: TBytes; Is64: Boolean; const ExportName: AnsiString);
var
  RawInput: TBytes;
  V1, V2, RawBack: TAlignedBuf;
  V1Size, V2Size, RawBackSize: NativeUInt;
begin
  RawInput := FixtureVirtualToRaw(VirtualFixture);
  V1 := PeRawToVirtual(@RawInput[0], Length(RawInput), V1Size, False);
  Assert.IsTrue(V1 <> nil);
  try
    AssertCommonSemantics(@VirtualFixture[0], V1, Length(VirtualFixture), V1Size, Is64);
    Assert.IsTrue(GetExportedFunc(V1, PAnsiChar(ExportName)) <> nil);
    RawBack := PeVirtualToRaw(V1, V1Size, GetImageBase(V1), RawBackSize, True);
    Assert.IsTrue(RawBack <> nil);
    try
      V2 := PeRawToVirtual(RawBack, RawBackSize, V2Size, False);
      Assert.IsTrue(V2 <> nil);
      try
        AssertCommonSemantics(V1, V2, V1Size, V2Size, Is64);
        Assert.IsTrue(GetExportedFunc(V2, PAnsiChar(ExportName)) <> nil);
      finally
        FreePeBuffer(V2, V2Size);
      end;
    finally
      FreePeBuffer(RawBack, V1Size);
    end;
  finally
    FreePeBuffer(V1, V1Size);
  end;
end;


procedure TExceptionDirectoryRobustnessTests.SetupExceptionsRejectsNilWithoutRegistration;
begin
  Assert.IsFalse(SetupExceptions(nil, 0));
end;

procedure TExceptionDirectoryRobustnessTests.ExceptionDirectoryAbsentAccepted;
var
  Data: TBytes;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
  Assert.IsTrue(Count = 0);
end;

procedure TExceptionDirectoryRobustnessTests.SingleRuntimeFunctionAccepted;
var
  Data: TBytes;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  AddExceptionDirectory64(Data, 1);
  Assert.IsTrue(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
  Assert.IsTrue(Count = 1);
end;

procedure TExceptionDirectoryRobustnessTests.MultipleRuntimeFunctionsAccepted;
var
  Data: TBytes;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  AddExceptionDirectory64(Data, 3);
  Assert.IsTrue(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
  Assert.IsTrue(Count = 3);
end;

procedure TExceptionDirectoryRobustnessTests.TruncatedPdataRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  AddExceptionDirectory64(Data, 1);
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size := SizeOf(TRuntimeFunctionEntryTest) - 1;
  Assert.IsFalse(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
end;

procedure TExceptionDirectoryRobustnessTests.ExceptionDirectoryOutsideImageRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress := TEST_IMAGE_SIZE - 4;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size := SizeOf(TRuntimeFunctionEntryTest);
  Assert.IsFalse(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
end;

procedure TExceptionDirectoryRobustnessTests.InvalidUnwindRvaRejected;
var
  Data: TBytes;
  Entry: PRuntimeFunctionEntryTest;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  AddExceptionDirectory64(Data, 1);
  Entry := PRuntimeFunctionEntryTest(@Data[$2800]);
  Entry.UnwindInfoAddress := TEST_IMAGE_SIZE + $100;
  Assert.IsFalse(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
end;



procedure TExceptionDirectoryRobustnessTests.InvalidRuntimeFunctionRangeRejected;
var
  Data: TBytes;
  Entry: PRuntimeFunctionEntryTest;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  AddExceptionDirectory64(Data, 1);
  Entry := PRuntimeFunctionEntryTest(@Data[$2800]);
  Entry.BeginAddress := $1100;
  Entry.EndAddress := $1000;
  Assert.IsFalse(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
end;

procedure TExceptionDirectoryRobustnessTests.ExceptionDirectorySizeOverflowRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress := $1000;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size := $FFFFFFF0;
  Assert.IsFalse(ParseExceptionDirectoryForTest(@Data[0], Length(Data), Count));
end;

procedure TSectionLayoutRobustnessTests.VirtualSizeGreaterThanRawSizeZeroFillsTail;
var
  Data: TBytes;
  Sec: PImageSectionHeader;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  Sec := GetSectionHdr(@Data[0], Length(Data), 0);
  Sec.Misc.VirtualSize := $800;
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$1000 + $3FF] = Data[$400 + $3FF]);
    Assert.IsTrue(V[$1000 + $400] = 0);
    Assert.IsTrue(V[$1000 + $7FF] = 0);
  finally
    FreePeBuffer(V, VSize);
  end;
end;

procedure TSectionLayoutRobustnessTests.RawSizeGreaterThanVirtualSizeCopiesRawBytes;
var
  Data: TBytes;
  Sec: PImageSectionHeader;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  Sec := GetSectionHdr(@Data[0], Length(Data), 0);
  Sec.Misc.VirtualSize := $100;
  Data[$400 + $300] := $A5;
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$1300] = $A5);
  finally
    FreePeBuffer(V, VSize);
  end;
end;

procedure TSectionLayoutRobustnessTests.ZeroRawSizeLeavesVirtualSectionZeroed;
var
  Data: TBytes;
  Sec: PImageSectionHeader;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  Sec := GetSectionHdr(@Data[0], Length(Data), 0);
  Sec.SizeOfRawData := 0;
  Sec.Misc.VirtualSize := $400;
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$1000] = 0);
    Assert.IsTrue(V[$13FF] = 0);
  finally
    FreePeBuffer(V, VSize);
  end;
end;

procedure TSectionLayoutRobustnessTests.SectionGapRemainsZero;
var
  Data: TBytes;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$1800] = 0);
    Assert.IsTrue(V[$1FFF] = 0);
  finally
    FreePeBuffer(V, VSize);
  end;
end;

procedure TSectionLayoutRobustnessTests.TruncatedLastSectionCopiesAvailablePrefix;
var
  Data: TBytes;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  SetLength(Data, $1480);
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$3000] = Data[$1400]);
    Assert.IsTrue(V[$307F] = Data[$147F]);
    Assert.IsTrue(V[$3080] = 0);
  finally
    FreePeBuffer(V, VSize);
  end;
end;

procedure TSectionLayoutRobustnessTests.InvalidRawOffsetIsSkippedSafely;
var
  Data: TBytes;
  Sec: PImageSectionHeader;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  Sec := GetSectionHdr(@Data[0], Length(Data), 0);
  Sec.PointerToRawData := DWORD(Length(Data) + $100);
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$1000] = 0);
  finally
    FreePeBuffer(V, VSize);
  end;
end;

procedure TSectionLayoutRobustnessTests.OverlappingSectionsUseSectionTableOrder;
var
  Data: TBytes;
  Sec0, Sec1: PImageSectionHeader;
  V: TAlignedBuf;
  VSize: NativeUInt;
begin
  Data := BuildRichRawPe64;
  Sec0 := GetSectionHdr(@Data[0], Length(Data), 0);
  Sec1 := GetSectionHdr(@Data[0], Length(Data), 1);
  Sec0.SizeOfRawData := $200;
  Sec1.VirtualAddress := $1100;
  Sec1.SizeOfRawData := $200;
  FillChar(Data[$400], $200, $11);
  FillChar(Data[$800], $200, $22);
  V := PeRawToVirtual(@Data[0], Length(Data), VSize, False);
  Assert.IsTrue(V <> nil);
  try
    Assert.IsTrue(V[$10FF] = $11);
    Assert.IsTrue(V[$1100] = $22);
    Assert.IsTrue(V[$11FF] = $22);
  finally
    FreePeBuffer(V, VSize);
  end;
end;


procedure TSectionLayoutRobustnessTests.LowSectionAlignmentAcceptedWhenConsistent;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
begin
  Data := BuildRichRawPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.SectionAlignment := $200;
  Nt.OptionalHeader.FileAlignment := $200;
  Assert.IsTrue(IsValidSectionsAlignment(@Data[0], Length(Data), False));
  Assert.IsTrue(IsValidSectionsAlignment(@Data[0], Length(Data), True));
end;

procedure TSectionLayoutRobustnessTests.UnusualFileAlignmentAcceptedWhenConsistent;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
begin
  Data := BuildRichRawPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.FileAlignment := $400;
  Assert.IsTrue(IsValidSectionsAlignment(@Data[0], Length(Data), True));
end;

procedure TSectionLayoutRobustnessTests.SectionSizeOverflowDoesNotWrap;
var
  Data: TBytes;
  Sec: PImageSectionHeader;
begin
  Data := BuildRichRawPe64;
  Sec := GetSectionHdr(@Data[0], Length(Data), 0);
  Sec.PointerToRawData := $FFFFFFF0;
  Sec.SizeOfRawData := $100;
  Assert.IsTrue(CalcPeSize(@Data[0], Length(Data), True) = TEST_RAW_SIZE);
end;

procedure TResourceRobustnessTests.MultipleRootEntriesKeepOwnRootIdentity;
var
  Data: TBytes;
begin
  Data := BuildResourceTree64;
  ResetResourceCapture;
  Assert.IsTrue(ParseResources(@Data[0], CaptureComplexResource));
  Assert.IsTrue(GResCount = 3);
  Assert.IsTrue(GResRootNamed[0]);
  Assert.IsTrue(GResRoots[1] = 10);
  Assert.IsTrue(GResRoots[2] = 10);
end;

procedure TResourceRobustnessTests.NamedRootEntryTraverses;
var
  Data: TBytes;
begin
  Data := BuildResourceTree64;
  ResetResourceCapture;
  Assert.IsTrue(ParseResources(@Data[0], CaptureComplexResource));
  Assert.IsTrue(GResRootNamed[0]);
  Assert.IsTrue((GResRoots[0] and $7FFFFFFF) = $180);
end;

procedure TResourceRobustnessTests.MultipleLanguagesEnumerated;
var
  Data: TBytes;
begin
  Data := BuildResourceTree64;
  ResetResourceCapture;
  Assert.IsTrue(ParseResources(@Data[0], CaptureComplexResource));
  Assert.IsTrue(GResCount = 3);
  Assert.IsTrue(GResSizes[0] = 6);
  Assert.IsTrue(GResSizes[1] = 4);
  Assert.IsTrue(GResSizes[2] = 5);
end;

procedure TResourceRobustnessTests.InvalidResourceDirectoryOffsetRejected;
var
  Data: TBytes;
  Entry: PImageResourceDirectoryEntry;
begin
  Data := BuildResourceTree64;
  Entry := PImageResourceDirectoryEntry(@Data[$2310]);
  Entry.OffsetToDataOrDirectory := $80003FF0;
  ResetResourceCapture;
  Assert.IsFalse(ParseResources(@Data[0], CaptureComplexResource));
end;

procedure TResourceRobustnessTests.InvalidResourceDataRvaRejected;
var
  Data: TBytes;
  DataEntry: PImageResourceDataEntry;
begin
  Data := BuildResourceTree64;
  DataEntry := PImageResourceDataEntry(@Data[$23E0]);
  DataEntry.OffsetToData := TEST_IMAGE_SIZE + $100;
  ResetResourceCapture;
  Assert.IsFalse(ParseResources(@Data[0], CaptureComplexResource));
end;

procedure TResourceRobustnessTests.ResourceCycleRejectedByDepthGuard;
var
  Data: TBytes;
  Entry: PImageResourceDirectoryEntry;
begin
  Data := BuildResourceTree64;
  Entry := PImageResourceDirectoryEntry(@Data[$2350]);
  Entry.OffsetToDataOrDirectory := $80000040;
  ResetResourceCapture;
  Assert.IsFalse(ParseResources(@Data[0], CaptureComplexResource));
end;

procedure TResourceRobustnessTests.OversizedResourceEntryCountRejected;
var
  Data: TBytes;
  Dir: PImageResourceDirectory;
begin
  Data := BuildResourceTree64;
  Dir := PImageResourceDirectory(@Data[$2300]);
  Dir.NumberOfIdEntries := High(Word);
  ResetResourceCapture;
  Assert.IsFalse(ParseResources(@Data[0], CaptureComplexResource));
end;


procedure TResourceRobustnessTests.TruncatedResourceImageRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
begin
  Data := BuildResourceTree64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.SizeOfImage := $2314;
  ResetResourceCapture;
  Assert.IsFalse(ParseResources(@Data[0], CaptureComplexResource));
end;

procedure TExportRobustnessTests.OrdinalOnlyExportResolves;
var
  Data: TBytes;
  Exp: PImageExportDirectory;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'ordinal.dll', 'Unused', $1050);
  Exp := PImageExportDirectory(@Data[$2100]);
  Exp.NumberOfNames := 0;
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(NativeUInt(1))) = FARPROC(@Data[$1050]));
end;

procedure TExportRobustnessTests.ExportHoleByOrdinalReturnsNil;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'hole.dll', 'Hole', 0);
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(NativeUInt(1))) = nil);
end;

procedure TExportRobustnessTests.NamedExportHoleReturnsNil;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'hole.dll', 'Hole', 0);
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(AnsiString('Hole'))) = nil);
end;


procedure TExportRobustnessTests.HoleBeforeValidNamedExportDoesNotHideIt;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  PDWORD(@Data[$2200])^ := 0;
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(AnsiString('Beta'))) = FARPROC(@Data[$1060]));
end;

procedure TExportRobustnessTests.InvalidNameOrdinalIndexReturnsNil;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'badord.dll', 'Bad', $1050);
  PWord(@Data[$2240])^ := 4;
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(AnsiString('Bad'))) = nil);
end;

procedure TExportRobustnessTests.MapperRejectsInvalidNameOrdinalIndex;
var
  Data: TBytes;
  Mapper: TExportsMapper;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'badord.dll', 'Bad', $1050);
  PWord(@Data[$2240])^ := 4;
  Mapper := TExportsMapper.Create;
  try
    Assert.IsTrue(Mapper.AddToLookup('badord.dll', HMODULE(NativeUInt(@Data[0])), Length(Data), TEST_IMAGE_BASE64) = 0);
  finally
    Mapper.Free;
  end;
end;

procedure TExportRobustnessTests.MapperSkipsExportHole;
var
  Data: TBytes;
  Mapper: TExportsMapper;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'hole.dll', 'Hole', 0);
  Mapper := TExportsMapper.Create;
  try
    Assert.IsTrue(Mapper.AddToLookup('hole.dll', HMODULE(NativeUInt(@Data[0])), Length(Data), $10000000) = 0);
    Assert.IsTrue(Mapper.FindExportsByVa($10000000) = nil);
  finally
    Mapper.Free;
  end;
end;

procedure TExportRobustnessTests.ForwarderChainResolvesToConcreteAddress;
var
  TargetData, MiddleData, SourceData: TBytes;
  Mapper: TExportsMapper;
  SetFound: TExportedFuncSet;
begin
  TargetData := BuildRichVirtualPe64;
  MiddleData := BuildRichVirtualPe64;
  SourceData := BuildRichVirtualPe64;
  ConfigureSingleExport64(TargetData, 'target.dll', 'Real', $1050);
  ConfigureSingleExport64(MiddleData, 'middle.dll', 'Middle', $2170);
  ConfigureSingleExport64(SourceData, 'source.dll', 'Alias', $2170);
  PutAnsiZLocal(MiddleData, $2170, 'target.Real');
  PutAnsiZLocal(SourceData, $2170, 'middle.Middle');
  Mapper := TExportsMapper.Create;
  try
    Mapper.AddToLookup('target.dll', HMODULE(NativeUInt(@TargetData[0])), Length(TargetData), $10000000);
    Mapper.AddToLookup('middle.dll', HMODULE(NativeUInt(@MiddleData[0])), Length(MiddleData), $20000000);
    Mapper.AddToLookup('source.dll', HMODULE(NativeUInt(@SourceData[0])), Length(SourceData), $30000000);
    SetFound := Mapper.FindExportsByVa($10000000 + $1050);
    Assert.IsTrue(SetFound <> nil);
    Assert.IsTrue(SetFound.Count = 3);
  finally
    Mapper.Free;
  end;
end;


procedure TExportRobustnessTests.InvalidForwarderDoesNotMapConcreteAddress;
var
  Data: TBytes;
  Mapper: TExportsMapper;
begin
  Data := BuildRichVirtualPe64;
  ConfigureSingleExport64(Data, 'invalid.dll', 'Broken', $2170);
  PutAnsiZLocal(Data, $2170, 'not-a-forwarder');
  Mapper := TExportsMapper.Create;
  try
    Assert.IsTrue(Mapper.AddToLookup('invalid.dll', HMODULE(NativeUInt(@Data[0])), Length(Data), $10000000) = 0);
    Assert.IsTrue(Mapper.FindExportsByVa($10000000 + $2170) = nil);
  finally
    Mapper.Free;
  end;
end;


procedure TExportRobustnessTests.StringLikeCodeOutsideExportDirectoryStillResolves;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  PutAnsiZLocal(Data, $1050, 'x.y');
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(AnsiString('Alpha'))) = FARPROC(@Data[$1050]));
end;

procedure TExportRobustnessTests.ForwarderCycleDoesNotMapConcreteAddress;
var
  AData, BData: TBytes;
  Mapper: TExportsMapper;
begin
  AData := BuildRichVirtualPe64;
  BData := BuildRichVirtualPe64;
  ConfigureSingleExport64(AData, 'a.dll', 'A', $2170);
  ConfigureSingleExport64(BData, 'b.dll', 'B', $2170);
  PutAnsiZLocal(AData, $2170, 'b.B');
  PutAnsiZLocal(BData, $2170, 'a.A');
  Mapper := TExportsMapper.Create;
  try
    Assert.IsTrue(Mapper.AddToLookup('a.dll', HMODULE(NativeUInt(@AData[0])), Length(AData), $10000000) = 0);
    Assert.IsTrue(Mapper.AddToLookup('b.dll', HMODULE(NativeUInt(@BData[0])), Length(BData), $20000000) = 0);
    Assert.IsTrue(Mapper.FindExportsByVa($10000000 + $1050) = nil);
  finally
    Mapper.Free;
  end;
end;

procedure TMalformedMatrixTests.TruncatedDosHeaderRejected;
var
  Data: TBytes;
begin
  SetLength(Data, SizeOf(TImageDosHeader) - 1);
  FillChar(Data[0], Length(Data), 0);
  Assert.IsTrue(GetNtHdrs(@Data[0], Length(Data)) = nil);
end;

procedure TMalformedMatrixTests.TruncatedNtHeaderRejected;
var
  Data: TBytes;
  Dos: PImageDosHeader;
begin
  SetLength(Data, TEST_NT_OFFSET + SizeOf(DWORD) + 2);
  FillChar(Data[0], Length(Data), 0);
  Dos := PImageDosHeader(@Data[0]);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := TEST_NT_OFFSET;
  PDWORD(@Data[TEST_NT_OFFSET])^ := IMAGE_NT_SIGNATURE;
  Assert.IsTrue(GetNtHdrs(@Data[0], Length(Data)) = nil);
end;

procedure TMalformedMatrixTests.InvalidOptionalHeaderSizeRejectsSectionTable;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
begin
  Data := BuildRichRawPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.FileHeader.SizeOfOptionalHeader := High(Word);
  Assert.IsFalse(IsValidSectionsHdrOffset(@Data[0], Length(Data)));
end;

procedure TMalformedMatrixTests.ExcessiveSectionCountRejectsSectionTable;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
begin
  Data := BuildRichRawPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.FileHeader.NumberOfSections := High(Word);
  Assert.IsFalse(IsValidSectionsHdrOffset(@Data[0], Length(Data)));
end;

procedure TMalformedMatrixTests.ExportNameOutsideImageRejected;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  PDWORD(@Data[$2220])^ := TEST_IMAGE_SIZE + $10;
  Assert.IsTrue(GetExportedFunc(@Data[0], PAnsiChar(AnsiString('Alpha'))) = nil);
end;

procedure TMalformedMatrixTests.TlsCallbackTableOutsideImageRejected;
var
  Data: TBytes;
  Tls: PImageTlsDirectory64;
  Callbacks: TList<UInt64>;
begin
  Data := BuildRichVirtualPe64;
  Tls := PImageTlsDirectory64(@Data[$2400]);
  Tls.AddressOfCallBacks := TEST_IMAGE_SIZE + $100;
  Callbacks := TList<UInt64>.Create;
  try
    Assert.IsTrue(ListTlsCallbacks(@Data[0], Length(Data), Callbacks) = 0);
    Assert.IsTrue(Callbacks.Count = 0);
  finally
    Callbacks.Free;
  end;
end;

procedure TFullRoundTripTests.Pe64DirectoriesSurviveRawVirtualRawVirtual;
var
  Data: TBytes;
begin
  Data := BuildFullVirtual64;
  RunFullRoundTrip(Data, True, 'Alpha');
end;

procedure TFullRoundTripTests.Pe32DirectoriesSurviveRawVirtualRawVirtual;
var
  Data: TBytes;
begin
  Data := BuildRoundTripVirtual32;
  RunFullRoundTrip(Data, False, 'Only32');
end;

initialization
  TDUnitX.RegisterTestFixture(TExceptionDirectoryRobustnessTests);
  TDUnitX.RegisterTestFixture(TSectionLayoutRobustnessTests);
  TDUnitX.RegisterTestFixture(TResourceRobustnessTests);
  TDUnitX.RegisterTestFixture(TExportRobustnessTests);
  TDUnitX.RegisterTestFixture(TMalformedMatrixTests);
  TDUnitX.RegisterTestFixture(TFullRoundTripTests);

end.
