unit NativePe.Pe.Tests;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  DUnitX.TestFramework,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.PeRawToVirtual,
  NativePe.PeVirtualToRaw,
  NativePe.PeModeDetector,
  NativePe.ExportsLookup,
  NativePe.ResourceParser,
  NativePe.TlsParser,
  NativePe.Relocate,
  NativePe.ImportsLoader,
  NativePe.ExportedFunc,
  NativePe.TestFixtures;

type
  {$M+}

  [TestFixture]
  TPeHeaderTests = class
  public
    [Test] procedure RecognizesPe32;
    [Test] procedure RecognizesPe64;
    [Test] procedure ReadsRichHeaderValues;
    [Test] procedure UpdatesImageSize;
    [Test] procedure UpdatesImageBase;
    [Test] procedure UpdatesEntryPoint;
    [Test] procedure UpdatesSubsystem;
    [Test] procedure ReportsDllCharacteristics;
    [Test] procedure ReadsSections;
    [Test] procedure CalculatesRawAndVirtualSize;
    [Test] procedure FindsLastSection;
    [Test] procedure ValidatesSectionAlignment;
    [Test] procedure CalculatesRoundedVirtualSectionSize;
  end;

  [TestFixture]
  TPeDirectoryTests = class
  public
    [Test] procedure DirectoryCountGuardPe32;
    [Test] procedure DirectoryCountGuardPe64;
    [Test] procedure DirectoryCountCorruptValueClamped;
    [Test] procedure EmptyDirectoryFilteredByDefault;
    [Test] procedure EmptyDirectoryAllowedExplicitly;
    [Test] procedure DotNetDirectoryRecognized;
    [Test] procedure RelocationDirectoryRecognized;
  end;

  [TestFixture]
  TPeStructuredDirectoryTests = class
  public
    [Test] procedure ExportNamesMatchFixture;
    [Test] procedure ExportLookupByNameMatchesRva;
    [Test] procedure ExportLookupIsCaseInsensitive;
    [Test] procedure ExportLookupByOrdinalMatchesRva;
    [Test] procedure ExportDllNameMatchesFixture;
    [Test] procedure ResourceParserReturnsExpectedEntry;
    [Test] procedure TlsParserReturnsExpectedCallbacks;
    [Test] procedure ImportTableIsValid;
    [Test] procedure ImportThunksMatchFixture;
    [Test] procedure ImportMetadataMatchesFixture;
    [Test] procedure ImportTableWithoutCallbackPe32;
    [Test] procedure ImportTableWithoutCallbackPe64;
    [Test] procedure RelocationTableIsValid;
    [Test] procedure RelocationAppliesExpectedDelta;
    [Test] procedure RelocationRoundTripRestoresOriginal;
    [Test] procedure RelocationRejectsZeroModuleSize;
    [Test] procedure RelocationHighLowPe32AppliesExpectedDelta;
    [Test] procedure MultipleRelocationBlocksWithPaddingApplyExpectedDelta;
    [Test] procedure InvalidRelocationBlockSizeRejected;
    [Test] procedure RelocationFieldOutsideImageRejected;
    [Test] procedure UnsupportedRelocationTypeRejected;
  end;

  [TestFixture]
  TPeRawVirtualTests = class
  public
    [Test] procedure RawFixtureDetectedAsRaw;
    [Test] procedure RawAndVirtualOffsetsDiffer;
    [Test] procedure RawToVirtualCopiesExpectedBytes;
    [Test] procedure RawVirtualRawRoundTrip;
    [Test] procedure RealignChangesSectionFileLayout;
    [Test] procedure RealignRestoresHeaderImageBase;
  end;

  [TestFixture]
  TMalformedPeTests = class
  public
    [Test] procedure InvalidDosSignatureRejected;
    [Test] procedure InvalidNtSignatureRejected;
    [Test] procedure NegativeNtOffsetRejected;
    [Test] procedure ExcessiveNtOffsetRejected;
    [Test] procedure TruncatedOptionalHeaderRejected;
    [Test] procedure OversizedHeadersRejectedByRawMapper;
    [Test] procedure HeaderDestinationOverflowRejectedByRawMapper;
    [Test] procedure RawOffsetIndependentFromVirtualImageSize;
    [Test] procedure TruncatedTlsDirectoryRejected;
    [Test] procedure TruncatedImportThunkRejected;
    [Test] procedure CorruptImportTableDistinguishedFromAbsent;
    [Test] procedure ImportDirectorySizeValidationModes;
    [Test] procedure RoundUpOverflowDoesNotWrap;
  end;

implementation

var
  GResourceSeen: Boolean;
  GResourceId: Word;
  GResourceSize: DWORD;
  GResourceCodePage: DWORD;
  GResourceData: array [0 .. 3] of Byte;

function CaptureResource(ModulePtr: PByte; RootDir: PImageResourceDirectoryEntry;
  CurrEntry: PImageResourceDataEntry): Boolean;
var
  P: PByte;
begin
  GResourceSeen := True;
  GResourceId := RootDir.Id;
  GResourceSize := CurrEntry.Size;
  GResourceCodePage := CurrEntry.CodePage;
  FillChar(GResourceData, SizeOf(GResourceData), 0);
  if CurrEntry.Size >= SizeOf(GResourceData) then
  begin
    P := ModulePtr + CurrEntry.OffsetToData;
    Move(P^, GResourceData[0], SizeOf(GResourceData));
  end;
  Result := True;
end;

function FindName(const List: TList<string>; const Name: string): Boolean;
var
  S: string;
begin
  for S in List do
    if S = Name then
      Exit(True);
  Result := False;
end;

procedure TPeHeaderTests.RecognizesPe32;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe32;
  P := @Data[0];
  Assert.IsTrue(GetNtHdrs(P, Length(Data)) <> nil);
  Assert.IsTrue(GetNtHdrs32(P) <> nil);
  Assert.IsTrue(GetNtHdrs64(P) = nil);
  Assert.IsFalse(Is64Bit(P));
  Assert.IsTrue(GetNtHdrArchitecture(P) = IMAGE_NT_OPTIONAL_HDR32_MAGIC);
  Assert.IsTrue(GetImageBase(P) = TEST_IMAGE_BASE32);
end;

procedure TPeHeaderTests.RecognizesPe64;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe64;
  P := @Data[0];
  Assert.IsTrue(GetNtHdrs(P, Length(Data)) <> nil);
  Assert.IsTrue(GetNtHdrs64(P) <> nil);
  Assert.IsTrue(GetNtHdrs32(P) = nil);
  Assert.IsTrue(Is64Bit(P));
  Assert.IsTrue(GetNtHdrArchitecture(P) = IMAGE_NT_OPTIONAL_HDR64_MAGIC);
  Assert.IsTrue(GetImageBase(P) = TEST_IMAGE_BASE64);
end;

procedure TPeHeaderTests.ReadsRichHeaderValues;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(GetImageSize(P) = TEST_IMAGE_SIZE);
  Assert.IsTrue(GetHdrsSize(P) = TEST_HEADERS_SIZE);
  Assert.IsTrue(GetEntryPointRva(P) = $1050);
  Assert.IsTrue(GetImageBase(P) = TEST_IMAGE_BASE64);
  Assert.IsTrue(GetSubsystem(P) = 3);
  Assert.IsTrue(GetSecAlignment(P, False) = TEST_SECTION_ALIGNMENT);
  Assert.IsTrue(GetSecAlignment(P, True) = TEST_FILE_ALIGNMENT);
  Assert.IsTrue(GetOptionalHdr(P, Length(Data)) <> nil);
  Assert.IsTrue(GetFileHdr(P, Length(Data)) <> nil);
end;

procedure TPeHeaderTests.UpdatesImageSize;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(UpdateImageSize(P, $9000));
  Assert.IsTrue(GetImageSize(P) = $9000);
end;

procedure TPeHeaderTests.UpdatesImageBase;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(UpdateImageBase(P, $0000000180000000));
  Assert.IsTrue(GetImageBase(P) = $0000000180000000);
end;

procedure TPeHeaderTests.UpdatesEntryPoint;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(UpdateEntryPointRva(P, $1234));
  Assert.IsTrue(GetEntryPointRva(P) = $1234);
end;

procedure TPeHeaderTests.UpdatesSubsystem;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(SetSubsystem(P, 2));
  Assert.IsTrue(GetSubsystem(P) = 2);
end;

procedure TPeHeaderTests.ReportsDllCharacteristics;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(IsModuleDll(P));
  Assert.IsTrue(GetDllCharacteristics(P) = $8160);
  Assert.IsTrue((GetFileCharacteristics(P) and IMAGE_FILE_DLL) <> 0);
end;

procedure TPeHeaderTests.ReadsSections;
var
  Data: TBytes;
  P: PByte;
  S0, S1, S2: PImageSectionHeader;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(GetSectionsCount(P, Length(Data)) = 3);
  Assert.IsTrue(IsValidSectionsHdrOffset(P, Length(Data)));
  S0 := GetSectionHdr(P, Length(Data), 0);
  S1 := GetSectionHdr(P, Length(Data), 1);
  S2 := GetSectionHdr(P, Length(Data), 2);
  Assert.IsTrue(SectionName(S0) = '.text');
  Assert.IsTrue(SectionName(S1) = '.rdata');
  Assert.IsTrue(SectionName(S2) = '.reloc');
  Assert.IsTrue(S0.VirtualAddress = $1000);
  Assert.IsTrue(S1.PointerToRawData = $800);
  Assert.IsTrue(GetSectionHdr(P, Length(Data), 3) = nil);
end;

procedure TPeHeaderTests.CalculatesRawAndVirtualSize;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(CalcPeSize(P, Length(Data), True) = TEST_RAW_SIZE);
  Assert.IsTrue(CalcPeSize(P, Length(Data), False) = $3200);
end;

procedure TPeHeaderTests.FindsLastSection;
var
  Data: TBytes;
  P: PByte;
  S: PImageSectionHeader;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  S := GetLastSection(P, Length(Data), True);
  Assert.IsTrue(S <> nil);
  Assert.IsTrue(SectionName(S) = '.reloc');
  S := GetLastSection(P, Length(Data), False);
  Assert.IsTrue(S <> nil);
  Assert.IsTrue(SectionName(S) = '.reloc');
end;

procedure TPeHeaderTests.ValidatesSectionAlignment;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(IsValidSectionsAlignment(P, Length(Data), True));
  Assert.IsTrue(IsValidSectionsAlignment(P, Length(Data), False));
  GetSectionHdr(P, Length(Data), 1).PointerToRawData := $801;
  Assert.IsFalse(IsValidSectionsAlignment(P, Length(Data), True));
end;

procedure TPeHeaderTests.CalculatesRoundedVirtualSectionSize;
var
  Data: TBytes;
  P: PByte;
  S: PImageSectionHeader;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  S := GetSectionHdr(P, Length(Data), 2);
  Assert.IsTrue(GetVirtualSecSize(P, S, False) = $200);
  Assert.IsTrue(GetVirtualSecSize(P, S, True) = $1000);
end;

procedure TPeDirectoryTests.DirectoryCountGuardPe32;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe32(2);
  P := @Data[0];
  Assert.IsTrue(GetDirectoryEntry(P, 0, True) <> nil);
  Assert.IsTrue(GetDirectoryEntry(P, 1, True) <> nil);
  Assert.IsTrue(GetDirectoryEntry(P, 2, True) = nil);
  Assert.IsTrue(GetDirectoryEntry(P, 15, True) = nil);
  Assert.IsTrue(GetDirectoryEntry(P, 16, True) = nil);
end;

procedure TPeDirectoryTests.DirectoryCountGuardPe64;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe64(2);
  P := @Data[0];
  Assert.IsTrue(GetDirectoryEntry(P, 0, True) <> nil);
  Assert.IsTrue(GetDirectoryEntry(P, 1, True) <> nil);
  Assert.IsTrue(GetDirectoryEntry(P, 2, True) = nil);
  Assert.IsTrue(GetDirectoryEntry(P, 15, True) = nil);
end;

procedure TPeDirectoryTests.DirectoryCountCorruptValueClamped;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe64(100);
  P := @Data[0];
  Assert.IsTrue(GetDirectoryEntry(P, 15, True) <> nil);
  Assert.IsTrue(GetDirectoryEntry(P, 16, True) = nil);
end;

procedure TPeDirectoryTests.EmptyDirectoryFilteredByDefault;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe64;
  P := @Data[0];
  Assert.IsTrue(GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_RESOURCE) = nil);
end;

procedure TPeDirectoryTests.EmptyDirectoryAllowedExplicitly;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe64;
  P := @Data[0];
  Assert.IsTrue(GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_RESOURCE, True) <> nil);
end;

procedure TPeDirectoryTests.DotNetDirectoryRecognized;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(IsDotNet(@Data[0], Length(Data)));
  PDWORD(@Data[$2580])^ := 0;
  Assert.IsFalse(IsDotNet(@Data[0], Length(Data)));
end;

procedure TPeDirectoryTests.RelocationDirectoryRecognized;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(HasRelocations(@Data[0]));
  PImageNtHeaders64(@Data[TEST_NT_OFFSET]).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress := 0;
  Assert.IsFalse(HasRelocations(@Data[0]));
end;

procedure TPeStructuredDirectoryTests.ExportNamesMatchFixture;
var
  Data: TBytes;
  Names: TList<string>;
  Count: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  Names := TList<string>.Create;
  try
    Count := GetExportedNames(@Data[0], Names);
    Assert.IsTrue(Count = 2);
    Assert.IsTrue(Names.Count = 2);
    Assert.IsTrue(FindName(Names, 'Alpha'));
    Assert.IsTrue(FindName(Names, 'Beta'));
  finally
    Names.Free;
  end;
end;

procedure TPeStructuredDirectoryTests.ExportLookupByNameMatchesRva;
var
  Data: TBytes;
  Name: AnsiString;
  F: FARPROC;
begin
  Data := BuildRichVirtualPe64;
  Name := 'Alpha';
  F := GetExportedFunc(@Data[0], PAnsiChar(Name));
  Assert.IsTrue(NativeUInt(F) = NativeUInt(@Data[0]) + $1050);
end;

procedure TPeStructuredDirectoryTests.ExportLookupIsCaseInsensitive;
var
  Data: TBytes;
  Name: AnsiString;
  F: FARPROC;
begin
  Data := BuildRichVirtualPe64;
  Name := 'aLpHa';
  F := GetExportedFunc(@Data[0], PAnsiChar(Name));
  Assert.IsTrue(NativeUInt(F) = NativeUInt(@Data[0]) + $1050);
end;

procedure TPeStructuredDirectoryTests.ExportLookupByOrdinalMatchesRva;
var
  Data: TBytes;
  F: FARPROC;
begin
  Data := BuildRichVirtualPe64;
  F := GetExportedFunc(@Data[0], PAnsiChar(NativeUInt(2)));
  Assert.IsTrue(NativeUInt(F) = NativeUInt(@Data[0]) + $1060);
end;

procedure TPeStructuredDirectoryTests.ExportDllNameMatchesFixture;
var
  Data: TBytes;
  P: PAnsiChar;
begin
  Data := BuildRichVirtualPe64;
  P := ReadDllName(@Data[0]);
  Assert.IsTrue(P <> nil);
  Assert.IsTrue(string(AnsiString(P)) = 'fixture64.dll');
end;

procedure TPeStructuredDirectoryTests.ResourceParserReturnsExpectedEntry;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  GResourceSeen := False;
  GResourceId := 0;
  GResourceSize := 0;
  GResourceCodePage := 0;
  FillChar(GResourceData, SizeOf(GResourceData), 0);
  Assert.IsTrue(ParseResources(@Data[0], CaptureResource));
  Assert.IsTrue(GResourceSeen);
  Assert.IsTrue(GResourceId = 10);
  Assert.IsTrue(GResourceSize = 4);
  Assert.IsTrue(GResourceCodePage = 1200);
  Assert.IsTrue((GResourceData[0] = $DE) and (GResourceData[1] = $AD) and
    (GResourceData[2] = $BE) and (GResourceData[3] = $EF));
end;

procedure TPeStructuredDirectoryTests.TlsParserReturnsExpectedCallbacks;
var
  Data: TBytes;
  List: TList<UInt64>;
  N: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  List := TList<UInt64>.Create;
  try
    N := ListTlsCallbacks(@Data[0], Length(Data), List);
    Assert.IsTrue(N = 2);
    Assert.IsTrue(List.Count = 2);
    Assert.IsTrue(List[0] = $11111111);
    Assert.IsTrue(List[1] = $22222222);
  finally
    List.Free;
  end;
end;

procedure TPeStructuredDirectoryTests.ImportTableIsValid;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(HasValidImportTable(@Data[0], Length(Data)));
end;

procedure TPeStructuredDirectoryTests.ImportThunksMatchFixture;
var
  Data: TBytes;
  Thunks: TList<DWORD>;
begin
  Data := BuildRichVirtualPe64;
  Thunks := TList<DWORD>.Create;
  try
    Assert.IsTrue(CollectThunks(@Data[0], Length(Data), Thunks));
    Assert.IsTrue(Thunks.Count = 2);
    Assert.IsTrue(Thunks[0] = $26A0);
    Assert.IsTrue(Thunks[1] = $26A8);
  finally
    Thunks.Free;
  end;
end;

procedure TPeStructuredDirectoryTests.ImportMetadataMatchesFixture;
var
  Data: TBytes;
  Imports: TImportsCollection;
  F: TExportedFunc;
begin
  Data := BuildRichVirtualPe64;
  Imports := TImportsCollection.Create;
  try
    Assert.IsTrue(CollectImports(@Data[0], Length(Data), Imports));
    Assert.IsTrue(Imports.ThunkToFunc.Count = 2);
    Assert.IsTrue(Imports.ThunkToFunc.TryGetValue($26A0, F));
    Assert.IsTrue(F.LibName = 'fixturedep');
    Assert.IsTrue(F.FuncName = 'NamedFunc');
    Assert.IsFalse(F.IsByOrdinal);
    Assert.IsTrue(F.FuncOrdinal = 42);
    Assert.IsTrue(Imports.ThunkToFunc.TryGetValue($26A8, F));
    Assert.IsTrue(F.LibName = 'fixturedep');
    Assert.IsTrue(F.IsByOrdinal);
    Assert.IsTrue(F.FuncOrdinal = 7);
  finally
    Imports.Free;
  end;
end;

procedure TPeStructuredDirectoryTests.ImportTableWithoutCallbackPe32;
var
  Data: TBytes;
  Nt: PImageNtHeaders32;
  Imp: PImageImportDescriptor;
  Thunk: PImageThunkData32;
  Name: AnsiString;
begin
  Data := BuildMinimalPe32;
  Nt := GetNtHdrs32(@Data[0]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress := $300;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size := 2 * SizeOf(TImageImportDescriptor);
  Imp := PImageImportDescriptor(@Data[$300]);
  Imp.OriginalFirstThunk := $380;
  Imp.Name := $350;
  Imp.FirstThunk := $390;
  Name := 'kernel32.dll';
  Move(Name[1], Data[$350], Length(Name));
  Data[$350 + Length(Name)] := 0;
  Thunk := PImageThunkData32(@Data[$380]);
  Thunk.AddressOfData := $3A0;
  Inc(Thunk);
  Thunk.Func := 0;
  Thunk := PImageThunkData32(@Data[$390]);
  Thunk.Func := $1234;
  Inc(Thunk);
  Thunk.Func := 0;
  PImageImportByName(@Data[$3A0]).Hint := 0;
  Name := 'ExitProcess';
  Move(Name[1], Data[$3A2], Length(Name));
  Data[$3A2 + Length(Name)] := 0;
  Assert.IsTrue(ProcessImportTable(@Data[0], Length(Data), nil));
end;

procedure TPeStructuredDirectoryTests.ImportTableWithoutCallbackPe64;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(ProcessImportTable(@Data[0], Length(Data), nil));
end;

procedure TPeStructuredDirectoryTests.RelocationTableIsValid;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(HasValidRelocationTable(@Data[0], Length(Data)));
end;

procedure TPeStructuredDirectoryTests.RelocationAppliesExpectedDelta;
const
  NewBase = UInt64($0000000180000000);
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Assert.IsTrue(PUInt64(P + $1020)^ = TEST_IMAGE_BASE64 + $1234);
  Assert.IsTrue(RelocateModule(P, Length(Data), NewBase, TEST_IMAGE_BASE64));
  Assert.IsTrue(PUInt64(P + $1020)^ = NewBase + $1234);
end;

procedure TPeStructuredDirectoryTests.RelocationRoundTripRestoresOriginal;
const
  NewBase = UInt64($0000000180000000);
var
  Data: TBytes;
  P: PByte;
  OriginalValue: UInt64;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  OriginalValue := PUInt64(P + $1020)^;
  Assert.IsTrue(RelocateModule(P, Length(Data), NewBase, TEST_IMAGE_BASE64));
  Assert.IsTrue(RelocateModule(P, Length(Data), TEST_IMAGE_BASE64, NewBase));
  Assert.IsTrue(PUInt64(P + $1020)^ = OriginalValue);
end;

procedure TPeStructuredDirectoryTests.RelocationRejectsZeroModuleSize;
var
  Data: TBytes;
begin
  Data := BuildMinimalPe64;
  Assert.IsFalse(RelocateModule(@Data[0], 0, TEST_IMAGE_BASE64));
end;

procedure TPeStructuredDirectoryTests.RelocationHighLowPe32AppliesExpectedDelta;
const
  NewBase = DWORD($00600000);
  RelocRva = $400;
  FieldRva = $820;
var
  Data: TBytes;
  P: PByte;
  Nt: PImageNtHeaders32;
  Reloc: PImageBaseRelocation;
  Entry: PWord;
begin
  Data := BuildMinimalPe32;
  P := @Data[0];
  Nt := PImageNtHeaders32(P + TEST_NT_OFFSET);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress := RelocRva;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 12;
  Reloc := PImageBaseRelocation(P + RelocRva);
  Reloc.VirtualAddress := $800;
  Reloc.SizeOfBlock := 12;
  Entry := PWord(P + RelocRva + 8);
  Entry^ := Word((3 shl 12) or $20);
  Inc(Entry);
  Entry^ := 0;
  PDWORD(P + FieldRva)^ := TEST_IMAGE_BASE32 + $1234;
  Assert.IsTrue(HasValidRelocationTable(P, Length(Data)));
  Assert.IsTrue(RelocateModule(P, Length(Data), NewBase, TEST_IMAGE_BASE32));
  Assert.IsTrue(PDWORD(P + FieldRva)^ = NewBase + $1234);
end;

procedure TPeStructuredDirectoryTests.MultipleRelocationBlocksWithPaddingApplyExpectedDelta;
const
  NewBase = UInt64($0000000180000000);
var
  Data: TBytes;
  P: PByte;
  Nt: PImageNtHeaders64;
  Reloc: PImageBaseRelocation;
  Entry: PWord;
begin
  Data := BuildRichVirtualPe64;
  P := @Data[0];
  Nt := PImageNtHeaders64(P + TEST_NT_OFFSET);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 24;
  PUInt64(P + $2030)^ := TEST_IMAGE_BASE64 + $5678;
  Reloc := PImageBaseRelocation(P + $300C);
  Reloc.VirtualAddress := $2000;
  Reloc.SizeOfBlock := 12;
  Entry := PWord(P + $3014);
  Entry^ := Word(($A shl 12) or $30);
  Inc(Entry);
  Entry^ := 0;
  Assert.IsTrue(HasValidRelocationTable(P, Length(Data)));
  Assert.IsTrue(RelocateModule(P, Length(Data), NewBase, TEST_IMAGE_BASE64));
  Assert.IsTrue(PUInt64(P + $1020)^ = NewBase + $1234);
  Assert.IsTrue(PUInt64(P + $2030)^ = NewBase + $5678);
end;

procedure TPeStructuredDirectoryTests.InvalidRelocationBlockSizeRejected;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  PImageBaseRelocation(@Data[$3000]).SizeOfBlock := 6;
  Assert.IsFalse(HasValidRelocationTable(@Data[0], Length(Data)));
end;

procedure TPeStructuredDirectoryTests.RelocationFieldOutsideImageRejected;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  PImageBaseRelocation(@Data[$3000]).VirtualAddress := TEST_IMAGE_SIZE;
  Assert.IsFalse(HasValidRelocationTable(@Data[0], Length(Data)));
end;

procedure TPeStructuredDirectoryTests.UnsupportedRelocationTypeRejected;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  PWord(@Data[$3008])^ := Word(($5 shl 12) or $20);
  Assert.IsFalse(HasValidRelocationTable(@Data[0], Length(Data)));
end;

procedure TPeRawVirtualTests.RawFixtureDetectedAsRaw;
var
  Raw: TBytes;
begin
  Raw := BuildRichRawPe64;
  Assert.IsTrue(IsPeRaw(@Raw[0], Length(Raw)));
end;

procedure TPeRawVirtualTests.RawAndVirtualOffsetsDiffer;
var
  Raw: TBytes;
begin
  Raw := BuildRichRawPe64;
  Assert.IsFalse(IsPeRawEqVirtual(@Raw[0], Length(Raw)));
end;

procedure TPeRawVirtualTests.RawToVirtualCopiesExpectedBytes;
var
  Raw: TBytes;
  Mapped: TAlignedBuf;
  OutSize: NativeUInt;
begin
  Raw := BuildRichRawPe64;
  OutSize := 0;
  Mapped := PeRawToVirtual(@Raw[0], Length(Raw), OutSize, False);
  try
    Assert.IsTrue(Mapped <> nil);
    Assert.IsTrue(OutSize = TEST_IMAGE_SIZE);
    Assert.IsTrue((Mapped + $1050)^ = $C3);
    Assert.IsTrue(string(AnsiString(PAnsiChar(Mapped + $2260))) = 'Alpha');
    Assert.IsTrue(PDWORD(Mapped + $2580)^ = DOTNET_METADATA_SIGNATURE);
  finally
    FreePeBuffer(Mapped);
  end;
end;

procedure TPeRawVirtualTests.RawVirtualRawRoundTrip;
var
  Raw: TBytes;
  Mapped, Back: TAlignedBuf;
  MappedSize, BackSize: NativeUInt;
begin
  Raw := BuildRichRawPe64;
  MappedSize := 0;
  Mapped := PeRawToVirtual(@Raw[0], Length(Raw), MappedSize, False);
  try
    Assert.IsTrue(Mapped <> nil);
    BackSize := 0;
    Back := PeVirtualToRaw(Mapped, MappedSize, GetImageBase(Mapped), BackSize, True);
    try
      Assert.IsTrue(Back <> nil);
      Assert.IsTrue(BackSize = TEST_RAW_SIZE);
      Assert.IsTrue(CompareMem(Back, @Raw[0], TEST_RAW_SIZE), 'RAW -> virtual -> RAW differs');
    finally
      FreePeBuffer(Back);
    end;
  finally
    FreePeBuffer(Mapped);
  end;
end;

procedure TPeRawVirtualTests.RealignChangesSectionFileLayout;
var
  Raw: TBytes;
  OutBuf: TAlignedBuf;
  OutSize: NativeUInt;
  S: PImageSectionHeader;
begin
  Raw := BuildRichRawPe64;
  OutSize := 0;
  OutBuf := PeRealignRawToVirtual(@Raw[0], Length(Raw), GetImageBase(@Raw[0]), OutSize);
  try
    Assert.IsTrue(OutBuf <> nil);
    Assert.IsTrue(OutSize = NativeUInt(Length(Raw)));
    Assert.IsTrue(GetSecAlignment(OutBuf, True) = TEST_SECTION_ALIGNMENT);
    S := GetSectionHdr(OutBuf, OutSize, 0);
    Assert.IsTrue(S.PointerToRawData = S.VirtualAddress);
    Assert.IsTrue(S.SizeOfRawData = S.Misc.VirtualSize);
  finally
    FreePeBuffer(OutBuf);
  end;
end;

procedure TPeRawVirtualTests.RealignRestoresHeaderImageBase;
const
  LoadBase = UInt64($0000000180000000);
var
  Data: TBytes;
  OutBuf: TAlignedBuf;
  OutSize: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  PUInt64(@Data[$1020])^ := LoadBase + $1234;
  OutSize := 0;
  OutBuf := PeRealignRawToVirtual(@Data[0], Length(Data), LoadBase, OutSize);
  try
    Assert.IsTrue(OutBuf <> nil);
    Assert.IsTrue(PUInt64(OutBuf + $1020)^ = TEST_IMAGE_BASE64 + $1234);
  finally
    FreePeBuffer(OutBuf);
  end;
end;

procedure TMalformedPeTests.InvalidDosSignatureRejected;
var
  Data: TBytes;
begin
  Data := BuildMinimalPe64;
  PImageDosHeader(@Data[0]).e_magic := 0;
  Assert.IsTrue(GetNtHdrs(@Data[0], Length(Data)) = nil);
end;

procedure TMalformedPeTests.InvalidNtSignatureRejected;
var
  Data: TBytes;
begin
  Data := BuildMinimalPe64;
  PImageNtHeaders64(@Data[TEST_NT_OFFSET]).Signature := 0;
  Assert.IsTrue(GetNtHdrs(@Data[0], Length(Data)) = nil);
end;

procedure TMalformedPeTests.NegativeNtOffsetRejected;
var
  Data: TBytes;
begin
  Data := BuildMinimalPe64;
  PImageDosHeader(@Data[0]).e_lfanew := -1;
  Assert.IsTrue(GetNtHdrs(@Data[0], Length(Data)) = nil);
end;

procedure TMalformedPeTests.ExcessiveNtOffsetRejected;
var
  Data: TBytes;
begin
  Data := BuildMinimalPe64;
  PImageDosHeader(@Data[0]).e_lfanew := PE_PAGE_SIZE + 1;
  Assert.IsTrue(GetNtHdrs(@Data[0], Length(Data)) = nil);
end;

procedure TMalformedPeTests.TruncatedOptionalHeaderRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  SmallSize: NativeUInt;
begin
  Data := BuildMinimalPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  SmallSize := TEST_NT_OFFSET + SizeOf(DWORD) + SizeOf(TImageFileHeader) + 16;
  Assert.IsTrue(GetOptionalHdr(@Data[0], SmallSize) = nil);
end;

procedure TMalformedPeTests.OversizedHeadersRejectedByRawMapper;
var
  Raw: TBytes;
  Nt: PImageNtHeaders64;
  OutSize: NativeUInt;
  Mapped: TAlignedBuf;
begin
  Raw := BuildMinimalPe64;
  SetLength(Raw, 512);
  Nt := PImageNtHeaders64(@Raw[TEST_NT_OFFSET]);
  Nt.OptionalHeader.SizeOfImage := $2000;
  Nt.OptionalHeader.SizeOfHeaders := 600;
  OutSize := 0;
  Mapped := PeRawToVirtual(@Raw[0], Length(Raw), OutSize, False);
  try
    Assert.IsTrue(Mapped = nil);
  finally
    if Mapped <> nil then
      FreePeBuffer(Mapped);
  end;
end;

procedure TMalformedPeTests.HeaderDestinationOverflowRejectedByRawMapper;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  Mapped: TAlignedBuf;
  MappedSize: NativeUInt;
begin
  Data := BuildMinimalPe64(0);
  SetLength(Data, $2000);
  Nt := GetNtHdrs64(@Data[0]);
  Nt.OptionalHeader.SizeOfImage := $800;
  Nt.OptionalHeader.SizeOfHeaders := $1800;
  MappedSize := 0;
  Mapped := PeRawToVirtual(@Data[0], Length(Data), MappedSize, False);
  try
    Assert.IsTrue(Mapped = nil);
    Assert.IsTrue(MappedSize = 0);
  finally
    if Mapped <> nil then
      FreePeBuffer(Mapped);
  end;
end;

procedure TMalformedPeTests.RawOffsetIndependentFromVirtualImageSize;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  Sec: PImageSectionHeader;
  Mapped: TAlignedBuf;
  MappedSize: NativeUInt;
begin
  Data := BuildMinimalPe64(0);
  SetLength(Data, $3200);
  Nt := GetNtHdrs64(@Data[0]);
  Nt.FileHeader.NumberOfSections := 1;
  Nt.OptionalHeader.SizeOfImage := $2000;
  Nt.OptionalHeader.SizeOfHeaders := $400;
  Sec := PImageSectionHeader(PByte(@Nt.OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader);
  FillChar(Sec^, SizeOf(TImageSectionHeader), 0);
  Sec.Misc.VirtualSize := $200;
  Sec.VirtualAddress := $1000;
  Sec.SizeOfRawData := $200;
  Sec.PointerToRawData := $3000;
  Data[$3000] := $5A;
  MappedSize := 0;
  Mapped := PeRawToVirtual(@Data[0], Length(Data), MappedSize, False);
  try
    Assert.IsTrue(Mapped <> nil);
    Assert.IsTrue(MappedSize = $2000);
    Assert.IsTrue((Mapped + $1000)^ = $5A);
  finally
    if Mapped <> nil then
      FreePeBuffer(Mapped);
  end;
end;

procedure TMalformedPeTests.TruncatedTlsDirectoryRejected;
var
  Data: TBytes;
  DeclaredSize: NativeUInt;
  List: TList<UInt64>;
  N: NativeUInt;
begin
  BuildTruncatedTls64(Data, DeclaredSize);
  List := TList<UInt64>.Create;
  try
    N := ListTlsCallbacks(@Data[0], DeclaredSize, List);
    Assert.IsTrue(N = 0);
    Assert.IsTrue(List.Count = 0);
  finally
    List.Free;
  end;
end;

procedure TMalformedPeTests.TruncatedImportThunkRejected;
var
  Data: TBytes;
  DeclaredSize: NativeUInt;
  Thunks: TList<DWORD>;
begin
  BuildTruncatedImport64(Data, DeclaredSize);
  Thunks := TList<DWORD>.Create;
  try
    Assert.IsFalse(CollectThunks(@Data[0], DeclaredSize, Thunks));
    Assert.IsFalse(ProcessImportTable(@Data[0], DeclaredSize, nil));
  finally
    Thunks.Free;
  end;
end;

procedure TMalformedPeTests.CorruptImportTableDistinguishedFromAbsent;
var
  Data: TBytes;
  DeclaredSize: NativeUInt;
begin
  BuildTruncatedImport64(Data, DeclaredSize);
  Assert.IsTrue(GetDirectoryEntry(@Data[0], IMAGE_DIRECTORY_ENTRY_IMPORT) <> nil);
  Assert.IsFalse(HasValidImportTable(@Data[0], DeclaredSize));
  Data := BuildMinimalPe64(1);
  Assert.IsTrue(GetDirectoryEntry(@Data[0], IMAGE_DIRECTORY_ENTRY_IMPORT) = nil);
end;

procedure TMalformedPeTests.ImportDirectorySizeValidationModes;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
begin
  Data := BuildRichVirtualPe64;
  Nt := PImageNtHeaders64(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size := SizeOf(TImageImportDescriptor);
  Assert.IsTrue(HasValidImportTable(@Data[0], Length(Data)));
  Assert.IsFalse(HasValidImportTable(@Data[0], Length(Data), 0, True));
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size := 2 * SizeOf(TImageImportDescriptor);
  Assert.IsTrue(HasValidImportTable(@Data[0], Length(Data), 0, True));
end;

procedure TMalformedPeTests.RoundUpOverflowDoesNotWrap;
begin
  Assert.IsTrue(RoundUpToUnitD(High(DWORD), PE_PAGE_SIZE) = High(DWORD));
  Assert.IsTrue(RoundUpToUnitU(High(NativeUInt), PE_PAGE_SIZE) = High(NativeUInt));
end;

initialization
  TDUnitX.RegisterTestFixture(TPeHeaderTests);
  TDUnitX.RegisterTestFixture(TPeDirectoryTests);
  TDUnitX.RegisterTestFixture(TPeStructuredDirectoryTests);
  TDUnitX.RegisterTestFixture(TPeRawVirtualTests);
  TDUnitX.RegisterTestFixture(TMalformedPeTests);

end.
