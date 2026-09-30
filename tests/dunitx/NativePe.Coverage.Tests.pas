unit NativePe.Coverage.Tests;

interface

uses
  System.SysUtils,
  Winapi.Windows,
  DUnitX.TestFramework,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.TestFixtures,
  NativePe.PeHdrsHelper,
  NativePe.Caves,
  NativePe.PeRecycler,
  NativePe.LoadConfig,
  NativePe.SecurityCookie,
  NativePe.ResourceUtil
{$IFDEF WIN64}
  , NativePe.Syscall
{$ENDIF}
  ;

type
  {$M+}

  [TestFixture]
  TCaveCoverageTests = class
  public
    [Test] procedure EndingCaveReservesExpectedRange;
    [Test] procedure EndingCaveRejectsOversizedRequest;
    [Test] procedure AlignmentCaveFindsRawSlack;
    [Test] procedure AlignmentCaveReservesRequestedBytes;
    [Test] procedure PaddingCaveFindsZeroPadding;
    [Test] procedure PaddingCaveFindsExecutableCcPadding;
  end;

  [TestFixture]
  TPeRecyclerCoverageTests = class
  public
    [Test] procedure InjectIntoAlignmentCaveCopiesPayload;
    [Test] procedure InjectIntoPaddingCaveCopiesPayload;
    [Test] procedure InjectRejectsInvalidInput;
    [Test] procedure FixLoadConfigKeepsValidDirectory;
    [Test] procedure FixLoadConfigClearsOutOfRangeDirectory;
    [Test] procedure FixLoadConfigClearsInconsistentDeclaredSize;
  end;

  [TestFixture]
  TLoadConfigCoverageTests = class
  public
    [Test] procedure FindsValidLoadConfigDirectory;
    [Test] procedure RejectsOutOfRangeLoadConfigDirectory;
    [Test] procedure RecognizesPe32LoadConfigVersions;
    [Test] procedure RecognizesPe64LoadConfigVersions;
    [Test] procedure RecognizesExtendedPe32LoadConfigAsW10;
    [Test] procedure RecognizesExtendedPe64LoadConfigAsW10;
    [Test] procedure RecognizesIntermediatePe64LoadConfigAsW8;
    [Test] procedure ReportsOlderSmallLoadConfigAsUnknown;
    [Test] procedure RecognizesNonCanonicalExtendedSizeAsW10;
    [Test] procedure ReportsDeclaredSizeBeyondBufferAsUnknown;
    [Test] procedure ReportsTruncatedLoadConfigAsNone;
  end;

  [TestFixture]
  TSecurityCookieCoverageTests = class
  public
    [Test] procedure NoLoadConfigSucceeds;
    [Test] procedure ZeroSecurityCookieIsNoOp;
    [Test] procedure InitializesDefaultCookie64;
    [Test] procedure KeepsCustomCookie64;
    [Test] procedure InvalidCookiePointerDoesNotFail;
    [Test] procedure InvalidModuleFails;
  end;

  [TestFixture]
  TResourceUtilCoverageTests = class
  public
    [Test] procedure CurrentModuleHandleMatchesWindows;
    [Test] procedure LoadsEmbeddedResource;
    [Test] procedure HonorsRequestedResourceSize;
    [Test] procedure MissingResourceReturnsNil;
  end;

{$IFDEF WIN64}
  [TestFixture]
  TSyscallCoverageTests = class
  public
    [Test] procedure DirectNtProtectChangesAndRestoresPageProtection;
  end;
{$ENDIF}

implementation

{$R 'NativePe.Coverage.Tests.res'}

const
  TEST_RESOURCE_ID = 401;
  TEST_RESOURCE_DATA: array [0 .. 7] of Byte = ($DE, $AD, $BE, $EF, $11, $22, $33, $44);
  TEST_LOAD_CONFIG_RVA = $500;
  TEST_COOKIE_RVA = $800;
  DEFAULT_COOKIE_64_TEST = UInt64($00002B992DDFA232);

procedure PrepareLoadConfig64(var Data: TBytes; DeclaredSize, DirectorySize: DWORD);
var
  P: PByte;
  Dir: PImageDataDirectory;
  Ld: PImageLoadConfigDir64W7;
begin
  Data := BuildMinimalPe64;
  P := BytesPtr(Data);
  Dir := GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  Dir.VirtualAddress := TEST_LOAD_CONFIG_RVA;
  Dir.Size := DirectorySize;
  Ld := PImageLoadConfigDir64W7(P + TEST_LOAD_CONFIG_RVA);
  FillChar(Ld^, DirectorySize, 0);
  Ld.Size := DeclaredSize;
end;

procedure PrepareLoadConfig32(var Data: TBytes; DeclaredSize: DWORD);
var
  P: PByte;
  Dir: PImageDataDirectory;
  Ld: PImageLoadConfigDir32W7;
begin
  Data := BuildMinimalPe32;
  P := BytesPtr(Data);
  Dir := GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  Dir.VirtualAddress := TEST_LOAD_CONFIG_RVA;
  Dir.Size := DeclaredSize;
  Ld := PImageLoadConfigDir32W7(P + TEST_LOAD_CONFIG_RVA);
  FillChar(Ld^, DeclaredSize, 0);
  Ld.Size := DeclaredSize;
end;

procedure TCaveCoverageTests.EndingCaveReservesExpectedRange;
var
  Data: TBytes;
  P, Cave: PByte;
  Sec: PImageSectionHeader;
  OldRaw: DWORD;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Sec := GetSectionHdr(P, Length(Data), 2);
  OldRaw := Sec.SizeOfRawData;
  Cave := FindEndingCave(P, Length(Data), $80, IMAGE_SCN_MEM_READ, True);
  Assert.IsTrue(Cave = P + Sec.VirtualAddress + OldRaw);
  Assert.IsTrue(Sec.SizeOfRawData = OldRaw + $80);
end;

procedure TCaveCoverageTests.EndingCaveRejectsOversizedRequest;
var
  Data: TBytes;
  P, Cave: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Cave := FindEndingCave(P, Length(Data), $E01, IMAGE_SCN_MEM_READ, True);
  Assert.IsTrue(Cave = nil);
end;

procedure TCaveCoverageTests.AlignmentCaveFindsRawSlack;
var
  Data: TBytes;
  P, Cave: PByte;
  Sec: PImageSectionHeader;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Sec := GetSectionHdr(P, Length(Data), 0);
  Sec.SizeOfRawData := $300;
  Cave := FindAlignmentCave(P, Length(Data), $80, IMAGE_SCN_MEM_READ, False);
  Assert.IsTrue(Cave = P + $700);
  Assert.IsTrue(Sec.SizeOfRawData = $300);
end;

procedure TCaveCoverageTests.AlignmentCaveReservesRequestedBytes;
var
  Data: TBytes;
  P, Cave: PByte;
  Sec: PImageSectionHeader;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Sec := GetSectionHdr(P, Length(Data), 0);
  Sec.SizeOfRawData := $300;
  Cave := FindAlignmentCave(P, Length(Data), $80, IMAGE_SCN_MEM_READ, True);
  Assert.IsTrue(Cave = P + $700);
  Assert.IsTrue(Sec.SizeOfRawData = $380);
end;

procedure TCaveCoverageTests.PaddingCaveFindsZeroPadding;
var
  Data: TBytes;
  P, Cave: PByte;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Cave := FindPaddingCave(P, Length(Data), $20, IMAGE_SCN_MEM_READ);
  Assert.IsTrue(Cave = P + $2BE0);
end;

procedure TCaveCoverageTests.PaddingCaveFindsExecutableCcPadding;
var
  Data: TBytes;
  P, Cave: PByte;
  I: Integer;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  for I := $13F0 to $13FF do
    P[I] := $CC;
  Cave := FindPaddingCave(P, Length(Data), $10, IMAGE_SCN_MEM_EXECUTE);
  Assert.IsTrue(Cave = P + $13F0);
end;

procedure TPeRecyclerCoverageTests.InjectIntoAlignmentCaveCopiesPayload;
var
  Data, Payload: TBytes;
  P: PByte;
  Sec: PImageSectionHeader;
  Rva: DWORD;
  I: Integer;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Sec := GetSectionHdr(P, Length(Data), 0);
  Sec.SizeOfRawData := $300;
  SetLength(Payload, 8);
  for I := 0 to High(Payload) do
    Payload[I] := Byte($A0 + I);
  Assert.IsTrue(InjectIntoCave(P, Length(Data), BytesPtr(Payload), Length(Payload), Rva));
  Assert.IsTrue(Rva = $700);
  for I := 0 to High(Payload) do
    Assert.IsTrue(P[Rva + DWORD(I)] = Payload[I]);
end;

procedure TPeRecyclerCoverageTests.InjectIntoPaddingCaveCopiesPayload;
var
  Data, Payload: TBytes;
  P: PByte;
  Rva: DWORD;
  I: Integer;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  SetLength(Payload, 8);
  for I := 0 to High(Payload) do
    Payload[I] := Byte($50 + I);
  Assert.IsTrue(InjectIntoCave(P, Length(Data), BytesPtr(Payload), Length(Payload), Rva));
  Assert.IsTrue(Rva = $2BF8);
  for I := 0 to High(Payload) do
    Assert.IsTrue(P[Rva + DWORD(I)] = Payload[I]);
end;

procedure TPeRecyclerCoverageTests.InjectRejectsInvalidInput;
var
  Data: TBytes;
  P: PByte;
  Rva: DWORD;
begin
  Data := BuildRichVirtualPe64;
  P := BytesPtr(Data);
  Assert.IsFalse(InjectIntoCave(nil, Length(Data), P, 1, Rva));
  Assert.IsFalse(InjectIntoCave(P, Length(Data), nil, 1, Rva));
  Assert.IsFalse(InjectIntoCave(P, Length(Data), P, 0, Rva));
end;

procedure TPeRecyclerCoverageTests.FixLoadConfigKeepsValidDirectory;
var
  Data: TBytes;
  P: PByte;
  Dir: PImageDataDirectory;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Dir := GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  Assert.IsTrue(FixLoadConfig(P, Length(Data)));
  Assert.IsTrue(Dir.VirtualAddress = TEST_LOAD_CONFIG_RVA);
  Assert.IsTrue(Dir.Size = SizeOf(TImageLoadConfigDir64W7));
end;

procedure TPeRecyclerCoverageTests.FixLoadConfigClearsOutOfRangeDirectory;
var
  Data: TBytes;
  P: PByte;
  Dir: PImageDataDirectory;
begin
  Data := BuildMinimalPe64;
  P := BytesPtr(Data);
  Dir := GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  Dir.VirtualAddress := $F80;
  Dir.Size := $100;
  Assert.IsTrue(FixLoadConfig(P, Length(Data)));
  Assert.IsTrue(Dir.VirtualAddress = 0);
  Assert.IsTrue(Dir.Size = 0);
end;

procedure TPeRecyclerCoverageTests.FixLoadConfigClearsInconsistentDeclaredSize;
var
  Data: TBytes;
  P: PByte;
  Dir: PImageDataDirectory;
  Ld: PImageLoadConfigDir64W7;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Dir := GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  Ld := PImageLoadConfigDir64W7(P + TEST_LOAD_CONFIG_RVA);
  Ld.Size := Dir.Size + 4;
  Assert.IsTrue(FixLoadConfig(P, Length(Data)));
  Assert.IsTrue(Dir.VirtualAddress = 0);
  Assert.IsTrue(Dir.Size = 0);
end;

procedure TLoadConfigCoverageTests.FindsValidLoadConfigDirectory;
var
  Data: TBytes;
  P, Ld: PByte;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Ld := GetLoadConfigPtr(P, Length(Data));
  Assert.IsTrue(Ld = P + TEST_LOAD_CONFIG_RVA);
end;

procedure TLoadConfigCoverageTests.RejectsOutOfRangeLoadConfigDirectory;
var
  Data: TBytes;
  P: PByte;
  Dir: PImageDataDirectory;
begin
  Data := BuildMinimalPe64;
  P := BytesPtr(Data);
  Dir := GetDirectoryEntry(P, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  Dir.VirtualAddress := $F80;
  Dir.Size := $100;
  Assert.IsTrue(GetLoadConfigPtr(P, Length(Data)) = nil);
end;

procedure TLoadConfigCoverageTests.RecognizesPe32LoadConfigVersions;
var
  Data: TBytes;
  P, Ld: PByte;
begin
  PrepareLoadConfig32(Data, SizeOf(TImageLoadConfigDir32W7));
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W7_VER);
  PDWORD(Ld)^ := SizeOf(TImageLoadConfigDir32W8);
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W8_VER);
  PDWORD(Ld)^ := SizeOf(TImageLoadConfigDir32W10);
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W10_VER);
end;

procedure TLoadConfigCoverageTests.RecognizesPe64LoadConfigVersions;
var
  Data: TBytes;
  P, Ld: PByte;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W10));
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W7_VER);
  PDWORD(Ld)^ := SizeOf(TImageLoadConfigDir64W8);
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W8_VER);
  PDWORD(Ld)^ := SizeOf(TImageLoadConfigDir64W10);
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W10_VER);
end;

procedure TLoadConfigCoverageTests.RecognizesExtendedPe32LoadConfigAsW10;
var
  Data: TBytes;
  P, Ld: PByte;
  ExtendedSize: DWORD;
begin
  ExtendedSize := SizeOf(TImageLoadConfigDir32W10) + 16;
  PrepareLoadConfig32(Data, ExtendedSize);
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W10_VER);
end;

procedure TLoadConfigCoverageTests.RecognizesExtendedPe64LoadConfigAsW10;
var
  Data: TBytes;
  P, Ld: PByte;
  ExtendedSize: DWORD;
begin
  ExtendedSize := SizeOf(TImageLoadConfigDir64W10) + 16;
  PrepareLoadConfig64(Data, ExtendedSize, ExtendedSize);
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W10_VER);
end;

procedure TLoadConfigCoverageTests.RecognizesIntermediatePe64LoadConfigAsW8;
var
  Data: TBytes;
  P, Ld: PByte;
  IntermediateSize: DWORD;
begin
  IntermediateSize := SizeOf(TImageLoadConfigDir64W8) + 8;
  Assert.IsTrue(IntermediateSize < SizeOf(TImageLoadConfigDir64W10));
  PrepareLoadConfig64(Data, IntermediateSize, SizeOf(TImageLoadConfigDir64W10));
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W8_VER);
end;

procedure TLoadConfigCoverageTests.ReportsOlderSmallLoadConfigAsUnknown;
var
  Data: TBytes;
  P, Ld: PByte;
  SmallSize: DWORD;
begin
  SmallSize := SizeOf(TImageLoadConfigDir64W7) - 8;
  PrepareLoadConfig64(Data, SmallSize, SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_UNK_VER);
end;

procedure TLoadConfigCoverageTests.RecognizesNonCanonicalExtendedSizeAsW10;
var
  Data: TBytes;
  P, Ld: PByte;
begin
  PrepareLoadConfig64(Data, $123, $200);
  P := BytesPtr(Data);
  Ld := P + TEST_LOAD_CONFIG_RVA;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_W10_VER);
end;

procedure TLoadConfigCoverageTests.ReportsDeclaredSizeBeyondBufferAsUnknown;
var
  Data: TBytes;
  P, Ld: PByte;
begin
  Data := BuildMinimalPe64;
  P := BytesPtr(Data);
  Ld := P + Length(Data) - 8;
  PDWORD(Ld)^ := $100;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_UNK_VER);
end;

procedure TLoadConfigCoverageTests.ReportsTruncatedLoadConfigAsNone;
var
  Data: TBytes;
  P, Ld: PByte;
begin
  Data := BuildMinimalPe64;
  P := BytesPtr(Data);
  Ld := P + Length(Data) - 8;
  Assert.IsTrue(GetLoadConfigVersion(P, Length(Data), Ld) = LOAD_CONFIG_NONE);
end;

procedure TSecurityCookieCoverageTests.NoLoadConfigSucceeds;
var
  Data: TBytes;
  P: PByte;
begin
  Data := BuildMinimalPe64;
  P := BytesPtr(Data);
  Assert.IsTrue(InitSecurityCookie(P, Length(Data)));
end;

procedure TSecurityCookieCoverageTests.ZeroSecurityCookieIsNoOp;
var
  Data: TBytes;
  P: PByte;
  Ld: PImageLoadConfigDir64W7;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Ld := PImageLoadConfigDir64W7(P + TEST_LOAD_CONFIG_RVA);
  Ld.SecurityCookie := 0;
  Assert.IsTrue(InitSecurityCookie(P, Length(Data)));
  Assert.IsTrue(Ld.SecurityCookie = 0);
end;

procedure TSecurityCookieCoverageTests.InitializesDefaultCookie64;
var
  Data: TBytes;
  P: PByte;
  Ld: PImageLoadConfigDir64W7;
  Cookie: PUInt64;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Ld := PImageLoadConfigDir64W7(P + TEST_LOAD_CONFIG_RVA);
  Cookie := PUInt64(P + TEST_COOKIE_RVA);
  Cookie^ := DEFAULT_COOKIE_64_TEST;
  Ld.SecurityCookie := UInt64(NativeUInt(Cookie));
  Assert.IsTrue(InitSecurityCookie(P, Length(Data)));
  Assert.IsTrue(Cookie^ <> 0);
  Assert.IsTrue(Cookie^ <> DEFAULT_COOKIE_64_TEST);
end;

procedure TSecurityCookieCoverageTests.KeepsCustomCookie64;
const
  CustomCookie = UInt64($0000123456789ABC);
var
  Data: TBytes;
  P: PByte;
  Ld: PImageLoadConfigDir64W7;
  Cookie: PUInt64;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Ld := PImageLoadConfigDir64W7(P + TEST_LOAD_CONFIG_RVA);
  Cookie := PUInt64(P + TEST_COOKIE_RVA);
  Cookie^ := CustomCookie;
  Ld.SecurityCookie := UInt64(NativeUInt(Cookie));
  Assert.IsTrue(InitSecurityCookie(P, Length(Data)));
  Assert.IsTrue(Cookie^ = CustomCookie);
end;

procedure TSecurityCookieCoverageTests.InvalidCookiePointerDoesNotFail;
var
  Data: TBytes;
  P: PByte;
  Ld: PImageLoadConfigDir64W7;
begin
  PrepareLoadConfig64(Data, SizeOf(TImageLoadConfigDir64W7), SizeOf(TImageLoadConfigDir64W7));
  P := BytesPtr(Data);
  Ld := PImageLoadConfigDir64W7(P + TEST_LOAD_CONFIG_RVA);
  Ld.SecurityCookie := 1;
  Assert.IsTrue(InitSecurityCookie(P, Length(Data)));
end;

procedure TSecurityCookieCoverageTests.InvalidModuleFails;
begin
  Assert.IsFalse(InitSecurityCookie(nil, 0));
end;

procedure TResourceUtilCoverageTests.CurrentModuleHandleMatchesWindows;
var
  A, B: HMODULE;
begin
  A := GetCurrentModuleHandle;
  B := GetModuleHandleW(nil);
  Assert.IsTrue(A <> 0);
  Assert.IsTrue(A = B);
end;

procedure TResourceUtilCoverageTests.LoadsEmbeddedResource;
var
  Buffer: TAlignedBuf;
  Size: NativeUInt;
  I: Integer;
begin
  Size := 0;
  Buffer := LoadResourceData(Size, TEST_RESOURCE_ID, RT_RCDATA_A, GetCurrentModuleHandle);
  try
    Assert.IsTrue(Buffer <> nil);
    Assert.IsTrue(Size = SizeOf(TEST_RESOURCE_DATA));
    for I := Low(TEST_RESOURCE_DATA) to High(TEST_RESOURCE_DATA) do
      Assert.IsTrue(Buffer[I] = TEST_RESOURCE_DATA[I]);
  finally
    FreeResourceData(Buffer);
  end;
end;

procedure TResourceUtilCoverageTests.HonorsRequestedResourceSize;
var
  Buffer: TAlignedBuf;
  Size: NativeUInt;
  I: Integer;
begin
  Size := 4;
  Buffer := LoadResourceData(Size, TEST_RESOURCE_ID, RT_RCDATA_A, GetCurrentModuleHandle);
  try
    Assert.IsTrue(Buffer <> nil);
    Assert.IsTrue(Size = 4);
    for I := 0 to 3 do
      Assert.IsTrue(Buffer[I] = TEST_RESOURCE_DATA[I]);
  finally
    FreeResourceData(Buffer);
  end;
end;

procedure TResourceUtilCoverageTests.MissingResourceReturnsNil;
var
  Buffer: TAlignedBuf;
  Size: NativeUInt;
begin
  Size := 0;
  Buffer := LoadResourceData(Size, 402, RT_RCDATA_A, GetCurrentModuleHandle);
  Assert.IsTrue(Buffer = nil);
end;

{$IFDEF WIN64}
procedure TSyscallCoverageTests.DirectNtProtectChangesAndRestoresPageProtection;
var
  Page: Pointer;
  OldProtect, RestoreProtect: DWORD;
  Info: TMemoryBasicInformation;
begin
  Page := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
  Assert.IsTrue(Page <> nil);
  try
    PByte(Page)^ := $5A;
    OldProtect := 0;
    Assert.IsTrue(DirectNtProtect(Page, $1000, PAGE_READONLY, @OldProtect));
    Assert.IsTrue((OldProtect and $FF) = PAGE_READWRITE);
    FillChar(Info, SizeOf(Info), 0);
    Assert.IsTrue(VirtualQuery(Page, Info, SizeOf(Info)) = SizeOf(Info));
    Assert.IsTrue((Info.Protect and $FF) = PAGE_READONLY);
    RestoreProtect := 0;
    Assert.IsTrue(DirectNtProtect(Page, $1000, PAGE_READWRITE, @RestoreProtect));
    PByte(Page)^ := $A5;
    Assert.IsTrue(PByte(Page)^ = $A5);
  finally
    VirtualFree(Page, 0, MEM_RELEASE);
  end;
end;
{$ENDIF}

initialization
  TDUnitX.RegisterTestFixture(TCaveCoverageTests);
  TDUnitX.RegisterTestFixture(TPeRecyclerCoverageTests);
  TDUnitX.RegisterTestFixture(TLoadConfigCoverageTests);
  TDUnitX.RegisterTestFixture(TSecurityCookieCoverageTests);
  TDUnitX.RegisterTestFixture(TResourceUtilCoverageTests);
{$IFDEF WIN64}
  TDUnitX.RegisterTestFixture(TSyscallCoverageTests);
{$ENDIF}

end.
