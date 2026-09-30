{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativePe.LibPeConv.Fidelity.Tests;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  DUnitX.TestFramework,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.FileUtil,
  NativePe.PeHdrsHelper,
  NativePe.PeLoader,
  NativePe.PeVirtualToRaw,
  NativePe.ExportsLookup,
  NativePe.ImportsLoader,
  NativePe.ExportedFunc,
  NativePe.TestFixtures,
  NativePe.LibPeConv.ReferenceData;

type
  {$M+}

  [TestFixture]
  TLibPeConvOriginalArrayTests = class
  public
    [Test] procedure Shellcode32MatchesOriginalHeaderByteForByte;
    [Test] procedure Shellcode64MatchesOriginalHeaderByteForByte;
  end;

  [TestFixture]
  TLibPeConvGreekToMeFixtureTests = class
  public
    [Test] procedure FileSizeMatchesOriginal;
    [Test] procedure PeHeaderMatchesOriginal;
    [Test] procedure SectionsMatchOriginal;
    [Test] procedure ImportAndIatDirectoriesMatchOriginal;
    [Test] procedure Ws2ImportsAreExactOriginalOrdinals;
    [Test] procedure EncodedBufferBytesAt107CMatchOriginal;
    [Test] procedure ChecksumFunctionBytesAt11E6MatchOriginal;
    [Test] procedure RawVirtualRawMatchesOriginalByteForByte;
  end;

  [TestFixture]
  TLibPeConvFlareOn6FixtureTests = class
  public
    [Test] procedure FileSizeMatchesOriginal;
    [Test] procedure PeHeaderMatchesOriginal;
    [Test] procedure SectionsMatchOriginal;
    [Test] procedure ExportMatchesOriginal;
    [Test] procedure ImportDllsMatchOriginal;
    [Test] procedure BytesAt4710MatchOriginal;
    [Test] procedure BytesAt5C00MatchOriginal;
    [Test] procedure BytesAt5D30MatchOriginal;
    [Test] procedure BytesAt664CMatchOriginal;
    [Test] procedure BytesAt6824MatchOriginal;
    [Test] procedure BytesAt78D4MatchOriginal;
    [Test] procedure BytesAt7900MatchOriginal;
    [Test] procedure RawVirtualRawMatchesOriginalByteForByte;
  end;

  [TestFixture]
  TLibPeConvCase3FixtureTests = class
  public
    [Test] procedure Win32FileAndHeaderMatchOriginal;
    [Test] procedure Win32SectionsMatchOriginal;
    [Test] procedure Win32CallSiteBytesMatchOriginal;
    [Test] procedure Win32ChecksumFunctionBytesMatchOriginal;
    [Test] procedure Win32CallSiteTargetsOriginalChecksumFunction;
    [Test] procedure Win64FileAndHeaderMatchOriginal;
    [Test] procedure Win64SectionsMatchOriginal;
    [Test] procedure Win64ChecksumFunctionBytesMatchOriginal;
    [Test] procedure Win32RawVirtualRawMatchesOriginalByteForByte;
    [Test] procedure Win64RawVirtualRawMatchesOriginalByteForByte;
  end;

implementation

function FixtureRoot: string;
begin
  Result := GetEnvironmentVariable('NATIVEPE_LIBPECONV_FIXTURES');
  if Result = '' then
    Result := ExpandFileName(IncludeTrailingPathDelimiter(ExtractFilePath(ParamStr(0))) +
      '..\..\..\tests\dunitx\fixtures\libpeconv');
end;

function FixturePath(const FileName: string): string;
begin
  Result := IncludeTrailingPathDelimiter(FixtureRoot) + FileName;
  Assert.IsTrue(FileExists(Result), 'Missing libpeconv fixture: ' + Result);
end;

function LoadFixture(const FileName: string; out FileSize: NativeUInt): TUnalignedBuf;
begin
  FileSize := 0;
  Result := LoadFile(FixturePath(FileName), FileSize);
  Assert.IsTrue(Result <> nil, 'Cannot load libpeconv fixture: ' + FileName);
end;

procedure AssertBytes(const Actual: PByte; ActualSize, Offset: NativeUInt; const Expected: array of Byte;
  const Context: string);
begin
  Assert.IsTrue(Actual <> nil, Context + ': nil buffer');
  Assert.IsTrue(Length(Expected) > 0, Context + ': empty expected byte array');
  Assert.IsTrue(Offset <= ActualSize, Context + ': offset outside buffer');
  Assert.IsTrue(NativeUInt(Length(Expected)) <= ActualSize - Offset, Context + ': expected bytes outside buffer');
  Assert.IsTrue(CompareMem(Actual + Offset, @Expected[0], Length(Expected)), Context + ': bytes differ');
end;

procedure AssertMappedRvaBytes(const FileName: string; Rva: DWORD; const Expected: array of Byte;
  const Context: string);
var
  VSize: NativeUInt;
  Mapped: TAlignedBuf;
begin
  VSize := 0;
  Mapped := LoadPeModule(FixturePath(FileName), VSize, False, False);
  Assert.IsTrue(Mapped <> nil, Context + ': mapping failed');
  try
    AssertBytes(Mapped, VSize, Rva, Expected, Context);
  finally
    FreePeBuffer(Mapped, VSize);
  end;
end;

procedure AssertSection(Pe: PByte; PeSize: NativeUInt; Index: NativeUInt; const ExpectedName: string;
  ExpectedVirtualSize, ExpectedRva, ExpectedRawSize, ExpectedRawOffset, ExpectedCharacteristics: DWORD);
var
  Sec: PImageSectionHeader;
begin
  Sec := GetSectionHdr(Pe, PeSize, Index);
  Assert.IsTrue(Sec <> nil, 'Missing section #' + IntToStr(Index));
  Assert.IsTrue(SectionName(Sec) = ExpectedName, 'Section name mismatch at #' + IntToStr(Index));
  Assert.IsTrue(Sec.Misc.VirtualSize = ExpectedVirtualSize, 'VirtualSize mismatch for ' + ExpectedName);
  Assert.IsTrue(Sec.VirtualAddress = ExpectedRva, 'VirtualAddress mismatch for ' + ExpectedName);
  Assert.IsTrue(Sec.SizeOfRawData = ExpectedRawSize, 'SizeOfRawData mismatch for ' + ExpectedName);
  Assert.IsTrue(Sec.PointerToRawData = ExpectedRawOffset, 'PointerToRawData mismatch for ' + ExpectedName);
  Assert.IsTrue(Sec.Characteristics = ExpectedCharacteristics, 'Characteristics mismatch for ' + ExpectedName);
end;

procedure AssertFileMatchesArray(const FileName: string; const Expected: array of Byte);
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture(FileName, FileSize);
  try
    Assert.IsTrue(FileSize = NativeUInt(Length(Expected)), FileName + ': exact byte count differs');
    AssertBytes(Buf, FileSize, 0, Expected, FileName);
  finally
    FreeFile(Buf);
  end;
end;


procedure AssertRawVirtualRawExact(const FileName: string);
var
  FileSize, VSize, OutSize: NativeUInt;
  Raw: TUnalignedBuf;
  Mapped, OutRaw: TAlignedBuf;
begin
  FileSize := 0;
  Raw := LoadFixture(FileName, FileSize);
  try
    VSize := 0;
    Mapped := LoadPeModule(Raw, FileSize, VSize, False, False);
    Assert.IsTrue(Mapped <> nil, FileName + ': raw-to-virtual failed');
    try
      OutSize := 0;
      OutRaw := PeVirtualToRaw(Mapped, VSize, GetImageBase(Mapped), OutSize, True);
      Assert.IsTrue(OutRaw <> nil, FileName + ': virtual-to-raw failed');
      try
        Assert.IsTrue(OutSize = FileSize, FileName + ': round-trip file size differs');
        Assert.IsTrue(CompareMem(OutRaw, Raw, NativeInt(FileSize)), FileName + ': round-trip bytes differ');
      finally
        FreePeBuffer(OutRaw, OutSize);
      end;
    finally
      FreePeBuffer(Mapped, VSize);
    end;
  finally
    FreeFile(Raw);
  end;
end;

procedure TLibPeConvOriginalArrayTests.Shellcode32MatchesOriginalHeaderByteForByte;
begin
  AssertFileMatchesArray('shellc32.bin', LIBPECONV_SHELLC32);
end;

procedure TLibPeConvOriginalArrayTests.Shellcode64MatchesOriginalHeaderByteForByte;
begin
  AssertFileMatchesArray('shellc64.bin', LIBPECONV_SHELLC64);
end;

procedure TLibPeConvGreekToMeFixtureTests.FileSizeMatchesOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture('greek_to_me.bin', FileSize);
  try
    Assert.IsTrue(FileSize = 2048, 'greek_to_me.bin size must be exactly 2048 bytes');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvGreekToMeFixtureTests.PeHeaderMatchesOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
  Nt: PImageNtHeaders32;
begin
  Buf := LoadFixture('greek_to_me.bin', FileSize);
  try
    Nt := GetNtHdrs32(Buf);
    Assert.IsTrue(Nt <> nil, 'greek_to_me.bin is not PE32');
    Assert.IsTrue(Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386, 'Machine differs');
    Assert.IsTrue(Nt.FileHeader.NumberOfSections = 2, 'NumberOfSections differs');
    Assert.IsTrue(Nt.FileHeader.SizeOfOptionalHeader = $E0, 'SizeOfOptionalHeader differs');
    Assert.IsTrue(Nt.FileHeader.Characteristics = $0103, 'Characteristics differs');
    Assert.IsTrue(Nt.OptionalHeader.AddressOfEntryPoint = $1000, 'EntryPoint differs');
    Assert.IsTrue(Nt.OptionalHeader.ImageBase = $400000, 'ImageBase differs');
    Assert.IsTrue(Nt.OptionalHeader.SectionAlignment = $1000, 'SectionAlignment differs');
    Assert.IsTrue(Nt.OptionalHeader.FileAlignment = $200, 'FileAlignment differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfImage = $3000, 'SizeOfImage differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfHeaders = $200, 'SizeOfHeaders differs');
    Assert.IsTrue(Nt.OptionalHeader.Subsystem = 3, 'Subsystem differs');
    Assert.IsTrue(Nt.OptionalHeader.NumberOfRvaAndSizes = 16, 'NumberOfRvaAndSizes differs');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvGreekToMeFixtureTests.SectionsMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture('greek_to_me.bin', FileSize);
  try
    AssertSection(Buf, FileSize, 0, '.text', $26C, $1000, $400, $200, $C0000020);
    AssertSection(Buf, FileSize, 1, '.rdata', $E4, $2000, $200, $600, $40000040);
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvGreekToMeFixtureTests.ImportAndIatDirectoriesMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
  Nt: PImageNtHeaders32;
begin
  Buf := LoadFixture('greek_to_me.bin', FileSize);
  try
    Nt := GetNtHdrs32(Buf);
    Assert.IsTrue(Nt <> nil);
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = $2080,
      'Import directory RVA differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = $28,
      'Import directory size differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = $2000,
      'IAT RVA differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = $30,
      'IAT size differs');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvGreekToMeFixtureTests.Ws2ImportsAreExactOriginalOrdinals;
var
  VSize: NativeUInt;
  Mapped: TAlignedBuf;
  Imports: TImportsCollection;
  Pair: TPair<DWORD, TExportedFunc>;
  Ordinals: TList<DWORD>;
  Thunks: TList<DWORD>;
  I: Integer;
begin
  VSize := 0;
  Mapped := LoadPeModule(FixturePath('greek_to_me.bin'), VSize, False, False);
  Assert.IsTrue(Mapped <> nil, 'Cannot map greek_to_me.bin');
  Imports := TImportsCollection.Create;
  Ordinals := TList<DWORD>.Create;
  Thunks := TList<DWORD>.Create;
  try
    Assert.IsTrue(CollectImports(Mapped, VSize, Imports), 'CollectImports failed');
    Assert.IsTrue(Imports.ThunkToFunc.Count = Length(LIBPECONV_GREEK_IMPORT_ORDINALS), 'Import count differs');
    for Pair in Imports.ThunkToFunc do
    begin
      Assert.IsTrue(Pair.Value <> nil, 'Import value is nil');
      Assert.IsTrue(Pair.Value.IsByOrdinal, 'Original greek_to_me import must be ordinal-only');
      Assert.IsTrue(Pair.Value.LibName = 'ws2_32', 'Original import library must be ws2_32');
      Ordinals.Add(Pair.Value.FuncOrdinal);
      Thunks.Add(Pair.Key);
    end;
    Ordinals.Sort;
    Thunks.Sort;
    for I := 0 to High(LIBPECONV_GREEK_IMPORT_ORDINALS) do
    begin
      Assert.IsTrue(Ordinals[I] = LIBPECONV_GREEK_IMPORT_ORDINALS[I], 'WS2_32 ordinal differs at index ' + IntToStr(I));
      Assert.IsTrue(Thunks[I] = DWORD($2000 + I * 4), 'IAT thunk RVA differs at index ' + IntToStr(I));
    end;
  finally
    Thunks.Free;
    Ordinals.Free;
    Imports.Free;
    FreePeBuffer(Mapped, VSize);
  end;
end;

procedure TLibPeConvGreekToMeFixtureTests.EncodedBufferBytesAt107CMatchOriginal;
begin
  AssertMappedRvaBytes('greek_to_me.bin', $107C, LIBPECONV_GREEK_RVA_107C, 'greek_to_me RVA 107C');
end;

procedure TLibPeConvGreekToMeFixtureTests.ChecksumFunctionBytesAt11E6MatchOriginal;
begin
  AssertMappedRvaBytes('greek_to_me.bin', $11E6, LIBPECONV_GREEK_RVA_11E6, 'greek_to_me RVA 11E6');
end;

procedure TLibPeConvGreekToMeFixtureTests.RawVirtualRawMatchesOriginalByteForByte;
begin
  AssertRawVirtualRawExact('greek_to_me.bin');
end;

procedure TLibPeConvFlareOn6FixtureTests.FileSizeMatchesOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture('payload.dll', FileSize);
  try
    Assert.IsTrue(FileSize = 105984, 'payload.dll size differs');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvFlareOn6FixtureTests.PeHeaderMatchesOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
  Nt: PImageNtHeaders64;
begin
  Buf := LoadFixture('payload.dll', FileSize);
  try
    Nt := GetNtHdrs64(Buf);
    Assert.IsTrue(Nt <> nil, 'payload.dll is not PE32+');
    Assert.IsTrue(Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64, 'Machine differs');
    Assert.IsTrue(Nt.FileHeader.NumberOfSections = 7, 'NumberOfSections differs');
    Assert.IsTrue(Nt.FileHeader.SizeOfOptionalHeader = $F0, 'SizeOfOptionalHeader differs');
    Assert.IsTrue(Nt.FileHeader.Characteristics = $2022, 'Characteristics differs');
    Assert.IsTrue(Nt.OptionalHeader.AddressOfEntryPoint = $6200, 'EntryPoint differs');
    Assert.IsTrue(Nt.OptionalHeader.ImageBase = UInt64($180000000), 'ImageBase differs');
    Assert.IsTrue(Nt.OptionalHeader.SectionAlignment = $1000, 'SectionAlignment differs');
    Assert.IsTrue(Nt.OptionalHeader.FileAlignment = $200, 'FileAlignment differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfImage = $1F000, 'SizeOfImage differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfHeaders = $400, 'SizeOfHeaders differs');
    Assert.IsTrue(Nt.OptionalHeader.Subsystem = 2, 'Subsystem differs');
    Assert.IsTrue(Nt.OptionalHeader.NumberOfRvaAndSizes = 16, 'NumberOfRvaAndSizes differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = $18000,
      'Export directory RVA differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size = $4C,
      'Export directory size differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = $1804C,
      'Import directory RVA differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = $3C,
      'Import directory size differs');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvFlareOn6FixtureTests.SectionsMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture('payload.dll', FileSize);
  try
    AssertSection(Buf, FileSize, 0, '.text', $EAD0, $1000, $EC00, $400, $60000020);
    AssertSection(Buf, FileSize, 1, '.rdata', $87FA, $10000, $8800, $F000, $40000040);
    AssertSection(Buf, FileSize, 2, '.data', $1B98, $19000, $A00, $17800, $C0000040);
    AssertSection(Buf, FileSize, 3, '.pdata', $E34, $1B000, $1000, $18200, $40000040);
    AssertSection(Buf, FileSize, 4, '.gfids', $94, $1C000, $200, $19200, $40000040);
    AssertSection(Buf, FileSize, 5, '.rsrc', $1E0, $1D000, $200, $19400, $40000040);
    AssertSection(Buf, FileSize, 6, '.reloc', $640, $1E000, $800, $19600, $42000040);
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvFlareOn6FixtureTests.ExportMatchesOriginal;
var
  VSize: NativeUInt;
  Mapped: TAlignedBuf;
  Names: TList<string>;
  Proc: FARPROC;
  DllName: PAnsiChar;
begin
  VSize := 0;
  Mapped := LoadPeModule(FixturePath('payload.dll'), VSize, False, False);
  Assert.IsTrue(Mapped <> nil, 'Cannot map payload.dll');
  Names := TList<string>.Create;
  try
    Assert.IsTrue(GetExportedNames(Mapped, Names) = 1, 'payload.dll must have exactly one named export');
    Assert.IsTrue(Names.Count = 1, 'payload.dll export-name count differs');
    Assert.IsTrue(Names[0] = 'EntryPoint', 'payload.dll export name differs');
    Proc := GetExportedFunc(Mapped, PAnsiChar(AnsiString('EntryPoint')));
    Assert.IsTrue(Assigned(Proc), 'EntryPoint export not resolved');
    Assert.IsTrue(NativeUInt(Proc) - NativeUInt(Mapped) = $5C00, 'EntryPoint export RVA differs');
    DllName := ReadDllName(Mapped);
    Assert.IsTrue(DllName <> nil, 'payload.dll export DLL name is missing');
    Assert.IsTrue(string(AnsiString(DllName)) = 'payload.dll', 'payload.dll export DLL name differs');
  finally
    Names.Free;
    FreePeBuffer(Mapped, VSize);
  end;
end;

procedure TLibPeConvFlareOn6FixtureTests.ImportDllsMatchOriginal;
var
  VSize: NativeUInt;
  Mapped: TAlignedBuf;
  Imports: TImportsCollection;
  Pair: TPair<DWORD, TExportedFunc>;
  HasKernel32, HasUser32: Boolean;
begin
  VSize := 0;
  Mapped := LoadPeModule(FixturePath('payload.dll'), VSize, False, False);
  Assert.IsTrue(Mapped <> nil, 'Cannot map payload.dll');
  Imports := TImportsCollection.Create;
  try
    Assert.IsTrue(CollectImports(Mapped, VSize, Imports), 'CollectImports(payload.dll) failed');
    HasKernel32 := False;
    HasUser32 := False;
    for Pair in Imports.ThunkToFunc do
    begin
      if Pair.Value.LibName = 'kernel32' then
        HasKernel32 := True;
      if Pair.Value.LibName = 'user32' then
        HasUser32 := True;
      Assert.IsTrue((Pair.Value.LibName = 'kernel32') or (Pair.Value.LibName = 'user32'),
        'Unexpected import DLL in original payload.dll: ' + Pair.Value.LibName);
    end;
    Assert.IsTrue(HasKernel32, 'KERNEL32.dll imports missing');
    Assert.IsTrue(HasUser32, 'USER32.dll imports missing');
  finally
    Imports.Free;
    FreePeBuffer(Mapped, VSize);
  end;
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt4710MatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $4710, LIBPECONV_PAYLOAD_RVA_4710, 'payload RVA 4710');
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt5C00MatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $5C00, LIBPECONV_PAYLOAD_RVA_5C00, 'payload RVA 5C00');
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt5D30MatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $5D30, LIBPECONV_PAYLOAD_RVA_5D30, 'payload RVA 5D30');
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt664CMatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $664C, LIBPECONV_PAYLOAD_RVA_664C, 'payload RVA 664C');
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt6824MatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $6824, LIBPECONV_PAYLOAD_RVA_6824, 'payload RVA 6824');
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt78D4MatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $78D4, LIBPECONV_PAYLOAD_RVA_78D4, 'payload RVA 78D4');
end;

procedure TLibPeConvFlareOn6FixtureTests.BytesAt7900MatchOriginal;
begin
  AssertMappedRvaBytes('payload.dll', $7900, LIBPECONV_PAYLOAD_RVA_7900, 'payload RVA 7900');
end;

procedure TLibPeConvFlareOn6FixtureTests.RawVirtualRawMatchesOriginalByteForByte;
begin
  AssertRawVirtualRawExact('payload.dll');
end;

procedure TLibPeConvCase3FixtureTests.Win32FileAndHeaderMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
  Nt: PImageNtHeaders32;
begin
  Buf := LoadFixture('test_case3_32.exe', FileSize);
  try
    Assert.IsTrue(FileSize = 181248, 'test_case3_32.exe size differs');
    Nt := GetNtHdrs32(Buf);
    Assert.IsTrue(Nt <> nil, 'test_case3_32.exe is not PE32');
    Assert.IsTrue(Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386, 'Machine differs');
    Assert.IsTrue(Nt.FileHeader.NumberOfSections = 5, 'NumberOfSections differs');
    Assert.IsTrue(Nt.OptionalHeader.AddressOfEntryPoint = $5763, 'EntryPoint differs');
    Assert.IsTrue(Nt.OptionalHeader.ImageBase = $400000, 'ImageBase differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfImage = $30000, 'SizeOfImage differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfHeaders = $400, 'SizeOfHeaders differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = $2A14C,
      'Import directory RVA differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = $1D000,
      'IAT RVA differs');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvCase3FixtureTests.Win32SectionsMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture('test_case3_32.exe', FileSize);
  try
    AssertSection(Buf, FileSize, 0, '.text', $1B359, $1000, $1B400, $400, $60000020);
    AssertSection(Buf, FileSize, 1, '.rdata', $D82A, $1D000, $DA00, $1B800, $40000040);
    AssertSection(Buf, FileSize, 2, '.data', $1C6C, $2B000, $1000, $29200, $C0000040);
    AssertSection(Buf, FileSize, 3, '.rsrc', $1E0, $2D000, $200, $2A200, $40000040);
    AssertSection(Buf, FileSize, 4, '.reloc', $1F44, $2E000, $2000, $2A400, $42000040);
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvCase3FixtureTests.Win32CallSiteBytesMatchOriginal;
begin
  AssertMappedRvaBytes('test_case3_32.exe', $2A4C, LIBPECONV_CASE3_32_RVA_2A4C, 'test_case3_32 RVA 2A4C');
end;

procedure TLibPeConvCase3FixtureTests.Win32ChecksumFunctionBytesMatchOriginal;
begin
  AssertMappedRvaBytes('test_case3_32.exe', $2AB0, LIBPECONV_CASE3_32_RVA_2AB0, 'test_case3_32 RVA 2AB0');
end;

procedure TLibPeConvCase3FixtureTests.Win32CallSiteTargetsOriginalChecksumFunction;
var
  VSize: NativeUInt;
  Mapped: TAlignedBuf;
  Delta: Integer;
  TargetRva: Int64;
begin
  VSize := 0;
  Mapped := LoadPeModule(FixturePath('test_case3_32.exe'), VSize, False, False);
  Assert.IsTrue(Mapped <> nil, 'Cannot map test_case3_32.exe');
  try
    Assert.IsTrue(Mapped[$2A4C] = $E8, 'Original instruction at RVA 2A4C must be CALL rel32');
    Move(Mapped[$2A4D], Delta, SizeOf(Delta));
    TargetRva := Int64($2A4C) + 5 + Delta;
    Assert.IsTrue(TargetRva = $2AB0, 'Original CALL target must be checksum function RVA 2AB0');
  finally
    FreePeBuffer(Mapped, VSize);
  end;
end;

procedure TLibPeConvCase3FixtureTests.Win64FileAndHeaderMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
  Nt: PImageNtHeaders64;
begin
  Buf := LoadFixture('test_case3_64.exe', FileSize);
  try
    Assert.IsTrue(FileSize = 215040, 'test_case3_64.exe size differs');
    Nt := GetNtHdrs64(Buf);
    Assert.IsTrue(Nt <> nil, 'test_case3_64.exe is not PE32+');
    Assert.IsTrue(Nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64, 'Machine differs');
    Assert.IsTrue(Nt.FileHeader.NumberOfSections = 6, 'NumberOfSections differs');
    Assert.IsTrue(Nt.OptionalHeader.AddressOfEntryPoint = $6238, 'EntryPoint differs');
    Assert.IsTrue(Nt.OptionalHeader.ImageBase = UInt64($140000000), 'ImageBase differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfImage = $3A000, 'SizeOfImage differs');
    Assert.IsTrue(Nt.OptionalHeader.SizeOfHeaders = $400, 'SizeOfHeaders differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = $317CC,
      'Import directory RVA differs');
    Assert.IsTrue(Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = $1F000,
      'IAT RVA differs');
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvCase3FixtureTests.Win64SectionsMatchOriginal;
var
  FileSize: NativeUInt;
  Buf: TUnalignedBuf;
begin
  Buf := LoadFixture('test_case3_64.exe', FileSize);
  try
    AssertSection(Buf, FileSize, 0, '.text', $1D390, $1000, $1D400, $400, $60000020);
    AssertSection(Buf, FileSize, 1, '.rdata', $13056, $1F000, $13200, $1D800, $40000040);
    AssertSection(Buf, FileSize, 2, '.data', $29B8, $33000, $1200, $30A00, $C0000040);
    AssertSection(Buf, FileSize, 3, '.pdata', $1BFC, $36000, $1C00, $31C00, $40000040);
    AssertSection(Buf, FileSize, 4, '.rsrc', $1E0, $38000, $200, $33800, $40000040);
    AssertSection(Buf, FileSize, 5, '.reloc', $C94, $39000, $E00, $33A00, $42000040);
  finally
    FreeFile(Buf);
  end;
end;

procedure TLibPeConvCase3FixtureTests.Win64ChecksumFunctionBytesMatchOriginal;
begin
  AssertMappedRvaBytes('test_case3_64.exe', $2B10, LIBPECONV_CASE3_64_RVA_2B10, 'test_case3_64 RVA 2B10');
end;

procedure TLibPeConvCase3FixtureTests.Win32RawVirtualRawMatchesOriginalByteForByte;
begin
  AssertRawVirtualRawExact('test_case3_32.exe');
end;

procedure TLibPeConvCase3FixtureTests.Win64RawVirtualRawMatchesOriginalByteForByte;
begin
  AssertRawVirtualRawExact('test_case3_64.exe');
end;

initialization
  TDUnitX.RegisterTestFixture(TLibPeConvOriginalArrayTests);
  TDUnitX.RegisterTestFixture(TLibPeConvGreekToMeFixtureTests);
  TDUnitX.RegisterTestFixture(TLibPeConvFlareOn6FixtureTests);
  TDUnitX.RegisterTestFixture(TLibPeConvCase3FixtureTests);

end.
