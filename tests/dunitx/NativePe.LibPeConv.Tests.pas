{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains test logic or reference data derived from the libpeconv test suite.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}

unit NativePe.LibPeConv.Tests;

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
  NativePe.PeModeDetector,
  NativePe.FindBase,
  NativePe.ExportsLookup,
  NativePe.ExportsMapper,
  NativePe.ExportedFunc,
  NativePe.FunctionResolver,
  NativePe.ImportsLoader,
  NativePe.DelayedImports,
  NativePe.DotNetEpFixer,
  NativePe.TlsParser,
  NativePe.PebLookup,
  NativePe.Hooks,
  NativePe.Util,
  NativePe.TestFixtures,
  NativePe.LibPeConv.ReferenceData;

type
  {$M+}

  [TestFixture]
  TLibPeConvLoadingTests = class
  public
    [Test] procedure SelfRawVirtualRawMatchesOriginal;
    [Test] procedure SelfFormatChangesFromRawToVirtual;
    [Test] procedure SelfFoundBaseMatchesMappedAddress;
    [Test] procedure InvalidBufferCannotBeLoaded;
    [Test] procedure ZeroSectionImageLoadsWithoutSectionMapping;
    [Test] procedure LoadPeExecutableResolvesSyntheticImports;
    [Test] procedure NtdllMappedExportRvaMatchesLoadedModule;
    [Test] procedure NtdllMappedDllNameMatches;
  end;

  [TestFixture]
  TLibPeConvImportTests = class
  public
    [Test] procedure NormalImportsResolveNameAndOrdinal;
    [Test] procedure NormalImportsWriteExpectedAddresses;
    [Test] procedure NormalImportsKeepOriginalLookupTable;
    [Test] procedure DelayImportDirectoryIsLocated;
    [Test] procedure DelayImportsResolveNameAndOrdinal;
    [Test] procedure DelayImportsWriteResolvedAddresses;
    [Test] procedure MissingDelayImportDirectoryIsNoOp;
    [Test] procedure TooSmallDelayImportDirectoryIsRejected;
    [Test] procedure SelfImportCollectionIsNonEmptyAndInBounds;
    [Test] procedure SyntheticImportCollectionHasExpectedEntries;
    [Test] procedure HookResolverCanPatchSyntheticImport;
    [Test] procedure NormalAndDelayedImportsResolveTogether;
    [Test] procedure ZeroedIatDoesNotTerminateLookupTable;
  end;

  [TestFixture]
  TLibPeConvDotNetTests = class
  public
    [Test] procedure JumpAtBufferStartFound;
    [Test] procedure JumpAtBufferEndFound;
    [Test] procedure JumpThirtyBytesBeforeEndFound;
    [Test] procedure WrongThunkIsNotFound;
    [Test] procedure TruncatedJumpIsNotFound;
  end;

  [TestFixture]
  TLibPeConvTlsTests = class
  public
    [Test] procedure ExecutableTlsCallbackRunsOnce;
    [Test] procedure TwoExecutableTlsCallbacksRunInOrder;
    [Test] procedure ZeroTlsCallbackTableRunsNone;
    [Test] procedure RelocatedSmallTlsCallbackTableAddress32IsRejected;
  end;

  [TestFixture]
  TLibPeConvPebTests = class
  public
    [Test] procedure User32MatchesWindowsLoader;
    [Test] procedure Advapi32MatchesWindowsLoader;
    [Test] procedure Ws2_32MatchesWindowsLoader;
    [Test] procedure ModuleLookupIsCaseInsensitive;
  end;

  [TestFixture]
  TLibPeConvHookTests = class
  public
    [Test] procedure HookResolverReturnsRegisteredReplacement;
    [Test] procedure DllReplacementIsCaseInsensitive;
    [Test] procedure Redirect64WritesExactStub;
    [Test] procedure Redirect64BackupRestoresOriginalBytes;
    [Test] procedure Redirect64ChangesExecutableTarget;
    [Test] procedure Redirect64BackupRestoresExecutableTarget;
    [Test] procedure RedirectNilReturnsZero;
    [Test] procedure ReplaceJmpTargetWritesExpectedDelta;
    [Test] procedure ReplaceCallTargetWritesExpectedDelta;
    [Test] procedure ReplaceTargetRejectsUnsupportedOpcode;
    [Test] procedure ReplaceTargetRejectsOutOfRangeDelta;
  end;

  [TestFixture]
  TLibPeConvMemoryTests = class
  public
    [Test] procedure StackMemoryIsReadable;
    [Test] procedure NilAndLowAddressAreUnreadable;
    [Test] procedure NoAccessPageIsUnreadable;
    [Test] procedure ReadOnlyPageIsReadable;
  end;

  [TestFixture]
  TLibPeConvForwarderTests = class
  public
    [Test] procedure ForwarderThenTargetMergesAlias;
    [Test] procedure TargetThenForwarderMergesAlias;
  end;

implementation

type
  TMockResolver = class(TFunctionResolver)
  private
    FCalls: TList<string>;
    FNamedValue: NativeUInt;
    FOrdinalValue: NativeUInt;
  public
    constructor Create(ANamedValue, AOrdinalValue: NativeUInt);
    destructor Destroy; override;
    function ResolveFunc(LibName: PAnsiChar; FuncName: PAnsiChar): FARPROC; override;
    function HasCall(const Value: string): Boolean;
  end;

constructor TMockResolver.Create(ANamedValue, AOrdinalValue: NativeUInt);
begin
  inherited Create;
  FCalls := TList<string>.Create;
  FNamedValue := ANamedValue;
  FOrdinalValue := AOrdinalValue;
end;

destructor TMockResolver.Destroy;
begin
  FCalls.Free;
  inherited Destroy;
end;

function TMockResolver.ResolveFunc(LibName: PAnsiChar; FuncName: PAnsiChar): FARPROC;
var
  Lib: string;
  V: NativeUInt;
  Func: string;
begin
  Lib := string(AnsiString(LibName));
  V := NativeUInt(FuncName);
  if V <= $FFFF then
  begin
    Func := '#' + IntToStr(V);
    FCalls.Add(Lib + '!' + Func);
    Result := FARPROC(FOrdinalValue);
  end
  else
  begin
    Func := string(AnsiString(FuncName));
    FCalls.Add(Lib + '!' + Func);
    Result := FARPROC(FNamedValue);
  end;
end;

function TMockResolver.HasCall(const Value: string): Boolean;
begin
  Result := FCalls.IndexOf(Value) >= 0;
end;

function CurrentExePath: string;
var
  Buf: array [0 .. 32767] of WideChar;
  N: DWORD;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  N := GetModuleFileNameW(0, @Buf[0], Length(Buf));
  Assert.IsTrue(N > 0, 'GetModuleFileNameW failed');
  Result := string(PWideChar(@Buf[0]));
end;

function ModulePath(Module: HMODULE): string;
var
  Buf: array [0 .. 32767] of WideChar;
  N: DWORD;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  N := GetModuleFileNameW(Module, @Buf[0], Length(Buf));
  Assert.IsTrue(N > 0, 'GetModuleFileNameW(module) failed');
  Result := string(PWideChar(@Buf[0]));
end;

procedure PutAnsiZ(var Data: TBytes; Offset: NativeUInt; const S: AnsiString);
var
  N: Integer;
begin
  N := Length(S);
  if N > 0 then
    Move(S[1], Data[Offset], N);
  Data[Offset + NativeUInt(N)] := 0;
end;

procedure BuildDelayImportFixture64(out Data: TBytes);
var
  Nt: PImageNtHeaders64;
  Desc: PImageDelayloadDescriptor;
  Thunk: PImageThunkData64;
  ByName: PImageImportByName;
begin
  Data := BuildRichVirtualPe64;
  Nt := GetNtHdrs64(@Data[0]);
  Assert.IsTrue(Nt <> nil);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress := $2700;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size := 2 * SizeOf(TImageDelayloadDescriptor);
  Desc := PImageDelayloadDescriptor(@Data[$2700]);
  Desc.AllAttributes := 1;
  Desc.DllNameRVA := $2780;
  Desc.ImportAddressTableRVA := $27A0;
  Desc.ImportNameTableRVA := $27C0;
  PutAnsiZ(Data, $2780, 'delayfixture.dll');
  PUInt64(@Data[$27A0])^ := $27E0;
  PUInt64(@Data[$27A8])^ := $27E8;
  PUInt64(@Data[$27B0])^ := 0;
  Thunk := PImageThunkData64(@Data[$27C0]);
  Thunk.AddressOfData := $2800;
  Inc(Thunk);
  Thunk.Ordinal := IMAGE_ORDINAL_FLAG64 or 7;
  Inc(Thunk);
  Thunk.Func := 0;
  ByName := PImageImportByName(@Data[$2800]);
  ByName.Hint := $33;
  PutAnsiZ(Data, $2802, 'DelayedNamed');
  PUInt64(@Data[$27E0])^ := 0;
  PUInt64(@Data[$27E8])^ := 0;
end;

function SearchJumpOffset(PatternOffset: NativeUInt; FromStart: Boolean; Thunk: DWORD): Int64;
const
  ImgBase: UInt64 = $400000;
  CorExeMainThunk: DWORD = $2000;
var
  Buf: array [0 .. $FF] of Byte;
  Pattern: array [0 .. 5] of Byte;
  AbsoluteTarget: DWORD;
  Offset: NativeUInt;
  Found: PByte;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Move(LIBPECONV_DOTNET_JUMP_PATTERN[0], Pattern[0], SizeOf(Pattern));
  if Thunk <> CorExeMainThunk then
  begin
    AbsoluteTarget := DWORD(ImgBase) + Thunk;
    Move(AbsoluteTarget, Pattern[2], SizeOf(AbsoluteTarget));
  end;
  Offset := PatternOffset;
  if not FromStart then
    Offset := NativeUInt(SizeOf(Buf) - SizeOf(Pattern)) - PatternOffset;
  if Offset + SizeOf(Pattern) <= SizeOf(Buf) then
    Move(Pattern[0], Buf[Offset], SizeOf(Pattern));
  Found := SearchJump(@Buf[0], SizeOf(Buf), CorExeMainThunk, ImgBase);
  if Found = nil then
    Exit(-1);
  Result := Int64(NativeUInt(Found) - NativeUInt(@Buf[0]));
end;

procedure AssertModuleParity(const Name: string);
var
  OsMod, PebMod: HMODULE;
  OsSize, PebSize: NativeUInt;
begin
  OsMod := LoadLibraryW(PWideChar(Name));
  Assert.IsTrue(OsMod <> 0, 'LoadLibraryW failed');
  PebMod := GetModuleViaPeb(PWideChar(Name));
  Assert.IsTrue(PebMod = OsMod, 'PEB module address differs from Windows loader');
  OsSize := GetImageSize(PByte(OsMod));
  PebSize := GetModuleSizeViaPeb(PebMod);
  Assert.IsTrue(OsSize > 0, 'OS module image size is zero');
  Assert.IsTrue(PebSize = OsSize, 'PEB module size differs from PE header');
end;

procedure ConfigureSingleExport(var Data: TBytes; const ExportName, ForwarderTarget: AnsiString; TargetRva: DWORD);
var
  P: PByte;
  Nt: PImageNtHeaders64;
  Exp: PImageExportDirectory;
begin
  P := BytesPtr(Data);
  Assert.IsTrue(P <> nil);

  Nt := PImageNtHeaders64(P + TEST_NT_OFFSET);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress := $2100;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size := $200;

  Exp := PImageExportDirectory(P + $2100);
  Exp.Base := 1;
  Exp.NumberOfFunctions := 1;
  Exp.NumberOfNames := 1;
  Exp.AddressOfFunctions := $2200;
  Exp.AddressOfNames := $2220;
  Exp.AddressOfNameOrdinals := $2240;

  PDWORD(P + $2200)^ := 0;
  PDWORD(P + $2204)^ := 0;
  PDWORD(P + $2220)^ := $2260;
  PDWORD(P + $2224)^ := 0;
  PWord(P + $2240)^ := 0;
  PWord(P + $2242)^ := 0;

  PutAnsiZ(Data, $2260, ExportName);

  if ForwarderTarget <> '' then
  begin
    PutAnsiZ(Data, $2280, ForwarderTarget);
    PDWORD(P + $2200)^ := $2280;
  end
  else
    PDWORD(P + $2200)^ := TargetRva;
end;

function ExportSetHas(ExportSet: TExportedFuncSet; const LibName, FuncName: string): Boolean;
var
  Pair: TPair<string, TExportedFunc>;
begin
  Result := False;
  if ExportSet = nil then
    Exit;

  for Pair in ExportSet do
    if SameText(Pair.Value.LibName, LibName) and SameText(Pair.Value.FuncName, FuncName) then
    begin
      Result := True;
      Exit;
    end;
end;

procedure TLibPeConvLoadingTests.SelfRawVirtualRawMatchesOriginal;
var
  Path: string;
  VSize, RawSize, FileSize, CompareSize: NativeUInt;
  I, FirstDiff: NativeUInt;
  Loaded, Unmapped: TAlignedBuf;
  FileData: TUnalignedBuf;
  UnmappedByte, FileByte: Byte;
begin
  Path := CurrentExePath;
  VSize := 0;

  Loaded := LoadPeModule(Path, VSize, True, True);
  Assert.IsTrue(Loaded <> nil, 'LoadPeModule(self) failed');

  try
    RawSize := 0;

    Unmapped := PeVirtualToRaw(
      Loaded,
      VSize,
      UInt64(NativeUInt(Loaded)),
      RawSize,
      True
    );

    Assert.IsTrue(Unmapped <> nil, 'PeVirtualToRaw(self) failed');

    try
      FileSize := 0;
      FileData := LoadFile(Path, FileSize);
      Assert.IsTrue(FileData <> nil, 'LoadFile(self) failed');

      try
        Assert.IsTrue(
          (RawSize > 0) and (FileSize > 0),
          Format(
            'invalid sizes: RawSize=%d FileSize=%d',
            [RawSize, FileSize]
          )
        );

        if RawSize < FileSize then
          CompareSize := RawSize
        else
          CompareSize := FileSize;

        FirstDiff := High(NativeUInt);

        if CompareSize > 0 then
        begin
          for I := 0 to CompareSize - 1 do
          begin
            UnmappedByte := PByte(NativeUInt(Unmapped) + I)^;
            FileByte := PByte(NativeUInt(FileData) + I)^;

            if UnmappedByte <> FileByte then
            begin
              FirstDiff := I;
              Break;
            end;
          end;
        end;

        if FirstDiff <> High(NativeUInt) then
        begin
          UnmappedByte := PByte(NativeUInt(Unmapped) + FirstDiff)^;
          FileByte := PByte(NativeUInt(FileData) + FirstDiff)^;

          Assert.Fail(
            Format(
              'first difference at RAW offset $%s: unmapped=$%s original=$%s RawSize=%d FileSize=%d',
              [
                IntToHex(FirstDiff, 8),
                IntToHex(UnmappedByte, 2),
                IntToHex(FileByte, 2),
                RawSize,
                FileSize
              ]
            )
          );
        end;

        Assert.IsTrue(
          RawSize = FileSize,
          Format(
            'contents match up to compare size, but sizes differ: RawSize=%d FileSize=%d',
            [RawSize, FileSize]
          )
        );
      finally
        FreeFile(FileData);
      end;
    finally
      FreePeBuffer(Unmapped, RawSize);
    end;
  finally
    FreePeBuffer(Loaded, VSize);
  end;
end;
procedure TLibPeConvLoadingTests.SelfFormatChangesFromRawToVirtual;
var
  Path: string;
  RawSize, VSize: NativeUInt;
  Raw: TUnalignedBuf;
  VirtualPe: TAlignedBuf;
begin
  Path := CurrentExePath;
  RawSize := 0;
  Raw := LoadFile(Path, RawSize);
  Assert.IsTrue(Raw <> nil);
  try
    Assert.IsTrue(IsPeRaw(Raw, RawSize), 'file image must be RAW');
    VSize := 0;
    VirtualPe := LoadPeModule(Path, VSize, False, False);
    Assert.IsTrue(VirtualPe <> nil);
    try
      Assert.IsFalse(IsPeRaw(VirtualPe, VSize), 'mapped image must not be RAW');
    finally
      FreePeBuffer(VirtualPe, VSize);
    end;
  finally
    FreeFile(Raw);
  end;
end;

procedure TLibPeConvLoadingTests.SelfFoundBaseMatchesMappedAddress;
var
  Path: string;
  VSize: NativeUInt;
  Pe: TAlignedBuf;
  FoundBase: UInt64;
begin
  Path := CurrentExePath;
  VSize := 0;
  Pe := LoadPeModule(Path, VSize, False, True);
  Assert.IsTrue(Pe <> nil);
  try
    FoundBase := FindBaseCandidate(Pe, VSize);
    Assert.IsTrue(FoundBase = UInt64(NativeUInt(Pe)), 'FindBaseCandidate returned a different base');
  finally
    FreePeBuffer(Pe, VSize);
  end;
end;

procedure TLibPeConvLoadingTests.InvalidBufferCannotBeLoaded;
var
  Data: array [0 .. 127] of Byte;
  VSize: NativeUInt;
  Pe: TAlignedBuf;
begin
  FillChar(Data, SizeOf(Data), 0);
  VSize := 123;
  Pe := LoadPeModule(@Data[0], SizeOf(Data), VSize, False, False);
  Assert.IsTrue(Pe = nil);
  Assert.IsTrue(VSize = 0);
end;

procedure TLibPeConvLoadingTests.ZeroSectionImageLoadsWithoutSectionMapping;
var
  Data: TBytes;
  VSize: NativeUInt;
  Pe: TAlignedBuf;
begin
  Data := BuildMinimalPe64;
  VSize := 0;
  Pe := LoadPeModule(@Data[0], Length(Data), VSize, False, False);
  Assert.IsTrue(Pe <> nil);
  try
    Assert.IsTrue(VSize >= PE_PAGE_SIZE);
    Assert.IsTrue(GetNtHdrs(Pe, VSize) <> nil);
    Assert.IsTrue(GetSectionsCount(Pe, VSize) = 0);
  finally
    FreePeBuffer(Pe, VSize);
  end;
end;

procedure TLibPeConvLoadingTests.LoadPeExecutableResolvesSyntheticImports;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Raw: TBytes;
  VSize: NativeUInt;
  Loaded: TAlignedBuf;
  Resolver: TMockResolver;
begin
  Raw := BuildRichRawPe64;
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    VSize := 0;
    Loaded := LoadPeExecutable(@Raw[0], Length(Raw), VSize, Resolver, 0, False);
    Assert.IsTrue(Loaded <> nil);
    try
      Assert.IsTrue(PUInt64(Loaded + $26A0)^ = NamedValue);
      Assert.IsTrue(PUInt64(Loaded + $26A8)^ = OrdinalValue);
      Assert.IsTrue(Resolver.HasCall('fixturedep.dll!NamedFunc'));
      Assert.IsTrue(Resolver.HasCall('fixturedep.dll!#7'));
    finally
      FreePeBuffer(Loaded, VSize);
    end;
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvLoadingTests.NtdllMappedExportRvaMatchesLoadedModule;
var
  OsMod: HMODULE;
  Path: string;
  VSize: NativeUInt;
  Pe: TAlignedBuf;
  MappedProc, OsProc: FARPROC;
  MappedRva, OsRva: NativeUInt;
  ProcName: AnsiString;
begin
  OsMod := GetModuleHandleW('ntdll.dll');
  Assert.IsTrue(OsMod <> 0);
  Path := ModulePath(OsMod);
  VSize := 0;
  Pe := LoadPeModule(Path, VSize, False, False);
  Assert.IsTrue(Pe <> nil);
  try
    ProcName := 'NtClose';
    MappedProc := GetExportedFunc(Pe, PAnsiChar(ProcName));
    OsProc := GetProcAddress(OsMod, PAnsiChar(ProcName));
    Assert.IsTrue(Assigned(MappedProc));
    Assert.IsTrue(Assigned(OsProc));
    MappedRva := NativeUInt(MappedProc) - NativeUInt(Pe);
    OsRva := NativeUInt(OsProc) - NativeUInt(OsMod);
    Assert.IsTrue(MappedRva = OsRva, 'NtClose RVA differs after manual mapping');
  finally
    FreePeBuffer(Pe, VSize);
  end;
end;

procedure TLibPeConvLoadingTests.NtdllMappedDllNameMatches;
var
  OsMod: HMODULE;
  Path: string;
  VSize: NativeUInt;
  Pe: TAlignedBuf;
  Name: PAnsiChar;
begin
  OsMod := GetModuleHandleW('ntdll.dll');
  Assert.IsTrue(OsMod <> 0);
  Path := ModulePath(OsMod);
  VSize := 0;
  Pe := LoadPeModule(Path, VSize, False, False);
  Assert.IsTrue(Pe <> nil);
  try
    Name := ReadDllName(Pe);
    Assert.IsTrue(Name <> nil);
    Assert.IsTrue(SameText(string(AnsiString(Name)), 'ntdll.dll'));
  finally
    FreePeBuffer(Pe, VSize);
  end;
end;

procedure TLibPeConvImportTests.NormalImportsResolveNameAndOrdinal;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Data: TBytes;
  Resolver: TMockResolver;
begin
  Data := BuildRichVirtualPe64;
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    Assert.IsTrue(LoadImports(@Data[0], Resolver));
    Assert.IsTrue(Resolver.HasCall('fixturedep.dll!NamedFunc'));
    Assert.IsTrue(Resolver.HasCall('fixturedep.dll!#7'));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.NormalImportsWriteExpectedAddresses;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Data: TBytes;
  Resolver: TMockResolver;
begin
  Data := BuildRichVirtualPe64;
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    Assert.IsTrue(LoadImports(@Data[0], Resolver));
    Assert.IsTrue(PUInt64(@Data[$26A0])^ = UInt64(NamedValue));
    Assert.IsTrue(PUInt64(@Data[$26A8])^ = UInt64(OrdinalValue));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.NormalImportsKeepOriginalLookupTable;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Data: TBytes;
  BeforeName, BeforeOrdinal: UInt64;
  Resolver: TMockResolver;
begin
  Data := BuildRichVirtualPe64;
  BeforeName := PUInt64(@Data[$2680])^;
  BeforeOrdinal := PUInt64(@Data[$2688])^;
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    Assert.IsTrue(LoadImports(@Data[0], Resolver));
    Assert.IsTrue(PUInt64(@Data[$2680])^ = BeforeName);
    Assert.IsTrue(PUInt64(@Data[$2688])^ = BeforeOrdinal);
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.DelayImportDirectoryIsLocated;
var
  Data: TBytes;
  Size: NativeUInt;
  Desc: PImageDelayloadDescriptor;
begin
  BuildDelayImportFixture64(Data);
  Size := 0;
  Desc := GetDelayedImps(@Data[0], Length(Data), Size);
  Assert.IsTrue(Desc <> nil);
  Assert.IsTrue(Size = 2 * SizeOf(TImageDelayloadDescriptor));
  Assert.IsTrue(Desc.DllNameRVA = $2780);
  Assert.IsTrue(Desc.ImportAddressTableRVA = $27A0);
  Assert.IsTrue(Desc.ImportNameTableRVA = $27C0);
end;

procedure TLibPeConvImportTests.DelayImportsResolveNameAndOrdinal;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Data: TBytes;
  Resolver: TMockResolver;
begin
  BuildDelayImportFixture64(Data);
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    Assert.IsTrue(LoadDelayedImports(@Data[0], TEST_IMAGE_BASE64, Resolver));
    Assert.IsTrue(Resolver.HasCall('delayfixture.dll!DelayedNamed'));
    Assert.IsTrue(Resolver.HasCall('delayfixture.dll!#7'));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.DelayImportsWriteResolvedAddresses;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Data: TBytes;
  Resolver: TMockResolver;
begin
  BuildDelayImportFixture64(Data);
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    Assert.IsTrue(LoadDelayedImports(@Data[0], TEST_IMAGE_BASE64, Resolver));
    Assert.IsTrue(PUInt64(@Data[$27A0])^ = UInt64(NamedValue));
    Assert.IsTrue(PUInt64(@Data[$27A8])^ = UInt64(OrdinalValue));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.MissingDelayImportDirectoryIsNoOp;
var
  Data: TBytes;
begin
  Data := BuildRichVirtualPe64;
  Assert.IsTrue(GetDirectoryEntry(@Data[0], IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) = nil);
  Assert.IsTrue(LoadDelayedImports(@Data[0], TEST_IMAGE_BASE64, nil));
end;

procedure TLibPeConvImportTests.TooSmallDelayImportDirectoryIsRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders64;
  Size: NativeUInt;
begin
  Data := BuildRichVirtualPe64;
  Nt := GetNtHdrs64(@Data[0]);
  Assert.IsTrue(Nt <> nil);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress := $2700;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size := SizeOf(TImageDelayloadDescriptor) - 1;
  Size := 123;
  Assert.IsTrue(GetDelayedImps(@Data[0], Length(Data), Size) = nil);
  Assert.IsTrue(Size = 0);
end;

procedure TLibPeConvImportTests.SelfImportCollectionIsNonEmptyAndInBounds;
var
  Path: string;
  VSize: NativeUInt;
  Pe: TAlignedBuf;
  Imports: TImportsCollection;
  Pair: TPair<DWORD, TExportedFunc>;
begin
  Path := CurrentExePath;
  VSize := 0;
  Pe := LoadPeModule(Path, VSize, False, False);
  Assert.IsTrue(Pe <> nil);
  try
    Imports := TImportsCollection.Create;
    try
      Assert.IsTrue(CollectImports(Pe, VSize, Imports));
      Assert.IsTrue(Imports.ThunkToFunc.Count > 0, 'self import list unexpectedly empty');
      for Pair in Imports.ThunkToFunc do
      begin
        Assert.IsTrue(Pair.Key < VSize, 'IAT RVA outside image');
        Assert.IsTrue(Pair.Value <> nil);
        Assert.IsTrue(Pair.Value.LibName <> '');
      end;
    finally
      Imports.Free;
    end;
  finally
    FreePeBuffer(Pe, VSize);
  end;
end;

procedure TLibPeConvImportTests.SyntheticImportCollectionHasExpectedEntries;
var
  Data: TBytes;
  Imports: TImportsCollection;
  F: TExportedFunc;
begin
  Data := BuildRichVirtualPe64;
  Imports := TImportsCollection.Create;
  try
    Assert.IsTrue(
      CollectImports(@Data[0], Length(Data), Imports),
      'CollectImports returned False'
    );

    Assert.IsTrue(
      Imports.ThunkToFunc.Count = 2,
      Format('expected 2 imports, got %d', [Imports.ThunkToFunc.Count])
    );

    F := nil;
    Assert.IsTrue(
      Imports.ThunkToFunc.TryGetValue($26A0, F),
      'named import thunk $26A0 missing'
    );

    Assert.IsTrue(F <> nil, 'named import object is nil');

    Assert.IsTrue(
      SameText(F.LibName, 'fixturedep'),
      'named import DLL mismatch: ' + F.LibName
    );

    Assert.IsFalse(
      F.IsByOrdinal,
      'NamedFunc unexpectedly marked as ordinal import'
    );

    Assert.IsTrue(
      F.FuncName = 'NamedFunc',
      'named import function mismatch: ' + F.FuncName
    );

    Assert.IsTrue(
      F.FuncOrdinal = 42,
      Format('named import FuncOrdinal expected 42, got %d', [F.FuncOrdinal])
    );

    F := nil;
    Assert.IsTrue(
      Imports.ThunkToFunc.TryGetValue($26A8, F),
      'ordinal import thunk $26A8 missing'
    );

    Assert.IsTrue(F <> nil, 'ordinal import object is nil');

    Assert.IsTrue(
      SameText(F.LibName, 'fixturedep'),
      'ordinal import DLL mismatch: ' + F.LibName
    );

    Assert.IsTrue(
      F.IsByOrdinal,
      'ordinal 7 unexpectedly marked as named import'
    );

    Assert.IsTrue(
      F.FuncOrdinal = 7,
      Format('ordinal import expected 7, got %d', [F.FuncOrdinal])
    );
  finally
    Imports.Free;
  end;
end;
procedure TLibPeConvImportTests.HookResolverCanPatchSyntheticImport;
var
  Data: TBytes;
  Resolver: THookingFuncResolver;
  Hook: FARPROC;
begin
  Data := BuildRichVirtualPe64;
  PUInt64(@Data[$2688])^ := 0;
  PUInt64(@Data[$26A8])^ := 0;
  Hook := FARPROC(NativeUInt($12345678));
  Resolver := THookingFuncResolver.Create;
  try
    Resolver.AddHook('NamedFunc', Hook);
    Assert.IsTrue(LoadImports(@Data[0], Resolver));
    Assert.IsTrue(PUInt64(@Data[$26A0])^ = UInt64(NativeUInt(Hook)));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.NormalAndDelayedImportsResolveTogether;
const
  NamedValue: UInt64 = $1111222233334444;
  OrdinalValue: UInt64 = $5555666677778888;
var
  Data: TBytes;
  Resolver: TMockResolver;
begin
  BuildDelayImportFixture64(Data);
  Resolver := TMockResolver.Create(NativeUInt(NamedValue), NativeUInt(OrdinalValue));
  try
    Assert.IsTrue(LoadImports(@Data[0], Resolver));
    Assert.IsTrue(LoadDelayedImports(@Data[0], TEST_IMAGE_BASE64, Resolver));
    Assert.IsTrue(PUInt64(@Data[$26A0])^ = NamedValue);
    Assert.IsTrue(PUInt64(@Data[$26A8])^ = OrdinalValue);
    Assert.IsTrue(PUInt64(@Data[$27A0])^ = NamedValue);
    Assert.IsTrue(PUInt64(@Data[$27A8])^ = OrdinalValue);
    Assert.IsTrue(Resolver.HasCall('fixturedep.dll!NamedFunc'));
    Assert.IsTrue(Resolver.HasCall('fixturedep.dll!#7'));
    Assert.IsTrue(Resolver.HasCall('delayfixture.dll!DelayedNamed'));
    Assert.IsTrue(Resolver.HasCall('delayfixture.dll!#7'));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvImportTests.ZeroedIatDoesNotTerminateLookupTable;
var
  Data: TBytes;
  Imports: TImportsCollection;
  Resolver: TMockResolver;
begin
  Data := BuildRichVirtualPe64;
  PUInt64(@Data[$26A0])^ := 0;
  PUInt64(@Data[$26A8])^ := 0;
  Imports := TImportsCollection.Create;
  try
    Assert.IsTrue(CollectImports(@Data[0], Length(Data), Imports));
    Assert.IsTrue(Imports.ThunkToFunc.Count = 2);
  finally
    Imports.Free;
  end;
  Resolver := TMockResolver.Create($11111111, $22222222);
  try
    Assert.IsTrue(LoadImports(@Data[0], Resolver));
    Assert.IsTrue(PUInt64(@Data[$26A0])^ = $11111111);
    Assert.IsTrue(PUInt64(@Data[$26A8])^ = $22222222);
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvDotNetTests.JumpAtBufferStartFound;
begin
  Assert.IsTrue(SearchJumpOffset(0, True, $2000) = 0);
end;

procedure TLibPeConvDotNetTests.JumpAtBufferEndFound;
const
  Expected = $100 - 6;
begin
  Assert.IsTrue(SearchJumpOffset(0, False, $2000) = Expected);
end;

procedure TLibPeConvDotNetTests.JumpThirtyBytesBeforeEndFound;
const
  Expected = ($100 - 6) - 30;
begin
  Assert.IsTrue(SearchJumpOffset(30, False, $2000) = Expected);
end;

procedure TLibPeConvDotNetTests.WrongThunkIsNotFound;
begin
  Assert.IsTrue(SearchJumpOffset(0, True, $2001) = -1);
end;

procedure TLibPeConvDotNetTests.TruncatedJumpIsNotFound;
const
  ImgBase: UInt64 = $400000;
  CorExeMainThunk: DWORD = $2000;
var
  Buf: array [0 .. 4] of Byte;
begin
  Buf[0] := $FF;
  Buf[1] := $25;
  Buf[2] := 0;
  Buf[3] := $20;
  Buf[4] := $40;
  Assert.IsTrue(SearchJump(@Buf[0], SizeOf(Buf), CorExeMainThunk, ImgBase) = nil);
end;

procedure TLibPeConvTlsTests.ExecutableTlsCallbackRunsOnce;
var
  Data: TBytes;
  Mem: PByte;
  Tls: PImageTlsDirectory64;
  List: TList<UInt64>;
  CallbackCount: Integer;
  CounterPtr: UInt64;
begin
  Data := BuildRichVirtualPe64;
  Mem := VirtualAlloc(nil, TEST_IMAGE_SIZE, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  Assert.IsTrue(Mem <> nil);
  try
    Move(Data[0], Mem^, Length(Data));
    CallbackCount := 0;
    CounterPtr := UInt64(NativeUInt(@CallbackCount));
    Mem[$1800] := $48;
    Mem[$1801] := $B8;
    Move(CounterPtr, Mem[$1802], SizeOf(CounterPtr));
    Mem[$180A] := $FF;
    Mem[$180B] := $00;
    Mem[$180C] := $C3;
    Tls := PImageTlsDirectory64(Mem + $2400);
    Tls.AddressOfCallBacks := UInt64(NativeUInt(Mem) + $2450);
    PUInt64(Mem + $2450)^ := UInt64(NativeUInt(Mem) + $1800);
    PUInt64(Mem + $2458)^ := 0;
    PImageBaseRelocation(Mem + $3000).VirtualAddress := $2000;
    PImageBaseRelocation(Mem + $3000).SizeOfBlock := 16;
    PWord(Mem + $3008)^ := Word(($A shl 12) or $418);
    PWord(Mem + $300A)^ := Word(($A shl 12) or $450);
    PWord(Mem + $300C)^ := 0;
    PWord(Mem + $300E)^ := 0;
    PImageNtHeaders64(Mem + TEST_NT_OFFSET).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 16;
    List := TList<UInt64>.Create;
    try
      Assert.IsTrue(ListTlsCallbacks(Mem, TEST_IMAGE_SIZE, List) = 1);
      Assert.IsTrue(List.Count = 1);
      Assert.IsTrue(List[0] = UInt64(NativeUInt(Mem) + $1800));
    finally
      List.Free;
    end;
    Assert.IsTrue(CallbackCount = 0);
    Assert.IsTrue(RunTlsCallbacks(Mem, TEST_IMAGE_SIZE, DLL_PROCESS_ATTACH) = 1);
    Assert.IsTrue(CallbackCount = 1, 'TLS callback body was not executed exactly once');
  finally
    VirtualFree(Mem, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvTlsTests.TwoExecutableTlsCallbacksRunInOrder;
var
  Data: TBytes;
  Mem: PByte;
  Tls: PImageTlsDirectory64;
  List: TList<UInt64>;
  ExecutionState: Integer;
  StatePtr: UInt64;
begin
  Data := BuildRichVirtualPe64;
  Mem := VirtualAlloc(nil, TEST_IMAGE_SIZE, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  Assert.IsTrue(Mem <> nil);
  try
    Move(Data[0], Mem^, Length(Data));
    ExecutionState := 0;
    StatePtr := UInt64(NativeUInt(@ExecutionState));
    Mem[$1800] := $48;
    Mem[$1801] := $B8;
    Move(StatePtr, Mem[$1802], SizeOf(StatePtr));
    Mem[$180A] := $C7;
    Mem[$180B] := $00;
    Mem[$180C] := $01;
    Mem[$180D] := $00;
    Mem[$180E] := $00;
    Mem[$180F] := $00;
    Mem[$1810] := $C3;
    Mem[$1820] := $48;
    Mem[$1821] := $B8;
    Move(StatePtr, Mem[$1822], SizeOf(StatePtr));
    Mem[$182A] := $83;
    Mem[$182B] := $00;
    Mem[$182C] := $02;
    Mem[$182D] := $C3;
    Tls := PImageTlsDirectory64(Mem + $2400);
    Tls.AddressOfCallBacks := UInt64(NativeUInt(Mem) + $2450);
    PUInt64(Mem + $2450)^ := UInt64(NativeUInt(Mem) + $1800);
    PUInt64(Mem + $2458)^ := UInt64(NativeUInt(Mem) + $1820);
    PUInt64(Mem + $2460)^ := 0;
    PImageBaseRelocation(Mem + $3000).VirtualAddress := $2000;
    PImageBaseRelocation(Mem + $3000).SizeOfBlock := 16;
    PWord(Mem + $3008)^ := Word(($A shl 12) or $418);
    PWord(Mem + $300A)^ := Word(($A shl 12) or $450);
    PWord(Mem + $300C)^ := Word(($A shl 12) or $458);
    PWord(Mem + $300E)^ := 0;
    PImageNtHeaders64(Mem + TEST_NT_OFFSET).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 16;
    List := TList<UInt64>.Create;
    try
      Assert.IsTrue(ListTlsCallbacks(Mem, TEST_IMAGE_SIZE, List) = 2);
      Assert.IsTrue(List.Count = 2);
      Assert.IsTrue(List[0] = UInt64(NativeUInt(Mem) + $1800));
      Assert.IsTrue(List[1] = UInt64(NativeUInt(Mem) + $1820));
    finally
      List.Free;
    end;
    Assert.IsTrue(RunTlsCallbacks(Mem, TEST_IMAGE_SIZE, DLL_PROCESS_ATTACH) = 2);
    Assert.IsTrue(ExecutionState = 3);
  finally
    VirtualFree(Mem, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvTlsTests.ZeroTlsCallbackTableRunsNone;
var
  Data: TBytes;
  Tls: PImageTlsDirectory64;
begin
  Data := BuildRichVirtualPe64;
  Tls := PImageTlsDirectory64(@Data[$2400]);
  Tls.AddressOfCallBacks := 0;
  Assert.IsTrue(RunTlsCallbacks(@Data[0], Length(Data), DLL_PROCESS_ATTACH) = 0);
end;

procedure TLibPeConvTlsTests.RelocatedSmallTlsCallbackTableAddress32IsRejected;
var
  Data: TBytes;
  Nt: PImageNtHeaders32;
  Tls: PImageTlsDirectory32;
  Reloc: PImageBaseRelocation;
  List: TList<UInt64>;
begin
  Data := BuildMinimalPe32;
  Nt := PImageNtHeaders32(@Data[TEST_NT_OFFSET]);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress := $300;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size := SizeOf(TImageTlsDirectory32);
  Tls := PImageTlsDirectory32(@Data[$300]);
  Tls.AddressOfCallBacks := $380;
  PDWORD(@Data[$380])^ := $11111111;
  PDWORD(@Data[$384])^ := 0;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress := $500;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 12;
  Reloc := PImageBaseRelocation(@Data[$500]);
  Reloc.VirtualAddress := 0;
  Reloc.SizeOfBlock := 12;
  PWord(@Data[$508])^ := Word((3 shl 12) or $30C);
  PWord(@Data[$50A])^ := 0;
  List := TList<UInt64>.Create;
  try
    Assert.IsTrue(ListTlsCallbacks(@Data[0], Length(Data), List) = 0);
    Assert.IsTrue(List.Count = 0);
  finally
    List.Free;
  end;
end;

procedure TLibPeConvPebTests.User32MatchesWindowsLoader;
begin
  AssertModuleParity('user32.dll');
end;

procedure TLibPeConvPebTests.Advapi32MatchesWindowsLoader;
begin
  AssertModuleParity('advapi32.dll');
end;

procedure TLibPeConvPebTests.Ws2_32MatchesWindowsLoader;
begin
  AssertModuleParity('ws2_32.dll');
end;

procedure TLibPeConvPebTests.ModuleLookupIsCaseInsensitive;
var
  A, B: HMODULE;
  LowerName, MixedName: string;
begin
  LowerName := 'kernel32.dll';
  MixedName := 'KeRnEl32.DlL';
  B := LoadLibraryW(PWideChar(LowerName));
  Assert.IsTrue(B <> 0);
  A := GetModuleViaPeb(PWideChar(MixedName));
  Assert.IsTrue(A = B);
end;

procedure TLibPeConvHookTests.HookResolverReturnsRegisteredReplacement;
var
  Resolver: THookingFuncResolver;
  Hook, Resolved: FARPROC;
  Lib, Name: AnsiString;
begin
  Hook := FARPROC(NativeUInt($11223344));
  Resolver := THookingFuncResolver.Create;
  try
    Resolver.AddHook('TargetFunction', Hook);
    Lib := 'does-not-need-to-exist.dll';
    Name := 'TargetFunction';
    Resolved := Resolver.ResolveFunc(PAnsiChar(Lib), PAnsiChar(Name));
    Assert.IsTrue(NativeUInt(Resolved) = NativeUInt(Hook));
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvHookTests.DllReplacementIsCaseInsensitive;
var
  Resolver: THookingFuncResolver;
  Kernel: HMODULE;
  Expected, Resolved: FARPROC;
  Lib, Name: AnsiString;
begin
  Kernel := GetModuleHandleW('kernel32.dll');
  Assert.IsTrue(Kernel <> 0);
  Name := 'GetCurrentProcessId';
  Expected := GetProcAddress(Kernel, PAnsiChar(Name));
  Assert.IsTrue(Expected <> nil);
  Resolver := THookingFuncResolver.Create;
  try
    Resolver.ReplaceDll('NaTiVePe-OrIgInAl.DlL', 'KERNEL32.DLL');
    Lib := 'nativepe-original.dll';
    Resolved := Resolver.ResolveFunc(PAnsiChar(Lib), PAnsiChar(Name));
    Assert.IsTrue(Resolved = Expected);
  finally
    Resolver.Free;
  end;
end;

procedure TLibPeConvHookTests.Redirect64WritesExactStub;
const
  Target: UInt64 = $1122334455667788;
var
  Mem: PByte;
  Expected: array [0 .. 11] of Byte;
  Patched: NativeUInt;
begin
  Mem := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  Assert.IsTrue(Mem <> nil);
  try
    FillChar(Mem^, $1000, $90);
    Expected[0] := $48;
    Expected[1] := $B8;
    Move(Target, Expected[2], SizeOf(Target));
    Expected[10] := $FF;
    Expected[11] := $E0;
    Patched := RedirectToLocal64(Mem, Target, nil, False);
    Assert.IsTrue(Patched = 12);
    Assert.IsTrue(CompareMem(Mem, @Expected[0], SizeOf(Expected)));
  finally
    VirtualFree(Mem, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvHookTests.Redirect64BackupRestoresOriginalBytes;
const
  Target: UInt64 = $1122334455667788;
var
  Mem: PByte;
  Backup: TPatchBackup;
  I: Integer;
begin
  Mem := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  Assert.IsTrue(Mem <> nil);
  Backup := TPatchBackup.Create;
  try
    FillChar(Mem^, $1000, $90);
    Assert.IsTrue(RedirectToLocal64(Mem, Target, Backup, False) = 12);
    Assert.IsTrue(Backup.IsBackup);
    Assert.IsTrue(Backup.ApplyBackup(False));
    for I := 0 to 11 do
      Assert.IsTrue(Mem[I] = $90, 'backup did not restore original byte');
  finally
    Backup.Free;
    VirtualFree(Mem, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvHookTests.Redirect64ChangesExecutableTarget;
type
  TNoArgIntFunc = function: Integer;
var
  Mem: PByte;
  SourceFunc, TargetFunc: TNoArgIntFunc;
begin
  Mem := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  Assert.IsTrue(Mem <> nil);
  try
    FillChar(Mem^, $1000, $90);
    Mem[$000] := $B8;
    PDWORD(Mem + $001)^ := 1;
    Mem[$005] := $C3;
    Mem[$100] := $B8;
    PDWORD(Mem + $101)^ := 2;
    Mem[$105] := $C3;
    SourceFunc := TNoArgIntFunc(Mem);
    TargetFunc := TNoArgIntFunc(Mem + $100);
    Assert.IsTrue(SourceFunc() = 1);
    Assert.IsTrue(TargetFunc() = 2);
    Assert.IsTrue(RedirectToLocal64(Mem, UInt64(NativeUInt(Mem + $100)), nil, False) = 12);
    Assert.IsTrue(SourceFunc() = 2, 'redirected executable code did not reach target');
  finally
    VirtualFree(Mem, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvHookTests.Redirect64BackupRestoresExecutableTarget;
type
  TNoArgIntFunc = function: Integer;
var
  Mem: PByte;
  SourceFunc: TNoArgIntFunc;
  Backup: TPatchBackup;
begin
  Mem := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  Assert.IsTrue(Mem <> nil);
  Backup := TPatchBackup.Create;
  try
    FillChar(Mem^, $1000, $90);
    Mem[$000] := $B8;
    PDWORD(Mem + $001)^ := 1;
    Mem[$005] := $C3;
    Mem[$100] := $B8;
    PDWORD(Mem + $101)^ := 2;
    Mem[$105] := $C3;
    SourceFunc := TNoArgIntFunc(Mem);
    Assert.IsTrue(SourceFunc() = 1);
    Assert.IsTrue(RedirectToLocal64(Mem, UInt64(NativeUInt(Mem + $100)), Backup, False) = 12);
    Assert.IsTrue(SourceFunc() = 2);
    Assert.IsTrue(Backup.ApplyBackup(False));
    Assert.IsTrue(SourceFunc() = 1, 'restored executable code did not return original value');
  finally
    Backup.Free;
    VirtualFree(Mem, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvHookTests.RedirectNilReturnsZero;
begin
  Assert.IsTrue(RedirectToLocal64(nil, $1234, nil, False) = 0);
end;

procedure TLibPeConvHookTests.ReplaceJmpTargetWritesExpectedDelta;
var
  Buf: array [0 .. 15] of Byte;
  Dest: UInt64;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Buf[0] := $E9;
  Dest := UInt64(NativeUInt(@Buf[0])) + 5 + 16;
  Assert.IsTrue(ReplaceTarget(@Buf[0], Dest));
  Assert.IsTrue(PInteger(@Buf[1])^ = 16);
end;

procedure TLibPeConvHookTests.ReplaceCallTargetWritesExpectedDelta;
var
  Buf: array [0 .. 15] of Byte;
  Dest: UInt64;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Buf[0] := $E8;
  Dest := UInt64(NativeUInt(@Buf[0])) + 5 - 16;
  Assert.IsTrue(ReplaceTarget(@Buf[0], Dest));
  Assert.IsTrue(PInteger(@Buf[1])^ = -16);
end;

procedure TLibPeConvHookTests.ReplaceTargetRejectsUnsupportedOpcode;
var
  Buf: array [0 .. 15] of Byte;
begin
  FillChar(Buf, SizeOf(Buf), $90);
  Assert.IsFalse(ReplaceTarget(@Buf[0], UInt64(NativeUInt(@Buf[0])) + 20));
end;

procedure TLibPeConvHookTests.ReplaceTargetRejectsOutOfRangeDelta;
var
  Buf: array [0 .. 15] of Byte;
  Dest: UInt64;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Buf[0] := $E9;
  Dest := UInt64(NativeUInt(@Buf[0])) + UInt64($100000000) + 5;
  Assert.IsFalse(ReplaceTarget(@Buf[0], Dest));
end;

procedure TLibPeConvMemoryTests.StackMemoryIsReadable;
var
  V: Integer;
begin
  V := 42;
  Assert.IsFalse(IsBadReadPointer(@V, SizeOf(V)));
end;

procedure TLibPeConvMemoryTests.NilAndLowAddressAreUnreadable;
begin
  Assert.IsTrue(IsBadReadPointer(nil, 1));
  Assert.IsTrue(IsBadReadPointer(Pointer(NativeUInt(1)), 1));
end;

procedure TLibPeConvMemoryTests.NoAccessPageIsUnreadable;
var
  Page: Pointer;
begin
  Page := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_NOACCESS);
  Assert.IsTrue(Page <> nil);
  try
    Assert.IsTrue(IsBadReadPointer(Page, $1000));
  finally
    VirtualFree(Page, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvMemoryTests.ReadOnlyPageIsReadable;
var
  Page: Pointer;
  OldProtect: DWORD;
begin
  Page := VirtualAlloc(nil, $1000, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
  Assert.IsTrue(Page <> nil);
  try
    PByte(Page)^ := $5A;
    OldProtect := 0;
    Assert.IsTrue(VirtualProtect(Page, $1000, PAGE_READONLY, OldProtect));
    Assert.IsFalse(IsBadReadPointer(Page, $1000));
  finally
    VirtualFree(Page, 0, MEM_RELEASE);
  end;
end;

procedure TLibPeConvForwarderTests.ForwarderThenTargetMergesAlias;
var
  SourceData, TargetData: TBytes;
  SourcePtr, TargetPtr: PByte;
  Mapper: TExportsMapper;
  ExportSet: TExportedFuncSet;
  TargetVa: UInt64;
begin
  SourceData := BuildRichVirtualPe64;
  TargetData := BuildRichVirtualPe64;
  ConfigureSingleExport(SourceData, 'Alias', 'target.Real', 0);
  ConfigureSingleExport(TargetData, 'Real', '', $1050);

  SourcePtr := BytesPtr(SourceData);
  TargetPtr := BytesPtr(TargetData);
  Assert.IsTrue(SourcePtr <> nil);
  Assert.IsTrue(TargetPtr <> nil);

  Mapper := TExportsMapper.Create;
  try
    Mapper.AddToLookup('source.dll', HMODULE(NativeUInt(SourcePtr)), Length(SourceData), UInt64(NativeUInt(SourcePtr)));
    Mapper.AddToLookup('target.dll', HMODULE(NativeUInt(TargetPtr)), Length(TargetData), UInt64(NativeUInt(TargetPtr)));

    TargetVa := UInt64(NativeUInt(TargetPtr)) + $1050;
    ExportSet := Mapper.FindExportsByVa(TargetVa);
    Assert.IsTrue(ExportSet <> nil, 'target RVA is not mapped');
    Assert.IsTrue(ExportSetHas(ExportSet, 'target', 'Real'), 'target.Real missing');
    Assert.IsTrue(ExportSetHas(ExportSet, 'source', 'Alias'), 'source.Alias forwarder was not merged');
  finally
    Mapper.Free;
  end;
end;

procedure TLibPeConvForwarderTests.TargetThenForwarderMergesAlias;
var
  SourceData, TargetData: TBytes;
  SourcePtr, TargetPtr: PByte;
  Mapper: TExportsMapper;
  ExportSet: TExportedFuncSet;
  TargetVa: UInt64;
begin
  SourceData := BuildRichVirtualPe64;
  TargetData := BuildRichVirtualPe64;
  ConfigureSingleExport(SourceData, 'Alias', 'target.Real', 0);
  ConfigureSingleExport(TargetData, 'Real', '', $1050);

  SourcePtr := BytesPtr(SourceData);
  TargetPtr := BytesPtr(TargetData);
  Assert.IsTrue(SourcePtr <> nil);
  Assert.IsTrue(TargetPtr <> nil);

  Mapper := TExportsMapper.Create;
  try
    Mapper.AddToLookup('target.dll', HMODULE(NativeUInt(TargetPtr)), Length(TargetData), UInt64(NativeUInt(TargetPtr)));
    Mapper.AddToLookup('source.dll', HMODULE(NativeUInt(SourcePtr)), Length(SourceData), UInt64(NativeUInt(SourcePtr)));

    TargetVa := UInt64(NativeUInt(TargetPtr)) + $1050;
    ExportSet := Mapper.FindExportsByVa(TargetVa);
    Assert.IsTrue(ExportSet <> nil, 'target RVA is not mapped');
    Assert.IsTrue(ExportSetHas(ExportSet, 'target', 'Real'), 'target.Real missing');
    Assert.IsTrue(ExportSetHas(ExportSet, 'source', 'Alias'), 'source.Alias forwarder was not merged');
  finally
    Mapper.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TLibPeConvLoadingTests);
  TDUnitX.RegisterTestFixture(TLibPeConvImportTests);
  TDUnitX.RegisterTestFixture(TLibPeConvDotNetTests);
  TDUnitX.RegisterTestFixture(TLibPeConvTlsTests);
  TDUnitX.RegisterTestFixture(TLibPeConvPebTests);
  TDUnitX.RegisterTestFixture(TLibPeConvHookTests);
  TDUnitX.RegisterTestFixture(TLibPeConvMemoryTests);
  TDUnitX.RegisterTestFixture(TLibPeConvForwarderTests);

end.
