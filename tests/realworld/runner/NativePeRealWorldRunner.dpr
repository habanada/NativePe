program NativePeRealWorldRunner;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Winapi.Windows,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.FileUtil,
  NativePe.PeHdrsHelper,
  NativePe.PeLoader,
  NativePe.PeVirtualToRaw,
  NativePe.ExportsLookup,
  NativePe.FunctionResolver,
  NativePe.ImportsLoader,
  NativePe.Relocate,
  NativePe.Caves,
  NativePe.PeRecycler,
  NativePe.ApiSet,
  NativePe.ExceptionsParser,
  NativePe.SecurityCookie,
  NativePe.LoadConfig;

const
  EXCEPTION_MAGIC = $4E504558;

type
  TFixtureAdd = function(A, B: Integer): Integer; stdcall;
  TFixtureImportedPid = function: DWORD; stdcall;
  TFixtureOle32Alloc = function(Size: NativeUInt): Integer; stdcall;
  TFixtureRaiseAndCatch = function(Divisor: Integer): Integer; stdcall;

procedure Fail(const Msg: string);
begin
  Writeln('RESULT: FAIL - ' + Msg);
  Halt(1);
end;

procedure Check(Value: Boolean; const Msg: string);
begin
  if not Value then
    Fail(Msg);
end;

function ProcAddressByName(ModuleHandle: HMODULE; const Name: AnsiString): FARPROC;
begin
  Result := GetProcAddress(ModuleHandle, PAnsiChar(Name));
end;

function ExportAddressByName(ModulePtr: PByte; const Name: AnsiString): FARPROC;
begin
  Result := GetExportedFunc(ModulePtr, PAnsiChar(Name));
end;

procedure CallFixtureWindows(const Path: string; out AddValue: Integer; out PidValue: DWORD; out OleValue: Integer);
var
  H: HMODULE;
  AddFn: TFixtureAdd;
  PidFn: TFixtureImportedPid;
  OleFn: TFixtureOle32Alloc;
begin
  H := LoadLibrary(PChar(Path));
  Check(H <> 0, 'LoadLibrary failed: ' + SysErrorMessage(GetLastError));
  try
    AddFn := TFixtureAdd(ProcAddressByName(H, 'FixtureAdd'));
    PidFn := TFixtureImportedPid(ProcAddressByName(H, 'FixtureImportedPid'));
    OleFn := TFixtureOle32Alloc(ProcAddressByName(H, 'FixtureOle32Alloc'));
    Check(Assigned(AddFn), 'FixtureAdd not found by Windows loader');
    Check(Assigned(PidFn), 'FixtureImportedPid not found by Windows loader');
    Check(Assigned(OleFn), 'FixtureOle32Alloc not found by Windows loader');
    AddValue := AddFn(7, 35);
    PidValue := PidFn();
    OleValue := OleFn(32);
  finally
    FreeLibrary(H);
  end;
end;

function ReservePreferredBase(Raw: PByte; out Reservation: Pointer): UInt64;
var
  PreferredBase: UInt64;
  ImageSize: DWORD;
begin
  PreferredBase := GetImageBase(Raw);
  ImageSize := GetImageSize(Raw);
  Check((PreferredBase <> 0) and (ImageSize <> 0), 'fixture has invalid image base or image size');
  Reservation := VirtualAlloc(Pointer(NativeUInt(PreferredBase)), ImageSize, MEM_RESERVE, PAGE_NOACCESS);
  if Reservation = nil then
    Writeln('PREFERRED_BASE: already unavailable')
  else
    Writeln('PREFERRED_BASE: reserved to force relocation');
  Result := PreferredBase;
end;

function ManualLoadFixture(const Path: string; RegisterExceptions: Boolean; out VSize: NativeUInt): TAlignedBuf;
var
  RawSize: NativeUInt;
  Raw: TUnalignedBuf;
  Reservation: Pointer;
  PreferredBase: UInt64;
  Resolver: TDefaultFuncResolver;
begin
  Result := nil;
  VSize := 0;
  RawSize := 0;
  Raw := LoadFile(Path, RawSize);
  Check(Raw <> nil, 'fixture file could not be read');
  Reservation := nil;
  try
    Check(HasRelocations(Raw), 'fixture has no relocation directory');
    PreferredBase := ReservePreferredBase(Raw, Reservation);
    UseApiSetResolution := True;
    AutoRegisterExceptions := False;
    AutoInitSecurityCookie := False;
    Resolver := TDefaultFuncResolver.Create;
    try
      Result := LoadPeExecutable(Raw, RawSize, VSize, Resolver, 0, False);
    finally
      Resolver.Free;
    end;
    Check(Result <> nil, 'LoadPeExecutable failed');
    Check(NativeUInt(Result) <> NativeUInt(PreferredBase), 'fixture was not relocated');
    Check(HasValidImportTable(Result, VSize), 'mapped fixture has invalid import table');
    Check(HasValidRelocationTable(Result, VSize), 'mapped fixture has invalid relocation table');
    Check(InitSecurityCookie(Result, VSize), 'InitSecurityCookie failed');
    if RegisterExceptions then
      Check(SetupExceptions(Result, VSize), 'SetupExceptions failed');
  finally
    if Reservation <> nil then
      VirtualFree(Reservation, 0, MEM_RELEASE);
    FreeFile(Raw);
  end;
end;

procedure RunLoader(const FixturePath: string);
var
  WinAdd, WinOle, NativeAdd, NativeOle: Integer;
  WinPid, NativePid: DWORD;
  Loaded: TAlignedBuf;
  VSize: NativeUInt;
  AddFn: TFixtureAdd;
  PidFn: TFixtureImportedPid;
  OleFn: TFixtureOle32Alloc;
  LoadConfigPtr: PByte;
begin
  Check(FileExists(FixturePath), 'fixture not found: ' + FixturePath);
  CallFixtureWindows(FixturePath, WinAdd, WinPid, WinOle);
  Loaded := ManualLoadFixture(FixturePath, False, VSize);
  try
    AddFn := TFixtureAdd(ExportAddressByName(Loaded, 'FixtureAdd'));
    PidFn := TFixtureImportedPid(ExportAddressByName(Loaded, 'FixtureImportedPid'));
    OleFn := TFixtureOle32Alloc(ExportAddressByName(Loaded, 'FixtureOle32Alloc'));
    Check(Assigned(AddFn), 'FixtureAdd not found in manual image');
    Check(Assigned(PidFn), 'FixtureImportedPid not found in manual image');
    Check(Assigned(OleFn), 'FixtureOle32Alloc not found in manual image');
    NativeAdd := AddFn(7, 35);
    NativePid := PidFn();
    NativeOle := OleFn(32);
    Check(NativeAdd = WinAdd, 'FixtureAdd differs from Windows loader baseline');
    Check(NativePid = WinPid, 'FixtureImportedPid differs from Windows loader baseline');
    Check(NativeOle = WinOle, 'FixtureOle32Alloc differs from Windows loader baseline');
    Check(NativeAdd = 42, 'FixtureAdd returned unexpected value');
    Check(NativePid = GetCurrentProcessId, 'manual fixture imported GetCurrentProcessId incorrectly');
    Check(NativeOle = $5A, 'manual fixture ole32 import call failed');
    LoadConfigPtr := GetLoadConfigPtr(Loaded, VSize);
    if LoadConfigPtr = nil then
      Writeln('LOAD_CONFIG: absent')
    else
      Writeln('LOAD_CONFIG: present');
    Writeln('RESULT: PASS - loader baseline matches Windows loader and forced relocation succeeded');
  finally
    FreePeBuffer(Loaded, VSize);
  end;
end;

procedure RunExceptions(const FixturePath: string);
var
  H: HMODULE;
  WindowsFn: TFixtureRaiseAndCatch;
  ManualFn: TFixtureRaiseAndCatch;
  WindowsValue, ManualValue: Integer;
  Loaded: TAlignedBuf;
  VSize: NativeUInt;
begin
  Check(FileExists(FixturePath), 'fixture not found: ' + FixturePath);
  H := LoadLibrary(PChar(FixturePath));
  Check(H <> 0, 'LoadLibrary failed for exception baseline');
  try
    WindowsFn := TFixtureRaiseAndCatch(ProcAddressByName(H, 'FixtureRaiseAndCatch'));
    Check(Assigned(WindowsFn), 'FixtureRaiseAndCatch not found by Windows loader');
    WindowsValue := WindowsFn(0);
  finally
    FreeLibrary(H);
  end;
  Check(WindowsValue = EXCEPTION_MAGIC, 'Windows loader exception baseline failed');
  Loaded := ManualLoadFixture(FixturePath, True, VSize);
  ManualFn := TFixtureRaiseAndCatch(ExportAddressByName(Loaded, 'FixtureRaiseAndCatch'));
  Check(Assigned(ManualFn), 'FixtureRaiseAndCatch not found in manual image');
  ManualValue := ManualFn(0);
  Check(ManualValue = WindowsValue, 'manual exception result differs from Windows loader baseline');
  Writeln('RESULT: PASS - exception handling succeeded in manually loaded image');
  Halt(0);
end;

function RvaBelongsToSection(ModulePtr: PByte; ModuleSize: NativeUInt; Rva, DataSize: DWORD): Boolean;
var
  I, Count: NativeUInt;
  Sec: PImageSectionHeader;
  Span, SecEnd: UInt64;
begin
  Result := False;
  Count := GetSectionsCount(ModulePtr, ModuleSize);
  I := 0;
  while I < Count do
  begin
    Sec := GetSectionHdr(ModulePtr, ModuleSize, I);
    if Sec <> nil then
    begin
      Span := Sec.Misc.VirtualSize;
      if Span < Sec.SizeOfRawData then
        Span := Sec.SizeOfRawData;
      SecEnd := UInt64(Sec.VirtualAddress) + Span;
      if (UInt64(Rva) >= Sec.VirtualAddress) and (UInt64(Rva) + DataSize <= SecEnd) then
        Exit(True);
    end;
    Inc(I);
  end;
end;

procedure RunRecycler(const FixturePath: string);
const
  Marker: array [0 .. 31] of Byte = (
    $4E,$41,$54,$49,$56,$45,$50,$45,$2D,$52,$45,$41,$4C,$57,$4F,$52,
    $4C,$44,$2D,$43,$41,$56,$45,$2D,$54,$45,$53,$54,$2D,$30,$31,$21);
var
  RawSize, VSize, OutSize, ReloadSize: NativeUInt;
  Raw: TUnalignedBuf;
  VirtualPe, OutRaw, Reloaded: TAlignedBuf;
  Rva: DWORD;
  OutPath: string;
  AddFn: TFixtureAdd;
begin
  Check(FileExists(FixturePath), 'fixture not found: ' + FixturePath);
  RawSize := 0;
  Raw := LoadFile(FixturePath, RawSize);
  Check(Raw <> nil, 'fixture file could not be read');
  VirtualPe := nil;
  OutRaw := nil;
  Reloaded := nil;
  try
    VirtualPe := LoadPeModule(Raw, RawSize, VSize, False, False);
    Check(VirtualPe <> nil, 'fixture could not be mapped for recycler');
    Check(InjectIntoCave(VirtualPe, VSize, PByte(@Marker[0]), SizeOf(Marker), Rva), 'InjectIntoCave found no usable cave');
    Check(RvaBelongsToSection(VirtualPe, VSize, Rva, SizeOf(Marker)), 'returned cave RVA is outside section virtual ranges');
    Check(CompareMem(PByte(NativeUInt(VirtualPe) + Rva), @Marker[0], SizeOf(Marker)), 'marker was not copied to returned cave RVA');
    OutSize := 0;
    OutRaw := PeVirtualToRaw(VirtualPe, VSize, UInt64(NativeUInt(VirtualPe)), OutSize, True);
    Check((OutRaw <> nil) and (OutSize <> 0), 'PeVirtualToRaw failed after cave injection');
    OutPath := ChangeFileExt(FixturePath, '.recycled.dll');
    Check(DumpToFile(OutPath, OutRaw, OutSize), 'could not write recycled fixture');
    ReloadSize := 0;
    UseApiSetResolution := True;
    Reloaded := LoadPeExecutable(OutPath, ReloadSize, nil, False);
    Check(Reloaded <> nil, 'recycled fixture could not be loaded again');
    AddFn := TFixtureAdd(ExportAddressByName(Reloaded, 'FixtureAdd'));
    Check(Assigned(AddFn), 'FixtureAdd missing after recycler roundtrip');
    Check(AddFn(7, 35) = 42, 'recycled fixture execution failed');
    Writeln('RECYCLED: ' + OutPath);
    Writeln('CAVE_RVA: 0x' + IntToHex(Rva, 8));
    Writeln('RESULT: PASS - real compiled fixture survived cave injection and raw roundtrip');
  finally
    if Reloaded <> nil then
      FreePeBuffer(Reloaded, ReloadSize);
    if OutRaw <> nil then
      FreePeBuffer(OutRaw, OutSize);
    if VirtualPe <> nil then
      FreePeBuffer(VirtualPe, VSize);
    FreeFile(Raw);
  end;
end;

procedure RunVerifyDump(const DumpPath, ExpectedBitsText: string);
var
  RawSize, VSize: NativeUInt;
  ExpectedBits: Integer;
  Raw: TUnalignedBuf;
  VirtualPe: TAlignedBuf;
  ImportDir, RelocDir: PImageDataDirectory;
begin
  Check(FileExists(DumpPath), 'dump not found: ' + DumpPath);
  Check(TryStrToInt(ExpectedBitsText, ExpectedBits), 'expected bits must be 32 or 64');
  Check((ExpectedBits = 32) or (ExpectedBits = 64), 'expected bits must be 32 or 64');
  RawSize := 0;
  Raw := LoadFile(DumpPath, RawSize);
  Check(Raw <> nil, 'dump could not be read');
  VirtualPe := nil;
  try
    VirtualPe := LoadPeModule(Raw, RawSize, VSize, False, False);
    Check(VirtualPe <> nil, 'dump cannot be mapped as PE');
    Check(GetSectionsCount(VirtualPe, VSize) > 0, 'dump has no sections');
    Check(GetImageSize(VirtualPe) <> 0, 'dump has invalid image size');
    if ExpectedBits = 64 then
      Check(Is64Bit(VirtualPe), 'dump is not PE32+')
    else
      Check(not Is64Bit(VirtualPe), 'dump is not PE32');
    ImportDir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if ImportDir <> nil then
      Check(HasValidImportTable(VirtualPe, VSize), 'dump import table is invalid');
    RelocDir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if RelocDir <> nil then
      Check(HasValidRelocationTable(VirtualPe, VSize), 'dump relocation table is invalid');
    Writeln('RESULT: PASS - dumped PE parsed and core directories validated');
  finally
    if VirtualPe <> nil then
      FreePeBuffer(VirtualPe, VSize);
    FreeFile(Raw);
  end;
end;

procedure Usage;
begin
  Writeln('NativePeRealWorldRunner loader <fixture.dll>');
  Writeln('NativePeRealWorldRunner exceptions <fixture.dll>');
  Writeln('NativePeRealWorldRunner recycler <fixture.dll>');
  Writeln('NativePeRealWorldRunner verify-dump <dump.exe> <32|64>');
end;

begin
  try
    if ParamCount < 2 then
    begin
      Usage;
      Halt(2);
    end;
    if SameText(ParamStr(1), 'loader') then
      RunLoader(ParamStr(2))
    else if SameText(ParamStr(1), 'exceptions') then
      RunExceptions(ParamStr(2))
    else if SameText(ParamStr(1), 'recycler') then
      RunRecycler(ParamStr(2))
    else if SameText(ParamStr(1), 'verify-dump') and (ParamCount >= 3) then
      RunVerifyDump(ParamStr(2), ParamStr(3))
    else
    begin
      Usage;
      Halt(2);
    end;
  except
    on E: Exception do
    begin
      Writeln('RESULT: FAIL - ' + E.ClassName + ': ' + E.Message);
      Halt(99);
    end;
  end;
end.
