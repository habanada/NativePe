unit NativePe.Windows.Tests;

interface

uses
  System.SysUtils,
  System.Generics.Collections,
  Winapi.Windows,
  DUnitX.TestFramework,
  NativePe.PeHdrsHelper,
  NativePe.PebLookup,
  NativePe.ExportsLookup,
  NativePe.FunctionResolver,
  NativePe.MemoryProvider,
  NativePe.NtMemoryProvider,
{$IFDEF WIN64}
  NativePe.SyscallMemoryProvider,
{$ENDIF}
  NativePe.BufferUtil,
  NativePe.RemotePeReader,
  NativePe.Hooks;

type
  {$M+}

  [TestFixture]
  TPebIntegrationTests = class
  public
    [Test] procedure CurrentModuleMatchesWindows;
    [Test] procedure CurrentModuleSizeMatchesHeader;
    [Test] procedure NtdllMatchesWindows;
    [Test] procedure Kernel32MatchesWindows;
    [Test] procedure WrongFirstCharacterDoesNotMatchNtdll;
    [Test] procedure WrongSuffixDoesNotMatchNtdll;
    [Test] procedure PartialSuffixDoesNotMatchNtdll;
    [Test] procedure MissingModuleReturnsZero;
    [Test] procedure PebPointerAvailable;
  end;

  [TestFixture]
  TMemoryProviderIntegrationTests = class
  public
    [Test] procedure ProviderBackedAllocationUsesInjectedProvider;
    [Test] procedure ProviderBackedRemoteReadUsesInjectedProvider;
    [Test] procedure ProviderBackedPatchRestoreUsesInjectedProvider;
  end;

  [TestFixture]
  TNtApiMemoryProviderIntegrationTests = class
  public
    [Test] procedure AllocationAndFree;
    [Test] procedure QueryAndRead;
    [Test] procedure ProtectAndFlush;
  end;

{$IFDEF WIN64}
  [TestFixture]
  TSyscallMemoryProviderIntegrationTests = class
  public
    [Test] procedure AllocationAndFree;
    [Test] procedure QueryAndRead;
    [Test] procedure ProtectAndFlush;
  end;
{$ENDIF}

  [TestFixture]
  TExportsIntegrationTests = class
  public
    [Test] procedure NtdllDllNameReadable;
    [Test] procedure NtdllExportListContainsNtClose;
    [Test] procedure NtdllNtCloseMatchesGetProcAddress;
    [Test] procedure DefaultResolverMatchesGetProcAddress;
    [Test] procedure ExportResolverMatchesGetProcAddress;
  end;

implementation

type
  TTrackingMemoryProvider = class(TWinApiMemoryProvider)
  public
    AllocCalls: Integer;
    FreeCalls: Integer;
    QueryCalls: Integer;
    ReadCalls: Integer;
    ProtectLocalCalls: Integer;
    FlushCalls: Integer;
    function AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType, Protect: DWORD;
      out ErrorCode: DWORD): Pointer; override;
    function FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD; out ErrorCode: DWORD): Boolean; override;
    function QueryProcess(ProcessHandle: THandle; Address: Pointer; out MemoryInfo: TMemoryBasicInformation;
      out ErrorCode: DWORD): Boolean; override;
    function ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
      out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean; override;
    function ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD; OldProtect: PDWORD;
      out ErrorCode: DWORD): Boolean; override;
    function FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer; Size: NativeUInt;
      out ErrorCode: DWORD): Boolean; override;
  end;

function TTrackingMemoryProvider.AllocLocal(DesiredBase: Pointer; Size: NativeUInt; AllocationType, Protect: DWORD;
  out ErrorCode: DWORD): Pointer;
begin
  Inc(AllocCalls);
  Result := inherited AllocLocal(DesiredBase, Size, AllocationType, Protect, ErrorCode);
end;

function TTrackingMemoryProvider.FreeLocal(BaseAddress: Pointer; Size: NativeUInt; FreeType: DWORD;
  out ErrorCode: DWORD): Boolean;
begin
  Inc(FreeCalls);
  Result := inherited FreeLocal(BaseAddress, Size, FreeType, ErrorCode);
end;

function TTrackingMemoryProvider.QueryProcess(ProcessHandle: THandle; Address: Pointer;
  out MemoryInfo: TMemoryBasicInformation; out ErrorCode: DWORD): Boolean;
begin
  Inc(QueryCalls);
  Result := inherited QueryProcess(ProcessHandle, Address, MemoryInfo, ErrorCode);
end;

function TTrackingMemoryProvider.ReadProcess(ProcessHandle: THandle; Address, Buffer: Pointer; Size: NativeUInt;
  out BytesRead: NativeUInt; out ErrorCode: DWORD): Boolean;
begin
  Inc(ReadCalls);
  Result := inherited ReadProcess(ProcessHandle, Address, Buffer, Size, BytesRead, ErrorCode);
end;

function TTrackingMemoryProvider.ProtectLocal(Address: Pointer; Size: NativeUInt; NewProtect: DWORD;
  OldProtect: PDWORD; out ErrorCode: DWORD): Boolean;
begin
  Inc(ProtectLocalCalls);
  Result := inherited ProtectLocal(Address, Size, NewProtect, OldProtect, ErrorCode);
end;

function TTrackingMemoryProvider.FlushProcessInstructionCache(ProcessHandle: THandle; Address: Pointer;
  Size: NativeUInt; out ErrorCode: DWORD): Boolean;
begin
  Inc(FlushCalls);
  Result := inherited FlushProcessInstructionCache(ProcessHandle, Address, Size, ErrorCode);
end;

function LoadKnownModule(const Name: PWideChar): HMODULE;
begin
  Result := GetModuleHandleW(Name);
  if Result = 0 then
    Result := LoadLibraryW(Name);
end;

procedure TPebIntegrationTests.CurrentModuleMatchesWindows;
var
  A, B: HMODULE;
begin
  A := GetModuleViaPeb(nil);
  B := GetModuleHandleW(nil);
  Assert.IsTrue(A <> 0);
  Assert.IsTrue(A = B);
  Assert.IsTrue(GetMainModuleViaPeb = B);
end;

procedure TPebIntegrationTests.CurrentModuleSizeMatchesHeader;
var
  M: HMODULE;
  A, B: NativeUInt;
begin
  M := GetModuleHandleW(nil);
  A := GetModuleSizeViaPeb(M);
  B := GetImageSize(PByte(M));
  Assert.IsTrue(A <> 0);
  Assert.IsTrue(A = B);
end;

procedure TPebIntegrationTests.NtdllMatchesWindows;
var
  A, B: HMODULE;
begin
  B := LoadKnownModule('ntdll.dll');
  A := GetModuleViaPeb(PWideChar('ntdll.dll'));
  Assert.IsTrue(B <> 0);
  Assert.IsTrue(A = B);
  Assert.IsTrue(GetModuleSizeViaPeb(A) = GetImageSize(PByte(B)));
end;

procedure TPebIntegrationTests.Kernel32MatchesWindows;
var
  A, B: HMODULE;
begin
  B := LoadKnownModule('kernel32.dll');
  A := GetModuleViaPeb(PWideChar('kernel32.dll'));
  Assert.IsTrue(B <> 0);
  Assert.IsTrue(A = B);
  Assert.IsTrue(GetModuleSizeViaPeb(A) = GetImageSize(PByte(B)));
end;

procedure TPebIntegrationTests.WrongFirstCharacterDoesNotMatchNtdll;
begin
  LoadKnownModule('ntdll.dll');
  Assert.IsTrue(GetModuleViaPeb(PWideChar('atdll.dll')) = 0);
end;

procedure TPebIntegrationTests.WrongSuffixDoesNotMatchNtdll;
begin
  LoadKnownModule('ntdll.dll');
  Assert.IsTrue(GetModuleViaPeb(PWideChar('ntdll.dlx')) = 0);
end;

procedure TPebIntegrationTests.PartialSuffixDoesNotMatchNtdll;
begin
  LoadKnownModule('ntdll.dll');
  Assert.IsTrue(GetModuleViaPeb(PWideChar('tdll.dll')) = 0);
end;

procedure TPebIntegrationTests.MissingModuleReturnsZero;
begin
  Assert.IsTrue(GetModuleViaPeb(PWideChar('nativepe_dunitx_missing_module_8f37.dll')) = 0);
end;

procedure TPebIntegrationTests.PebPointerAvailable;
begin
  Assert.IsTrue(GetCurrentPeb <> nil);
end;

procedure TMemoryProviderIntegrationTests.ProviderBackedAllocationUsesInjectedProvider;
var
  Provider: TTrackingMemoryProvider;
  Buffer: TAlignedBuf;
  Freed: Boolean;
begin
  Buffer := nil;
  Provider := TTrackingMemoryProvider.Create;
  try
    Buffer := AllocAligned(Provider, $1000, PAGE_READWRITE);
    Assert.IsTrue(Buffer <> nil);
    Assert.IsTrue(Provider.AllocCalls = 1);
    Freed := FreeAligned(Provider, Buffer);
    Assert.IsTrue(Freed);
    if Freed then
      Buffer := nil;
    Assert.IsTrue(Provider.FreeCalls = 1);
  finally
    if Buffer <> nil then
      FreeAligned(Provider, Buffer);
    Provider.Free;
  end;
end;

procedure TMemoryProviderIntegrationTests.ProviderBackedRemoteReadUsesInjectedProvider;
var
  Provider: TTrackingMemoryProvider;
  PageInfo: TMemoryBasicInformation;
  Source, Target: array [0 .. 31] of Byte;
  I: Integer;
  ReadSize: NativeUInt;
begin
  for I := Low(Source) to High(Source) do
    Source[I] := Byte(I + 1);
  FillChar(Target, SizeOf(Target), 0);
  Provider := TTrackingMemoryProvider.Create;
  try
    Assert.IsTrue(FetchRegionInfo(Provider, GetCurrentProcess, @Source[0], PageInfo));
    Assert.IsTrue(Provider.QueryCalls = 1);
    ReadSize := ReadRemoteMemory(Provider, GetCurrentProcess, @Source[0], @Target[0], SizeOf(Target), 1);
    Assert.IsTrue(ReadSize = SizeOf(Target));
    Assert.IsTrue(Provider.ReadCalls > 0);
    Assert.IsTrue(CompareMem(@Source[0], @Target[0], SizeOf(Source)));
  finally
    Provider.Free;
  end;
end;

procedure TMemoryProviderIntegrationTests.ProviderBackedPatchRestoreUsesInjectedProvider;
var
  Provider: TTrackingMemoryProvider;
  Backup: TPatchBackup;
  Buffer: TAlignedBuf;
  Freed: Boolean;
begin
  Buffer := nil;
  Provider := TTrackingMemoryProvider.Create;
  Backup := TPatchBackup.Create;
  try
    Buffer := AllocAligned(Provider, $1000, PAGE_READWRITE);
    Assert.IsTrue(Buffer <> nil);
    Buffer[0] := $41;
    Assert.IsTrue(Backup.MakeBackup(Buffer, 1));
    Buffer[0] := $42;
    Assert.IsTrue(Backup.ApplyBackup(Provider));
    Assert.IsTrue(Buffer[0] = $41);
    Assert.IsTrue(Provider.ProtectLocalCalls = 2);
    Assert.IsTrue(Provider.FlushCalls = 1);
    Freed := FreeAligned(Provider, Buffer);
    Assert.IsTrue(Freed);
    if Freed then
      Buffer := nil;
  finally
    Backup.Free;
    if Buffer <> nil then
      FreeAligned(Provider, Buffer);
    Provider.Free;
  end;
end;

procedure TNtApiMemoryProviderIntegrationTests.AllocationAndFree;
var
  Provider: TNativePeMemoryProvider;
  Buffer: TAlignedBuf;
  Freed: Boolean;
begin
  Provider := GetNtApiMemoryProvider;
  Buffer := nil;
  try
    Buffer := AllocAligned(Provider, $1000, PAGE_READWRITE);
    Assert.IsTrue(Buffer <> nil);
    Buffer[0] := $5A;
    Assert.IsTrue(Buffer[0] = $5A);
    Freed := FreeAligned(Provider, Buffer);
    Assert.IsTrue(Freed);
    if Freed then
      Buffer := nil;
  finally
    if Buffer <> nil then
      FreeAligned(Provider, Buffer);
  end;
end;

procedure TNtApiMemoryProviderIntegrationTests.QueryAndRead;
var
  Provider: TNativePeMemoryProvider;
  PageInfo: TMemoryBasicInformation;
  Source, Target: array [0 .. 31] of Byte;
  I: Integer;
  ReadSize: NativeUInt;
begin
  for I := Low(Source) to High(Source) do
    Source[I] := Byte(I + $20);
  FillChar(Target, SizeOf(Target), 0);
  Provider := GetNtApiMemoryProvider;
  Assert.IsTrue(FetchRegionInfo(Provider, GetCurrentProcess, @Source[0], PageInfo));
  Assert.IsTrue(PageInfo.RegionSize <> 0);
  ReadSize := ReadRemoteMemory(Provider, GetCurrentProcess, @Source[0], @Target[0], SizeOf(Target), 1);
  Assert.IsTrue(ReadSize = SizeOf(Target));
  Assert.IsTrue(CompareMem(@Source[0], @Target[0], SizeOf(Source)));
end;

procedure TNtApiMemoryProviderIntegrationTests.ProtectAndFlush;
var
  Provider: TNativePeMemoryProvider;
  Buffer: TAlignedBuf;
  OldProtect, RestoreProtect: DWORD;
  ErrorCode: DWORD;
  Freed: Boolean;
begin
  Provider := GetNtApiMemoryProvider;
  Buffer := nil;
  try
    Buffer := AllocAligned(Provider, $1000, PAGE_READWRITE);
    Assert.IsTrue(Buffer <> nil);
    OldProtect := 0;
    Assert.IsTrue(Provider.ProtectProcess(GetCurrentProcess, Buffer, $1000, PAGE_READONLY, OldProtect, ErrorCode));
    Assert.IsTrue(ErrorCode = ERROR_SUCCESS);
    Assert.IsTrue(OldProtect = PAGE_READWRITE);
    RestoreProtect := 0;
    Assert.IsTrue(Provider.ProtectLocal(Buffer, $1000, OldProtect, @RestoreProtect, ErrorCode));
    Assert.IsTrue(ErrorCode = ERROR_SUCCESS);
    Assert.IsTrue(RestoreProtect = PAGE_READONLY);
    Assert.IsTrue(Provider.FlushProcessInstructionCache(GetCurrentProcess, Buffer, $1000, ErrorCode));
    Assert.IsTrue(ErrorCode = ERROR_SUCCESS);
    Freed := FreeAligned(Provider, Buffer);
    Assert.IsTrue(Freed);
    if Freed then
      Buffer := nil;
  finally
    if Buffer <> nil then
      FreeAligned(Provider, Buffer);
  end;
end;

{$IFDEF WIN64}
procedure TSyscallMemoryProviderIntegrationTests.AllocationAndFree;
var
  Provider: TNativePeMemoryProvider;
  Buffer: TAlignedBuf;
  Freed: Boolean;
begin
  Provider := GetSyscallMemoryProvider;
  Buffer := nil;
  try
    Buffer := AllocAligned(Provider, $1000, PAGE_READWRITE);
    Assert.IsTrue(Buffer <> nil);
    Buffer[0] := $6A;
    Assert.IsTrue(Buffer[0] = $6A);
    Freed := FreeAligned(Provider, Buffer);
    Assert.IsTrue(Freed);
    if Freed then
      Buffer := nil;
  finally
    if Buffer <> nil then
      FreeAligned(Provider, Buffer);
  end;
end;

procedure TSyscallMemoryProviderIntegrationTests.QueryAndRead;
var
  Provider: TNativePeMemoryProvider;
  PageInfo: TMemoryBasicInformation;
  Source, Target: array [0 .. 31] of Byte;
  I: Integer;
  ReadSize: NativeUInt;
begin
  for I := Low(Source) to High(Source) do
    Source[I] := Byte(I + $30);
  FillChar(Target, SizeOf(Target), 0);
  Provider := GetSyscallMemoryProvider;
  Assert.IsTrue(FetchRegionInfo(Provider, GetCurrentProcess, @Source[0], PageInfo));
  Assert.IsTrue(PageInfo.RegionSize <> 0);
  ReadSize := ReadRemoteMemory(Provider, GetCurrentProcess, @Source[0], @Target[0], SizeOf(Target), 1);
  Assert.IsTrue(ReadSize = SizeOf(Target));
  Assert.IsTrue(CompareMem(@Source[0], @Target[0], SizeOf(Source)));
end;

procedure TSyscallMemoryProviderIntegrationTests.ProtectAndFlush;
var
  Provider: TNativePeMemoryProvider;
  Buffer: TAlignedBuf;
  OldProtect, RestoreProtect: DWORD;
  ErrorCode: DWORD;
  Freed: Boolean;
begin
  Provider := GetSyscallMemoryProvider;
  Buffer := nil;
  try
    Buffer := AllocAligned(Provider, $1000, PAGE_READWRITE);
    Assert.IsTrue(Buffer <> nil);
    OldProtect := 0;
    Assert.IsTrue(Provider.ProtectProcess(GetCurrentProcess, Buffer, $1000, PAGE_READONLY, OldProtect, ErrorCode));
    Assert.IsTrue(ErrorCode = ERROR_SUCCESS);
    Assert.IsTrue(OldProtect = PAGE_READWRITE);
    RestoreProtect := 0;
    Assert.IsTrue(Provider.ProtectLocal(Buffer, $1000, OldProtect, @RestoreProtect, ErrorCode));
    Assert.IsTrue(ErrorCode = ERROR_SUCCESS);
    Assert.IsTrue(RestoreProtect = PAGE_READONLY);
    Assert.IsTrue(Provider.FlushProcessInstructionCache(GetCurrentProcess, Buffer, $1000, ErrorCode));
    Assert.IsTrue(ErrorCode = ERROR_SUCCESS);
    Freed := FreeAligned(Provider, Buffer);
    Assert.IsTrue(Freed);
    if Freed then
      Buffer := nil;
  finally
    if Buffer <> nil then
      FreeAligned(Provider, Buffer);
  end;
end;
{$ENDIF}

procedure TExportsIntegrationTests.NtdllDllNameReadable;
var
  M: HMODULE;
  Name: PAnsiChar;
begin
  M := LoadKnownModule('ntdll.dll');
  Assert.IsTrue(M <> 0);
  Name := ReadDllName(Pointer(M));
  Assert.IsTrue(Name <> nil);
  Assert.IsTrue(SameText(string(AnsiString(Name)), 'ntdll.dll'));
end;

procedure TExportsIntegrationTests.NtdllExportListContainsNtClose;
var
  M: HMODULE;
  Names: TList<string>;
  N: NativeUInt;
  S: string;
  Found: Boolean;
begin
  M := LoadKnownModule('ntdll.dll');
  Assert.IsTrue(M <> 0);
  Names := TList<string>.Create;
  try
    N := GetExportedNames(Pointer(M), Names);
    Assert.IsTrue(N > 0);
    Found := False;
    for S in Names do
      if S = 'NtClose' then
      begin
        Found := True;
        Break;
      end;
    Assert.IsTrue(Found, 'NtClose not found in ntdll export list');
  finally
    Names.Free;
  end;
end;

procedure TExportsIntegrationTests.NtdllNtCloseMatchesGetProcAddress;
var
  M: HMODULE;
  Name: AnsiString;
  A, B: FARPROC;
begin
  M := LoadKnownModule('ntdll.dll');
  Assert.IsTrue(M <> 0);
  Name := 'NtClose';
  A := GetExportedFunc(Pointer(M), PAnsiChar(Name));
  B := GetProcAddress(M, PAnsiChar(Name));
  Assert.IsTrue(Assigned(A));
  Assert.IsTrue(NativeUInt(A) = NativeUInt(B));
end;

procedure TExportsIntegrationTests.DefaultResolverMatchesGetProcAddress;
var
  M: HMODULE;
  Resolver: TDefaultFuncResolver;
  Lib, Name: AnsiString;
  A, B: FARPROC;
begin
  M := LoadKnownModule('ntdll.dll');
  Assert.IsTrue(M <> 0);
  Lib := 'ntdll.dll';
  Name := 'NtClose';
  Resolver := TDefaultFuncResolver.Create;
  try
    A := Resolver.ResolveFunc(PAnsiChar(Lib), PAnsiChar(Name));
    B := GetProcAddress(M, PAnsiChar(Name));
    Assert.IsTrue(Assigned(A));
    Assert.IsTrue(NativeUInt(A) = NativeUInt(B));
  finally
    Resolver.Free;
  end;
end;

procedure TExportsIntegrationTests.ExportResolverMatchesGetProcAddress;
var
  M: HMODULE;
  Resolver: TExportBasedResolver;
  Lib, Name: AnsiString;
  A, B: FARPROC;
begin
  M := LoadKnownModule('ntdll.dll');
  Assert.IsTrue(M <> 0);
  Lib := 'ntdll.dll';
  Name := 'NtClose';
  Resolver := TExportBasedResolver.Create;
  try
    A := Resolver.ResolveFunc(PAnsiChar(Lib), PAnsiChar(Name));
    B := GetProcAddress(M, PAnsiChar(Name));
    Assert.IsTrue(Assigned(A));
    Assert.IsTrue(NativeUInt(A) = NativeUInt(B));
  finally
    Resolver.Free;
  end;
end;

initialization
  TDUnitX.RegisterTestFixture(TPebIntegrationTests);
  TDUnitX.RegisterTestFixture(TMemoryProviderIntegrationTests);
  TDUnitX.RegisterTestFixture(TNtApiMemoryProviderIntegrationTests);
{$IFDEF WIN64}
  TDUnitX.RegisterTestFixture(TSyscallMemoryProviderIntegrationTests);
{$ENDIF}
  TDUnitX.RegisterTestFixture(TExportsIntegrationTests);

end.
