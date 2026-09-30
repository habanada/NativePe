program NativePeProcessDump;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  System.Classes,
  System.Hash,
  System.Generics.Collections,
  Winapi.Windows,
  Winapi.TlHelp32,
  NativePe.ExportsMapper,
  NativePe.ApiSet,
  NativePe.PeDumper,
  NativePe.RemotePeReader,
  NativePe.Logger;

const
  TH32CS_SNAPMODULE32          = $00000010;
  LOAD_LIBRARY_AS_IMAGE_RESOURCE = $00000020;

type
  TModuleInfo = record
    Base: UInt64;
    Size: NativeUInt;
    Name: string;
    Path: string;
  end;

function LevelName(Level: TNativePeLogLevel): string;
begin
  case Level of
    llError: Result := 'ERROR';
    llWarning: Result := 'WARN';
    llInfo: Result := 'INFO';
    llDebug: Result := 'DEBUG';
  else
    Result := 'NONE';
  end;
end;

procedure ConsoleLogSink(Level: TNativePeLogLevel; const Msg: string);
begin
  Writeln('[' + LevelName(Level) + '] ' + Msg);
end;

function EnableDebugPrivilege: Boolean;
var
  TokenHandle: THandle;
  Luid: TLargeInteger;
  Tp: TTokenPrivileges;
  ReturnLen: DWORD;
begin
  Result := False;
  if not OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY, TokenHandle) then
    Exit;
  try
    if not LookupPrivilegeValue(nil, 'SeDebugPrivilege', Luid) then
      Exit;
    Tp.PrivilegeCount := 1;
    Tp.Privileges[0].Luid := Luid;
    Tp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    ReturnLen := 0;
    Result := AdjustTokenPrivileges(TokenHandle, False, Tp, SizeOf(Tp), nil, ReturnLen)
      and (GetLastError = ERROR_SUCCESS);
  finally
    CloseHandle(TokenHandle);
  end;
end;

function EnumTargetModules(Pid: DWORD; Modules: TList<TModuleInfo>): Boolean;
var
  Snap: THandle;
  Me: TModuleEntry32;
  Info: TModuleInfo;
begin
  Result := False;
  Snap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE or TH32CS_SNAPMODULE32, Pid);
  if Snap = INVALID_HANDLE_VALUE then
    Exit;
  try
    FillChar(Me, SizeOf(Me), 0);
    Me.dwSize := SizeOf(Me);
    if not Module32First(Snap, Me) then
      Exit;
    repeat
      Info.Base := UInt64(NativeUInt(Me.modBaseAddr));
      Info.Size := Me.modBaseSize;
      Info.Name := string(PChar(@Me.szModule[0]));
      Info.Path := string(PChar(@Me.szExePath[0]));
      Modules.Add(Info);
    until not Module32Next(Snap, Me);
    Result := Modules.Count > 0;
  finally
    CloseHandle(Snap);
  end;
end;

function ComputeSha256HexFile(const Path: string; out FileSizeOut: Int64): string;
var
  Stream: TFileStream;
begin
  Result := '';
  FileSizeOut := 0;
  if not FileExists(Path) then
    Exit;
  Stream := TFileStream.Create(Path, fmOpenRead or fmShareDenyNone);
  try
    FileSizeOut := Stream.Size;
    Result := LowerCase(THashSHA2.GetHashString(Stream));
  finally
    Stream.Free;
  end;
end;

function BuildExportsMap(const Modules: TList<TModuleInfo>; LoadedHandles: TList<HMODULE>): TExportsMapper;
var
  M: TModuleInfo;
  LocalHandle: HMODULE;
  Masked: Pointer;
  Added: NativeUInt;
begin
  Result := TExportsMapper.Create;
  for M in Modules do
  begin
    if M.Path = '' then
      Continue;
    LocalHandle := LoadLibraryEx(PChar(M.Path), 0, LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if LocalHandle = 0 then
    begin
      Writeln(Format('  exports skipped : %-24s (LoadLibraryEx failed, error %u)', [M.Name, GetLastError]));
      Continue;
    end;
    LoadedHandles.Add(LocalHandle);
    Masked := Pointer(NativeUInt(LocalHandle) and not NativeUInt(3));
    Added := Result.AddToLookup(M.Name, HMODULE(Masked), M.Base);
    Writeln('  exports mapped  : ' + Format('%-24s', [M.Name]) +
      ' base=0x' + IntToHex(Int64(M.Base), 16) + ' funcs=' + UIntToStr(Added));
  end;
end;

procedure FreeLoadedHandles(Handles: TList<HMODULE>);
var
  H: HMODULE;
begin
  for H in Handles do
    FreeLibrary(H);
end;

function FindArg(const Name, Default: string): string;
var
  I: Integer;
begin
  Result := Default;
  I := 1;
  while I <= ParamCount do
  begin
    if SameText(ParamStr(I), Name) and (I < ParamCount) then
      Exit(ParamStr(I + 1));
    Inc(I);
  end;
end;

function FindArgFlag(const Name: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if SameText(ParamStr(I), Name) then
      Exit(True);
end;

function DumpModeName(Mode: TPeDumpMode): string;
begin
  case Mode of
    PE_DUMP_VIRTUAL: Result := 'VIRTUAL (already raw-aligned)';
    PE_DUMP_UNMAP: Result := 'UNMAP (virtual->raw rebuild)';
    PE_DUMP_REALIGN: Result := 'REALIGN (expanded raw realign)';
  else
    Result := 'AUTO/UNKNOWN(' + IntToStr(Mode) + ')';
  end;
end;

procedure Usage;
begin
  Writeln('NativePeProcessDump.exe --pid <pid> [--module <name>] [--out <path>] [--verbose]');
  Writeln('');
  Writeln('  --pid <pid>       target process id (required)');
  Writeln('  --module <name>   module to dump, e.g. kernel32.dll (default: main exe)');
  Writeln('  --out <path>      output file (default: .\NativePeDump-PID<pid>-<timestamp>.exe)');
  Writeln('  --verbose         enable NativePe debug logging');
end;

var
  Pid: DWORD;
  PidValue: Integer;
  ModuleName, OutPath, PidText: string;
  ProcessHandle: THandle;
  Modules: TList<TModuleInfo>;
  Target: TModuleInfo;
  Found: Boolean;
  M: TModuleInfo;
  ExportsMap: TExportsMapper;
  LoadedHandles: TList<HMODULE>;
  DumpMode: TPeDumpMode;
  Ok: Boolean;
  Sha: string;
  OutFileSize: Int64;
begin
  try
    if (ParamCount = 0) or FindArgFlag('--help') or FindArgFlag('/?') then
    begin
      Usage;
      Halt(1);
    end;

    if FindArgFlag('--verbose') then
      NativePeSetLogVerbosity(llDebug)
    else
      NativePeSetLogVerbosity(llWarning);
    NativePeSetLogSink(ConsoleLogSink);
    UseApiSetResolution := True;

    PidText := FindArg('--pid', '');
    if (PidText = '') or not TryStrToInt(PidText, PidValue) or (PidValue <= 0) then
    begin
      Writeln('error: --pid is required and must be a positive number.');
      Usage;
      Halt(2);
    end;
    Pid := DWORD(PidValue);

    ModuleName := FindArg('--module', '');
    OutPath := FindArg('--out', Format('.\NativePeDump-PID%u-%s.exe',
      [Pid, FormatDateTime('yyyymmdd-hhnnss', Now)]));

    if not EnableDebugPrivilege then
      Writeln('[WARN] Could not enable SeDebugPrivilege (continuing; may fail for protected/elevated processes).');

    ProcessHandle := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ, False, Pid);
    if ProcessHandle = 0 then
    begin
      Writeln(Format('error: OpenProcess failed for PID %u (WinError %u).', [Pid, GetLastError]));
      Halt(3);
    end;

    Modules := TList<TModuleInfo>.Create;
    try
      if not EnumTargetModules(Pid, Modules) then
      begin
        Writeln(Format('error: could not enumerate modules of PID %u (WinError %u). ' +
          'Note: a 32-bit build of this tool cannot enumerate a 64-bit process and vice versa.',
          [Pid, GetLastError]));
        CloseHandle(ProcessHandle);
        Halt(4);
      end;

      Found := False;
      if ModuleName <> '' then
      begin
        for M in Modules do
          if SameText(M.Name, ModuleName) then
          begin
            Target := M;
            Found := True;
            Break;
          end;
        if not Found then
        begin
          Writeln('error: module "' + ModuleName + '" not found in target process.');
          CloseHandle(ProcessHandle);
          Halt(5);
        end;
      end
      else
      begin
        Target := Modules[0];
        Found := True;
      end;

      Writeln('Target module   : ' + Target.Name);
      Writeln('Base / size     : 0x' + IntToHex(Int64(Target.Base), 16) +
        ' / 0x' + IntToHex(Int64(Target.Size), 8));
      Writeln(Format('Building exports map from %d loaded module(s)...', [Modules.Count]));

      LoadedHandles := TList<HMODULE>.Create;
      try
        ExportsMap := BuildExportsMap(Modules, LoadedHandles);
        try
          DumpMode := PE_DUMP_AUTO;
          Ok := DumpRemotePe(OutPath, ProcessHandle, Pointer(NativeUInt(Target.Base)), DumpMode, ExportsMap);

          if not Ok then
          begin
            Writeln('RESULT: FAIL - dump failed, see log above.');
            Halt(6);
          end;

          Sha := ComputeSha256HexFile(OutPath, OutFileSize);

          Writeln('');
          Writeln('RESULT: PASS');
          Writeln('  DumpMode : ' + DumpModeName(DumpMode));
          Writeln('  Out      : ' + OutPath);
          Writeln('  Size     : ' + IntToStr(OutFileSize));
          Writeln('  SHA256   : ' + Sha);
        finally
          ExportsMap.Free;
        end;
      finally
        FreeLoadedHandles(LoadedHandles);
        LoadedHandles.Free;
      end;
    finally
      Modules.Free;
      CloseHandle(ProcessHandle);
    end;
  except
    on E: Exception do
    begin
      Writeln('FATAL: ' + E.ClassName + ': ' + E.Message);
      Halt(99);
    end;
  end;
end.
