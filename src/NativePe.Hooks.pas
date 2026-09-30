{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/hooks.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.Hooks;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.FunctionResolver,
  NativePe.MemoryProvider;

type
  TPatchBackup = class
  private
    FBuffer: PByte;
    FBufferSize: NativeUInt;
    FSourcePtr: PByte;
  public
    constructor Create;
    destructor Destroy; override;
    procedure DeleteBackup;
    function MakeBackup(PatchPtr: PByte; PatchSize: NativeUInt): Boolean;
    function ApplyBackup(ThreadSafe: Boolean = False): Boolean; overload;
    function ApplyBackup(Provider: TNativePeMemoryProvider; ThreadSafe: Boolean = False): Boolean; overload;
    function IsBackup: Boolean;
  end;

  THookingFuncResolver = class(TDefaultFuncResolver)
  private
    FHooksMap: TDictionary<string, FARPROC>;
    FDllReplacementsMap: TDictionary<string, string>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddHook(const Name: string; Func: FARPROC);
    procedure ReplaceDll(const DllName: string; const NewDll: string);
    function ResolveFunc(LibName, FuncName: PAnsiChar): FARPROC; override;
  end;

function SuspendOtherThreads(out ThreadIds: TArray<DWORD>; out SuspendedCount: Integer): Boolean;
procedure ResumeOtherThreads(const ThreadIds: TArray<DWORD>; SuspendedCount: Integer);

function RedirectToLocal64(Ptr: Pointer; NewOffset: UInt64; Backup: TPatchBackup = nil;
  ThreadSafe: Boolean = False): NativeUInt; overload;
function RedirectToLocal64(Provider: TNativePeMemoryProvider; Ptr: Pointer; NewOffset: UInt64; Backup: TPatchBackup = nil;
  ThreadSafe: Boolean = False): NativeUInt; overload;
function RedirectToLocal32(Ptr: Pointer; NewOffset: DWORD; Backup: TPatchBackup = nil;
  ThreadSafe: Boolean = False): NativeUInt; overload;
function RedirectToLocal32(Provider: TNativePeMemoryProvider; Ptr: Pointer; NewOffset: DWORD; Backup: TPatchBackup = nil;
  ThreadSafe: Boolean = False): NativeUInt; overload;
function RedirectToLocal(Ptr: Pointer; NewFunctionPtr: Pointer; Backup: TPatchBackup = nil;
  ThreadSafe: Boolean = False): NativeUInt; overload;
function RedirectToLocal(Provider: TNativePeMemoryProvider; Ptr: Pointer; NewFunctionPtr: Pointer;
  Backup: TPatchBackup = nil; ThreadSafe: Boolean = False): NativeUInt; overload;
function ReplaceTarget(PatchPtr: PByte; DestAddr: UInt64): Boolean; overload;
function ReplaceTarget(Provider: TNativePeMemoryProvider; PatchPtr: PByte; DestAddr: UInt64): Boolean; overload;

implementation

uses
  System.SysUtils,
  Winapi.TlHelp32,
  NativePe.BufferUtil,
  NativePe.HookMemoryProvider,
  NativePe.Util,
  NativePe.PebLookup,
  NativePe.Lde,
  NativePe.Logger;

const
  THREAD_SUSPEND_RESUME = $0002;

function OpenThread(dwDesiredAccess: DWORD; bInheritHandle: BOOL;
  dwThreadId: DWORD): THandle; stdcall;
  external 'kernel32.dll' name 'OpenThread';

function IsPointerInNtdll(LpAddress: Pointer): Boolean;
var
  Mod_: HMODULE;
  ModuleSize: NativeUInt;
begin
  Mod_ := GetModuleViaPeb(PWideChar('ntdll.dll'));
  ModuleSize := GetModuleSizeViaPeb(Mod_);
  Result := ValidatePtr(Pointer(Mod_), ModuleSize, LpAddress, SizeOf(Byte));
end;

function SuspendOtherThreads(out ThreadIds: TArray<DWORD>; out SuspendedCount: Integer): Boolean;
var
  hSnap: THandle;
  Entry: TThreadEntry32;
  CurrentPid, CurrentTid: DWORD;
  Candidates: TArray<DWORD>;
  CandidateCount, I: Integer;
  hThread: THandle;
begin
  SuspendedCount := 0;
  SetLength(ThreadIds, 0);
  CurrentPid := GetCurrentProcessId;
  CurrentTid := GetCurrentThreadId;

  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if hSnap = INVALID_HANDLE_VALUE then
  begin
    LogWarning('Could not snapshot the thread list, proceeding without thread-safety.');
    Exit(False);
  end;

  CandidateCount := 0;
  SetLength(Candidates, 0);
  try
    Entry.dwSize := SizeOf(Entry);
    if Thread32First(hSnap, Entry) then
    begin
      repeat
        if (Entry.th32OwnerProcessID = CurrentPid) and (Entry.th32ThreadID <> CurrentTid) then
        begin
          if CandidateCount >= Length(Candidates) then
            SetLength(Candidates, Length(Candidates) + 64);
          Candidates[CandidateCount] := Entry.th32ThreadID;
          Inc(CandidateCount);
        end;
      until not Thread32Next(hSnap, Entry);
    end;
  finally
    CloseHandle(hSnap);
  end;

  SetLength(ThreadIds, CandidateCount);
  for I := 0 to CandidateCount - 1 do
  begin
    hThread := OpenThread(THREAD_SUSPEND_RESUME, False, Candidates[I]);
    if hThread = 0 then
      Continue;
    if SuspendThread(hThread) <> DWORD(-1) then
    begin
      ThreadIds[SuspendedCount] := Candidates[I];
      Inc(SuspendedCount);
    end;
    CloseHandle(hThread);
  end;
  Result := True;
end;

procedure ResumeOtherThreads(const ThreadIds: TArray<DWORD>; SuspendedCount: Integer);
var
  I: Integer;
  hThread: THandle;
begin
  for I := 0 to SuspendedCount - 1 do
  begin
    hThread := OpenThread(THREAD_SUSPEND_RESUME, False, ThreadIds[I]);
    if hThread <> 0 then
    begin
      ResumeThread(hThread);
      CloseHandle(hThread);
    end;
  end;
end;

constructor TPatchBackup.Create;
begin
  inherited Create;
  FBuffer := nil;
  FBufferSize := 0;
  FSourcePtr := nil;
end;

destructor TPatchBackup.Destroy;
begin
  DeleteBackup;
  inherited Destroy;
end;

procedure TPatchBackup.DeleteBackup;
begin
  if FBuffer <> nil then
  begin
    FreeMem(FBuffer);
    FBuffer := nil;
    FBufferSize := 0;
    FSourcePtr := nil;
  end;
end;

function TPatchBackup.IsBackup: Boolean;
begin
  Result := FBuffer <> nil;
end;

function TPatchBackup.MakeBackup(PatchPtr: PByte; PatchSize: NativeUInt): Boolean;
begin
  Result := False;
  if PatchPtr = nil then
    Exit;
  DeleteBackup;
  FSourcePtr := PatchPtr;
  GetMem(FBuffer, PatchSize);
  FBufferSize := PatchSize;
  Move(PatchPtr^, FBuffer^, PatchSize);
  Result := True;
end;

function TPatchBackup.ApplyBackup(ThreadSafe: Boolean): Boolean;
begin
  Result := ApplyBackup(GetDefaultHookMemoryProvider, ThreadSafe);
end;

function TPatchBackup.ApplyBackup(Provider: TNativePeMemoryProvider; ThreadSafe: Boolean): Boolean;
var
  OldProtect, RestoreProtect, ErrorCode: DWORD;
  FrozenThreads: TArray<DWORD>;
  FrozenCount: Integer;
begin
  Result := False;
  if (Provider = nil) or (not IsBackup) then
    Exit;
  FrozenCount := 0;
  if ThreadSafe then
    SuspendOtherThreads(FrozenThreads, FrozenCount);
  try
    OldProtect := 0;
    if not Provider.ProtectLocal(FSourcePtr, FBufferSize, PAGE_EXECUTE_READWRITE, @OldProtect, ErrorCode) then
      Exit;
    Move(FBuffer^, FSourcePtr^, FBufferSize);
    RestoreProtect := 0;
    if not Provider.ProtectLocal(FSourcePtr, FBufferSize, OldProtect, @RestoreProtect, ErrorCode) then
      LogWarning('Failed to restore protection of region: 0x%x', [NativeUInt(FSourcePtr)]);
    Provider.FlushProcessInstructionCache(GetCurrentProcess, FSourcePtr, FBufferSize, ErrorCode);
    Result := True;
  finally
    if ThreadSafe then
      ResumeOtherThreads(FrozenThreads, FrozenCount);
  end;
end;

constructor THookingFuncResolver.Create;
begin
  inherited Create;
  FHooksMap := TDictionary<string, FARPROC>.Create;
  FDllReplacementsMap := TDictionary<string, string>.Create;
end;

destructor THookingFuncResolver.Destroy;
begin
  FHooksMap.Free;
  FDllReplacementsMap.Free;
  inherited Destroy;
end;

procedure THookingFuncResolver.AddHook(const Name: string; Func: FARPROC);
begin
  FHooksMap.AddOrSetValue(Name, Func);
end;

procedure THookingFuncResolver.ReplaceDll(const DllName: string; const NewDll: string);
begin
  FDllReplacementsMap.AddOrSetValue(LowerCase(DllName), NewDll);
end;

function THookingFuncResolver.ResolveFunc(LibName, FuncName: PAnsiChar): FARPROC;
var
  FuncNameStr: string;
  LibNameStr: string;
  Hook: FARPROC;
  Replacement: string;
begin
  if not IsBadReadPointer(FuncName, 1) then
  begin
    FuncNameStr := string(AnsiString(FuncName));
    if FHooksMap.TryGetValue(FuncNameStr, Hook) then
    begin
      LogDebug('Replacing: %s by: 0x%x.', [FuncNameStr, NativeUInt(Hook)]);
      Exit(Hook);
    end;
  end;

  if IsBadReadPointer(LibName, 1) then
    LibNameStr := ''
  else
    LibNameStr := string(AnsiString(LibName));

  if FDllReplacementsMap.TryGetValue(LowerCase(LibNameStr), Replacement) then
  begin
    LogDebug('Replacing DLL: %s by: %s.', [LibNameStr, Replacement]);
    LibNameStr := Replacement;
  end;

  Result := inherited ResolveFunc(PAnsiChar(AnsiString(LibNameStr)), FuncName);
end;

function RedirectToLocal64(Ptr: Pointer; NewOffset: UInt64; Backup: TPatchBackup; ThreadSafe: Boolean): NativeUInt;
begin
  Result := RedirectToLocal64(GetDefaultHookMemoryProvider, Ptr, NewOffset, Backup, ThreadSafe);
end;

function RedirectToLocal64(Provider: TNativePeMemoryProvider; Ptr: Pointer; NewOffset: UInt64; Backup: TPatchBackup;
  ThreadSafe: Boolean): NativeUInt;
const
  Hook64: array [0 .. 11] of Byte = ($48, $B8, $44, $55, $66, $77, $88, $99, $EE, $FF, $FF, $E0);
var
  HookBuf: array [0 .. 11] of Byte;
  OldProtect, RestoreProtect, ErrorCode: DWORD;
  FrozenThreads: TArray<DWORD>;
  FrozenCount: Integer;
  ActualSize: Integer;
begin
  Result := 0;
  if (Provider = nil) or (Ptr = nil) then
    Exit;
  if IsPointerInNtdll(Ptr) then
  begin
    LogWarning('Patching NTDLL is not allowed because of possible stability issues.');
    Exit;
  end;

  ActualSize := LdeGetTrampolineSize(Ptr, SizeOf(Hook64), True);
  if ActualSize < SizeOf(Hook64) then
    ActualSize := SizeOf(Hook64);

  FrozenCount := 0;
  if ThreadSafe then
    SuspendOtherThreads(FrozenThreads, FrozenCount);
  try
    OldProtect := 0;
    if not Provider.ProtectLocal(Ptr, NativeUInt(ActualSize), PAGE_EXECUTE_READWRITE, @OldProtect, ErrorCode) then
      Exit;

    if Assigned(Backup) then
      Backup.MakeBackup(PByte(Ptr), NativeUInt(ActualSize));

    Move(Hook64[0], HookBuf[0], SizeOf(HookBuf));
    Move(NewOffset, HookBuf[2], SizeOf(UInt64));
    Move(HookBuf, PByte(Ptr)^, SizeOf(HookBuf));

    RestoreProtect := 0;
    if not Provider.ProtectLocal(Ptr, NativeUInt(ActualSize), OldProtect, @RestoreProtect, ErrorCode) then
      LogWarning('Failed to restore protection of region: 0x%x', [NativeUInt(Ptr)]);

    Provider.FlushProcessInstructionCache(GetCurrentProcess, Ptr, NativeUInt(ActualSize), ErrorCode);
    Result := NativeUInt(ActualSize);
  finally
    if ThreadSafe then
      ResumeOtherThreads(FrozenThreads, FrozenCount);
  end;
end;

function RedirectToLocal32(Ptr: Pointer; NewOffset: DWORD; Backup: TPatchBackup; ThreadSafe: Boolean): NativeUInt;
begin
  Result := RedirectToLocal32(GetDefaultHookMemoryProvider, Ptr, NewOffset, Backup, ThreadSafe);
end;

function RedirectToLocal32(Provider: TNativePeMemoryProvider; Ptr: Pointer; NewOffset: DWORD; Backup: TPatchBackup;
  ThreadSafe: Boolean): NativeUInt;
const
  Hook32: array [0 .. 6] of Byte = ($B8, $CC, $DD, $EE, $FF, $FF, $E0);
var
  HookBuf: array [0 .. 6] of Byte;
  OldProtect, RestoreProtect, ErrorCode: DWORD;
  FrozenThreads: TArray<DWORD>;
  FrozenCount: Integer;
  ActualSize: Integer;
begin
  Result := 0;
  if (Provider = nil) or (Ptr = nil) then
    Exit;
  if IsPointerInNtdll(Ptr) then
  begin
    LogWarning('Patching NTDLL is not allowed because of possible stability issues.');
    Exit;
  end;

  ActualSize := LdeGetTrampolineSize(Ptr, SizeOf(Hook32), False);
  if ActualSize < SizeOf(Hook32) then
    ActualSize := SizeOf(Hook32);

  FrozenCount := 0;
  if ThreadSafe then
    SuspendOtherThreads(FrozenThreads, FrozenCount);
  try
    OldProtect := 0;
    if not Provider.ProtectLocal(Ptr, NativeUInt(ActualSize), PAGE_EXECUTE_READWRITE, @OldProtect, ErrorCode) then
      Exit;

    if Assigned(Backup) then
      Backup.MakeBackup(PByte(Ptr), NativeUInt(ActualSize));

    Move(Hook32[0], HookBuf[0], SizeOf(HookBuf));
    Move(NewOffset, HookBuf[1], SizeOf(DWORD));
    Move(HookBuf, PByte(Ptr)^, SizeOf(HookBuf));

    RestoreProtect := 0;
    if not Provider.ProtectLocal(Ptr, NativeUInt(ActualSize), OldProtect, @RestoreProtect, ErrorCode) then
      LogWarning('Failed to restore protection of region: 0x%x', [NativeUInt(Ptr)]);

    Provider.FlushProcessInstructionCache(GetCurrentProcess, Ptr, NativeUInt(ActualSize), ErrorCode);
    Result := NativeUInt(ActualSize);
  finally
    if ThreadSafe then
      ResumeOtherThreads(FrozenThreads, FrozenCount);
  end;
end;

function RedirectToLocal(Ptr: Pointer; NewFunctionPtr: Pointer; Backup: TPatchBackup; ThreadSafe: Boolean): NativeUInt;
begin
  Result := RedirectToLocal(GetDefaultHookMemoryProvider, Ptr, NewFunctionPtr, Backup, ThreadSafe);
end;

function RedirectToLocal(Provider: TNativePeMemoryProvider; Ptr: Pointer; NewFunctionPtr: Pointer; Backup: TPatchBackup;
  ThreadSafe: Boolean): NativeUInt;
begin
{$IFDEF WIN64}
  Result := RedirectToLocal64(Provider, Ptr, UInt64(NativeUInt(NewFunctionPtr)), Backup, ThreadSafe);
{$ELSE}
  Result := RedirectToLocal32(Provider, Ptr, DWORD(NativeUInt(NewFunctionPtr)), Backup, ThreadSafe);
{$ENDIF}
end;

function GetJmpDelta(CurrVA: UInt64; InstrLen: Integer; DestVA: UInt64): Int64;
begin
  Result := Int64(DestVA) - (Int64(CurrVA) + InstrLen);
end;

function IsValidDelta(Delta: Int64): Boolean;
var
  FirstDw: DWORD;
  MaxDword: DWORD;
  DeltaDw: DWORD;
begin
  FirstDw := DWORD(Delta shr 32);
  if FirstDw = 0 then
    Exit(True);
  MaxDword := DWORD(-1);
  if FirstDw <> MaxDword then
    Exit(False);
  DeltaDw := DWORD(Delta);
  if (DeltaDw and $80000000) <> 0 then
    Exit(True);
  Result := False;
end;

function ReplaceTarget(PatchPtr: PByte; DestAddr: UInt64): Boolean;
begin
  Result := ReplaceTarget(GetDefaultHookMemoryProvider, PatchPtr, DestAddr);
end;

function ReplaceTarget(Provider: TNativePeMemoryProvider; PatchPtr: PByte; DestAddr: UInt64): Boolean;
const
  OP_JMP = $E9;
  OP_CALL_DWORD = $E8;
var
  Delta: Int64;
  DeltaDw: DWORD;
  TargetPtr: PByte;
  ErrorCode: DWORD;
begin
  Result := False;
  if (Provider = nil) or (PatchPtr = nil) then
    Exit;
  if (PatchPtr[0] = OP_JMP) or (PatchPtr[0] = OP_CALL_DWORD) then
  begin
    Delta := GetJmpDelta(UInt64(NativeUInt(PatchPtr)), 5, DestAddr);
    if not IsValidDelta(Delta) then
    begin
      LogWarning('Cannot replace the target: delta 0x%x is too large for a DWORD.', [Delta]);
      Exit;
    end;
    DeltaDw := DWORD(Delta);
    TargetPtr := PByte(NativeUInt(PatchPtr) + 1);
    Move(DeltaDw, TargetPtr^, SizeOf(DWORD));
    Provider.FlushProcessInstructionCache(GetCurrentProcess, TargetPtr, SizeOf(DWORD), ErrorCode);
    Result := True;
  end;
end;

end.
