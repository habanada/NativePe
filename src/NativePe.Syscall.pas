{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.Syscall;

interface

uses
  Winapi.Windows;

var
  UseSyscalls: Boolean = False;

{$IFDEF WIN64}
function DirectNtAllocateVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; ZeroBits: NativeUInt;
  var RegionSize: NativeUInt; AllocationType, Protect: DWORD): LongInt;
function DirectNtFreeVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
  FreeType: DWORD): LongInt;
function DirectNtReadVirtualMemory(ProcessHandle: THandle; BaseAddress, Buffer: Pointer; BufferSize: NativeUInt;
  NumberOfBytesRead: PNativeUInt): LongInt;
function DirectNtProtectVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
  NewProtect: DWORD; OldProtect: PDWORD): LongInt;
function DirectNtQueryVirtualMemory(ProcessHandle: THandle; BaseAddress: Pointer; MemoryInformationClass: DWORD;
  MemoryInformation: Pointer; MemoryInformationLength: NativeUInt; ReturnLength: PNativeUInt): LongInt;
function DirectNtFlushInstructionCache(ProcessHandle: THandle; BaseAddress: Pointer; Length: NativeUInt): LongInt;
function DirectNtProtect(LpAddress: Pointer; DwSize: NativeUInt; FlNewProtect: DWORD; LpflOldProtect: PDWORD): Boolean;
{$ENDIF}

implementation

{$IFDEF WIN64}

uses
  NativePe.PebLookup,
  NativePe.ExportsLookup,
  NativePe.BufferUtil,
  NativePe.Logger;

const
  HaloRadius = 32;
  HaloStride = 32;
  StubStride = 16;
  StubCount = 6;
  StatusProcedureNotFound = LongInt(-1073741702);

type
  TSyscallIndex = (siAllocateVirtualMemory, siFreeVirtualMemory, siReadVirtualMemory, siProtectVirtualMemory,
    siQueryVirtualMemory, siFlushInstructionCache);
  TNtAllocateVirtualMemoryStub = function(ProcessHandle: THandle; var BaseAddress: Pointer; ZeroBits: NativeUInt;
    var RegionSize: NativeUInt; AllocationType, Protect: DWORD): LongInt; stdcall;
  TNtFreeVirtualMemoryStub = function(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
    FreeType: DWORD): LongInt; stdcall;
  TNtReadVirtualMemoryStub = function(ProcessHandle: THandle; BaseAddress, Buffer: Pointer; BufferSize: NativeUInt;
    NumberOfBytesRead: PNativeUInt): LongInt; stdcall;
  TNtProtectVirtualMemoryStub = function(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
    NewProtect: DWORD; OldProtect: PDWORD): LongInt; stdcall;
  TNtQueryVirtualMemoryStub = function(ProcessHandle: THandle; BaseAddress: Pointer; MemoryInformationClass: DWORD;
    MemoryInformation: Pointer; MemoryInformationLength: NativeUInt; ReturnLength: PNativeUInt): LongInt; stdcall;
  TNtFlushInstructionCacheStub = function(ProcessHandle: THandle; BaseAddress: Pointer; Length: NativeUInt): LongInt; stdcall;

var
  GStubPage: PByte = nil;
  GStubPointers: array[TSyscallIndex] of Pointer;
  GStubAttempted: array[TSyscallIndex] of Boolean;
  GInitLock: TRTLCriticalSection;

function CheckStubPattern(NtdllBase: Pointer; NtdllSize: NativeUInt; Ptr: PByte; out SSN: DWORD): Boolean;
begin
  Result := False;
  if not ValidatePtr(NtdllBase, NtdllSize, Ptr, 8) then
    Exit;
  if (Ptr[0] = $4C) and (Ptr[1] = $8B) and (Ptr[2] = $D1) and (Ptr[3] = $B8) and
     (Ptr[6] = $00) and (Ptr[7] = $00) then
  begin
    SSN := PDWORD(@Ptr[4])^;
    Result := True;
  end;
end;

function ResolveSSN(Name: PAnsiChar): Integer;
var
  NtdllBase: HMODULE;
  NtdllSize: NativeUInt;
  FuncPtr, Neighbor: PByte;
  SSN, NeighborSSN: DWORD;
  I: Integer;
  Inferred: Int64;
  Delta: NativeUInt;
begin
  Result := -1;
  NtdllBase := GetModuleViaPeb(PWideChar('ntdll.dll'));
  if NtdllBase = 0 then
    Exit;
  NtdllSize := GetModuleSizeViaPeb(NtdllBase);
  if NtdllSize = 0 then
    Exit;
  FuncPtr := PByte(GetExportedFunc(Pointer(NtdllBase), Name));
  if FuncPtr = nil then
    Exit;
  if CheckStubPattern(Pointer(NtdllBase), NtdllSize, FuncPtr, SSN) then
    Exit(Integer(SSN));
  for I := 1 to HaloRadius do
  begin
    Delta := NativeUInt(I * HaloStride);
    if NativeUInt(FuncPtr) <= High(NativeUInt) - Delta then
    begin
      Neighbor := PByte(NativeUInt(FuncPtr) + Delta);
      if CheckStubPattern(Pointer(NtdllBase), NtdllSize, Neighbor, NeighborSSN) then
      begin
        Inferred := Int64(NeighborSSN) - I;
        if (Inferred >= 0) and (Inferred <= High(Word)) then
          Exit(Integer(Inferred));
      end;
    end;
    if NativeUInt(FuncPtr) >= NativeUInt(NtdllBase) + Delta then
    begin
      Neighbor := PByte(NativeUInt(FuncPtr) - Delta);
      if CheckStubPattern(Pointer(NtdllBase), NtdllSize, Neighbor, NeighborSSN) then
      begin
        Inferred := Int64(NeighborSSN) + I;
        if Inferred <= High(Word) then
          Exit(Integer(Inferred));
      end;
    end;
  end;
end;

function BuildStub(Index: TSyscallIndex; Name: PAnsiChar): Boolean;
const
  StubTemplate: array[0..10] of Byte = ($4C, $8B, $D1, $B8, $00, $00, $00, $00, $0F, $05, $C3);
var
  SSN: Integer;
  Stub: PByte;
begin
  Result := False;
  SSN := ResolveSSN(Name);
  if SSN < 0 then
  begin
    LogWarning('DirectSyscall: could not resolve SSN for %s.', [string(AnsiString(Name))]);
    Exit;
  end;
  Stub := PByte(NativeUInt(GStubPage) + NativeUInt(Ord(Index) * StubStride));
  Move(StubTemplate, Stub^, SizeOf(StubTemplate));
  PDWORD(NativeUInt(Stub) + 4)^ := DWORD(SSN);
  GStubPointers[Index] := Stub;
  Result := True;
end;

function GetStub(Index: TSyscallIndex; Name: PAnsiChar): Pointer;
begin
  if GStubAttempted[Index] then
    Exit(GStubPointers[Index]);
  EnterCriticalSection(GInitLock);
  try
    if not GStubAttempted[Index] then
    begin
      if GStubPage = nil then
      begin
        GStubPage := VirtualAlloc(nil, StubStride * StubCount, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if GStubPage = nil then
          LogWarning('DirectSyscall: could not allocate stub page.');
      end;
      if GStubPage <> nil then
      begin
        BuildStub(Index, Name);
        if GStubPointers[Index] <> nil then
          FlushInstructionCache(GetCurrentProcess, GStubPointers[Index], StubStride);
      end;
      GStubAttempted[Index] := True;
    end;
    Result := GStubPointers[Index];
  finally
    LeaveCriticalSection(GInitLock);
  end;
end;

function DirectNtAllocateVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; ZeroBits: NativeUInt;
  var RegionSize: NativeUInt; AllocationType, Protect: DWORD): LongInt;
var
  Stub: TNtAllocateVirtualMemoryStub;
begin
  Stub := TNtAllocateVirtualMemoryStub(GetStub(siAllocateVirtualMemory, 'NtAllocateVirtualMemory'));
  if not Assigned(Stub) then
    Exit(StatusProcedureNotFound);
  Result := Stub(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
end;

function DirectNtFreeVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
  FreeType: DWORD): LongInt;
var
  Stub: TNtFreeVirtualMemoryStub;
begin
  Stub := TNtFreeVirtualMemoryStub(GetStub(siFreeVirtualMemory, 'NtFreeVirtualMemory'));
  if not Assigned(Stub) then
    Exit(StatusProcedureNotFound);
  Result := Stub(ProcessHandle, BaseAddress, RegionSize, FreeType);
end;

function DirectNtReadVirtualMemory(ProcessHandle: THandle; BaseAddress, Buffer: Pointer; BufferSize: NativeUInt;
  NumberOfBytesRead: PNativeUInt): LongInt;
var
  Stub: TNtReadVirtualMemoryStub;
begin
  Stub := TNtReadVirtualMemoryStub(GetStub(siReadVirtualMemory, 'NtReadVirtualMemory'));
  if not Assigned(Stub) then
    Exit(StatusProcedureNotFound);
  Result := Stub(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
end;

function DirectNtProtectVirtualMemory(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
  NewProtect: DWORD; OldProtect: PDWORD): LongInt;
var
  Stub: TNtProtectVirtualMemoryStub;
begin
  Stub := TNtProtectVirtualMemoryStub(GetStub(siProtectVirtualMemory, 'NtProtectVirtualMemory'));
  if not Assigned(Stub) then
    Exit(StatusProcedureNotFound);
  Result := Stub(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
end;

function DirectNtQueryVirtualMemory(ProcessHandle: THandle; BaseAddress: Pointer; MemoryInformationClass: DWORD;
  MemoryInformation: Pointer; MemoryInformationLength: NativeUInt; ReturnLength: PNativeUInt): LongInt;
var
  Stub: TNtQueryVirtualMemoryStub;
begin
  Stub := TNtQueryVirtualMemoryStub(GetStub(siQueryVirtualMemory, 'NtQueryVirtualMemory'));
  if not Assigned(Stub) then
    Exit(StatusProcedureNotFound);
  Result := Stub(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
end;

function DirectNtFlushInstructionCache(ProcessHandle: THandle; BaseAddress: Pointer; Length: NativeUInt): LongInt;
var
  Stub: TNtFlushInstructionCacheStub;
begin
  Stub := TNtFlushInstructionCacheStub(GetStub(siFlushInstructionCache, 'NtFlushInstructionCache'));
  if not Assigned(Stub) then
    Exit(StatusProcedureNotFound);
  Result := Stub(ProcessHandle, BaseAddress, Length);
end;

function DirectNtProtect(LpAddress: Pointer; DwSize: NativeUInt; FlNewProtect: DWORD; LpflOldProtect: PDWORD): Boolean;
var
  BaseAddress: Pointer;
  RegionSize: NativeUInt;
begin
  if LpflOldProtect = nil then
    Exit(False);
  BaseAddress := LpAddress;
  RegionSize := DwSize;
  Result := DirectNtProtectVirtualMemory(THandle(NativeInt(-1)), BaseAddress, RegionSize, FlNewProtect, LpflOldProtect) = 0;
end;

initialization
  InitializeCriticalSection(GInitLock);

finalization
  if GStubPage <> nil then
  begin
    VirtualFree(GStubPage, 0, MEM_RELEASE);
    GStubPage := nil;
  end;
  FillChar(GStubPointers, SizeOf(GStubPointers), 0);
  FillChar(GStubAttempted, SizeOf(GStubAttempted), 0);
  DeleteCriticalSection(GInitLock);

{$ENDIF}

end.
