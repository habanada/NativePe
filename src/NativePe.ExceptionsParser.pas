{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/exceptions_parser.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.	
}
unit NativePe.ExceptionsParser;

interface

uses
  Winapi.Windows,
  NativePe.Types;

var
  AutoRegisterExceptions: Boolean = False;

function SetupExceptions(ModulePtr: PByte; ModuleSize: NativeUInt = 0): Boolean;

implementation

uses
  System.SysUtils,
  System.AnsiStrings,
  NativePe.PeHdrsHelper,
  NativePe.ExportsLookup,
  NativePe.PebLookup,
  NativePe.Logger;

const
  LDR_MODULES_UNLOADED = -2;
  IMAGE_DLLCHARACTERISTICS_NO_SEH = $0400;
  RTL_VERIFY_FLAGS_MAJOR_VERSION = 0;
  RTL_VERIFY_FLAGS_MINOR_VERSION = 1;
  RTL_VERIFY_FLAGS_BUILD_NUMBERS = 2;
  STATUS_NOT_SUPPORTED = LongInt(DWORD($C00000BB));
  STATUS_NO_MEMORY = LongInt(DWORD($C0000017));
  STATUS_SUCCESS = LongInt(0);
  MEMORY_BASIC_INFORMATION_CLASS = 0;

type
  TRtlGetNtVersionNumbers = procedure(out NtMajorVersion, NtMinorVersion, NtBuildNumber: DWORD); stdcall;
  TNtProtectVirtualMemory = function(ProcessHandle: THandle; var BaseAddress: Pointer; var RegionSize: NativeUInt;
    NewProtect: DWORD; OldProtect: PDWORD): LongInt; stdcall;
  TNtQueryVirtualMemory = function(ProcessHandle: THandle; BaseAddress: Pointer; MemoryInformationClass: DWORD;
    MemoryInformation: Pointer; MemoryInformationLength: NativeUInt; ReturnLength: PNativeUInt): LongInt; stdcall;
  TRtlEncodeSystemPointer = function(Ptr: Pointer): Pointer; stdcall;

  TSearchContext = record
    SearchPattern: PByte;
    PatternSize: NativeUInt;
    ResultPtr: PByte;
    MemoryBlockSize: NativeUInt;
  end;

  TRtlInvertedFunctionTableEntry64 = record
    ExceptionDirectory: Pointer;
    ImageBase: Pointer;
    ImageSize: DWORD;
    ExceptionDirectorySize: DWORD;
  end;

  PRtlInvertedFunctionTable64 = ^TRtlInvertedFunctionTable64;
  TRtlInvertedFunctionTable64 = record
    Count: DWORD;
    MaxCount: DWORD;
    Epoch: DWORD;
    Overflow: DWORD;
    Entries: array [0 .. $1FF] of TRtlInvertedFunctionTableEntry64;
  end;

  PRtlInvertedFunctionTableEntryWin8Plus32 = ^TRtlInvertedFunctionTableEntryWin8Plus32;
  TRtlInvertedFunctionTableEntryWin8Plus32 = record
    EntrySEHandlerTableEncoded: Pointer;
    ImageBase: Pointer;
    ImageSize: DWORD;
    SEHandlerCount: DWORD;
  end;

  TRtlInvertedFunctionTableEntryWin7_32 = record
    ImageBase: Pointer;
    ImageSize: DWORD;
    SEHandlerCount: DWORD;
    EntrySEHandlerTableEncoded: Pointer;
  end;

  PRtlInvertedFunctionTableWin7_32 = ^TRtlInvertedFunctionTableWin7_32;
  TRtlInvertedFunctionTableWin7_32 = record
    Count: DWORD;
    MaxCount: DWORD;
    Overflow: DWORD;
    NextEntrySEHandlerTableEncoded: DWORD;
    Entries: array [0 .. $1FF] of TRtlInvertedFunctionTableEntryWin7_32;
  end;

  PLdrDdagNodeWin8 = ^TLdrDdagNodeWin8;
  TLdrDdagNodeWin8 = record
    Modules: TListEntry;
    ServiceTagList: Pointer;
    LoadCount: DWORD;
    ReferenceCount: DWORD;
    DependencyCount: DWORD;
    Dependencies: Pointer;
    IncomingDependencies: Pointer;
    State: Integer;
  end;

  PLdrDataTableEntryWin8 = ^TLdrDataTableEntryWin8;
  TLdrDataTableEntryWin8 = record
    InLoadOrderLinks: TListEntry;
    InMemoryOrderLinks: TListEntry;
    InInitOrProgressLinks: TListEntry;
    DllBase: Pointer;
    EntryPoint: Pointer;
    SizeOfImage: DWORD;
    FullDllName: TUnicodeString;
    BaseDllName: TUnicodeString;
    FlagsUnion: DWORD;
    ObsoleteLoadCount: Word;
    TlsIndex: Word;
    HashLinks: TListEntry;
    TimeDateStamp: DWORD;
    EntryPointActivationContext: Pointer;
    PatchInformation: Pointer;
    DdagNode: PLdrDdagNodeWin8;
  end;

{$IFNDEF WIN64}
  PLoadConfigDir32Min = ^TLoadConfigDir32Min;
  TLoadConfigDir32Min = packed record
    Size: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    GlobalFlagsClear: DWORD;
    GlobalFlagsSet: DWORD;
    CriticalSectionDefaultTimeout: DWORD;
    DeCommitFreeBlockThreshold: DWORD;
    DeCommitTotalFreeThreshold: DWORD;
    LockPrefixTable: DWORD;
    MaximumAllocationSize: DWORD;
    VirtualMemoryThreshold: DWORD;
    ProcessHeapFlags: DWORD;
    ProcessAffinityMask: DWORD;
    CSDVersion: Word;
    Reserved1: Word;
    EditList: DWORD;
    SecurityCookie: DWORD;
    SEHandlerTable: DWORD;
    SEHandlerCount: DWORD;
  end;
{$ENDIF}

function ResolveNtdllProc(const Name: PAnsiChar): FARPROC;
begin
  Result := GetExportedFunc(Pointer(GetModuleViaPeb(PWideChar('ntdll.dll'))), Name);
end;

procedure RtlCurrentVersion(out MajorVersion, MinorVersion, BuildNumber: DWORD);
var
  Fn: TRtlGetNtVersionNumbers;
begin
  MajorVersion := 0;
  MinorVersion := 0;
  BuildNumber := 0;
  Fn := TRtlGetNtVersionNumbers(ResolveNtdllProc('RtlGetNtVersionNumbers'));
  if Assigned(Fn) then
    Fn(MajorVersion, MinorVersion, BuildNumber);
end;

function RtlIsWindowsVersionOrGreater(MajorVersion, MinorVersion, BuildNumber: DWORD): Boolean;
var
  CurMajor, CurMinor, CurBuild: DWORD;
begin
  RtlCurrentVersion(CurMajor, CurMinor, CurBuild);
  if CurMajor = MajorVersion then
  begin
    if CurMinor = MinorVersion then
      Result := CurBuild >= BuildNumber
    else
      Result := CurMinor > MinorVersion;
  end
  else
    Result := CurMajor > MajorVersion;
end;

function RtlVerifyVersion(MajorVersion, MinorVersion, BuildNumber: DWORD; Flags: Byte): Boolean;
var
  CurMajor, CurMinor, CurBuild: DWORD;
  MinorOk, BuildOk: Boolean;
begin
  RtlCurrentVersion(CurMajor, CurMinor, CurBuild);
  if (Flags and RTL_VERIFY_FLAGS_MINOR_VERSION) <> 0 then
    MinorOk := CurMinor = MinorVersion
  else
    MinorOk := True;
  if (Flags and RTL_VERIFY_FLAGS_BUILD_NUMBERS) <> 0 then
    BuildOk := CurBuild = BuildNumber
  else
    BuildOk := True;
  Result := (CurMajor = MajorVersion) and MinorOk and BuildOk;
end;

function IsModuleUnloaded(Entry: PLdrDataTableEntry): Boolean;
begin
  if RtlIsWindowsVersionOrGreater(6, 2, 0) then
    Result := PLdrDataTableEntryWin8(Entry).DdagNode.State = LDR_MODULES_UNLOADED
  else
    Result := Entry.DllBase = nil;
end;

function SectionNameMatches(SectionHdr: PImageSectionHeader; const Wanted: AnsiString): Boolean;
begin
  Result := System.AnsiStrings.StrLIComp(PAnsiChar(@SectionHdr.Name[0]), PAnsiChar(Wanted), 8) = 0;
end;

function RtlFindMemoryBlockFromModuleSection(ModuleHandle: HMODULE; const SectionName: AnsiString;
  var SearchContext: TSearchContext): Boolean;
var
  ModuleSize: NativeUInt;
  SecCount, I: NativeUInt;
  SectionHdr: PImageSectionHeader;
  Found: Boolean;
  EndPtr: PByte;
begin
  try
    if (SearchContext.SearchPattern = nil) or (SearchContext.PatternSize = 0) then
    begin
      SearchContext.ResultPtr := nil;
      SearchContext.MemoryBlockSize := 0;
      Exit(False);
    end;

    if SearchContext.ResultPtr <> nil then
    begin
      Inc(SearchContext.ResultPtr);
      Dec(SearchContext.MemoryBlockSize);
    end
    else
    begin
      ModuleSize := GetModuleSizeViaPeb(ModuleHandle);
      if ModuleSize = 0 then
        Exit(False);

      Found := False;
      SecCount := GetSectionsCount(PByte(ModuleHandle), ModuleSize);
      I := 0;
      while I < SecCount do
      begin
        SectionHdr := GetSectionHdr(PByte(ModuleHandle), ModuleSize, I);
        if (SectionHdr <> nil) and SectionNameMatches(SectionHdr, SectionName) then
        begin
          SearchContext.ResultPtr := PByte(NativeUInt(ModuleHandle) + SectionHdr.VirtualAddress);
          SearchContext.MemoryBlockSize := GetVirtualSecSize(PByte(ModuleHandle), SectionHdr, False);
          Found := True;
          Break;
        end;
        Inc(I);
      end;

      if (not Found) or (SearchContext.MemoryBlockSize = 0) or (SearchContext.MemoryBlockSize < SearchContext.PatternSize) then
      begin
        SearchContext.ResultPtr := nil;
        SearchContext.MemoryBlockSize := 0;
        Exit(False);
      end;
    end;

    EndPtr := SearchContext.ResultPtr + (SearchContext.MemoryBlockSize - SearchContext.PatternSize);
    while NativeUInt(SearchContext.ResultPtr) <= NativeUInt(EndPtr) do
    begin
      if CompareMem(SearchContext.SearchPattern, SearchContext.ResultPtr, SearchContext.PatternSize) then
        Exit(True);
      Inc(SearchContext.ResultPtr);
      Dec(SearchContext.MemoryBlockSize);
    end;

    SearchContext.ResultPtr := nil;
    SearchContext.MemoryBlockSize := 0;
    Result := False;
  except
    Result := False;
  end;
end;

var
  GMrdataBase: Pointer = nil;
  GMrdataSize: NativeUInt = 0;

function RtlProtectMrdata(NewProtect: DWORD; Mrdata: Pointer): LongInt;
var
  QueryFn: TNtQueryVirtualMemory;
  ProtectFn: TNtProtectVirtualMemory;
  Mbi: TMemoryBasicInformation;
  TmpPtr: Pointer;
  TmpLen: NativeUInt;
  OldProtect: DWORD;
begin
  if GMrdataBase = nil then
  begin
    QueryFn := TNtQueryVirtualMemory(ResolveNtdllProc('NtQueryVirtualMemory'));
    if not Assigned(QueryFn) then
      Exit(STATUS_NOT_SUPPORTED);
    FillChar(Mbi, SizeOf(Mbi), 0);
    Result := QueryFn(GetCurrentProcess, Mrdata, MEMORY_BASIC_INFORMATION_CLASS, @Mbi, SizeOf(Mbi), nil);
    if Result <> STATUS_SUCCESS then
      Exit;
    GMrdataBase := Mbi.BaseAddress;
    GMrdataSize := Mbi.RegionSize;
  end;

  ProtectFn := TNtProtectVirtualMemory(ResolveNtdllProc('NtProtectVirtualMemory'));
  if not Assigned(ProtectFn) then
    Exit(STATUS_NOT_SUPPORTED);
  TmpPtr := GMrdataBase;
  TmpLen := GMrdataSize;
  Result := ProtectFn(GetCurrentProcess, TmpPtr, TmpLen, NewProtect, @OldProtect);
end;

{$IFDEF WIN64}

function RtlFindInvertedFunctionTable: Pointer;
var
  HModule_, HNtdll: HMODULE;
  SectionName: AnsiString;
  Entry: TRtlInvertedFunctionTableEntry64;
  Dir: PImageDataDirectory;
  SearchContext: TSearchContext;
  Tab: PRtlInvertedFunctionTable64;
  Peb: PPeb;
  ListHead, ListEntry: PListEntry;
  CurEntry: PLdrDataTableEntry;
  ModuleHeaders, NtdllHeaders: PImageNtHeaders64;
begin
  Result := nil;
  HNtdll := GetModuleViaPeb(PWideChar('ntdll.dll'));
  if HNtdll = 0 then
    Exit;
  NtdllHeaders := GetNtHdrs64(PByte(HNtdll));
  SectionName := '.data';
  HModule_ := 0;
  ModuleHeaders := nil;

  if RtlVerifyVersion(6, 2, 0, RTL_VERIFY_FLAGS_MAJOR_VERSION or RTL_VERIFY_FLAGS_MINOR_VERSION) then
  begin
    HModule_ := HNtdll;
    ModuleHeaders := NtdllHeaders;
  end
  else if RtlIsWindowsVersionOrGreater(6, 3, 0) then
  begin
    HModule_ := HNtdll;
    ModuleHeaders := NtdllHeaders;
    SectionName := '.mrdata';
  end
  else
  begin
    Peb := GetCurrentPeb;
    if Peb = nil then
      Exit;
    ListHead := @Peb.Ldr.InLoadOrderModuleList;
    ListEntry := PListEntry(ListHead.Flink);
    while ListEntry <> ListHead do
    begin
      CurEntry := PLdrDataTableEntry(ListEntry);
      ListEntry := PListEntry(ListEntry.Flink);
      if (HModule_ = 0) or (NativeUInt(CurEntry.DllBase) < NativeUInt(HModule_)) then
        HModule_ := HMODULE(CurEntry.DllBase);
    end;
    if HModule_ <> 0 then
      ModuleHeaders := GetNtHdrs64(PByte(HModule_));
  end;

  if (HModule_ = 0) or (ModuleHeaders = nil) or (HNtdll = 0) or (NtdllHeaders = nil) then
    Exit;

  Dir := GetDirectoryEntry(PByte(HModule_), IMAGE_DIRECTORY_ENTRY_EXCEPTION, True);
  FillChar(Entry, SizeOf(Entry), 0);
  if (Dir <> nil) and (Dir.Size <> 0) then
    Entry.ExceptionDirectory := Pointer(NativeUInt(HModule_) + Dir.VirtualAddress)
  else
    Entry.ExceptionDirectory := nil;
  Entry.ImageBase := Pointer(HModule_);
  Entry.ImageSize := ModuleHeaders.OptionalHeader.SizeOfImage;
  if Dir <> nil then
    Entry.ExceptionDirectorySize := Dir.Size
  else
    Entry.ExceptionDirectorySize := 0;

  FillChar(SearchContext, SizeOf(SearchContext), 0);
  SearchContext.SearchPattern := PByte(@Entry);
  SearchContext.PatternSize := SizeOf(Entry);

  while RtlFindMemoryBlockFromModuleSection(HNtdll, SectionName, SearchContext) do
  begin
    Tab := PRtlInvertedFunctionTable64(SearchContext.ResultPtr - $10);
    if RtlIsWindowsVersionOrGreater(6, 2, 0) and (Tab.MaxCount = $200) and (Tab.Overflow = 0) then
      Exit(Tab);
    if (Tab.MaxCount = $200) and (Tab.Epoch = 0) then
      Exit(Tab);
  end;
  Result := nil;
end;

procedure RtlpInsertInvertedFunctionTable(InvertedTable: PRtlInvertedFunctionTable64; ImageBase: Pointer;
  SizeOfImage: DWORD);
var
  CurrentSize, Index: DWORD;
  IsWin8OrGreater: Boolean;
  Dir: PImageDataDirectory;
  FunctionTable: Pointer;
  SizeOfTable: DWORD;
begin
  CurrentSize := InvertedTable.Count;
  IsWin8OrGreater := RtlIsWindowsVersionOrGreater(6, 2, 0);
  if IsWin8OrGreater then
    Index := 1
  else
    Index := 0;

  if CurrentSize <> InvertedTable.MaxCount then
  begin
    if CurrentSize <> 0 then
    begin
      while Index < CurrentSize do
      begin
        if NativeUInt(ImageBase) < NativeUInt(InvertedTable.Entries[Index].ImageBase) then
          Break;
        Inc(Index);
      end;

      if Index <> CurrentSize then
        Move(InvertedTable.Entries[Index], InvertedTable.Entries[Index + 1],
          (CurrentSize - Index) * SizeOf(TRtlInvertedFunctionTableEntry64));
    end;

    Dir := GetDirectoryEntry(PByte(ImageBase), IMAGE_DIRECTORY_ENTRY_EXCEPTION, True);
    if (Dir <> nil) and (Dir.Size <> 0) then
    begin
      FunctionTable := Pointer(NativeUInt(ImageBase) + Dir.VirtualAddress);
      SizeOfTable := Dir.Size;
    end
    else
    begin
      FunctionTable := nil;
      SizeOfTable := 0;
    end;

    InvertedTable.Entries[Index].ExceptionDirectory := FunctionTable;
    InvertedTable.Entries[Index].ImageBase := ImageBase;
    InvertedTable.Entries[Index].ImageSize := SizeOfImage;
    InvertedTable.Entries[Index].ExceptionDirectorySize := SizeOfTable;
    Inc(InvertedTable.Count);
    LogInfo('Exception table was set.');
  end
  else
  begin
    if IsWin8OrGreater then
      InvertedTable.Overflow := 1
    else
      InvertedTable.Epoch := 1;
  end;
end;

{$ELSE}

function RtlCaptureImageExceptionValues(BaseAddress: Pointer; out SEHandlerTable, SEHandlerCount: DWORD): Integer;
var
  DllChar: Word;
  LoadConfigDir, ComDir: PImageDataDirectory;
  Cor20: PImageCor20Header;
  LcdPtr: PLoadConfigDir32Min;
begin
  Result := 0;
  DllChar := GetDllCharacteristics(PByte(BaseAddress));
  if (DllChar and IMAGE_DLLCHARACTERISTICS_NO_SEH) <> 0 then
  begin
    SEHandlerTable := DWORD(-1);
    SEHandlerCount := DWORD(-1);
    Exit(0);
  end;

  SEHandlerTable := 0;
  SEHandlerCount := 0;

  LoadConfigDir := GetDirectoryEntry(PByte(BaseAddress), IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, True);
  if (LoadConfigDir <> nil) and (LoadConfigDir.VirtualAddress <> 0) and (LoadConfigDir.Size = $40) then
  begin
    LcdPtr := PLoadConfigDir32Min(NativeUInt(BaseAddress) + LoadConfigDir.VirtualAddress);
    if LcdPtr.Size >= $48 then
      if (LcdPtr.SEHandlerTable <> 0) and (LcdPtr.SEHandlerCount <> 0) then
      begin
        SEHandlerTable := LcdPtr.SEHandlerTable;
        SEHandlerCount := LcdPtr.SEHandlerCount;
        Exit(SEHandlerCount);
      end;
  end;

  ComDir := GetDirectoryEntry(PByte(BaseAddress), IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, True);
  Cor20 := nil;
  if (ComDir <> nil) and (ComDir.VirtualAddress <> 0) then
    Cor20 := GetDotNetHdr(PByte(BaseAddress), GetImageSize(PByte(BaseAddress)), ComDir);
  if (Cor20 <> nil) and ((Cor20.Flags and 1) <> 0) then
  begin
    SEHandlerTable := DWORD(-1);
    SEHandlerCount := DWORD(-1);
  end
  else
  begin
    SEHandlerTable := 0;
    SEHandlerCount := 0;
  end;
  Result := 0;
end;

function ContainingLdrEntryFromMemOrderLinks(P: PListEntry): PLdrDataTableEntry;
begin
  Result := PLdrDataTableEntry(NativeUInt(P) - NativeUInt(@PLdrDataTableEntry(nil).InMemoryOrderLinks));
end;

function RtlFindInvertedFunctionTable: Pointer;
var
  HModule_, HNtdll: HMODULE;
  NtdllHeaders, ModuleHeaders: PImageNtHeaders32;
  EntryWin7: TRtlInvertedFunctionTableEntryWin7_32;
  Entry2: PRtlInvertedFunctionTableEntryWin8Plus32;
  SearchContext: TSearchContext;
  SectionName: AnsiString;
  Peb: PPeb;
  ListHead, ListEntry: PListEntry;
  CurEntry: PLdrDataTableEntry;
  SEHTable, SEHCount: DWORD;
  Offset: Byte;
  Tab: PRtlInvertedFunctionTableWin7_32;
  RtlEncodeSystemPointerFn: TRtlEncodeSystemPointer;
  EncodedPtr: Pointer;
begin
  Result := nil;
  HNtdll := GetModuleViaPeb(PWideChar('ntdll.dll'));
  if HNtdll = 0 then
    Exit;
  NtdllHeaders := GetNtHdrs32(PByte(HNtdll));

  FillChar(EntryWin7, SizeOf(EntryWin7), 0);
  SectionName := '.data';
  FillChar(SearchContext, SizeOf(SearchContext), 0);
  SearchContext.SearchPattern := PByte(@EntryWin7);
  SearchContext.PatternSize := SizeOf(EntryWin7);

  Offset := $20;
  if RtlIsWindowsVersionOrGreater(6, 3, 0) then
    SectionName := '.mrdata'
  else if not RtlIsWindowsVersionOrGreater(6, 2, 0) then
    Offset := $C;

  Peb := GetCurrentPeb;
  if Peb = nil then
    Exit;
  HModule_ := 0;
  ListHead := @Peb.Ldr.InMemoryOrderModuleList;
  ListEntry := PListEntry(ListHead.Flink);
  while ListEntry <> ListHead do
  begin
    CurEntry := ContainingLdrEntryFromMemOrderLinks(ListEntry);
    ListEntry := PListEntry(ListEntry.Flink);
    if IsModuleUnloaded(CurEntry) then
      Continue;
    if (HMODULE(CurEntry.DllBase) = HNtdll) and (Offset = $20) then
      Continue;
    if (HModule_ = 0) or (NativeUInt(CurEntry.DllBase) < NativeUInt(HModule_)) then
      HModule_ := HMODULE(CurEntry.DllBase);
  end;

  if HModule_ <> 0 then
    ModuleHeaders := GetNtHdrs32(PByte(HModule_))
  else
    ModuleHeaders := nil;
  if (HModule_ = 0) or (ModuleHeaders = nil) or (HNtdll = 0) or (NtdllHeaders = nil) then
    Exit;

  RtlCaptureImageExceptionValues(Pointer(HModule_), SEHTable, SEHCount);

  RtlEncodeSystemPointerFn := TRtlEncodeSystemPointer(ResolveNtdllProc('RtlEncodeSystemPointer'));
  if Assigned(RtlEncodeSystemPointerFn) then
    EncodedPtr := RtlEncodeSystemPointerFn(Pointer(NativeUInt(SEHTable)))
  else
    EncodedPtr := Pointer(NativeUInt(SEHTable));

  if RtlIsWindowsVersionOrGreater(6, 2, 0) then
  begin
    Entry2 := PRtlInvertedFunctionTableEntryWin8Plus32(@EntryWin7);
    Entry2.EntrySEHandlerTableEncoded := EncodedPtr;
    Entry2.ImageBase := Pointer(HModule_);
    Entry2.ImageSize := ModuleHeaders.OptionalHeader.SizeOfImage;
    Entry2.SEHandlerCount := SEHCount;
  end
  else
  begin
    EntryWin7.EntrySEHandlerTableEncoded := EncodedPtr;
    EntryWin7.ImageBase := Pointer(HModule_);
    EntryWin7.ImageSize := ModuleHeaders.OptionalHeader.SizeOfImage;
    EntryWin7.SEHandlerCount := SEHCount;
  end;

  while RtlFindMemoryBlockFromModuleSection(HNtdll, SectionName, SearchContext) do
  begin
    Tab := PRtlInvertedFunctionTableWin7_32(SearchContext.ResultPtr - Offset);
    if RtlIsWindowsVersionOrGreater(6, 2, 0) and (Tab.MaxCount = $200) and (Tab.NextEntrySEHandlerTableEncoded = 0) then
      Exit(Tab);
    if (Tab.MaxCount = $200) and (Tab.Overflow = 0) then
      Exit(Tab);
  end;
  Result := nil;
end;

procedure RtlpInsertInvertedFunctionTable(InvertedTable: PRtlInvertedFunctionTableWin7_32; ImageBase: Pointer;
  SizeOfImage: DWORD);
var
  Ptr, Count: DWORD;
  IsWin8OrGreater: Boolean;
  Index: DWORD;
  Entry2: PRtlInvertedFunctionTableEntryWin8Plus32;
  RtlEncodeSystemPointerFn: TRtlEncodeSystemPointer;
  EncodedPtr: Pointer;
begin
  Ptr := 0;
  Count := 0;
  IsWin8OrGreater := RtlIsWindowsVersionOrGreater(6, 2, 0);
  if IsWin8OrGreater then
    Index := 1
  else
    Index := 0;

  if InvertedTable.Count = InvertedTable.MaxCount then
  begin
    if IsWin8OrGreater then
      InvertedTable.NextEntrySEHandlerTableEncoded := 1
    else
      InvertedTable.Overflow := 1;
    Exit;
  end;

  while Index < InvertedTable.Count do
  begin
    if IsWin8OrGreater then
    begin
      if NativeUInt(ImageBase) < NativeUInt(PRtlInvertedFunctionTableEntryWin8Plus32(@InvertedTable.Entries[Index]).ImageBase) then
        Break;
    end
    else
    begin
      if NativeUInt(ImageBase) < NativeUInt(InvertedTable.Entries[Index].ImageBase) then
        Break;
    end;
    Inc(Index);
  end;

  if Index <> InvertedTable.Count then
  begin
    if IsWin8OrGreater then
      Move(InvertedTable.Entries[Index], InvertedTable.Entries[Index + 1],
        (InvertedTable.Count - Index) * SizeOf(TRtlInvertedFunctionTableEntryWin7_32))
    else if Index <> 0 then
      Move(InvertedTable.Entries[Index - 1].EntrySEHandlerTableEncoded, InvertedTable.Entries[Index].EntrySEHandlerTableEncoded,
        (InvertedTable.Count - Index) * SizeOf(TRtlInvertedFunctionTableEntryWin7_32))
    else
      Move(InvertedTable.NextEntrySEHandlerTableEncoded, InvertedTable.Entries[Index].EntrySEHandlerTableEncoded,
        (InvertedTable.Count - Index) * SizeOf(TRtlInvertedFunctionTableEntryWin7_32));
  end;

  RtlCaptureImageExceptionValues(ImageBase, Ptr, Count);

  RtlEncodeSystemPointerFn := TRtlEncodeSystemPointer(ResolveNtdllProc('RtlEncodeSystemPointer'));
  if Assigned(RtlEncodeSystemPointerFn) then
    EncodedPtr := RtlEncodeSystemPointerFn(Pointer(NativeUInt(Ptr)))
  else
    EncodedPtr := Pointer(NativeUInt(Ptr));

  if IsWin8OrGreater then
  begin
    Entry2 := PRtlInvertedFunctionTableEntryWin8Plus32(@InvertedTable.Entries[Index]);
    Entry2.EntrySEHandlerTableEncoded := EncodedPtr;
    Entry2.SEHandlerCount := Count;
    Entry2.ImageBase := ImageBase;
    Entry2.ImageSize := SizeOfImage;
  end
  else
  begin
    if Index <> 0 then
      InvertedTable.Entries[Index - 1].EntrySEHandlerTableEncoded := EncodedPtr
    else
      InvertedTable.NextEntrySEHandlerTableEncoded := DWORD(NativeUInt(EncodedPtr));
    InvertedTable.Entries[Index].ImageBase := ImageBase;
    InvertedTable.Entries[Index].ImageSize := SizeOfImage;
    InvertedTable.Entries[Index].SEHandlerCount := Count;
  end;
  LogDebug('Exception table was set.');
  Inc(InvertedTable.Count);
end;

{$ENDIF}

function RtlInsertInvertedFunctionTable(BaseAddress: Pointer; ImageSize: DWORD): LongInt;
var
  Table: Pointer;
  NeedVirtualProtect: Boolean;
  Overflow: Boolean;
begin
  Table := RtlFindInvertedFunctionTable;
  if Table = nil then
  begin
    LogInfo('Exception table not found.');
    Exit(STATUS_NOT_SUPPORTED);
  end;
  LogInfo('Found exception table: 0x%x.', [NativeUInt(Table)]);

  NeedVirtualProtect := RtlIsWindowsVersionOrGreater(6, 3, 0);
  if NeedVirtualProtect then
    LogDebug('Need virtual protect: true.')
  else
    LogDebug('Need virtual protect: false.');

  if NeedVirtualProtect then
  begin
    Result := RtlProtectMrdata(PAGE_READWRITE, Table);
    if Result <> STATUS_SUCCESS then
      Exit;
  end;

{$IFDEF WIN64}
  RtlpInsertInvertedFunctionTable(PRtlInvertedFunctionTable64(Table), BaseAddress, ImageSize);
{$ELSE}
  RtlpInsertInvertedFunctionTable(PRtlInvertedFunctionTableWin7_32(Table), BaseAddress, ImageSize);
{$ENDIF}

  if NeedVirtualProtect then
  begin
    Result := RtlProtectMrdata(PAGE_READONLY, Table);
    if Result <> STATUS_SUCCESS then
      Exit;
  end;

  if RtlIsWindowsVersionOrGreater(6, 2, 0) then
    Overflow := PRtlInvertedFunctionTable64(Table).Overflow <> 0
  else
    Overflow := PRtlInvertedFunctionTableWin7_32(Table).Overflow <> 0;

  if Overflow then
    Result := STATUS_NO_MEMORY
  else
    Result := STATUS_SUCCESS;
end;

function SetupExceptions(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;
var
  ImgSize: DWORD;
  Status: LongInt;
begin
  Result := False;
  if ModuleSize = 0 then
  begin
    ImgSize := GetImageSize(ModulePtr);
    if ImgSize = 0 then
      Exit;
    ModuleSize := ImgSize;
  end;
  Status := RtlInsertInvertedFunctionTable(ModulePtr, DWORD(ModuleSize));
  Result := Status >= 0;
end;

end.
