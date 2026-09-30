{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/load_config_util.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.LoadConfig;

interface

uses
  Winapi.Windows,
  NativePe.Types;

const
  LOAD_CONFIG_NONE = 0;
  LOAD_CONFIG_W7_VER = 7;
  LOAD_CONFIG_W8_VER = 8;
  LOAD_CONFIG_W10_VER = 10;
  LOAD_CONFIG_UNK_VER = -1;

type
  TLoadConfigVer = LongInt;

  TImageLoadConfigCodeIntegrityW10 = packed record
    Flags: Word;
    Catalog: Word;
    CatalogOffset: DWORD;
    Reserved: DWORD;
  end;

  TImageLoadConfigDir32W7 = packed record
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
    DependentLoadFlags: Word;
    EditList: DWORD;
    SecurityCookie: DWORD;
    SEHandlerTable: DWORD;
    SEHandlerCount: DWORD;
  end;
  PImageLoadConfigDir32W7 = ^TImageLoadConfigDir32W7;

  TImageLoadConfigDir64W7 = packed record
    Size: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    GlobalFlagsClear: DWORD;
    GlobalFlagsSet: DWORD;
    CriticalSectionDefaultTimeout: DWORD;
    DeCommitFreeBlockThreshold: UInt64;
    DeCommitTotalFreeThreshold: UInt64;
    LockPrefixTable: UInt64;
    MaximumAllocationSize: UInt64;
    VirtualMemoryThreshold: UInt64;
    ProcessAffinityMask: UInt64;
    ProcessHeapFlags: DWORD;
    CSDVersion: Word;
    DependentLoadFlags: Word;
    EditList: UInt64;
    SecurityCookie: UInt64;
    SEHandlerTable: UInt64;
    SEHandlerCount: UInt64;
  end;
  PImageLoadConfigDir64W7 = ^TImageLoadConfigDir64W7;

  TImageLoadConfigDir32W8 = packed record
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
    DependentLoadFlags: Word;
    EditList: DWORD;
    SecurityCookie: DWORD;
    SEHandlerTable: DWORD;
    SEHandlerCount: DWORD;
    GuardCFCheckFunctionPointer: DWORD;
    GuardCFDispatchFunctionPointer: DWORD;
    GuardCFFunctionTable: DWORD;
    GuardCFFunctionCount: DWORD;
    GuardFlags: DWORD;
  end;

  TImageLoadConfigDir64W8 = packed record
    Size: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    GlobalFlagsClear: DWORD;
    GlobalFlagsSet: DWORD;
    CriticalSectionDefaultTimeout: DWORD;
    DeCommitFreeBlockThreshold: UInt64;
    DeCommitTotalFreeThreshold: UInt64;
    LockPrefixTable: UInt64;
    MaximumAllocationSize: UInt64;
    VirtualMemoryThreshold: UInt64;
    ProcessAffinityMask: UInt64;
    ProcessHeapFlags: DWORD;
    CSDVersion: Word;
    DependentLoadFlags: Word;
    EditList: UInt64;
    SecurityCookie: UInt64;
    SEHandlerTable: UInt64;
    SEHandlerCount: UInt64;
    GuardCFCheckFunctionPointer: UInt64;
    GuardCFDispatchFunctionPointer: UInt64;
    GuardCFFunctionTable: UInt64;
    GuardCFFunctionCount: UInt64;
    GuardFlags: DWORD;
  end;

  TImageLoadConfigDir32W10 = packed record
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
    DependentLoadFlags: Word;
    EditList: DWORD;
    SecurityCookie: DWORD;
    SEHandlerTable: DWORD;
    SEHandlerCount: DWORD;
    GuardCFCheckFunctionPointer: DWORD;
    GuardCFDispatchFunctionPointer: DWORD;
    GuardCFFunctionTable: DWORD;
    GuardCFFunctionCount: DWORD;
    GuardFlags: DWORD;
    CodeIntegrity: TImageLoadConfigCodeIntegrityW10;
    GuardAddressTakenIatEntryTable: DWORD;
    GuardAddressTakenIatEntryCount: DWORD;
    GuardLongJumpTargetTable: DWORD;
    GuardLongJumpTargetCount: DWORD;
    DynamicValueRelocTable: DWORD;
    CHPEMetadataPointer: DWORD;
    GuardRFFailureRoutine: DWORD;
    GuardRFFailureRoutineFunctionPointer: DWORD;
    DynamicValueRelocTableOffset: DWORD;
    DynamicValueRelocTableSection: Word;
    Reserved2: Word;
    GuardRFVerifyStackPointerFunctionPointer: DWORD;
    HotPatchTableOffset: DWORD;
    Reserved3: DWORD;
    EnclaveConfigurationPointer: DWORD;
  end;

  TImageLoadConfigDir64W10 = packed record
    Size: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    GlobalFlagsClear: DWORD;
    GlobalFlagsSet: DWORD;
    CriticalSectionDefaultTimeout: DWORD;
    DeCommitFreeBlockThreshold: UInt64;
    DeCommitTotalFreeThreshold: UInt64;
    LockPrefixTable: UInt64;
    MaximumAllocationSize: UInt64;
    VirtualMemoryThreshold: UInt64;
    ProcessAffinityMask: UInt64;
    ProcessHeapFlags: DWORD;
    CSDVersion: Word;
    DependentLoadFlags: Word;
    EditList: UInt64;
    SecurityCookie: UInt64;
    SEHandlerTable: UInt64;
    SEHandlerCount: UInt64;
    GuardCFCheckFunctionPointer: UInt64;
    GuardCFDispatchFunctionPointer: UInt64;
    GuardCFFunctionTable: UInt64;
    GuardCFFunctionCount: UInt64;
    GuardFlags: DWORD;
    CodeIntegrity: TImageLoadConfigCodeIntegrityW10;
    GuardAddressTakenIatEntryTable: UInt64;
    GuardAddressTakenIatEntryCount: UInt64;
    GuardLongJumpTargetTable: UInt64;
    GuardLongJumpTargetCount: UInt64;
    DynamicValueRelocTable: UInt64;
    CHPEMetadataPointer: UInt64;
    GuardRFFailureRoutine: UInt64;
    GuardRFFailureRoutineFunctionPointer: UInt64;
    DynamicValueRelocTableOffset: DWORD;
    DynamicValueRelocTableSection: Word;
    Reserved2: Word;
    GuardRFVerifyStackPointerFunctionPointer: UInt64;
    HotPatchTableOffset: DWORD;
    Reserved3: DWORD;
    EnclaveConfigurationPointer: UInt64;
  end;

function GetLoadConfigPtr(Buffer: PByte; BufSize: NativeUInt): PByte;
function GetLoadConfigVersion(Buffer: PByte; BufSize: NativeUInt; LdConfigPtr: PByte): TLoadConfigVer;

implementation

uses
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper;

function GetLoadConfigPtr(Buffer: PByte; BufSize: NativeUInt): PByte;
var
  Dir: PImageDataDirectory;
  EntryRva, EntrySize: DWORD;
begin
  Result := nil;
  if (Buffer = nil) or (BufSize = 0) then
    Exit;
  Dir := GetDirectoryEntry(Buffer, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
  if Dir = nil then
    Exit;
  EntryRva := Dir.VirtualAddress;
  EntrySize := Dir.Size;
  if not ValidatePtr(Buffer, BufSize, PByte(NativeUInt(Buffer) + EntryRva), EntrySize) then
    Exit;
  Result := PByte(NativeUInt(Buffer) + EntryRva);
end;

function GetLoadConfigVersion(Buffer: PByte; BufSize: NativeUInt; LdConfigPtr: PByte): TLoadConfigVer;
var
  Is64B: Boolean;
  CurrSize: NativeUInt;
begin
  Result := LOAD_CONFIG_NONE;
  if (Buffer = nil) or (BufSize = 0) or (LdConfigPtr = nil) then
    Exit;
  if not ValidatePtr(Buffer, BufSize, LdConfigPtr, SizeOf(DWORD)) then
    Exit;
  CurrSize := PDWORD(LdConfigPtr)^;
  if CurrSize = 0 then
    Exit;
  if not ValidatePtr(Buffer, BufSize, LdConfigPtr, CurrSize) then
    Exit(LOAD_CONFIG_UNK_VER);
  Is64B := Is64Bit(Buffer);
  if Is64B then
  begin
    if CurrSize >= SizeOf(TImageLoadConfigDir64W10) then
      Exit(LOAD_CONFIG_W10_VER);
    if CurrSize >= SizeOf(TImageLoadConfigDir64W8) then
      Exit(LOAD_CONFIG_W8_VER);
    if CurrSize >= SizeOf(TImageLoadConfigDir64W7) then
      Exit(LOAD_CONFIG_W7_VER);
  end
  else
  begin
    if CurrSize >= SizeOf(TImageLoadConfigDir32W10) then
      Exit(LOAD_CONFIG_W10_VER);
    if CurrSize >= SizeOf(TImageLoadConfigDir32W8) then
      Exit(LOAD_CONFIG_W8_VER);
    if CurrSize >= SizeOf(TImageLoadConfigDir32W7) then
      Exit(LOAD_CONFIG_W7_VER);
  end;
  Result := LOAD_CONFIG_UNK_VER;
end;

end.
