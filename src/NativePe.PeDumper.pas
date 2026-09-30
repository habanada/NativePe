{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/pe_dumper.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PeDumper;

interface

uses
  Winapi.Windows,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.ExportsMapper;

const
  PE_DUMP_AUTO = 0;
  PE_DUMP_VIRTUAL = 1;
  PE_DUMP_UNMAP = 2;
  PE_DUMP_REALIGN = 3;
  PE_DUMP_MODES_COUNT = 4;

type
  TPeDumpMode = LongInt;

function DetectDumpMode(Buffer: PByte; ModSize: NativeUInt): TPeDumpMode;
function DumpPe(const OutPath: string; Buffer: PByte; ModSize: NativeUInt; StartAddr: UInt64;
  var DumpMode: TPeDumpMode; ExportsMap: TExportsMapper = nil): Boolean;

implementation

uses
  NativePe.PeHdrsHelper,
  NativePe.PeVirtualToRaw,
  NativePe.FixImports,
  NativePe.FileUtil,
  NativePe.PeModeDetector,
  NativePe.DotNetEpFixer,
  NativePe.Logger;

function DetectDumpMode(Buffer: PByte; ModSize: NativeUInt): TPeDumpMode;
const
  DefaultMode = PE_DUMP_UNMAP;
begin
  if IsPeRaw(Buffer, ModSize) then
    Exit(PE_DUMP_VIRTUAL);
  if IsPeExpanded(Buffer, ModSize) then
    Exit(PE_DUMP_REALIGN);
  Result := DefaultMode;
end;

function DumpPe(const OutPath: string; Buffer: PByte; ModSize: NativeUInt; StartAddr: UInt64;
  var DumpMode: TPeDumpMode; ExportsMap: TExportsMapper): Boolean;
var
  DumpData: PByte;
  DumpSize: NativeUInt;
  OutSize: NativeUInt;
  UnmappedModule: TAlignedBuf;
  HdrBase, TargetBase: UInt64;
begin
  if ExportsMap <> nil then
    if not FixImports(Buffer, ModSize, ExportsMap, nil) then
      LogError('Unable to fix imports.');

  if (DumpMode = PE_DUMP_AUTO) or (DumpMode >= PE_DUMP_MODES_COUNT) then
    DumpMode := DetectDumpMode(Buffer, ModSize);

  DumpData := Buffer;
  DumpSize := ModSize;
  OutSize := 0;
  UnmappedModule := nil;

  if (DumpMode = PE_DUMP_UNMAP) or (DumpMode = PE_DUMP_REALIGN) then
  begin
    if GetImageBase(Buffer) = 0 then
      UpdateImageBase(Buffer, StartAddr);
    if IsDotNet(Buffer, ModSize) then
      FixDotNetEp(Buffer, ModSize);

    HdrBase := GetImageBase(Buffer);
    TargetBase := StartAddr;
    if (DumpMode <> PE_DUMP_VIRTUAL) and HasRelocations(Buffer) then
    begin
      TargetBase := HdrBase;
      UpdateImageBase(Buffer, StartAddr);
    end;

    if DumpMode = PE_DUMP_UNMAP then
      UnmappedModule := PeVirtualToRaw(Buffer, ModSize, TargetBase, OutSize, False)
    else if DumpMode = PE_DUMP_REALIGN then
      UnmappedModule := PeRealignRawToVirtual(Buffer, ModSize, TargetBase, OutSize);

    if UnmappedModule <> nil then
    begin
      DumpData := UnmappedModule;
      DumpSize := OutSize;
    end;
  end;

  Result := DumpToFile(OutPath, DumpData, DumpSize);

  FreePeBuffer(UnmappedModule, ModSize);
end;

end.
