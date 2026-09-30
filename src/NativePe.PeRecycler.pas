{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.PeRecycler;

interface

uses
  Winapi.Windows,
  NativePe.Types;

function InjectIntoCave(ModulePtr: PByte; ModuleSize: NativeUInt; Data: PByte; DataSize: NativeUInt;
  out Rva: DWORD): Boolean;
function FixLoadConfig(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;

implementation

uses
  NativePe.PeHdrsHelper,
  NativePe.Caves,
  NativePe.LoadConfig,
  NativePe.Logger;

function InjectIntoCave(ModulePtr: PByte; ModuleSize: NativeUInt; Data: PByte; DataSize: NativeUInt;
  out Rva: DWORD): Boolean;
var
  CavePtr: PByte;
begin
  Result := False;
  Rva := 0;
  if (ModulePtr = nil) or (Data = nil) or (DataSize = 0) then
    Exit;

  CavePtr := FindAlignmentCave(ModulePtr, ModuleSize, DWORD(DataSize));
  if CavePtr = nil then
    CavePtr := FindPaddingCave(ModulePtr, ModuleSize, DataSize);
  if CavePtr = nil then
  begin
    LogInfo('No cave found to inject 0x%x bytes.', [DataSize]);
    Exit;
  end;

  Move(Data^, CavePtr^, DataSize);
  Rva := DWORD(NativeUInt(CavePtr) - NativeUInt(ModulePtr));
  LogDebug('Injected 0x%x bytes at RVA 0x%x.', [DataSize, Rva]);
  Result := True;
end;

function FixLoadConfig(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;
var
  Dir: PImageDataDirectory;
  LdConfigPtr: PByte;
  Ver: TLoadConfigVer;
  DeclaredSize: DWORD;
begin
  Result := True;
  if (ModulePtr = nil) or (ModuleSize = 0) then
    Exit(False);

  Dir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
  if (Dir = nil) or (Dir.VirtualAddress = 0) then
    Exit;

  LdConfigPtr := GetLoadConfigPtr(ModulePtr, ModuleSize);
  if LdConfigPtr = nil then
  begin
    LogWarning('Load config directory points out of the module -- clearing it.');
    Dir.VirtualAddress := 0;
    Dir.Size := 0;
    Exit;
  end;

  Ver := GetLoadConfigVersion(ModulePtr, ModuleSize, LdConfigPtr);
  if Ver = LOAD_CONFIG_NONE then
  begin
    LogWarning('Load config directory is truncated -- clearing it.');
    Dir.VirtualAddress := 0;
    Dir.Size := 0;
    Exit;
  end;

  DeclaredSize := PDWORD(LdConfigPtr)^;
  if (DeclaredSize = 0) or (DeclaredSize > Dir.Size) then
  begin
    LogWarning('Load config directory''s own declared Size (0x%x) is inconsistent with its data ' +
      'directory entry (0x%x) -- clearing it.', [DeclaredSize, Dir.Size]);
    Dir.VirtualAddress := 0;
    Dir.Size := 0;
  end;
end;

end.
