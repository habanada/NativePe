{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/pe_loader.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.PeLoader;

interface

uses
  Winapi.Windows,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.FunctionResolver;

function LoadPeModule(PayloadRaw: PByte; RSize: NativeUInt; out VSize: NativeUInt; Executable: Boolean;
  DoRelocate: Boolean; DesiredBase: NativeUInt = 0): TAlignedBuf; overload;
function LoadPeModule(const FileName: string; out VSize: NativeUInt; Executable: Boolean; DoRelocate: Boolean;
  DesiredBase: NativeUInt = 0): TAlignedBuf; overload;

function LoadPeExecutable(PayloadRaw: PByte; RSize: NativeUInt; out VSize: NativeUInt;
  ImportResolver: TFunctionResolver = nil; DesiredBase: NativeUInt = 0;
  StrictImportDirectorySize: Boolean = False): TAlignedBuf; overload;
function LoadPeExecutable(const FileName: string; out VSize: NativeUInt;
  ImportResolver: TFunctionResolver = nil; StrictImportDirectorySize: Boolean = False): TAlignedBuf; overload;

implementation

uses
  NativePe.PeHdrsHelper,
  NativePe.PeRawToVirtual,
  NativePe.Relocate,
  NativePe.ImportsLoader,
  NativePe.SecurityCookie,
  NativePe.ExceptionsParser,
  NativePe.FileUtil,
  NativePe.Logger;

function LoadNoSecPe(DllRawData: PByte; RSize: NativeUInt; out VSize: NativeUInt; Executable: Boolean): TAlignedBuf;
var
  DesiredBase: NativeUInt;
  OutSize: NativeUInt;
  Protect: DWORD;
  MappedPe: TAlignedBuf;
begin
  Result := nil;
  VSize := 0;
  DesiredBase := 0;
  if RSize < PE_PAGE_SIZE then
    OutSize := PE_PAGE_SIZE
  else
    OutSize := RSize;

  if Executable then
  begin
    DesiredBase := GetImageBase(DllRawData);
    OutSize := GetImageSize(DllRawData);
  end;
  if OutSize < RSize then
    OutSize := RSize;

  if Executable then
    Protect := PAGE_EXECUTE_READWRITE
  else
    Protect := PAGE_READWRITE;

  MappedPe := AllocPeBuffer(OutSize, Protect, Pointer(DesiredBase));
  if MappedPe = nil then
    Exit;
  Move(DllRawData^, MappedPe^, RSize);
  VSize := OutSize;
  Result := MappedPe;
end;

function LoadPeModule(PayloadRaw: PByte; RSize: NativeUInt; out VSize: NativeUInt; Executable: Boolean;
  DoRelocate: Boolean; DesiredBase: NativeUInt): TAlignedBuf;
var
  MappedDll: TAlignedBuf;
begin
  Result := nil;
  VSize := 0;
  if GetNtHdrs(PayloadRaw, RSize) = nil then
    Exit;

  if GetSectionsCount(PayloadRaw, RSize) = 0 then
    Exit(LoadNoSecPe(PayloadRaw, RSize, VSize, Executable));

  // by default, allow to load the PE at the supplied base
  // if relocating is required, but the PE has no relocation table...
  if DoRelocate and (not HasRelocations(PayloadRaw)) then
    // ...enforce loading the PE image at its default base (so that it will need no relocations)
    DesiredBase := GetImageBase(PayloadRaw);

  // load a virtual image of the PE file at the desired_base address (random if desired_base is 0):
  MappedDll := PeRawToVirtual(PayloadRaw, RSize, VSize, Executable, DesiredBase);
  if MappedDll <> nil then
  begin
    // if the image was loaded at its default base, RelocateModule will return always true (because relocating is already done)
    if DoRelocate and (not RelocateModule(MappedDll, VSize, UInt64(NativeUInt(MappedDll)))) then
    begin
      // relocating was required, but it failed - thus, the full PE image is useless
      LogError('Could not relocate the module.');
      FreePeBuffer(MappedDll, VSize);
      MappedDll := nil;
    end;
  end
  else
    LogError('Could not allocate memory at the desired base.');
  Result := MappedDll;
end;

function LoadPeModule(const FileName: string; out VSize: NativeUInt; Executable: Boolean; DoRelocate: Boolean;
  DesiredBase: NativeUInt): TAlignedBuf;
var
  RSize: NativeUInt;
  DllRawData: TUnalignedBuf;
  MappedPe: TAlignedBuf;
begin
  Result := nil;
  VSize := 0;
  RSize := 0;
  DllRawData := LoadFile(FileName, RSize);
  if DllRawData = nil then
  begin
    LogError('Cannot load the file.');
    Exit;
  end;
  MappedPe := LoadPeModule(DllRawData, RSize, VSize, Executable, DoRelocate, DesiredBase);
  FreeFile(DllRawData);
  Result := MappedPe;
end;

function ValidateAndLoadImports(LoadedPe: PByte; VSize: NativeUInt; ImportResolver: TFunctionResolver;
  StrictImportDirectorySize: Boolean): Boolean;
begin
  if GetDirectoryEntry(LoadedPe, IMAGE_DIRECTORY_ENTRY_IMPORT) = nil then
  begin
    LogWarning('PE does not have an Import Table.');
    Exit(True); // genuinely no imports, nothing to load
  end;
  if not HasValidImportTable(LoadedPe, VSize, 0, StrictImportDirectorySize) then
  begin
    LogError('PE has an Import Table directory, but it is malformed.');
    Exit(False); // corrupted table -> now a real failure
  end;
  if LoadImports(LoadedPe, ImportResolver) then
    Exit(True);
  LogError('Loading imports failed.');
  Result := False;
end;

function LoadPeExecutable(PayloadRaw: PByte; RSize: NativeUInt; out VSize: NativeUInt;
  ImportResolver: TFunctionResolver; DesiredBase: NativeUInt; StrictImportDirectorySize: Boolean): TAlignedBuf;
var
  LoadedPe: TAlignedBuf;
begin
  Result := nil;
  LoadedPe := LoadPeModule(PayloadRaw, RSize, VSize, True, True, DesiredBase);
  if LoadedPe = nil then
  begin
    LogError('Loading failed.');
    Exit;
  end;
  LogDebug('Loaded at: 0x%x.', [NativeUInt(LoadedPe)]);
  if not ValidateAndLoadImports(LoadedPe, VSize, ImportResolver, StrictImportDirectorySize) then
  begin
    FreePeBuffer(LoadedPe, VSize);
    Exit(nil);
  end;
  if AutoRegisterExceptions then
    SetupExceptions(LoadedPe, VSize);
  if AutoInitSecurityCookie then
    InitSecurityCookie(LoadedPe, VSize);
  Result := LoadedPe;
end;

function LoadPeExecutable(const FileName: string; out VSize: NativeUInt;
  ImportResolver: TFunctionResolver; StrictImportDirectorySize: Boolean): TAlignedBuf;
var
  LoadedPe: TAlignedBuf;
begin
  Result := nil;
  LoadedPe := LoadPeModule(FileName, VSize, True, True);
  if LoadedPe = nil then
  begin
    LogError('Loading failed.');
    Exit;
  end;
  LogDebug('Loaded at: 0x%x.', [NativeUInt(LoadedPe)]);
  if not ValidateAndLoadImports(LoadedPe, VSize, ImportResolver, StrictImportDirectorySize) then
  begin
    FreePeBuffer(LoadedPe, VSize);
    Exit(nil);
  end;
  if AutoRegisterExceptions then
    SetupExceptions(LoadedPe, VSize);
  if AutoInitSecurityCookie then
    InitSecurityCookie(LoadedPe, VSize);
  Result := LoadedPe;
end;

end.
