{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/delayed_imports_loader.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.	
}
unit NativePe.DelayedImports;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.Types,
  NativePe.FunctionResolver;

function GetDelayedImps(ModulePtr: PByte; ModuleSize: NativeUInt; out DirSize: NativeUInt): PImageDelayloadDescriptor;
function LoadDelayedImports(ModulePtr: PByte; ModuleBase: UInt64; FuncResolver: TFunctionResolver = nil): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.Relocate,
  NativePe.ImportsLoader,
  NativePe.Logger;

type
  TDelayedRelocSet = TDictionary<UInt64, Boolean>;

  TCollectRelocs = class(TRelocBlockCallback)
  private
    FRelocs: TDelayedRelocSet;
  public
    constructor Create(AIs64Bit: Boolean; ARelocs: TDelayedRelocSet);
    function ProcessRelocField(RelocField: NativeUInt): Boolean; override;
  end;

constructor TCollectRelocs.Create(AIs64Bit: Boolean; ARelocs: TDelayedRelocSet);
begin
  inherited Create(AIs64Bit);
  FRelocs := ARelocs;
end;

function TCollectRelocs.ProcessRelocField(RelocField: NativeUInt): Boolean;
var
  Rva: UInt64;
begin
  if FIs64Bit then
    Rva := PUInt64(RelocField)^
  else
    Rva := UInt64(PDWORD(RelocField)^);
  FRelocs.AddOrSetValue(Rva, True);
  Result := True;
end;

function ConvertVaToRva(RelocValues: TDelayedRelocSet; BaseAddr: UInt64; var Addr: UInt64): Boolean;
begin
  Result := True;
  if RelocValues.ContainsKey(Addr) then
  begin
    if Addr < BaseAddr then
    begin
      LogError('Invalid VA: 0x%x cannot convert safely', [Addr]);
      Exit(False);
    end;
    Addr := Addr - BaseAddr;
  end;
end;

function ParseDelayedDesc64(ModulePtr: PByte; ModuleSize: NativeUInt; ImgBase: UInt64; LibName: PAnsiChar;
  Desc: PImageDelayloadDescriptor; FuncResolver: TFunctionResolver; RelocValues: TDelayedRelocSet): Boolean;
var
  IatAddr, ThunkAddr: UInt64;
  RecordVa: PUInt64;
  ThunkVa: PImageThunkData64;
  IatRva: UInt64;
  IatRecordPtr: PUInt64;
  HProc: FARPROC;
  RawOrdinal: UInt64;
  NameRva: UInt64;
  ByName: PImageImportByName;
  FuncName: PAnsiChar;
begin
  Result := False;
  if not ValidatePtr(ModulePtr, ModuleSize, Desc, SizeOf(TImageDelayloadDescriptor)) then
  begin
    LogError('Invalid IMAGE_DELAYLOAD_DESCRIPTOR');
    Exit;
  end;

  IatAddr := Desc.ImportAddressTableRVA;
  ThunkAddr := Desc.ImportNameTableRVA;

  if (not ConvertVaToRva(RelocValues, ImgBase, IatAddr)) or (not ConvertVaToRva(RelocValues, ImgBase, ThunkAddr)) then
    Exit;

  if (IatAddr > ModuleSize) or (ThunkAddr > ModuleSize) then
    Exit;

  LogInfo('iat_addr: 0x%x, thunk_addr: 0x%x', [IatAddr, ThunkAddr]);

  RecordVa := PUInt64(NativeUInt(ModulePtr) + NativeUInt(IatAddr));
  ThunkVa := PImageThunkData64(NativeUInt(ModulePtr) + NativeUInt(ThunkAddr));

  while True do
  begin
    if (not ValidatePtr(ModulePtr, ModuleSize, RecordVa, SizeOf(UInt64))) or
      (not ValidatePtr(ModulePtr, ModuleSize, ThunkVa, SizeOf(TImageThunkData64))) then
      Exit(False);

    if RecordVa^ = 0 then
      Break;

    IatRva := RecordVa^;
    if not ConvertVaToRva(RelocValues, ImgBase, IatRva) then
      Exit(False);

    LogDebug('IAT VA: 0x%x RVA: 0x%x', [RecordVa^, IatRva]);

    IatRecordPtr := PUInt64(NativeUInt(ModulePtr) + NativeUInt(IatRva));
    if not ValidatePtr(ModulePtr, ModuleSize, IatRecordPtr, SizeOf(UInt64)) then
      Exit(False);

    HProc := nil;
    if (ThunkVa.Ordinal and IMAGE_ORDINAL_FLAG64) <> 0 then
    begin
      RawOrdinal := ThunkVa.Ordinal and (not IMAGE_ORDINAL_FLAG64);
      LogDebug('ord: 0x%x', [RawOrdinal]);
      if Assigned(FuncResolver) then
        HProc := FuncResolver.ResolveFunc(LibName, PAnsiChar(NativeUInt(RawOrdinal)));
    end
    else
    begin
      NameRva := ThunkVa.AddressOfData;
      if not ConvertVaToRva(RelocValues, ImgBase, NameRva) then
        Exit(False);

      ByName := PImageImportByName(NativeUInt(ModulePtr) + NativeUInt(NameRva));
      if not ValidatePtr(ModulePtr, ModuleSize, ByName, SizeOf(TImageImportByName)) then
      begin
        LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME');
        Exit(False);
      end;

      FuncName := @ByName.Name[0];
      if not IsValidImportName(ModulePtr, ModuleSize, FuncName) then
      begin
        Inc(RecordVa);
        Inc(ThunkVa);
        Continue;
      end;

      LogDebug('func: %s', [string(AnsiString(FuncName))]);
      if Assigned(FuncResolver) then
        HProc := FuncResolver.ResolveFunc(LibName, FuncName);
    end;

    if Assigned(HProc) then
    begin
      RecordVa^ := UInt64(NativeUInt(HProc));
      LogDebug('Delayload Function resolved');
    end
    else
      LogDebug('Delayload Function not resolved');

    Inc(RecordVa);
    Inc(ThunkVa);
  end;

  Result := True;
end;

function ParseDelayedDesc32(ModulePtr: PByte; ModuleSize: NativeUInt; ImgBase: UInt64; LibName: PAnsiChar;
  Desc: PImageDelayloadDescriptor; FuncResolver: TFunctionResolver; RelocValues: TDelayedRelocSet): Boolean;
var
  IatAddr, ThunkAddr: UInt64;
  RecordVa: PDWORD;
  ThunkVa: PImageThunkData32;
  IatRva: UInt64;
  IatRecordPtr: PDWORD;
  HProc: FARPROC;
  RawOrdinal: DWORD;
  NameRva: UInt64;
  ByName: PImageImportByName;
  FuncName: PAnsiChar;
begin
  Result := False;
  if not ValidatePtr(ModulePtr, ModuleSize, Desc, SizeOf(TImageDelayloadDescriptor)) then
  begin
    LogError('Invalid IMAGE_DELAYLOAD_DESCRIPTOR');
    Exit;
  end;

  IatAddr := Desc.ImportAddressTableRVA;
  ThunkAddr := Desc.ImportNameTableRVA;

  if (not ConvertVaToRva(RelocValues, ImgBase, IatAddr)) or (not ConvertVaToRva(RelocValues, ImgBase, ThunkAddr)) then
    Exit;

  if (IatAddr > ModuleSize) or (ThunkAddr > ModuleSize) then
    Exit;

  LogInfo('iat_addr: 0x%x, thunk_addr: 0x%x', [IatAddr, ThunkAddr]);

  RecordVa := PDWORD(NativeUInt(ModulePtr) + NativeUInt(IatAddr));
  ThunkVa := PImageThunkData32(NativeUInt(ModulePtr) + NativeUInt(ThunkAddr));

  while True do
  begin
    if (not ValidatePtr(ModulePtr, ModuleSize, RecordVa, SizeOf(DWORD))) or
      (not ValidatePtr(ModulePtr, ModuleSize, ThunkVa, SizeOf(TImageThunkData32))) then
      Exit(False);

    if RecordVa^ = 0 then
      Break;

    IatRva := RecordVa^;
    if not ConvertVaToRva(RelocValues, ImgBase, IatRva) then
      Exit(False);

    LogDebug('IAT VA: 0x%x RVA: 0x%x', [RecordVa^, IatRva]);

    IatRecordPtr := PDWORD(NativeUInt(ModulePtr) + NativeUInt(IatRva));
    if not ValidatePtr(ModulePtr, ModuleSize, IatRecordPtr, SizeOf(DWORD)) then
      Exit(False);

    HProc := nil;
    if (ThunkVa.Ordinal and IMAGE_ORDINAL_FLAG32) <> 0 then
    begin
      RawOrdinal := ThunkVa.Ordinal and (not IMAGE_ORDINAL_FLAG32);
      LogDebug('ord: 0x%x', [RawOrdinal]);
      if Assigned(FuncResolver) then
        HProc := FuncResolver.ResolveFunc(LibName, PAnsiChar(NativeUInt(RawOrdinal)));
    end
    else
    begin
      NameRva := ThunkVa.AddressOfData;
      if not ConvertVaToRva(RelocValues, ImgBase, NameRva) then
        Exit(False);

      ByName := PImageImportByName(NativeUInt(ModulePtr) + NativeUInt(NameRva));
      if not ValidatePtr(ModulePtr, ModuleSize, ByName, SizeOf(TImageImportByName)) then
      begin
        LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME');
        Exit(False);
      end;

      FuncName := @ByName.Name[0];
      if not IsValidImportName(ModulePtr, ModuleSize, FuncName) then
      begin
        Inc(RecordVa);
        Inc(ThunkVa);
        Continue;
      end;

      LogDebug('func: %s', [string(AnsiString(FuncName))]);
      if Assigned(FuncResolver) then
        HProc := FuncResolver.ResolveFunc(LibName, FuncName);
    end;

    if Assigned(HProc) then
    begin
      RecordVa^ := DWORD(NativeUInt(HProc));
      LogDebug('Delayload Function resolved');
    end
    else
      LogDebug('Delayload Function not resolved');

    Inc(RecordVa);
    Inc(ThunkVa);
  end;

  Result := True;
end;

function GetDelayedImps(ModulePtr: PByte; ModuleSize: NativeUInt; out DirSize: NativeUInt): PImageDelayloadDescriptor;
var
  DImpsDir: PImageDataDirectory;
  DImpsTable: PByte;
  MinSize: NativeUInt;
begin
  Result := nil;
  DirSize := 0;
  DImpsDir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
  if DImpsDir = nil then
    Exit;
  DImpsTable := PByte(NativeUInt(ModulePtr) + NativeUInt(DImpsDir.VirtualAddress));
  MinSize := SizeOf(TImageDelayloadDescriptor);
  if DImpsDir.Size < MinSize then
    Exit;
  if not ValidatePtr(ModulePtr, ModuleSize, DImpsTable, MinSize) then
    Exit;
  DirSize := DImpsDir.Size;
  Result := PImageDelayloadDescriptor(DImpsTable);
end;

function LoadDelayedImports(ModulePtr: PByte; ModuleBase: UInt64; FuncResolver: TFunctionResolver): Boolean;
var
  Is64, IsLoader64: Boolean;
  ModuleSize: NativeUInt;
  DefaultRes: TDefaultFuncResolver;
  Resolver: TFunctionResolver;
  TableSize: NativeUInt;
  FirstDesc: PImageDelayloadDescriptor;
  RelocValues: TDelayedRelocSet;
  Callback: TCollectRelocs;
  MaxCount, I: NativeUInt;
  Desc: PImageDelayloadDescriptor;
  DllNameRva: UInt64;
  DllName: PAnsiChar;
  IsOk: Boolean;
begin
  Result := False;
  if GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) = nil then
    Exit(True);

  Is64 := Is64Bit(ModulePtr);
{$IFDEF WIN64}
  IsLoader64 := True;
{$ELSE}
  IsLoader64 := False;
{$ENDIF}
  if Is64 <> IsLoader64 then
  begin
    LogError('Loader/Payload bitness mismatch.');
    Exit;
  end;

  ModuleSize := GetImageSize(ModulePtr);
  DefaultRes := nil;
  Resolver := FuncResolver;
  if not Assigned(Resolver) then
  begin
    DefaultRes := TDefaultFuncResolver.Create;
    Resolver := DefaultRes;
  end;

  try
    TableSize := 0;
    FirstDesc := GetDelayedImps(ModulePtr, ModuleSize, TableSize);
    if FirstDesc = nil then
      Exit(False);

    RelocValues := TDelayedRelocSet.Create;
    try
      Callback := TCollectRelocs.Create(Is64, RelocValues);
      try
        ProcessRelocationTable(ModulePtr, ModuleSize, Callback);
      finally
        Callback.Free;
      end;

      LogDebug('Delay-import table found, table_size = %u bytes.', [TableSize]);
      IsOk := True;
      MaxCount := TableSize div SizeOf(TImageDelayloadDescriptor);
      I := 0;
      while I < MaxCount do
      begin
        Desc := PImageDelayloadDescriptor(NativeUInt(FirstDesc) + I * SizeOf(TImageDelayloadDescriptor));
        if not ValidatePtr(ModulePtr, ModuleSize, Desc, SizeOf(TImageDelayloadDescriptor)) then
          Break;
        if Desc.DllNameRVA = 0 then
          Break;

        DllNameRva := Desc.DllNameRVA;
        if not ConvertVaToRva(RelocValues, ModuleBase, DllNameRva) then
          Exit(False);

        DllName := PAnsiChar(NativeUInt(ModulePtr) + NativeUInt(DllNameRva));
        if not IsValidStringA(ModulePtr, ModuleSize, DllName) then
        begin
          Inc(I);
          Continue;
        end;
        LogDebug('Processing delayed imports for: %s', [string(AnsiString(DllName))]);

        if Is64 then
        begin
          if not ParseDelayedDesc64(ModulePtr, ModuleSize, ModuleBase, DllName, Desc, Resolver, RelocValues) then
            IsOk := False;
        end
        else
        begin
          if not ParseDelayedDesc32(ModulePtr, ModuleSize, ModuleBase, DllName, Desc, Resolver, RelocValues) then
            IsOk := False;
        end;

        Inc(I);
      end;
      Result := IsOk;
    finally
      RelocValues.Free;
    end;
  finally
    DefaultRes.Free;
  end;
end;

end.
