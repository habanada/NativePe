{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/tls_parser.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.TlsParser;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.Types;

function VirtualAddrToRva(ImgBase: UInt64; ImgSize: DWORD; VirtualAddr: UInt64; out OutRva: DWORD): Boolean;
function ListTlsCallbacks(ModulePtr: Pointer; ModuleSize: NativeUInt; TlsCallbacks: TList<UInt64>): NativeUInt;
function RunTlsCallbacks(ModulePtr: Pointer; ModuleSize: NativeUInt = 0; DwReason: DWORD = DLL_PROCESS_ATTACH): NativeUInt;

implementation

uses
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.Relocate,
  NativePe.Logger;

type
  TTlsCallback = procedure(DllHandle: Pointer; DwReason: DWORD; Reserved: Pointer); stdcall;
  TRelocValueSet = TDictionary<UInt64, Byte>;

  TCollectRelocValues = class(TRelocBlockCallback)
  private
    FModulePtr: Pointer;
    FModuleSize: NativeUInt;
    FRelocs: TRelocValueSet;
  public
    constructor Create(AModulePtr: Pointer; AModuleSize: NativeUInt; AIs64Bit: Boolean; ARelocs: TRelocValueSet);
    function ProcessRelocField(RelocField: NativeUInt): Boolean; override;
  end;

constructor TCollectRelocValues.Create(AModulePtr: Pointer; AModuleSize: NativeUInt; AIs64Bit: Boolean;
  ARelocs: TRelocValueSet);
begin
  inherited Create(AIs64Bit);
  FModulePtr := AModulePtr;
  FModuleSize := AModuleSize;
  FRelocs := ARelocs;
end;

function TCollectRelocValues.ProcessRelocField(RelocField: NativeUInt): Boolean;
var
  Value: UInt64;
begin
  if FIs64Bit then
  begin
    if not ValidatePtr(FModulePtr, FModuleSize, Pointer(RelocField), SizeOf(UInt64)) then
      Exit(False);
    Value := PUInt64(RelocField)^;
  end
  else
  begin
    if not ValidatePtr(FModulePtr, FModuleSize, Pointer(RelocField), SizeOf(DWORD)) then
      Exit(False);
    Value := PDWORD(RelocField)^;
  end;
  FRelocs.AddOrSetValue(Value, 0);
  Result := True;
end;

function VirtualAddrToRva(ImgBase: UInt64; ImgSize: DWORD; VirtualAddr: UInt64; out OutRva: DWORD): Boolean;
begin
  OutRva := 0;
  if (ImgSize = 0) or (VirtualAddr = 0) then
    Exit(False);
  if (VirtualAddr >= ImgBase) and (VirtualAddr < (ImgBase + ImgSize)) then
  begin
    OutRva := MaskToDword(VirtualAddr - ImgBase);
    Exit(True);
  end;
  if VirtualAddr < ImgSize then
  begin
    OutRva := MaskToDword(VirtualAddr);
    Exit(True);
  end;
  Result := False;
end;

function CollectRelocValues(ModulePtr: PByte; ModuleSize: NativeUInt; Relocs: TRelocValueSet): Boolean;
var
  Callback: TCollectRelocValues;
begin
  Callback := TCollectRelocValues.Create(ModulePtr, ModuleSize, Is64Bit(ModulePtr), Relocs);
  try
    Result := ProcessRelocationTable(ModulePtr, ModuleSize, Callback);
  finally
    Callback.Free;
  end;
end;

function VirtualAddrToRvaWithRelocs(ModulePtr: PByte; ModuleSize: NativeUInt; VirtualAddr: UInt64;
  Relocs: TRelocValueSet; out OutRva: DWORD): Boolean;
var
  ImgBase, Delta: UInt64;
begin
  OutRva := 0;
  if (ModulePtr = nil) or (ModuleSize = 0) or (VirtualAddr = 0) then
    Exit(False);
  if (Relocs = nil) or (Relocs.Count = 0) then
  begin
    if ModuleSize > High(DWORD) then
      Exit(False);
    Exit(VirtualAddrToRva(UInt64(NativeUInt(ModulePtr)), DWORD(ModuleSize), VirtualAddr, OutRva));
  end;
  ImgBase := UInt64(NativeUInt(ModulePtr));
  if Relocs.ContainsKey(VirtualAddr) then
  begin
    if VirtualAddr < ImgBase then
    begin
      LogError('Invalid VA: 0x%x cannot convert safely.', [VirtualAddr]);
      Exit(False);
    end;
    Delta := VirtualAddr - ImgBase;
    if Delta > High(DWORD) then
      Exit(False);
    OutRva := DWORD(Delta);
    Exit(True);
  end;
  if (VirtualAddr > ModuleSize) or (VirtualAddr > High(DWORD)) then
    Exit(False);
  OutRva := DWORD(VirtualAddr);
  Result := True;
end;

function VirtualAddrToRvaMapped(ModulePtr: PByte; ModuleSize: NativeUInt; VirtualAddr: UInt64; out OutRva: DWORD): Boolean;
var
  Relocs: TRelocValueSet;
begin
  OutRva := 0;
  if (ModulePtr = nil) or (ModuleSize = 0) or (VirtualAddr = 0) then
    Exit(False);
  Relocs := TRelocValueSet.Create;
  try
    if HasRelocations(ModulePtr) then
      CollectRelocValues(ModulePtr, ModuleSize, Relocs);
    Result := VirtualAddrToRvaWithRelocs(ModulePtr, ModuleSize, VirtualAddr, Relocs, OutRva);
  finally
    Relocs.Free;
  end;
end;

function FetchCallbacksList32(ModulePtr: Pointer; ModuleSize: NativeUInt; CallbacksRva: DWORD;
  TlsCallbacks: TList<UInt64>): NativeUInt;
var
  CallbacksListPtr, NextCallback: PDWORD;
  Value: DWORD;
begin
  Result := 0;
  CallbacksListPtr := PDWORD(NativeUInt(CallbacksRva) + NativeUInt(ModulePtr));
  if not ValidatePtr(ModulePtr, ModuleSize, CallbacksListPtr, SizeOf(DWORD)) then
    Exit;
  NextCallback := CallbacksListPtr;
  while ValidatePtr(ModulePtr, ModuleSize, NextCallback, SizeOf(DWORD)) do
  begin
    Value := NextCallback^;
    if Value = 0 then
      Break;
    TlsCallbacks.Add(Value);
    Inc(Result);
    Inc(NextCallback);
  end;
end;

function FetchCallbacksList64(ModulePtr: Pointer; ModuleSize: NativeUInt; CallbacksRva: DWORD;
  TlsCallbacks: TList<UInt64>): NativeUInt;
var
  CallbacksListPtr, NextCallback: PUInt64;
  Value: UInt64;
begin
  Result := 0;
  CallbacksListPtr := PUInt64(NativeUInt(CallbacksRva) + NativeUInt(ModulePtr));
  if not ValidatePtr(ModulePtr, ModuleSize, CallbacksListPtr, SizeOf(UInt64)) then
    Exit;
  NextCallback := CallbacksListPtr;
  while ValidatePtr(ModulePtr, ModuleSize, NextCallback, SizeOf(UInt64)) do
  begin
    Value := NextCallback^;
    if Value = 0 then
      Break;
    TlsCallbacks.Add(Value);
    Inc(Result);
    Inc(NativeUInt(NextCallback), SizeOf(UInt64));
  end;
end;

function ListTlsCallbacksWithRelocs(ModulePtr: Pointer; ModuleSize: NativeUInt; TlsCallbacks: TList<UInt64>;
  Relocs: TRelocValueSet): NativeUInt;
var
  ImgSize: DWORD;
  TlsDir: PImageTlsDirectory64;
  TlsDir32: PImageTlsDirectory32 absolute TlsDir;
  CallbacksAddr: UInt64;
  CallbacksRva: DWORD;
begin
  Result := 0;
  ImgSize := GetImageSize(PByte(ModulePtr));
  if ImgSize = 0 then
    Exit;
  if ModuleSize = 0 then
    ModuleSize := ImgSize;
  TlsDir := PImageTlsDirectory64(GetTypeDirectoryPtr(ModulePtr, IMAGE_DIRECTORY_ENTRY_TLS));
  if TlsDir = nil then
    Exit;
  if Is64Bit(PByte(ModulePtr)) then
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, TlsDir, SizeOf(TImageTlsDirectory64)) then
      Exit;
    CallbacksAddr := TlsDir.AddressOfCallBacks;
  end
  else
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, TlsDir32, SizeOf(TImageTlsDirectory32)) then
      Exit;
    CallbacksAddr := TlsDir32.AddressOfCallBacks;
  end;
  if CallbacksAddr = 0 then
    Exit;
  LogDebug('TLS Callbacks Table: 0x%x.', [CallbacksAddr]);
  CallbacksRva := 0;
  if Relocs <> nil then
  begin
    if not VirtualAddrToRvaWithRelocs(PByte(ModulePtr), ModuleSize, CallbacksAddr, Relocs, CallbacksRva) then
      Exit;
  end
  else if not VirtualAddrToRvaMapped(PByte(ModulePtr), ModuleSize, CallbacksAddr, CallbacksRva) then
    Exit;
  LogDebug('TLS Callbacks RVA: 0x%x.', [CallbacksRva]);
  if Is64Bit(PByte(ModulePtr)) then
    Result := FetchCallbacksList64(ModulePtr, ModuleSize, CallbacksRva, TlsCallbacks)
  else
    Result := FetchCallbacksList32(ModulePtr, ModuleSize, CallbacksRva, TlsCallbacks);
end;

function ListTlsCallbacks(ModulePtr: Pointer; ModuleSize: NativeUInt; TlsCallbacks: TList<UInt64>): NativeUInt;
begin
  Result := ListTlsCallbacksWithRelocs(ModulePtr, ModuleSize, TlsCallbacks, nil);
end;

function RunTlsCallbacks(ModulePtr: Pointer; ModuleSize: NativeUInt; DwReason: DWORD): NativeUInt;
var
  ImgSize: DWORD;
  Relocs: TRelocValueSet;
  TlsCallbacks: TList<UInt64>;
  I: NativeUInt;
  CallbackAddr: UInt64;
  Rva: DWORD;
  CallbackVa: NativeUInt;
  CallbackFunc: TTlsCallback;
begin
  Result := 0;
  ImgSize := GetImageSize(PByte(ModulePtr));
  if ImgSize = 0 then
    Exit;
  if ModuleSize = 0 then
    ModuleSize := ImgSize;
  Relocs := TRelocValueSet.Create;
  TlsCallbacks := TList<UInt64>.Create;
  try
    CollectRelocValues(PByte(ModulePtr), ModuleSize, Relocs);
    if ListTlsCallbacksWithRelocs(ModulePtr, ModuleSize, TlsCallbacks, Relocs) = 0 then
      Exit(0);
    I := 0;
    while I < NativeUInt(TlsCallbacks.Count) do
    begin
      CallbackAddr := TlsCallbacks[I];
      Rva := 0;
      if not VirtualAddrToRvaWithRelocs(PByte(ModulePtr), ImgSize, CallbackAddr, Relocs, Rva) then
      begin
        Inc(I);
        Continue;
      end;
      LogDebug('TLS RVA: 0x%x.', [Rva]);
      CallbackVa := NativeUInt(Rva) + NativeUInt(ModulePtr);
      if not ValidatePtr(ModulePtr, ModuleSize, Pointer(CallbackVa), SizeOf(Byte)) then
      begin
        Inc(I);
        Continue;
      end;
      CallbackFunc := TTlsCallback(CallbackVa);
      LogInfo('Calling TLS callback[%u].', [I]);
      CallbackFunc(ModulePtr, DwReason, nil);
      Inc(I);
    end;
    Result := I;
  finally
    TlsCallbacks.Free;
    Relocs.Free;
  end;
end;

end.
