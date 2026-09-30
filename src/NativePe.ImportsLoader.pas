{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/imports_loader.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ImportsLoader;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.Types,
  NativePe.FunctionResolver,
  NativePe.ExportedFunc;

type
  TImportThunksCallback = class abstract
  protected
    FModulePtr: PByte;
    FModuleSize: NativeUInt;
    FIs64B: Boolean;
  public
    constructor Create(AModulePtr: PByte; AModuleSize: NativeUInt);
    function ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr: NativeUInt; FirstThunkPtr: NativeUInt): Boolean;
      virtual; abstract;
  end;

  TImportsCollection = class
  public
    ThunkToFunc: TObjectDictionary<DWORD, TExportedFunc>;
    constructor Create;
    destructor Destroy; override;
  end;

function ProcessImportTable(ModulePtr: PByte; ModuleSize: NativeUInt; Callback: TImportThunksCallback): Boolean;
function LoadImports(ModulePtr: PByte; FuncResolver: TFunctionResolver = nil): Boolean;
function HasValidImportTable(ModulePtr: PByte; ModuleSize: NativeUInt; MaxCount: NativeUInt = 0;
  StrictImportDirectorySize: Boolean = False): Boolean;
function IsValidImportName(ModulePtr: PByte; ModuleSize: NativeUInt; LibName: PAnsiChar): Boolean;
function CollectThunks(ModulePtr: PByte; ModuleSize: NativeUInt; ThunkRvas: TList<DWORD>): Boolean;
function CollectImports(ModulePtr: PByte; ModuleSize: NativeUInt; Collection: TImportsCollection): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.Logger;

constructor TImportThunksCallback.Create(AModulePtr: PByte; AModuleSize: NativeUInt);
begin
  inherited Create;
  FModulePtr := AModulePtr;
  FModuleSize := AModuleSize;
  FIs64B := Is64Bit(AModulePtr);
end;

constructor TImportsCollection.Create;
begin
  inherited Create;
  ThunkToFunc := TObjectDictionary<DWORD, TExportedFunc>.Create([doOwnsValues]);
end;

destructor TImportsCollection.Destroy;
begin
  ThunkToFunc.Free;
  inherited Destroy;
end;

type
  TFillImportThunks = class(TImportThunksCallback)
  private
    FFuncResolver: TFunctionResolver;
  public
    constructor Create(AModulePtr: PByte; AModuleSize: NativeUInt; AFuncResolver: TFunctionResolver);
    function ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, FirstThunkPtr: NativeUInt): Boolean; override;
  end;

  TCollectThunksCallback = class(TImportThunksCallback)
  private
    FFields: TList<DWORD>;
  public
    constructor Create(AModulePtr: PByte; AModuleSize: NativeUInt; AFields: TList<DWORD>);
    function ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, Va: NativeUInt): Boolean; override;
  end;

  TCollectImportsCallback = class(TImportThunksCallback)
  private
    FThunkToFunc: TObjectDictionary<DWORD, TExportedFunc>;
  public
    constructor Create(AModulePtr: PByte; AModuleSize: NativeUInt; AThunkToFunc: TObjectDictionary<DWORD, TExportedFunc>);
    function ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, FirstThunkPtr: NativeUInt): Boolean; override;
  end;

constructor TFillImportThunks.Create(AModulePtr: PByte; AModuleSize: NativeUInt; AFuncResolver: TFunctionResolver);
begin
  inherited Create(AModulePtr, AModuleSize);
  FFuncResolver := AFuncResolver;
end;

function TFillImportThunks.ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, FirstThunkPtr: NativeUInt): Boolean;
var
  IsByOrd: Boolean;
  HProc: FARPROC;
  RawOrdinal32: DWORD;
  RawOrdinal64: UInt64;
  ByName: PImageImportByName;
  FuncNamePtr: PAnsiChar;
begin
  Result := False;
  if not Assigned(FFuncResolver) then
    Exit;
  if FIs64B then
  begin
    IsByOrd := (PImageThunkData64(OrigFirstThunkPtr).Ordinal and IMAGE_ORDINAL_FLAG64) <> 0;
    HProc := nil;
    if IsByOrd then
    begin
      RawOrdinal64 := PImageThunkData64(OrigFirstThunkPtr).Ordinal and (not IMAGE_ORDINAL_FLAG64);
      LogDebug('raw ordinal: 0x%x.', [RawOrdinal64]);
      HProc := FFuncResolver.ResolveFunc(LibName, PAnsiChar(NativeUInt(RawOrdinal64)));
    end
    else
    begin
      ByName := PImageImportByName(NativeUInt(FModulePtr) + PImageThunkData64(OrigFirstThunkPtr).AddressOfData);
      if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
      begin
        LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME.');
        Exit(False);
      end;
      FuncNamePtr := @ByName.Name[0];
      if not IsValidStringA(FModulePtr, FModuleSize, FuncNamePtr) then
      begin
        LogError('Invalid pointer to function name.');
        Exit(False);
      end;
      LogDebug('name: %s.', [string(AnsiString(FuncNamePtr))]);
      HProc := FFuncResolver.ResolveFunc(LibName, FuncNamePtr);
    end;
    if not Assigned(HProc) then
    begin
      LogError('Could not resolve the function.');
      Exit(False);
    end;
    PImageThunkData64(FirstThunkPtr).Func := UInt64(HProc);
    Result := True;
  end
  else
  begin
    IsByOrd := (PImageThunkData32(OrigFirstThunkPtr).Ordinal and IMAGE_ORDINAL_FLAG32) <> 0;
    HProc := nil;
    if IsByOrd then
    begin
      RawOrdinal32 := PImageThunkData32(OrigFirstThunkPtr).Ordinal and (not IMAGE_ORDINAL_FLAG32);
      LogDebug('raw ordinal: 0x%x.', [RawOrdinal32]);
      HProc := FFuncResolver.ResolveFunc(LibName, PAnsiChar(NativeUInt(RawOrdinal32)));
    end
    else
    begin
      ByName := PImageImportByName(NativeUInt(FModulePtr) + PImageThunkData32(OrigFirstThunkPtr).AddressOfData);
      if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
      begin
        LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME.');
        Exit(False);
      end;
      FuncNamePtr := @ByName.Name[0];
      if not IsValidStringA(FModulePtr, FModuleSize, FuncNamePtr) then
      begin
        LogError('Invalid pointer to function name.');
        Exit(False);
      end;
      LogDebug('name: %s.', [string(AnsiString(FuncNamePtr))]);
      HProc := FFuncResolver.ResolveFunc(LibName, FuncNamePtr);
    end;
    if not Assigned(HProc) then
    begin
      LogError('Could not resolve the function.');
      Exit(False);
    end;
    PImageThunkData32(FirstThunkPtr).Func := DWORD(NativeUInt(HProc));
    Result := True;
  end;
end;

constructor TCollectThunksCallback.Create(AModulePtr: PByte; AModuleSize: NativeUInt; AFields: TList<DWORD>);
begin
  inherited Create(AModulePtr, AModuleSize);
  FFields := AFields;
end;

function TCollectThunksCallback.ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, Va: NativeUInt): Boolean;
var
  ModuleBase: NativeUInt;
  ThunkRva: DWORD;
begin
  if Va = 0 then
    Exit(False);
  ModuleBase := NativeUInt(FModulePtr);
  if Va < ModuleBase then
    Exit(False);
  if Va >= ModuleBase + FModuleSize then
    Exit(False);
  ThunkRva := MaskToDword(Va - ModuleBase);
  if FFields.IndexOf(ThunkRva) < 0 then
    FFields.Add(ThunkRva);
  Result := True;
end;

constructor TCollectImportsCallback.Create(AModulePtr: PByte; AModuleSize: NativeUInt;
  AThunkToFunc: TObjectDictionary<DWORD, TExportedFunc>);
begin
  inherited Create(AModulePtr, AModuleSize);
  FThunkToFunc := AThunkToFunc;
end;

function TCollectImportsCallback.ProcessThunks(LibName: PAnsiChar; OrigFirstThunkPtr, FirstThunkPtr: NativeUInt): Boolean;
var
  ShortName: string;
  IsByOrd: Boolean;
  Func: TExportedFunc;
  Rva: DWORD;
  ByName: PImageImportByName;
  FuncNamePtr: PAnsiChar;
  Ordinal: Word;
begin
  Result := False;
  if FirstThunkPtr = 0 then
    Exit;
  ShortName := GetDllShortName(string(AnsiString(LibName)));
  Func := nil;
  if FIs64B then
  begin
    IsByOrd := (PImageThunkData64(OrigFirstThunkPtr).Ordinal and IMAGE_ORDINAL_FLAG64) <> 0;
    if IsByOrd then
      Func := TExportedFunc.Create(ShortName, DWORD(PImageThunkData64(OrigFirstThunkPtr).Ordinal and (not IMAGE_ORDINAL_FLAG64)))
    else
    begin
      ByName := PImageImportByName(NativeUInt(FModulePtr) + PImageThunkData64(OrigFirstThunkPtr).AddressOfData);
      if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
      begin
        LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME.');
        Exit(False);
      end;
      FuncNamePtr := @ByName.Name[0];
      if not IsValidStringA(FModulePtr, FModuleSize, FuncNamePtr) then
      begin
        LogError('Invalid pointer to function name.');
        Exit(False);
      end;
      Ordinal := ByName.Hint;
      Func := TExportedFunc.Create(ShortName, string(AnsiString(FuncNamePtr)), Ordinal);
    end;
  end
  else
  begin
    IsByOrd := (PImageThunkData32(OrigFirstThunkPtr).Ordinal and IMAGE_ORDINAL_FLAG32) <> 0;
    if IsByOrd then
      Func := TExportedFunc.Create(ShortName, PImageThunkData32(OrigFirstThunkPtr).Ordinal and (not IMAGE_ORDINAL_FLAG32))
    else
    begin
      ByName := PImageImportByName(NativeUInt(FModulePtr) + PImageThunkData32(OrigFirstThunkPtr).AddressOfData);
      if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
      begin
        LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME.');
        Exit(False);
      end;
      FuncNamePtr := @ByName.Name[0];
      if not IsValidStringA(FModulePtr, FModuleSize, FuncNamePtr) then
      begin
        LogError('Invalid pointer to function name.');
        Exit(False);
      end;
      Ordinal := ByName.Hint;
      Func := TExportedFunc.Create(ShortName, string(AnsiString(FuncNamePtr)), Ordinal);
    end;
  end;
  if Func = nil then
    Exit(False);
  Rva := MaskToDword(FirstThunkPtr - NativeUInt(FModulePtr));
  FThunkToFunc.AddOrSetValue(Rva, Func);
  Result := True;
end;

function ProcessImpFunctions32(ModulePtr: PByte; ModuleSize: NativeUInt; LibName: PAnsiChar; CallVia, ThunkAddr: DWORD;
  Callback: TImportThunksCallback): Boolean;
var
  Index: NativeUInt;
  ThunkPtr, CallerPtr: PImageThunkData32;
  IsByOrd: Boolean;
  ByName: PImageImportByName;
begin
  Result := True;
  Index := 0;
  while True do
  begin
    CallerPtr := PImageThunkData32(NativeUInt(ModulePtr) + CallVia + Index * SizeOf(TImageThunkData32));
    ThunkPtr := PImageThunkData32(NativeUInt(ModulePtr) + ThunkAddr + Index * SizeOf(TImageThunkData32));
    if not ValidatePtr(ModulePtr, ModuleSize, CallerPtr, SizeOf(TImageThunkData32)) then
      Exit(False);
    if not ValidatePtr(ModulePtr, ModuleSize, ThunkPtr, SizeOf(TImageThunkData32)) then
      Exit(False);
    if ThunkPtr.Func = 0 then
      Break;
    IsByOrd := (ThunkPtr.Ordinal and IMAGE_ORDINAL_FLAG32) <> 0;
    if not IsByOrd then
    begin
      ByName := PImageImportByName(NativeUInt(ModulePtr) + ThunkPtr.AddressOfData);
      if not ValidatePtr(ModulePtr, ModuleSize, ByName, SizeOf(TImageImportByName)) then
        Exit(False);
    end;
    if (Callback <> nil) and (not Callback.ProcessThunks(LibName, NativeUInt(ThunkPtr), NativeUInt(CallerPtr))) then
      Result := False;
    Inc(Index);
  end;
end;

function ProcessImpFunctions64(ModulePtr: PByte; ModuleSize: NativeUInt; LibName: PAnsiChar; CallVia, ThunkAddr: DWORD;
  Callback: TImportThunksCallback): Boolean;
var
  Index: NativeUInt;
  ThunkPtr, CallerPtr: PImageThunkData64;
  IsByOrd: Boolean;
  ByName: PImageImportByName;
begin
  Result := True;
  Index := 0;
  while True do
  begin
    CallerPtr := PImageThunkData64(NativeUInt(ModulePtr) + CallVia + Index * SizeOf(TImageThunkData64));
    ThunkPtr := PImageThunkData64(NativeUInt(ModulePtr) + ThunkAddr + Index * SizeOf(TImageThunkData64));
    if not ValidatePtr(ModulePtr, ModuleSize, CallerPtr, SizeOf(TImageThunkData64)) then
      Exit(False);
    if not ValidatePtr(ModulePtr, ModuleSize, ThunkPtr, SizeOf(TImageThunkData64)) then
      Exit(False);
    if ThunkPtr.Func = 0 then
      Break;
    IsByOrd := (ThunkPtr.Ordinal and IMAGE_ORDINAL_FLAG64) <> 0;
    if not IsByOrd then
    begin
      ByName := PImageImportByName(NativeUInt(ModulePtr) + ThunkPtr.AddressOfData);
      if not ValidatePtr(ModulePtr, ModuleSize, ByName, SizeOf(TImageImportByName)) then
        Exit(False);
    end;
    if (Callback <> nil) and (not Callback.ProcessThunks(LibName, NativeUInt(ThunkPtr), NativeUInt(CallerPtr))) then
      Result := False;
    Inc(Index);
  end;
end;

function ProcessDlls(ModulePtr: PByte; ModuleSize: NativeUInt; FirstDesc: PImageImportDescriptor;
  Callback: TImportThunksCallback): Boolean;
var
  IsAllFilled, Is64, AllSolved: Boolean;
  LibDesc: PImageImportDescriptor;
  I: NativeUInt;
  LibName: PAnsiChar;
  CallVia, ThunkAddr: DWORD;
begin
  IsAllFilled := True;
  LogDebug('---IMP---');
  Is64 := Is64Bit(ModulePtr);
  I := 0;
  while True do
  begin
    LibDesc := PImageImportDescriptor(NativeUInt(FirstDesc) + I * SizeOf(TImageImportDescriptor));
    if not ValidatePtr(ModulePtr, ModuleSize, LibDesc, SizeOf(TImageImportDescriptor)) then
      Exit(False);
    if (LibDesc.OriginalFirstThunk = 0) and (LibDesc.FirstThunk = 0) then
      Break;
    LibName := PAnsiChar(NativeUInt(ModulePtr) + LibDesc.Name);
    if not IsValidImportName(ModulePtr, ModuleSize, LibName) then
      Exit(False);
    CallVia := LibDesc.FirstThunk;
    ThunkAddr := LibDesc.OriginalFirstThunk;
    if ThunkAddr = 0 then
      ThunkAddr := LibDesc.FirstThunk;
    LogDebug('Imported Lib: 0x%x : 0x%x : 0x%x', [LibDesc.FirstThunk, LibDesc.OriginalFirstThunk, LibDesc.Name]);
    if Is64 then
      AllSolved := ProcessImpFunctions64(ModulePtr, ModuleSize, LibName, CallVia, ThunkAddr, Callback)
    else
      AllSolved := ProcessImpFunctions32(ModulePtr, ModuleSize, LibName, CallVia, ThunkAddr, Callback);
    if not AllSolved then
      IsAllFilled := False;
    Inc(I);
  end;
  LogDebug('---------');
  Result := IsAllFilled;
end;

function ProcessImportTable(ModulePtr: PByte; ModuleSize: NativeUInt; Callback: TImportThunksCallback): Boolean;
var
  ImportsDir: PImageDataDirectory;
  ImpAddr: DWORD;
  FirstDesc: PImageImportDescriptor;
begin
  Result := False;
  if ModuleSize = 0 then
    ModuleSize := GetImageSize(ModulePtr);
  if ModuleSize = 0 then
    Exit;
  ImportsDir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if ImportsDir = nil then
    Exit(True);
  ImpAddr := ImportsDir.VirtualAddress;
  FirstDesc := PImageImportDescriptor(NativeUInt(ImpAddr) + NativeUInt(ModulePtr));
  if not ValidatePtr(ModulePtr, ModuleSize, FirstDesc, SizeOf(TImageImportDescriptor)) then
    Exit;
  Result := ProcessDlls(ModulePtr, ModuleSize, FirstDesc, Callback);
end;

function LoadImports(ModulePtr: PByte; FuncResolver: TFunctionResolver): Boolean;
var
  ModuleSize: NativeUInt;
  Is64, IsLoader64: Boolean;
  DefaultRes: TDefaultFuncResolver;
  Callback: TFillImportThunks;
  Resolver: TFunctionResolver;
begin
  Result := False;
  ModuleSize := GetImageSize(ModulePtr);
  if ModuleSize = 0 then
    Exit;
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
  DefaultRes := nil;
  Resolver := FuncResolver;
  if not Assigned(Resolver) then
  begin
    DefaultRes := TDefaultFuncResolver.Create;
    Resolver := DefaultRes;
  end;
  try
    Callback := TFillImportThunks.Create(ModulePtr, ModuleSize, Resolver);
    try
      Result := ProcessImportTable(ModulePtr, ModuleSize, Callback);
    finally
      Callback.Free;
    end;
  finally
    DefaultRes.Free;
  end;
end;

function IsValidImportName(ModulePtr: PByte; ModuleSize: NativeUInt; LibName: PAnsiChar): Boolean;
var
  I: NativeUInt;
  IsTerminated: Boolean;
  NextChar: AnsiChar;
  P: PAnsiChar;
begin
  IsTerminated := False;
  P := LibName;
  for I := 0 to MAX_PATH - 1 do
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, P, SizeOf(AnsiChar)) then
      Exit(False);
    NextChar := P^;
    if NextChar = #0 then
    begin
      IsTerminated := True;
      Break;
    end;
    if (Ord(NextChar) < $20) or (Ord(NextChar) >= $7E) then
      Exit(False);
    Inc(P);
  end;
  Result := IsTerminated;
end;

function InternalHasValidImportTable32(ModulePtr: PByte; ModuleSize: NativeUInt; MaxCount: NativeUInt;
  StrictImportDirectorySize: Boolean): Boolean;
var
  ImportsDir: PImageDataDirectory;
  ImpAddr: DWORD;
  LibDesc: PImageImportDescriptor;
  ParsedSize, ValidRecords, MaxSize, AvailableSize: NativeUInt;
  IsTerminated: Boolean;
  LibName: PAnsiChar;
  CallVia, ThunkAddr: DWORD;
  Thunks, Callers: PDWORD;
begin
  Result := False;
  ImportsDir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if ImportsDir = nil then
    Exit;
  ImpAddr := ImportsDir.VirtualAddress;
  if (ImpAddr = 0) or (ImpAddr >= ModuleSize) then
    Exit;
  AvailableSize := ModuleSize - NativeUInt(ImpAddr);
  if StrictImportDirectorySize then
    MaxSize := ImportsDir.Size
  else
    MaxSize := AvailableSize;
  if MaxSize > AvailableSize then
    MaxSize := AvailableSize;
  ParsedSize := 0;
  ValidRecords := 0;
  IsTerminated := False;
  while ParsedSize < MaxSize do
  begin
    if (MaxCount <> 0) and (ValidRecords >= MaxCount) then
      Break;
    if StrictImportDirectorySize and (SizeOf(TImageImportDescriptor) > MaxSize - ParsedSize) then
      Exit(False);
    LibDesc := PImageImportDescriptor(NativeUInt(ImpAddr) + ParsedSize + NativeUInt(ModulePtr));
    if not ValidatePtr(ModulePtr, ModuleSize, LibDesc, SizeOf(TImageImportDescriptor)) then
      Exit(False);
    Inc(ParsedSize, SizeOf(TImageImportDescriptor));
    if (LibDesc.OriginalFirstThunk = 0) and (LibDesc.FirstThunk = 0) then
    begin
      IsTerminated := True;
      Break;
    end;
    LibName := PAnsiChar(NativeUInt(ModulePtr) + LibDesc.Name);
    if not IsValidImportName(ModulePtr, ModuleSize, LibName) then
      Exit(False);
    CallVia := LibDesc.FirstThunk;
    ThunkAddr := LibDesc.OriginalFirstThunk;
    if ThunkAddr = 0 then
      ThunkAddr := LibDesc.FirstThunk;
    Thunks := PDWORD(NativeUInt(ModulePtr) + ThunkAddr);
    if not ValidatePtr(ModulePtr, ModuleSize, Thunks, SizeOf(DWORD)) then
      Exit(False);
    Callers := PDWORD(NativeUInt(ModulePtr) + CallVia);
    if not ValidatePtr(ModulePtr, ModuleSize, Callers, SizeOf(DWORD)) then
      Exit(False);
    Inc(ValidRecords);
  end;
  Result := IsTerminated and (ValidRecords > 0);
end;

function InternalHasValidImportTable64(ModulePtr: PByte; ModuleSize: NativeUInt; MaxCount: NativeUInt;
  StrictImportDirectorySize: Boolean): Boolean;
var
  ImportsDir: PImageDataDirectory;
  ImpAddr: DWORD;
  LibDesc: PImageImportDescriptor;
  ParsedSize, ValidRecords, MaxSize, AvailableSize: NativeUInt;
  IsTerminated: Boolean;
  LibName: PAnsiChar;
  CallVia, ThunkAddr: DWORD;
  Thunks, Callers: PUInt64;
begin
  Result := False;
  ImportsDir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if ImportsDir = nil then
    Exit;
  ImpAddr := ImportsDir.VirtualAddress;
  if (ImpAddr = 0) or (ImpAddr >= ModuleSize) then
    Exit;
  AvailableSize := ModuleSize - NativeUInt(ImpAddr);
  if StrictImportDirectorySize then
    MaxSize := ImportsDir.Size
  else
    MaxSize := AvailableSize;
  if MaxSize > AvailableSize then
    MaxSize := AvailableSize;
  ParsedSize := 0;
  ValidRecords := 0;
  IsTerminated := False;
  while ParsedSize < MaxSize do
  begin
    if (MaxCount <> 0) and (ValidRecords >= MaxCount) then
      Break;
    if StrictImportDirectorySize and (SizeOf(TImageImportDescriptor) > MaxSize - ParsedSize) then
      Exit(False);
    LibDesc := PImageImportDescriptor(NativeUInt(ImpAddr) + ParsedSize + NativeUInt(ModulePtr));
    if not ValidatePtr(ModulePtr, ModuleSize, LibDesc, SizeOf(TImageImportDescriptor)) then
      Exit(False);
    Inc(ParsedSize, SizeOf(TImageImportDescriptor));
    if (LibDesc.OriginalFirstThunk = 0) and (LibDesc.FirstThunk = 0) then
    begin
      IsTerminated := True;
      Break;
    end;
    LibName := PAnsiChar(NativeUInt(ModulePtr) + LibDesc.Name);
    if not IsValidImportName(ModulePtr, ModuleSize, LibName) then
      Exit(False);
    CallVia := LibDesc.FirstThunk;
    ThunkAddr := LibDesc.OriginalFirstThunk;
    if ThunkAddr = 0 then
      ThunkAddr := LibDesc.FirstThunk;
    Thunks := PUInt64(NativeUInt(ModulePtr) + ThunkAddr);
    if not ValidatePtr(ModulePtr, ModuleSize, Thunks, SizeOf(UInt64)) then
      Exit(False);
    Callers := PUInt64(NativeUInt(ModulePtr) + CallVia);
    if not ValidatePtr(ModulePtr, ModuleSize, Callers, SizeOf(UInt64)) then
      Exit(False);
    Inc(ValidRecords);
  end;
  Result := IsTerminated and (ValidRecords > 0);
end;

function HasValidImportTable(ModulePtr: PByte; ModuleSize: NativeUInt; MaxCount: NativeUInt;
  StrictImportDirectorySize: Boolean): Boolean;
begin
  if Is64Bit(ModulePtr) then
    Result := InternalHasValidImportTable64(ModulePtr, ModuleSize, MaxCount, StrictImportDirectorySize)
  else
    Result := InternalHasValidImportTable32(ModulePtr, ModuleSize, MaxCount, StrictImportDirectorySize);
end;

function CollectThunks(ModulePtr: PByte; ModuleSize: NativeUInt; ThunkRvas: TList<DWORD>): Boolean;
var
  Collector: TCollectThunksCallback;
begin
  Collector := TCollectThunksCallback.Create(ModulePtr, ModuleSize, ThunkRvas);
  try
    Result := ProcessImportTable(ModulePtr, ModuleSize, Collector);
  finally
    Collector.Free;
  end;
end;

function CollectImports(ModulePtr: PByte; ModuleSize: NativeUInt; Collection: TImportsCollection): Boolean;
var
  Collector: TCollectImportsCallback;
begin
  Collector := TCollectImportsCallback.Create(ModulePtr, ModuleSize, Collection.ThunkToFunc);
  try
    Result := ProcessImportTable(ModulePtr, ModuleSize, Collector);
  finally
    Collector.Free;
  end;
end;

end.
