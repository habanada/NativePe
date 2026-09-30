{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/imports_uneraser.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ImportsUneraser;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  NativePe.Types,
  NativePe.ExportedFunc,
  NativePe.ExportsMapper;

type
  TAddrToFuncMap = TObjectDictionary<UInt64, TExportedFuncSet>;

  TImpsNotCovered = class
  public
    ThunkToAddr: TDictionary<DWORD, UInt64>;
    constructor Create;
    destructor Destroy; override;
    function Count: NativeUInt;
    procedure Insert(ThunkRva: DWORD; SearchedAddr: UInt64);
  end;

  TImportedDllCoverage = class
  private
    FAddresses: TList<UInt64>;
    FExportsMap: TExportsMapper;
    FMappedDllName: string;
  public
    AddrToFunc: TAddrToFuncMap;
    NotFound: TList<UInt64>;
    DllName: string;
    constructor Create(AAddresses: TList<UInt64>; AExportsMap: TExportsMapper);
    destructor Destroy; override;
    function FindCoveringDll: Boolean;
    function MapAddressesToFunctions(const AMappedDllName: string): NativeUInt;
    function IsMappingComplete: Boolean;
  end;

  TImportsUneraser = class
  private
    FModulePtr: PByte;
    FModuleSize: NativeUInt;
    FIs64: Boolean;
    function WriteFoundDllName(LibDesc: PImageImportDescriptor; const FoundName: AnsiString): Boolean;
    function WriteFoundFunction32(Desc: PImageThunkData32; OrdinalFlag: DWORD; FoundFunc: TExportedFunc): Boolean;
    function WriteFoundFunction64(Desc: PImageThunkData64; OrdinalFlag: UInt64; FoundFunc: TExportedFunc): Boolean;
    function FindNameInBinaryAndFill32(LibDesc: PImageImportDescriptor; CallViaPtr, ThunkPtr: PByte;
      OrdinalFlag: DWORD; AddrToFunc: TAddrToFuncMap): Boolean;
    function FindNameInBinaryAndFill64(LibDesc: PImageImportDescriptor; CallViaPtr, ThunkPtr: PByte;
      OrdinalFlag: UInt64; AddrToFunc: TAddrToFuncMap): Boolean;
    function FillImportNames32(LibDesc: PImageImportDescriptor; OrdinalFlag: DWORD; AddrToFunc: TAddrToFuncMap;
      NotCovered: TImpsNotCovered): Boolean;
    function FillImportNames64(LibDesc: PImageImportDescriptor; OrdinalFlag: UInt64; AddrToFunc: TAddrToFuncMap;
      NotCovered: TImpsNotCovered): Boolean;
  public
    constructor Create(ModulePtr: Pointer; ModuleSize: NativeUInt);
    function UneraseDllImports(LibDesc: PImageImportDescriptor; DllCoverage: TImportedDllCoverage;
      NotCovered: TImpsNotCovered): Boolean;
    function UneraseDllName(LibDesc: PImageImportDescriptor; const DllName: AnsiString): Boolean;
  end;

implementation

uses
  System.SysUtils,
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.Caves,
  NativePe.Logger;

function SearchName(const Name: AnsiString; ModulePtr: PByte; ModuleSize: NativeUInt): PByte;
var
  SearchedLen, I, MaxStart: NativeUInt;
begin
  Result := nil;
  SearchedLen := NativeUInt(Length(Name)) + 1;
  if SearchedLen > ModuleSize then
    Exit;
  MaxStart := ModuleSize - SearchedLen;
  I := 0;
  while I <= MaxStart do
  begin
    if CompareMem(Pointer(PAnsiChar(Name)), Pointer(NativeUInt(ModulePtr) + I), SearchedLen) then
      Exit(PByte(NativeUInt(ModulePtr) + I));
    Inc(I);
  end;
end;

function GetAllDllsExportingFunction(FuncAddr: UInt64; ExportsMap: TExportsMapper): TList<string>;
var
  ExportsForVa: TExportedFuncSet;
  Pair: TPair<string, TExportedFunc>;
  Seen: TDictionary<string, Boolean>;
  DllNm: string;
begin
  Result := TList<string>.Create;
  ExportsForVa := ExportsMap.FindExportsByVa(FuncAddr);
  if ExportsForVa = nil then
  begin
    LogWarning('Cannot find any DLL exporting: 0x%x.', [FuncAddr]);
    Exit;
  end;
  Seen := TDictionary<string, Boolean>.Create;
  try
    for Pair in ExportsForVa do
    begin
      DllNm := Pair.Value.LibName;
      if not Seen.ContainsKey(DllNm) then
      begin
        Seen.Add(DllNm, True);
        Result.Add(DllNm);
      end;
    end;
  finally
    Seen.Free;
  end;
  Result.Sort;
end;

function GetDllsIntersection(DllNames, CurrDllNames: TList<string>): TList<string>;
var
  S: string;
begin
  Result := TList<string>.Create;
  for S in DllNames do
    if CurrDllNames.Contains(S) then
      Result.Add(S);
  Result.Sort;
end;

function FindCoveringDllFree(Addresses: TList<UInt64>; ExportsMap: TExportsMapper): string;
var
  MainDllsSet, ReserveDllSet, CurrDllNames, ResultSet: TList<string>;
  IsFresh: Boolean;
  SearchedAddr: UInt64;
  I: Integer;
begin
  Result := '';
  MainDllsSet := TList<string>.Create;
  ReserveDllSet := TList<string>.Create;
  try
    IsFresh := True;
    for I := 0 to Addresses.Count - 1 do
    begin
      SearchedAddr := Addresses[I];
      CurrDllNames := GetAllDllsExportingFunction(SearchedAddr, ExportsMap);
      try
        if IsFresh then
        begin
          MainDllsSet.Clear;
          MainDllsSet.AddRange(CurrDllNames);
          IsFresh := False;
          Continue;
        end;

        ResultSet := GetDllsIntersection(MainDllsSet, CurrDllNames);
        try
          if ResultSet.Count > 0 then
          begin
            MainDllsSet.Clear;
            MainDllsSet.AddRange(ResultSet);
            Continue;
          end;
        finally
          ResultSet.Free;
        end;

        ResultSet := GetDllsIntersection(ReserveDllSet, CurrDllNames);
        try
          if ResultSet.Count > 0 then
          begin
            ReserveDllSet.Clear;
            ReserveDllSet.AddRange(MainDllsSet);
            MainDllsSet.Clear;
            MainDllsSet.AddRange(ResultSet);
            Continue;
          end;
        finally
          ResultSet.Free;
        end;

        ReserveDllSet.Clear;
        ReserveDllSet.AddRange(CurrDllNames);
      finally
        CurrDllNames.Free;
      end;
    end;
    if MainDllsSet.Count > 0 then
      Result := MainDllsSet[0];
  finally
    MainDllsSet.Free;
    ReserveDllSet.Free;
  end;
end;

function MapAddressesToFunctionsFree(Addresses: TList<UInt64>; const ChosenDll: string; ExportsMap: TExportsMapper;
  AddrToFunc: TAddrToFuncMap; NotFound: TList<UInt64>): NativeUInt;
var
  CoveredAddresses: TList<UInt64>;
  I: Integer;
  SearchedAddr: UInt64;
  ExportsForVa: TExportedFuncSet;
  Pair: TPair<string, TExportedFunc>;
  FuncSet: TExportedFuncSet;
  Func: TExportedFunc;
begin
  CoveredAddresses := TList<UInt64>.Create;
  try
    for I := 0 to Addresses.Count - 1 do
    begin
      SearchedAddr := Addresses[I];
      ExportsForVa := ExportsMap.FindExportsByVa(SearchedAddr);
      if ExportsForVa = nil then
      begin
        if not NotFound.Contains(SearchedAddr) then
          NotFound.Add(SearchedAddr);
        LogWarning('Cannot find any DLL exporting: 0x%x.', [SearchedAddr]);
        Continue;
      end;

      for Pair in ExportsForVa do
      begin
        if Pair.Value.LibName <> ChosenDll then
          Continue;
        if not AddrToFunc.TryGetValue(SearchedAddr, FuncSet) then
        begin
          FuncSet := TExportedFuncSet.Create([doOwnsValues]);
          AddrToFunc.Add(SearchedAddr, FuncSet);
        end;
        if not FuncSet.ContainsKey(Pair.Value.MapKey) then
          FuncSet.Add(Pair.Value.MapKey, TExportedFunc.Create(Pair.Value));
        if not CoveredAddresses.Contains(SearchedAddr) then
          CoveredAddresses.Add(SearchedAddr);
      end;

      if not AddrToFunc.ContainsKey(SearchedAddr) then
      begin
        Func := ExportsMap.FindExportByVa(SearchedAddr);
        if not NotFound.Contains(SearchedAddr) then
          NotFound.Add(SearchedAddr);
        if Func <> nil then
          LogWarning('Function ''%s'' not found in the covering DLL: %s.', [Func.ToStringFull, ChosenDll])
        else
          LogWarning('Function at [0x%x] not found in the covering DLL: %s.', [SearchedAddr, ChosenDll]);
      end;
    end;
    Result := NativeUInt(CoveredAddresses.Count);
  finally
    CoveredAddresses.Free;
  end;
end;

{ TImpsNotCovered }

constructor TImpsNotCovered.Create;
begin
  inherited Create;
  ThunkToAddr := TDictionary<DWORD, UInt64>.Create;
end;

destructor TImpsNotCovered.Destroy;
begin
  ThunkToAddr.Free;
  inherited Destroy;
end;

function TImpsNotCovered.Count: NativeUInt;
begin
  Result := NativeUInt(ThunkToAddr.Count);
end;

procedure TImpsNotCovered.Insert(ThunkRva: DWORD; SearchedAddr: UInt64);
begin
  LogWarning('Function not recovered: [0x%x].', [SearchedAddr]);
  ThunkToAddr.AddOrSetValue(ThunkRva, SearchedAddr);
end;

{ TImportedDllCoverage }

constructor TImportedDllCoverage.Create(AAddresses: TList<UInt64>; AExportsMap: TExportsMapper);
begin
  inherited Create;
  FAddresses := AAddresses;
  FExportsMap := AExportsMap;
  AddrToFunc := TAddrToFuncMap.Create([doOwnsValues]);
  NotFound := TList<UInt64>.Create;
end;

destructor TImportedDllCoverage.Destroy;
begin
  AddrToFunc.Free;
  NotFound.Free;
  inherited Destroy;
end;

function TImportedDllCoverage.FindCoveringDll: Boolean;
var
  FoundName: string;
begin
  FoundName := FindCoveringDllFree(FAddresses, FExportsMap);
  if FoundName = '' then
  begin
    LogWarning('Cannot find a covering DLL.');
    Exit(False);
  end;
  DllName := FoundName;
  LogDebug('Found DLL name: %s.', [FoundName]);
  Result := True;
end;

function TImportedDllCoverage.MapAddressesToFunctions(const AMappedDllName: string): NativeUInt;
begin
  FMappedDllName := AMappedDllName;
  if AddrToFunc.Count > 0 then
    AddrToFunc.Clear;
  NotFound.Clear;

  Result := MapAddressesToFunctionsFree(FAddresses, AMappedDllName, FExportsMap, AddrToFunc, NotFound);
  if NotFound.Count > 0 then
    LogWarning('Not all addresses are covered! Not found: %u.', [NativeUInt(NotFound.Count)])
  else
    LogDebug('All addresses covered.');
end;

function TImportedDllCoverage.IsMappingComplete: Boolean;
begin
  Result := FAddresses.Count = AddrToFunc.Count;
end;

{ TImportsUneraser }

constructor TImportsUneraser.Create(ModulePtr: Pointer; ModuleSize: NativeUInt);
begin
  inherited Create;
  FModulePtr := PByte(ModulePtr);
  FModuleSize := ModuleSize;
  FIs64 := Is64Bit(FModulePtr);
end;

function TImportsUneraser.WriteFoundDllName(LibDesc: PImageImportDescriptor; const FoundName: AnsiString): Boolean;
var
  NamePtr: PAnsiChar;
  FullNameLen: NativeUInt;
begin
  Result := False;
  LogDebug('Found name: %s.', [string(FoundName)]);
  NamePtr := PAnsiChar(NativeUInt(FModulePtr) + LibDesc.Name);
  FullNameLen := NativeUInt(Length(FoundName)) + 1;
  if not ValidatePtr(FModulePtr, FModuleSize, NamePtr, FullNameLen) then
  begin
    Dec(FullNameLen);
    if not ValidatePtr(FModulePtr, FModuleSize, NamePtr, FullNameLen) then
      Exit;
  end;
  Move(PAnsiChar(FoundName)^, NamePtr^, FullNameLen);
  Result := True;
end;

function TImportsUneraser.UneraseDllName(LibDesc: PImageImportDescriptor; const DllName: AnsiString): Boolean;
var
  NamePtr: PAnsiChar;
  DllLen: NativeUInt;
  CaveSize: DWORD;
  Ptr: PByte;
  CaveRva: DWORD;
begin
  Result := False;
  NamePtr := nil;
  if LibDesc.Name <> 0 then
    NamePtr := PAnsiChar(NativeUInt(FModulePtr) + LibDesc.Name);
  DllLen := NativeUInt(Length(DllName));
  if (NamePtr = nil) or (not ValidatePtr(FModulePtr, FModuleSize, NamePtr, DllLen)) then
  begin
    CaveSize := DWORD(DllLen + 1 + 5);
    Ptr := FindEndingCave(FModulePtr, FModuleSize, CaveSize);
    if Ptr = nil then
    begin
      LogError('Cannot save the DLL name: %s.', [string(DllName)]);
      Exit;
    end;
    CaveRva := DWORD(NativeUInt(Ptr) - NativeUInt(FModulePtr));
    LibDesc.Name := CaveRva;
  end;
  Result := WriteFoundDllName(LibDesc, DllName);
end;

function TImportsUneraser.WriteFoundFunction32(Desc: PImageThunkData32; OrdinalFlag: DWORD;
  FoundFunc: TExportedFunc): Boolean;
var
  Ordinal: DWORD;
  ByName: PImageImportByName;
  FuncNamePtr: PAnsiChar;
  FoundNameA: AnsiString;
  FullNameLen: NativeUInt;
begin
  Result := False;
  if FoundFunc.IsByOrdinal then
  begin
    Ordinal := FoundFunc.FuncOrdinal or OrdinalFlag;
    Desc.Ordinal := Ordinal;
    LogDebug('Saved ordinal: %u', [Ordinal]);
    Exit(True);
  end;
  ByName := PImageImportByName(NativeUInt(FModulePtr) + Desc.AddressOfData);
  if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
  begin
    LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME.');
    Exit;
  end;
  FuncNamePtr := PAnsiChar(@ByName.Name[0]);
  FoundNameA := AnsiString(FoundFunc.FuncName);
  FullNameLen := NativeUInt(Length(FoundNameA)) + 1;
  if not ValidatePtr(FModulePtr, FModuleSize, FuncNamePtr, FullNameLen) then
  begin
    LogError('Cannot save the name: not enough space.');
    Exit;
  end;
  ByName.Hint := MaskToWord(FoundFunc.FuncOrdinal);
  Move(PAnsiChar(FoundNameA)^, FuncNamePtr^, FullNameLen);
  LogDebug('Saved name: %s', [FoundFunc.FuncName]);
  Result := True;
end;

function TImportsUneraser.WriteFoundFunction64(Desc: PImageThunkData64; OrdinalFlag: UInt64;
  FoundFunc: TExportedFunc): Boolean;
var
  Ordinal: UInt64;
  ByName: PImageImportByName;
  FuncNamePtr: PAnsiChar;
  FoundNameA: AnsiString;
  FullNameLen: NativeUInt;
begin
  Result := False;
  if FoundFunc.IsByOrdinal then
  begin
    Ordinal := UInt64(FoundFunc.FuncOrdinal) or OrdinalFlag;
    Desc.Ordinal := Ordinal;
    LogDebug('Saved ordinal: %u', [Ordinal]);
    Exit(True);
  end;
  ByName := PImageImportByName(NativeUInt(FModulePtr) + NativeUInt(Desc.AddressOfData));
  if not ValidatePtr(FModulePtr, FModuleSize, ByName, SizeOf(TImageImportByName)) then
  begin
    LogError('Invalid pointer to IMAGE_IMPORT_BY_NAME.');
    Exit;
  end;
  FuncNamePtr := PAnsiChar(@ByName.Name[0]);
  FoundNameA := AnsiString(FoundFunc.FuncName);
  FullNameLen := NativeUInt(Length(FoundNameA)) + 1;
  if not ValidatePtr(FModulePtr, FModuleSize, FuncNamePtr, FullNameLen) then
  begin
    LogError('Cannot save the name: not enough space.');
    Exit;
  end;
  ByName.Hint := MaskToWord(FoundFunc.FuncOrdinal);
  Move(PAnsiChar(FoundNameA)^, FuncNamePtr^, FullNameLen);
  LogDebug('Saved name: %s', [FoundFunc.FuncName]);
  Result := True;
end;

function TImportsUneraser.FindNameInBinaryAndFill32(LibDesc: PImageImportDescriptor; CallViaPtr, ThunkPtr: PByte;
  OrdinalFlag: DWORD; AddrToFunc: TAddrToFuncMap): Boolean;
var
  ImportsDir: PImageDataDirectory;
  ImpAddr: DWORD;
  CallViaVal: PDWORD;
  SearchedAddr: UInt64;
  ExportsWithAddr: TExportedFuncSet;
  FuncsList: TList<TExportedFunc>;
  Func: TExportedFunc;
  IsNameSaved: Boolean;
  LastOrdinal: DWORD;
  NamesStart: PByte;
  RemainingSize: NativeUInt;
  FoundPtr: PByte;
  NameOffset: NativeUInt;
  ImpRva: DWORD;
  OrdThunk: DWORD;
  I: Integer;
begin
  Result := False;
  if (CallViaPtr = nil) or (FModulePtr = nil) or (LibDesc = nil) then
    Exit;
  ImportsDir := GetDirectoryEntry(FModulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if ImportsDir = nil then
    Exit;
  ImpAddr := ImportsDir.VirtualAddress;

  CallViaVal := PDWORD(CallViaPtr);
  if CallViaVal^ = 0 then
    Exit;
  SearchedAddr := UInt64(CallViaVal^);

  if not AddrToFunc.TryGetValue(SearchedAddr, ExportsWithAddr) then
  begin
    LogWarning('No mapped export mapped to the given address: 0x%x.', [SearchedAddr]);
    Exit;
  end;

  IsNameSaved := False;
  LastOrdinal := 0;

  FuncsList := TList<TExportedFunc>.Create;
  try
    FuncsList.AddRange(ExportsWithAddr.Values);
    FuncsList.Sort(ExpFuncComparer);
    for I := 0 to FuncsList.Count - 1 do
    begin
      Func := FuncsList[I];
      LastOrdinal := Func.FuncOrdinal;
      if Func.FuncName = '' then
        Continue;
      NamesStart := PByte(NativeUInt(FModulePtr) + ImpAddr);
      RemainingSize := FModuleSize - (NativeUInt(NamesStart) - NativeUInt(FModulePtr));
      FoundPtr := SearchName(AnsiString(Func.FuncName), NamesStart, RemainingSize);
      if FoundPtr = nil then
        Continue;
      if I <> 0 then
        LogDebug('>[*][0x%x] %s.', [SearchedAddr, Func.ToStringFull]);
      NameOffset := NativeUInt(FoundPtr) - NativeUInt(FModulePtr);
      LogDebug('Found the name at: 0x%x.', [NameOffset]);
      if NameOffset < SizeOf(Word) then
        Continue;
      ImpRva := DWORD(NameOffset - SizeOf(Word));
      Move(ImpRva, ThunkPtr^, SizeOf(DWORD));
      LogDebug('Wrote found to offset: 0x%x.', [NativeUInt(CallViaPtr)]);
      IsNameSaved := True;
      Break;
    end;
  finally
    FuncsList.Free;
  end;

  if (not IsNameSaved) and (LastOrdinal <> 0) then
  begin
    LogDebug('Filling ordinal: 0x%x.', [LastOrdinal]);
    OrdThunk := LastOrdinal or OrdinalFlag;
    Move(OrdThunk, ThunkPtr^, SizeOf(DWORD));
    IsNameSaved := True;
  end;
  Result := IsNameSaved;
end;

function TImportsUneraser.FindNameInBinaryAndFill64(LibDesc: PImageImportDescriptor; CallViaPtr, ThunkPtr: PByte;
  OrdinalFlag: UInt64; AddrToFunc: TAddrToFuncMap): Boolean;
var
  ImportsDir: PImageDataDirectory;
  ImpAddr: DWORD;
  CallViaVal: PUInt64;
  SearchedAddr: UInt64;
  ExportsWithAddr: TExportedFuncSet;
  FuncsList: TList<TExportedFunc>;
  Func: TExportedFunc;
  IsNameSaved: Boolean;
  LastOrdinal: DWORD;
  NamesStart: PByte;
  RemainingSize: NativeUInt;
  FoundPtr: PByte;
  NameOffset: NativeUInt;
  ImpRva: UInt64;
  OrdThunk: UInt64;
  I: Integer;
begin
  Result := False;
  if (CallViaPtr = nil) or (FModulePtr = nil) or (LibDesc = nil) then
    Exit;
  ImportsDir := GetDirectoryEntry(FModulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
  if ImportsDir = nil then
    Exit;
  ImpAddr := ImportsDir.VirtualAddress;

  CallViaVal := PUInt64(CallViaPtr);
  if CallViaVal^ = 0 then
    Exit;
  SearchedAddr := CallViaVal^;

  if not AddrToFunc.TryGetValue(SearchedAddr, ExportsWithAddr) then
  begin
    LogWarning('No mapped export mapped to the given address: 0x%x.', [SearchedAddr]);
    Exit;
  end;

  IsNameSaved := False;
  LastOrdinal := 0;

  FuncsList := TList<TExportedFunc>.Create;
  try
    FuncsList.AddRange(ExportsWithAddr.Values);
    FuncsList.Sort(ExpFuncComparer);
    for I := 0 to FuncsList.Count - 1 do
    begin
      Func := FuncsList[I];
      LastOrdinal := Func.FuncOrdinal;
      if Func.FuncName = '' then
        Continue;
      NamesStart := PByte(NativeUInt(FModulePtr) + ImpAddr);
      RemainingSize := FModuleSize - (NativeUInt(NamesStart) - NativeUInt(FModulePtr));
      FoundPtr := SearchName(AnsiString(Func.FuncName), NamesStart, RemainingSize);
      if FoundPtr = nil then
        Continue;
      if I <> 0 then
        LogDebug('>[*][0x%x] %s.', [SearchedAddr, Func.ToStringFull]);
      NameOffset := NativeUInt(FoundPtr) - NativeUInt(FModulePtr);
      LogDebug('Found the name at: 0x%x.', [NameOffset]);
      if NameOffset < SizeOf(Word) then
        Continue;
      ImpRva := UInt64(NameOffset - SizeOf(Word));
      Move(ImpRva, ThunkPtr^, SizeOf(UInt64));
      LogDebug('Wrote found to offset: 0x%x.', [NativeUInt(CallViaPtr)]);
      IsNameSaved := True;
      Break;
    end;
  finally
    FuncsList.Free;
  end;

  if (not IsNameSaved) and (LastOrdinal <> 0) then
  begin
    LogDebug('Filling ordinal: 0x%x.', [LastOrdinal]);
    OrdThunk := UInt64(LastOrdinal) or OrdinalFlag;
    Move(OrdThunk, ThunkPtr^, SizeOf(UInt64));
    IsNameSaved := True;
  end;
  Result := IsNameSaved;
end;

function TImportsUneraser.FillImportNames32(LibDesc: PImageImportDescriptor; OrdinalFlag: DWORD;
  AddrToFunc: TAddrToFuncMap; NotCovered: TImpsNotCovered): Boolean;
var
  CallVia, ThunkAddr: DWORD;
  ProcessedImps, RecoveredImps: NativeUInt;
  CallViaPtr, ThunkPtr: PByte;
  CallViaVal: PDWORD;
  Desc: PImageThunkData32;
  SearchedAddr: UInt64;
  FuncSet: TExportedFuncSet;
  FirstFunc: TExportedFunc;
  IsNameSaved: Boolean;
  ThunkRva: DWORD;
  SortedFuncs: TList<TExportedFunc>;
begin
  Result := False;
  if LibDesc = nil then
    Exit;
  CallVia := LibDesc.FirstThunk;
  if CallVia = 0 then
    Exit;

  ProcessedImps := 0;
  RecoveredImps := 0;

  ThunkAddr := LibDesc.OriginalFirstThunk;
  if ThunkAddr = 0 then
    ThunkAddr := CallVia;

  CallViaPtr := PByte(NativeUInt(FModulePtr) + CallVia);
  ThunkPtr := PByte(NativeUInt(FModulePtr) + ThunkAddr);

  while ValidatePtr(FModulePtr, FModuleSize, CallViaPtr, SizeOf(DWORD)) and
    ValidatePtr(FModulePtr, FModuleSize, ThunkPtr, SizeOf(DWORD)) do
  begin
    CallViaVal := PDWORD(CallViaPtr);
    if CallViaVal^ = 0 then
      Break;
    Desc := PImageThunkData32(ThunkPtr);
    if not ValidatePtr(FModulePtr, FModuleSize, Desc, SizeOf(TImageThunkData32)) then
    begin
      LogWarning('Invalid descriptor pointer: [0x%x].', [NativeUInt(Desc)]);
      Break;
    end;
    if Desc.Func = 0 then
      Break;

    SearchedAddr := UInt64(CallViaVal^);
    if (not AddrToFunc.TryGetValue(SearchedAddr, FuncSet)) or (FuncSet.Count = 0) then
    begin
      if NotCovered <> nil then
      begin
        ThunkRva := MaskToDword(NativeUInt(CallViaPtr) - NativeUInt(FModulePtr));
        NotCovered.Insert(ThunkRva, SearchedAddr);
      end;
    end
    else
    begin
      SortedFuncs := TList<TExportedFunc>.Create;
      try
        SortedFuncs.AddRange(FuncSet.Values);
        SortedFuncs.Sort(ExpFuncComparer);
        FirstFunc := SortedFuncs[0];
        LogDebug('[*][0x%x] %s.', [SearchedAddr, FirstFunc.ToStringFull]);
        IsNameSaved := WriteFoundFunction32(Desc, OrdinalFlag, FirstFunc);
      finally
        SortedFuncs.Free;
      end;
      if not IsNameSaved then
        IsNameSaved := FindNameInBinaryAndFill32(LibDesc, CallViaPtr, ThunkPtr, OrdinalFlag, AddrToFunc);
      Inc(ProcessedImps);
      if IsNameSaved then
        Inc(RecoveredImps);
    end;

    Inc(CallViaPtr, SizeOf(DWORD));
    Inc(ThunkPtr, SizeOf(DWORD));
  end;

  Result := RecoveredImps = ProcessedImps;
end;

function TImportsUneraser.FillImportNames64(LibDesc: PImageImportDescriptor; OrdinalFlag: UInt64;
  AddrToFunc: TAddrToFuncMap; NotCovered: TImpsNotCovered): Boolean;
var
  CallVia, ThunkAddr: UInt64;
  ProcessedImps, RecoveredImps: NativeUInt;
  CallViaPtr, ThunkPtr: PByte;
  CallViaVal: PUInt64;
  Desc: PImageThunkData64;
  SearchedAddr: UInt64;
  FuncSet: TExportedFuncSet;
  FirstFunc: TExportedFunc;
  IsNameSaved: Boolean;
  ThunkRva: DWORD;
  SortedFuncs: TList<TExportedFunc>;
begin
  Result := False;
  if LibDesc = nil then
    Exit;
  CallVia := LibDesc.FirstThunk;
  if CallVia = 0 then
    Exit;

  ProcessedImps := 0;
  RecoveredImps := 0;

  ThunkAddr := LibDesc.OriginalFirstThunk;
  if ThunkAddr = 0 then
    ThunkAddr := CallVia;

  CallViaPtr := PByte(NativeUInt(FModulePtr) + CallVia);
  ThunkPtr := PByte(NativeUInt(FModulePtr) + ThunkAddr);

  while ValidatePtr(FModulePtr, FModuleSize, CallViaPtr, SizeOf(UInt64)) and
    ValidatePtr(FModulePtr, FModuleSize, ThunkPtr, SizeOf(UInt64)) do
  begin
    CallViaVal := PUInt64(CallViaPtr);
    if CallViaVal^ = 0 then
      Break;
    Desc := PImageThunkData64(ThunkPtr);
    if not ValidatePtr(FModulePtr, FModuleSize, Desc, SizeOf(TImageThunkData64)) then
    begin
      LogWarning('Invalid descriptor pointer: [0x%x].', [NativeUInt(Desc)]);
      Break;
    end;
    if Desc.Func = 0 then
      Break;

    SearchedAddr := CallViaVal^;
    if (not AddrToFunc.TryGetValue(SearchedAddr, FuncSet)) or (FuncSet.Count = 0) then
    begin
      if NotCovered <> nil then
      begin
        ThunkRva := MaskToDword(NativeUInt(CallViaPtr) - NativeUInt(FModulePtr));
        NotCovered.Insert(ThunkRva, SearchedAddr);
      end;
    end
    else
    begin
      SortedFuncs := TList<TExportedFunc>.Create;
      try
        SortedFuncs.AddRange(FuncSet.Values);
        SortedFuncs.Sort(ExpFuncComparer);
        FirstFunc := SortedFuncs[0];
        LogDebug('[*][0x%x] %s.', [SearchedAddr, FirstFunc.ToStringFull]);
        IsNameSaved := WriteFoundFunction64(Desc, OrdinalFlag, FirstFunc);
      finally
        SortedFuncs.Free;
      end;
      if not IsNameSaved then
        IsNameSaved := FindNameInBinaryAndFill64(LibDesc, CallViaPtr, ThunkPtr, OrdinalFlag, AddrToFunc);
      Inc(ProcessedImps);
      if IsNameSaved then
        Inc(RecoveredImps);
    end;

    Inc(CallViaPtr, SizeOf(UInt64));
    Inc(ThunkPtr, SizeOf(UInt64));
  end;

  Result := RecoveredImps = ProcessedImps;
end;

function TImportsUneraser.UneraseDllImports(LibDesc: PImageImportDescriptor; DllCoverage: TImportedDllCoverage;
  NotCovered: TImpsNotCovered): Boolean;
var
  IsFilled: Boolean;
begin
  if not FIs64 then
    IsFilled := FillImportNames32(LibDesc, IMAGE_ORDINAL_FLAG32, DllCoverage.AddrToFunc, NotCovered)
  else
    IsFilled := FillImportNames64(LibDesc, IMAGE_ORDINAL_FLAG64, DllCoverage.AddrToFunc, NotCovered);
  if not IsFilled then
  begin
    LogError('Could not fill some import names.');
    Exit(False);
  end;
  Result := IsFilled;
end;

end.
