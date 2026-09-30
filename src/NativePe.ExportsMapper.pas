{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/exports_mapper.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ExportsMapper;

interface

uses
  Winapi.Windows,
  System.Generics.Collections,
  System.Generics.Defaults,
  NativePe.ExportedFunc;

function ExpFuncComparer: IComparer<TExportedFunc>;

type
  TDllInfo = class
  public
    ModuleBase: UInt64;
    ModuleSize: NativeUInt;
    ModuleName: string;
    ShortName: string;
    Is64B: Boolean;
    constructor Create(AModuleBase: UInt64; AModuleSize: NativeUInt; AIs64B: Boolean; const AModuleName: string);
  end;

  TExportedFuncSet = TObjectDictionary<string, TExportedFunc>;

  TExportsMapper = class
  private
    FVaToFunc: TObjectDictionary<UInt64, TExportedFuncSet>;
    FForwardersLookup: TObjectDictionary<string, TExportedFuncSet>;
    FFuncToVa: TDictionary<string, UInt64>;
    FDllShortnameToBase: TObjectDictionary<string, TList<UInt64>>;
    FDllBaseToInfo: TObjectDictionary<UInt64, TDllInfo>;

    procedure AssociateVaAndFunc(Va: UInt64; Func: TExportedFunc);
    procedure AddToMaps(Va: UInt64; CurrFunc: TExportedFunc);
    function ResolveForwarders(Va: UInt64; CurrFunc: TExportedFunc): NativeUInt;
    function AddForwarded(CurrFunc: TExportedFunc; CallRva: DWORD; ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;
    function AddFunctionToLookup(ModulePtr: HMODULE; ModuleBase: UInt64; ModuleSize: NativeUInt;
      CurrFunc: TExportedFunc; CallRva: DWORD): Integer;
    function MakeOrdLookupTables(ModulePtr: Pointer; ModuleSize: NativeUInt;
      VaToOrd: TDictionary<NativeUInt, DWORD>): NativeUInt;
  public
    constructor Create;
    destructor Destroy; override;

    function AddToLookup(const ModuleName: string; ModulePtr: HMODULE; ModuleSize: NativeUInt;
      ModuleBase: UInt64): NativeUInt; overload;
    function AddToLookup(const ModuleName: string; ModulePtr: HMODULE; ModuleBase: UInt64): NativeUInt; overload;
    function AddToLookup(const ModuleName: string; ModulePtr: HMODULE): NativeUInt; overload;

    function FindExportsByVa(Va: UInt64): TExportedFuncSet;
    function FindExportByVa(Va: UInt64): TExportedFunc;
    function FindDllBaseByFuncVa(FuncRva: UInt64): UInt64;
    function GetDllPath(Base: UInt64): string; overload;
    function GetDllPath(const ShortName: string): string; overload;
    function GetDllPaths(const ShortName: string; Paths: TList<string>): NativeUInt;
    function GetDllFullName(const ShortName: string): string;

    function PrintVaToFunc: string;
    function PrintFuncToVa: string;
  end;

implementation

uses
  System.SysUtils,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.Util,
  NativePe.PeHdrsHelper,
  NativePe.FileUtil,
  NativePe.ApiSet,
  NativePe.Logger;

const
  RES_INVALID = 0;
  RES_MAPPED = 1;
  RES_FORWARDED = 2;

function ExpFuncComparer: IComparer<TExportedFunc>;
begin
  Result := TComparer<TExportedFunc>.Construct(
    function(const L, R: TExportedFunc): Integer
    begin
      if L.IsLessThan(R) then
        Exit(-1);
      if R.IsLessThan(L) then
        Exit(1);
      Result := 0;
    end);
end;

function GetOrdinal(RecordPtr: NativeUInt; VaToOrd: TDictionary<NativeUInt, DWORD>): DWORD;
begin
  if not VaToOrd.TryGetValue(RecordPtr, Result) then
    Exit(DWORD(-1));
  VaToOrd.Remove(RecordPtr);
end;

function IsForwarderRva(ModulePtr: PByte; Rva: DWORD): Boolean;
var
  Dir: PImageDataDirectory;
  EndRva: UInt64;
begin
  Result := False;
  Dir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_EXPORT);
  if Dir = nil then
    Exit;
  EndRva := UInt64(Dir.VirtualAddress) + UInt64(Dir.Size);
  Result := (Rva >= Dir.VirtualAddress) and (UInt64(Rva) < EndRva);
end;

function IsValidExportTable(Exp: PImageExportDirectory; ModulePtr: Pointer; ModuleSize: NativeUInt): Boolean;
var
  NamesCount, FuncCount: NativeUInt;
  FuncsListRva, FuncNamesListRva, NamesOrdsListRva: DWORD;
  I: NativeUInt;
  RecordRva, NameRva, FuncRva: PDWORD;
  NameIndex: PWord;
begin
  Result := False;
  if Exp = nil then
    Exit;
  NamesCount := Exp.NumberOfNames;
  FuncCount := Exp.NumberOfFunctions;
  FuncsListRva := Exp.AddressOfFunctions;
  FuncNamesListRva := Exp.AddressOfNames;
  NamesOrdsListRva := Exp.AddressOfNameOrdinals;

  I := 0;
  while I < FuncCount do
  begin
    RecordRva := PDWORD(NativeUInt(FuncsListRva) + NativeUInt(ModulePtr) + I * SizeOf(DWORD));
    if not ValidatePtr(ModulePtr, ModuleSize, RecordRva, SizeOf(DWORD)) then
      Exit(False);
    Inc(I);
  end;

  I := 0;
  while I < NamesCount do
  begin
    NameRva := PDWORD(NativeUInt(FuncNamesListRva) + NativeUInt(ModulePtr) + I * SizeOf(DWORD));
    NameIndex := PWord(NativeUInt(NamesOrdsListRva) + NativeUInt(ModulePtr) + I * SizeOf(Word));
    if (not ValidatePtr(ModulePtr, ModuleSize, NameRva, SizeOf(DWORD))) or
      (not ValidatePtr(ModulePtr, ModuleSize, NameIndex, SizeOf(Word))) then
      Exit(False);
    if NameIndex^ >= FuncCount then
      Exit(False);
    FuncRva := PDWORD(NativeUInt(FuncsListRva) + NativeUInt(ModulePtr) + NativeUInt(NameIndex^) * SizeOf(DWORD));
    if not ValidatePtr(ModulePtr, ModuleSize, FuncRva, SizeOf(DWORD)) then
      Exit(False);
    Inc(I);
  end;
  Result := True;
end;

constructor TDllInfo.Create(AModuleBase: UInt64; AModuleSize: NativeUInt; AIs64B: Boolean; const AModuleName: string);
begin
  inherited Create;
  ModuleBase := AModuleBase;
  ModuleSize := AModuleSize;
  Is64B := AIs64B;
  ModuleName := AModuleName;
  ShortName := GetDllShortName(AModuleName);
end;

constructor TExportsMapper.Create;
begin
  inherited Create;
  FVaToFunc := TObjectDictionary<UInt64, TExportedFuncSet>.Create([doOwnsValues]);
  FForwardersLookup := TObjectDictionary<string, TExportedFuncSet>.Create([doOwnsValues]);
  FFuncToVa := TDictionary<string, UInt64>.Create;
  FDllShortnameToBase := TObjectDictionary<string, TList<UInt64>>.Create([doOwnsValues]);
  FDllBaseToInfo := TObjectDictionary<UInt64, TDllInfo>.Create([doOwnsValues]);
end;

destructor TExportsMapper.Destroy;
begin
  FVaToFunc.Free;
  FForwardersLookup.Free;
  FFuncToVa.Free;
  FDllShortnameToBase.Free;
  FDllBaseToInfo.Free;
  inherited Destroy;
end;

procedure TExportsMapper.AssociateVaAndFunc(Va: UInt64; Func: TExportedFunc);
var
  FuncSet: TExportedFuncSet;
  Key: string;
begin
  Key := Func.MapKey;
  if not FVaToFunc.TryGetValue(Va, FuncSet) then
  begin
    FuncSet := TExportedFuncSet.Create([doOwnsValues]);
    FVaToFunc.Add(Va, FuncSet);
  end;
  if not FuncSet.ContainsKey(Key) then
    FuncSet.Add(Key, TExportedFunc.Create(Func));
  FFuncToVa.AddOrSetValue(Key, Va);
end;

function TExportsMapper.ResolveForwarders(Va: UInt64; CurrFunc: TExportedFunc): NativeUInt;
var
  FwdSet: TExportedFuncSet;
  Pair: TPair<string, TExportedFunc>;
begin
  Result := 0;
  if FForwardersLookup.TryGetValue(CurrFunc.MapKey, FwdSet) then
    for Pair in FwdSet do
    begin
      AssociateVaAndFunc(Va, Pair.Value);
      Inc(Result);
    end;
end;

procedure TExportsMapper.AddToMaps(Va: UInt64; CurrFunc: TExportedFunc);
begin
  AssociateVaAndFunc(Va, CurrFunc);
  ResolveForwarders(Va, CurrFunc);
end;

function TExportsMapper.AddForwarded(CurrFunc: TExportedFunc; CallRva: DWORD; ModulePtr: PByte;
  ModuleSize: NativeUInt): Boolean;
var
  FPtr: PByte;
  ForwardedFuncStr: string;
  Forwarder: TExportedFunc;
  Key: string;
  FwdSet: TExportedFuncSet;
  FoundVa: UInt64;
  ResolvedDll: string;
begin
  Result := False;
  FPtr := PByte(NativeUInt(ModulePtr) + CallRva);
  if not IsValidStringA(ModulePtr, ModuleSize, PAnsiChar(FPtr)) then
    Exit;
  if ForwarderNameLen(PAnsiChar(FPtr)) < 1 then
    Exit;
  ForwardedFuncStr := FormatDllFunc(string(AnsiString(PAnsiChar(FPtr))));
  if ForwardedFuncStr = '' then
    Exit;

  Forwarder := TExportedFunc.CreateFromForwarder(ForwardedFuncStr);
  try
    if not Forwarder.IsValid then
    begin
      LogInfo('Skipped invalid forwarder.');
      Exit;
    end;

    if UseApiSetResolution then
    begin
      ResolvedDll := ResolveApiSetSchema(Forwarder.LibName);
      if not SameText(ResolvedDll, Forwarder.LibName) then
        Forwarder.LibName := GetDllShortName(ResolvedDll);
    end;

    Key := Forwarder.MapKey;
    if not FForwardersLookup.TryGetValue(Key, FwdSet) then
    begin
      FwdSet := TExportedFuncSet.Create([doOwnsValues]);
      FForwardersLookup.Add(Key, FwdSet);
    end;
    if not FwdSet.ContainsKey(CurrFunc.MapKey) then
      FwdSet.Add(CurrFunc.MapKey, TExportedFunc.Create(CurrFunc));

    if FFuncToVa.TryGetValue(Key, FoundVa) and (FoundVa <> 0) then
      AssociateVaAndFunc(FoundVa, CurrFunc);

    Result := True;
  finally
    Forwarder.Free;
  end;
end;

function TExportsMapper.AddFunctionToLookup(ModulePtr: HMODULE; ModuleBase: UInt64; ModuleSize: NativeUInt;
  CurrFunc: TExportedFunc; CallRva: DWORD): Integer;
var
  CallVa: UInt64;
begin
  if CallRva = 0 then
    Exit(RES_INVALID);
  if IsForwarderRva(PByte(ModulePtr), CallRva) then
  begin
    if AddForwarded(CurrFunc, CallRva, PByte(ModulePtr), ModuleSize) then
    begin
      LogDebug('FWD %s -> 0x%x.', [CurrFunc.ToStringFull, NativeUInt(ModulePtr) + CallRva]);
      Exit(RES_FORWARDED);
    end;
    Exit(RES_INVALID);
  end;

  CallVa := UInt64(CallRva) + ModuleBase;
  if not ValidatePtr(Pointer(NativeUInt(ModuleBase)), ModuleSize, Pointer(NativeUInt(CallVa)), SizeOf(UInt64)) then
  begin
    LogInfo('Validation failed: %s.', [CurrFunc.ToStringFull]);
    Exit(RES_INVALID);
  end;
  AddToMaps(CallVa, CurrFunc);
  Result := RES_MAPPED;
end;

function TExportsMapper.MakeOrdLookupTables(ModulePtr: Pointer; ModuleSize: NativeUInt;
  VaToOrd: TDictionary<NativeUInt, DWORD>): NativeUInt;
var
  Exp: PImageExportDirectory;
  FunctCount: NativeUInt;
  FuncsListRva, OrdBase: DWORD;
  I: DWORD;
  RecordRva: PDWORD;
  Ordinal: DWORD;
begin
  Result := 0;
  Exp := GetExportDirectory(ModulePtr);
  if Exp = nil then
    Exit;
  FunctCount := Exp.NumberOfFunctions;
  FuncsListRva := Exp.AddressOfFunctions;
  OrdBase := Exp.Base;
  I := 0;
  while I < FunctCount do
  begin
    RecordRva := PDWORD(NativeUInt(FuncsListRva) + NativeUInt(ModulePtr) + NativeUInt(I) * SizeOf(DWORD));
    if not ValidatePtr(ModulePtr, ModuleSize, RecordRva, SizeOf(DWORD)) then
      Break;
    if RecordRva^ = 0 then
    begin
      Inc(I);
      Continue;
    end;
    Ordinal := OrdBase + I;
    VaToOrd.AddOrSetValue(NativeUInt(RecordRva), Ordinal);
    Inc(I);
  end;
  Result := FunctCount;
end;

function TExportsMapper.AddToLookup(const ModuleName: string; ModulePtr: HMODULE; ModuleSize: NativeUInt;
  ModuleBase: UInt64): NativeUInt;
var
  Exp: PImageExportDirectory;
  Is64B: Boolean;
  Info: TDllInfo;
  DllName: string;
  Bases: TList<UInt64>;
  VaToOrd: TDictionary<NativeUInt, DWORD>;
  ForwardedCtr, MappedCtr: NativeUInt;
  NamesCount: NativeUInt;
  FuncsListRva, FuncNamesListRva, NamesOrdsListRva: DWORD;
  I: NativeUInt;
  NameRvaPtr: PDWORD;
  NameIndexPtr: PWord;
  FuncRvaPtr: PDWORD;
  NamePtr: PAnsiChar;
  FuncOrd: DWORD;
  CallRva: DWORD;
  CurrFunc: TExportedFunc;
  Res: Integer;
  OrdKeys: TList<NativeUInt>;
  OrdKey: NativeUInt;
begin
  Result := 0;
  Exp := GetExportDirectory(Pointer(ModulePtr));
  if Exp = nil then
    Exit;
  if ModuleSize = 0 then
  begin
    ModuleSize := GetImageSize(PByte(ModulePtr));
    if ModuleSize = 0 then
      Exit;
  end;
  if not IsValidExportTable(Exp, Pointer(ModulePtr), ModuleSize) then
    Exit;

  Is64B := Is64Bit(PByte(ModulePtr));
  Info := TDllInfo.Create(ModuleBase, ModuleSize, Is64B, ModuleName);
  if FDllBaseToInfo.ContainsKey(ModuleBase) then
    FDllBaseToInfo.Remove(ModuleBase);
  FDllBaseToInfo.Add(ModuleBase, Info);

  DllName := Info.ShortName;
  if not FDllShortnameToBase.TryGetValue(DllName, Bases) then
  begin
    Bases := TList<UInt64>.Create;
    FDllShortnameToBase.Add(DllName, Bases);
  end;
  if not Bases.Contains(ModuleBase) then
    Bases.Add(ModuleBase);

  VaToOrd := TDictionary<NativeUInt, DWORD>.Create;
  try
    MakeOrdLookupTables(Pointer(ModulePtr), ModuleSize, VaToOrd);

    ForwardedCtr := 0;
    MappedCtr := 0;
    NamesCount := Exp.NumberOfNames;
    FuncsListRva := Exp.AddressOfFunctions;
    FuncNamesListRva := Exp.AddressOfNames;
    NamesOrdsListRva := Exp.AddressOfNameOrdinals;

    I := 0;
    while I < NamesCount do
    begin
      NameRvaPtr := PDWORD(NativeUInt(FuncNamesListRva) + NativeUInt(ModulePtr) + I * SizeOf(DWORD));
      NameIndexPtr := PWord(NativeUInt(NamesOrdsListRva) + NativeUInt(ModulePtr) + I * SizeOf(Word));
      FuncRvaPtr := PDWORD(NativeUInt(FuncsListRva) + NativeUInt(ModulePtr) + NativeUInt(NameIndexPtr^) * SizeOf(DWORD));
      if FuncRvaPtr^ = 0 then
      begin
        Inc(I);
        Continue;
      end;

      NamePtr := PAnsiChar(NativeUInt(NameRvaPtr^) + NativeUInt(ModulePtr));
      if not IsValidStringA(Pointer(ModulePtr), ModuleSize, NamePtr) then
        Break;

      FuncOrd := GetOrdinal(NativeUInt(FuncRvaPtr), VaToOrd);
      CallRva := FuncRvaPtr^;
      CurrFunc := TExportedFunc.Create(DllName, string(AnsiString(NamePtr)), FuncOrd);
      try
        Res := AddFunctionToLookup(ModulePtr, ModuleBase, ModuleSize, CurrFunc, CallRva);
        if Res = RES_FORWARDED then
          Inc(ForwardedCtr);
        if Res = RES_MAPPED then
          Inc(MappedCtr);
      finally
        CurrFunc.Free;
      end;
      Inc(I);
    end;

    OrdKeys := TList<NativeUInt>.Create;
    try
      OrdKeys.AddRange(VaToOrd.Keys);
      for OrdKey in OrdKeys do
      begin
        CallRva := PDWORD(OrdKey)^;
        CurrFunc := TExportedFunc.Create(DllName, VaToOrd[OrdKey]);
        try
          Res := AddFunctionToLookup(ModulePtr, ModuleBase, ModuleSize, CurrFunc, CallRva);
          if Res = RES_FORWARDED then
            Inc(ForwardedCtr);
          if Res = RES_MAPPED then
            Inc(MappedCtr);
        finally
          CurrFunc.Free;
        end;
      end;
    finally
      OrdKeys.Free;
    end;

    LogDebug('Finished exports parsing, mapped: %u forwarded: %u.', [MappedCtr, ForwardedCtr]);
    Result := MappedCtr;
  finally
    VaToOrd.Free;
  end;
end;

function TExportsMapper.AddToLookup(const ModuleName: string; ModulePtr: HMODULE; ModuleBase: UInt64): NativeUInt;
begin
  Result := AddToLookup(ModuleName, ModulePtr, 0, ModuleBase);
end;

function TExportsMapper.AddToLookup(const ModuleName: string; ModulePtr: HMODULE): NativeUInt;
begin
  Result := AddToLookup(ModuleName, ModulePtr, UInt64(NativeUInt(ModulePtr)));
end;

function TExportsMapper.FindExportsByVa(Va: UInt64): TExportedFuncSet;
begin
  if not FVaToFunc.TryGetValue(Va, Result) then
    Result := nil;
end;

function TExportsMapper.FindExportByVa(Va: UInt64): TExportedFunc;
var
  ExpSet: TExportedFuncSet;
  List: TList<TExportedFunc>;
begin
  Result := nil;
  ExpSet := FindExportsByVa(Va);
  if (ExpSet = nil) or (ExpSet.Count = 0) then
    Exit;
  List := TList<TExportedFunc>.Create;
  try
    List.AddRange(ExpSet.Values);
    List.Sort(ExpFuncComparer);
    Result := List[0];
  finally
    List.Free;
  end;
end;

function TExportsMapper.FindDllBaseByFuncVa(FuncRva: UInt64): UInt64;
var
  Bases: TList<UInt64>;
  Base: UInt64;
  Info: TDllInfo;
begin
  Result := 0;
  Bases := TList<UInt64>.Create;
  try
    Bases.AddRange(FDllBaseToInfo.Keys);
    Bases.Sort;
    for Base in Bases do
    begin
      if Base > FuncRva then
        Break;
      Info := FDllBaseToInfo[Base];
      if (FuncRva >= Info.ModuleBase) and (FuncRva <= (Info.ModuleBase + Info.ModuleSize)) then
        Exit(Info.ModuleBase);
    end;
  finally
    Bases.Free;
  end;
end;

function TExportsMapper.GetDllPath(Base: UInt64): string;
var
  Info: TDllInfo;
begin
  Result := '';
  if FDllBaseToInfo.TryGetValue(Base, Info) then
    Result := Info.ModuleName;
end;

function TExportsMapper.GetDllPath(const ShortName: string): string;
var
  Bases, SortedBases: TList<UInt64>;
  Base: UInt64;
  Path: string;
begin
  Result := '';
  if not FDllShortnameToBase.TryGetValue(ShortName, Bases) then
    Exit;
  SortedBases := TList<UInt64>.Create(Bases);
  try
    SortedBases.Sort;
    for Base in SortedBases do
    begin
      Path := GetDllPath(Base);
      if Path <> '' then
        Exit(Path);
    end;
  finally
    SortedBases.Free;
  end;
end;

function TExportsMapper.GetDllPaths(const ShortName: string; Paths: TList<string>): NativeUInt;
var
  Bases: TList<UInt64>;
  Base: UInt64;
  Path: string;
begin
  Result := 0;
  if not FDllShortnameToBase.TryGetValue(ShortName, Bases) then
    Exit;
  for Base in Bases do
  begin
    Path := GetDllPath(Base);
    if not Paths.Contains(Path) then
      Paths.Add(Path);
    Inc(Result);
  end;
end;

function TExportsMapper.GetDllFullName(const ShortName: string): string;
var
  DllPath: string;
begin
  DllPath := GetDllPath(ShortName);
  if DllPath = '' then
    Exit('');
  Result := GetFileNamePart(DllPath);
end;

function TExportsMapper.PrintVaToFunc: string;
var
  SB: TStringBuilder;
  Keys: TList<UInt64>;
  Va: UInt64;
  FuncSet: TExportedFuncSet;
  Func: TExportedFunc;
  FuncsList: TList<TExportedFunc>;
begin
  SB := TStringBuilder.Create;
  Keys := TList<UInt64>.Create;
  try
    Keys.AddRange(FVaToFunc.Keys);
    Keys.Sort;
    for Va in Keys do
    begin
      SB.Append(IntToHex(Va, 1)).Append(' :').AppendLine;
      FuncSet := FVaToFunc[Va];
      FuncsList := TList<TExportedFunc>.Create;
      try
        FuncsList.AddRange(FuncSet.Values);
        FuncsList.Sort(ExpFuncComparer);
        for Func in FuncsList do
          SB.Append(#9).Append(Func.ToStringFull).AppendLine;
      finally
        FuncsList.Free;
      end;
    end;
    Result := SB.ToString;
  finally
    Keys.Free;
    SB.Free;
  end;
end;

function TExportsMapper.PrintFuncToVa: string;
var
  SB: TStringBuilder;
  Keys: TList<string>;
  Key: string;
  Va: UInt64;
begin
  SB := TStringBuilder.Create;
  Keys := TList<string>.Create;
  try
    Keys.AddRange(FFuncToVa.Keys);
    Keys.Sort;
    for Key in Keys do
    begin
      Va := FFuncToVa[Key];
      SB.Append(Key).Append(' : ').Append(IntToHex(Va, 1)).AppendLine;
    end;
    Result := SB.ToString;
  finally
    Keys.Free;
    SB.Free;
  end;
end;

end.
