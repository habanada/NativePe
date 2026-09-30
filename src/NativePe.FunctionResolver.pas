{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/function_resolver.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.FunctionResolver;

interface

uses
  Winapi.Windows,
  System.Generics.Collections;

type
  TFunctionResolver = class abstract
  public
    function ResolveFunc(LibName: PAnsiChar; FuncName: PAnsiChar): FARPROC; virtual; abstract;
  end;

  TDefaultFuncResolver = class(TFunctionResolver)
  protected
    FNameToModule: TDictionary<string, HMODULE>;
  public
    constructor Create;
    destructor Destroy; override;
    function LoadLibraryByName(LibName: PAnsiChar): HMODULE; virtual;
    function ResolveFunc(LibName: PAnsiChar; FuncName: PAnsiChar): FARPROC; override;
  end;

implementation

uses
  System.SysUtils,
  NativePe.ApiSet,
  NativePe.Logger;

constructor TDefaultFuncResolver.Create;
begin
  inherited Create;
  FNameToModule := TDictionary<string, HMODULE>.Create;
end;

destructor TDefaultFuncResolver.Destroy;
begin
  FNameToModule.Free;
  inherited Destroy;
end;

function TDefaultFuncResolver.LoadLibraryByName(LibName: PAnsiChar): HMODULE;
var
  ModName: string;
  Mod_: HMODULE;
  ResolvedName: string;
begin
  Result := 0;
  if LibName = nil then
    Exit;
  ModName := LowerCase(string(AnsiString(LibName)));
  if FNameToModule.TryGetValue(ModName, Mod_) then
    Exit(Mod_);
  if UseApiSetResolution then
  begin
    ResolvedName := ResolveApiSetSchema(ModName);
    if ResolvedName <> ModName then
    begin
      LogDebug('ApiSet resolved %s -> %s.', [ModName, ResolvedName]);
      ModName := LowerCase(ResolvedName);
      if FNameToModule.TryGetValue(ModName, Mod_) then
        Exit(Mod_);
      Result := Winapi.Windows.LoadLibraryA(PAnsiChar(AnsiString(ResolvedName)));
      if Result <> 0 then
      begin
        LogDebug('Loaded DLL: %s at 0x%x.', [ResolvedName, NativeUInt(Result)]);
        FNameToModule.Add(ModName, Result);
      end;
      Exit;
    end;
  end;
  Result := Winapi.Windows.LoadLibraryA(LibName);
  if Result <> 0 then
  begin
    LogDebug('Loaded DLL: %s at 0x%x.', [string(AnsiString(LibName)), NativeUInt(Result)]);
    FNameToModule.Add(ModName, Result);
  end;
end;

function TDefaultFuncResolver.ResolveFunc(LibName, FuncName: PAnsiChar): FARPROC;
var
  LibBasePtr: HMODULE;
  FuncVal: NativeUInt;
  IsOrd: Boolean;
begin
  LibBasePtr := LoadLibraryByName(LibName);
  if LibBasePtr = 0 then
  begin
    LogError('Could not load the library: %s.', [string(AnsiString(LibName))]);
    Exit(nil);
  end;
  Result := GetProcAddress(LibBasePtr, FuncName);
  if not Assigned(Result) then
  begin
    FuncVal := NativeUInt(FuncName);
    IsOrd := (FuncVal and NativeUInt($FFFF)) = FuncVal;
    if IsOrd then
      LogError('Could not load the function: %s.0x%x.', [string(AnsiString(LibName)), FuncVal])
    else
      LogError('Could not load the function: %s.%s.', [string(AnsiString(LibName)), string(AnsiString(FuncName))]);
  end;
end;

end.
