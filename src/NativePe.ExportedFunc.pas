{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2017-2026 hasherezade
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of libpeconv/src/exported_func.cpp.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}
unit NativePe.ExportedFunc;

interface

uses
  Winapi.Windows;

const
  INVALID_ORD_VALUE = DWORD($FFFFFFFF);

function ForwarderNameLen(FPtr: PAnsiChar): NativeUInt;
function GetDllShortName(const S: string): string;
function GetExportedFuncNamePart(const S: string): string;
function OrdinalToString(FuncOrdinal: DWORD): string;
function IsOrdinalString(const S: string): Boolean;
function OrdinalStringToVal(const S: string): DWORD;
function FormatDllFunc(const S: string): string;

type
  TExportedFunc = class
  public
    LibName: string;
    FuncName: string;
    FuncOrdinal: DWORD;
    IsByOrdinal: Boolean;
    constructor Create; overload;
    constructor Create(const ALibName, AFuncName: string; AFuncOrdinal: DWORD); overload;
    constructor Create(const ALibName: string; AFuncOrdinal: DWORD); overload;
    constructor Create(Other: TExportedFunc); overload;
    constructor CreateFromForwarder(const ForwarderName: string);
    class function FormatNamePart(const Name: string): string;
    class function IsTheSameFuncName(Func1, Func2: TExportedFunc): Boolean;
    class function IsTheSameDllName(Func1, Func2: TExportedFunc): Boolean;
    class function IsTheSameFunc(Func1, Func2: TExportedFunc): Boolean;
    function IsLessThan(Other: TExportedFunc): Boolean;
    function ToStringFull: string;
    function MapKey: string;
    function NameToString: string;
    function IsValid: Boolean;
  end;

implementation

uses
  System.SysUtils,
  NativePe.FileUtil,
  NativePe.Logger;

function ForwarderNameLen(FPtr: PAnsiChar): NativeUInt;
var
  HasDot: Boolean;
  Len: NativeUInt;
  C: AnsiChar;
begin
  HasDot := False;
  Len := 0;
  C := FPtr[0];
  while ((C >= 'a') and (C <= 'z')) or ((C >= 'A') and (C <= 'Z')) or ((C >= '0') and (C <= '9')) or (C = '.') or
    (C = '_') or (C = '#') or (C = '@') or (C = '?') or (C = '-') do
  begin
    if C = '.' then
      HasDot := True;
    Inc(Len);
    C := FPtr[Len];
  end;
  if C = #0 then
  begin
    if not HasDot then
      Exit(0);
    Exit(Len);
  end;
  Result := 0;
end;

function GetDllShortName(const S: string): string;
var
  K: Integer;
  SepPos, DotPos, StartPos, EndPos: Integer;
begin
  SepPos := 0;
  for K := Length(S) downto 1 do
    if (S[K] = '\') or (S[K] = '/') then
    begin
      SepPos := K;
      Break;
    end;
  StartPos := SepPos + 1;
  DotPos := 0;
  for K := Length(S) downto StartPos do
    if S[K] = '.' then
    begin
      DotPos := K;
      Break;
    end;
  if DotPos = 0 then
    EndPos := Length(S)
  else
    EndPos := DotPos - 1;
  Result := LowerCase(Copy(S, StartPos, EndPos - StartPos + 1));
end;

function GetExportedFuncNamePart(const S: string): string;
var
  Ext: Integer;
begin
  Ext := LastDelimiter('.', S);
  if Ext = 0 then
    Exit('');
  Result := Copy(S, Ext + 1, MaxInt);
end;

function OrdinalToString(FuncOrdinal: DWORD): string;
begin
  Result := '#' + IntToStr(FuncOrdinal);
end;

function IsOrdinalString(const S: string): Boolean;
begin
  Result := (Length(S) >= 2) and (S[1] = '#');
end;

function OrdinalStringToVal(const S: string): DWORD;
var
  I: Integer;
  Val: Int64;
  Neg: Boolean;
begin
  Result := 0;
  if not IsOrdinalString(S) then
    Exit;
  I := 2;
  Val := 0;
  Neg := False;
  while (I <= Length(S)) and (S[I] = ' ') do
    Inc(I);
  if (I <= Length(S)) and ((S[I] = '+') or (S[I] = '-')) then
  begin
    Neg := S[I] = '-';
    Inc(I);
  end;
  while (I <= Length(S)) and (S[I] >= '0') and (S[I] <= '9') do
  begin
    Val := Val * 10 + (Ord(S[I]) - Ord('0'));
    Inc(I);
  end;
  if Neg then
    Val := -Val;
  Result := DWORD(Val);
end;

function FormatDllFunc(const S: string): string;
var
  DllName, FuncNamePart: string;
begin
  DllName := GetDllShortName(S);
  FuncNamePart := GetExportedFuncNamePart(S);
  if (DllName = '') or (FuncNamePart = '') then
    Exit('');
  Result := LowerCase(DllName) + '.' + FuncNamePart;
end;

function IsValidExtension(const Ext: string): Boolean;
var
  C: Char;
begin
  if Length(Ext) > 3 then
    Exit(False);
  for C in Ext do
    if not (((C >= 'A') and (C <= 'Z')) or ((C >= 'a') and (C <= 'z'))) then
      Exit(False);
  Result := True;
end;

function RemoveModuleExtension(const S: string): string;
var
  Len, ExtPos: Integer;
  Ext: string;
begin
  Len := Length(S);
  ExtPos := FindExtensionPos(S);
  if ExtPos = Len + 1 then
    Exit(S);
  Ext := Copy(S, ExtPos + 1, MaxInt);
  if IsValidExtension(Ext) then
    Exit(Copy(S, 1, ExtPos - 1));
  Result := S;
end;

class function TExportedFunc.FormatNamePart(const Name: string): string;
begin
  if Name = '' then
    Exit('');
  Result := LowerCase(Name);
end;

constructor TExportedFunc.Create;
begin
  inherited Create;
  FuncOrdinal := INVALID_ORD_VALUE;
  IsByOrdinal := False;
end;

constructor TExportedFunc.Create(const ALibName, AFuncName: string; AFuncOrdinal: DWORD);
begin
  inherited Create;
  LibName := FormatNamePart(ALibName);
  FuncName := AFuncName;
  FuncOrdinal := AFuncOrdinal;
  IsByOrdinal := False;
end;

constructor TExportedFunc.Create(const ALibName: string; AFuncOrdinal: DWORD);
begin
  inherited Create;
  LibName := FormatNamePart(ALibName);
  FuncOrdinal := AFuncOrdinal;
  IsByOrdinal := True;
end;

constructor TExportedFunc.Create(Other: TExportedFunc);
begin
  inherited Create;
  LibName := Other.LibName;
  FuncName := Other.FuncName;
  FuncOrdinal := Other.FuncOrdinal;
  IsByOrdinal := Other.IsByOrdinal;
end;

constructor TExportedFunc.CreateFromForwarder(const ForwarderName: string);
var
  FuncNameStr: string;
begin
  inherited Create;
  LibName := GetDllShortName(ForwarderName);
  FuncNameStr := GetExportedFuncNamePart(ForwarderName);
  if Length(FuncNameStr) < 2 then
  begin
    FuncOrdinal := INVALID_ORD_VALUE;
    FuncName := '';
    IsByOrdinal := False;
    LogWarning('Invalid function name: %s from forwarder: %s', [FuncNameStr, ForwarderName]);
    Exit;
  end;
  if IsOrdinalString(FuncNameStr) then
  begin
    FuncOrdinal := OrdinalStringToVal(FuncNameStr);
    IsByOrdinal := True;
    FuncName := '';
  end
  else
  begin
    FuncName := FuncNameStr;
    IsByOrdinal := False;
    FuncOrdinal := 0;
  end;
end;

class function TExportedFunc.IsTheSameFuncName(Func1, Func2: TExportedFunc): Boolean;
begin
  if (not Func1.IsByOrdinal) and (not Func2.IsByOrdinal) then
    if Func1.FuncName = Func2.FuncName then
      Exit(True);
  Result := Func1.FuncOrdinal = Func2.FuncOrdinal;
end;

class function TExportedFunc.IsTheSameDllName(Func1, Func2: TExportedFunc): Boolean;
var
  File1, File2, Short1, Short2: string;
begin
  File1 := GetFileNamePart(Func1.LibName);
  File2 := GetFileNamePart(Func2.LibName);
  if File1 = File2 then
    Exit(True);
  Short1 := RemoveModuleExtension(File1);
  Short2 := RemoveModuleExtension(File2);
  Result := Short1 = Short2;
end;

class function TExportedFunc.IsTheSameFunc(Func1, Func2: TExportedFunc): Boolean;
begin
  if not IsTheSameFuncName(Func1, Func2) then
    Exit(False);
  if not IsTheSameDllName(Func1, Func2) then
    Exit(False);
  Result := True;
end;

function TExportedFunc.IsLessThan(Other: TExportedFunc): Boolean;
var
  ThisNameLen, OtherNameLen, Cmp: Integer;
begin
  ThisNameLen := Length(FuncName);
  OtherNameLen := Length(Other.FuncName);
  if (ThisNameLen = 0) and (OtherNameLen > 0) then
    Exit(False);
  if (ThisNameLen > 0) and (OtherNameLen = 0) then
    Exit(True);
  Cmp := CompareStr(LibName, Other.LibName);
  if Cmp <> 0 then
    Exit(Cmp < 0);
  if (ThisNameLen = 0) or (OtherNameLen = 0) then
    Exit(FuncOrdinal < Other.FuncOrdinal);
  if ThisNameLen <> OtherNameLen then
    Exit(ThisNameLen < OtherNameLen);
  Cmp := CompareStr(FuncName, Other.FuncName);
  Result := Cmp < 0;
end;

function TExportedFunc.IsValid: Boolean;
begin
  Result := (FuncName <> '') or (FuncOrdinal <> INVALID_ORD_VALUE);
end;

function TExportedFunc.ToStringFull: string;
begin
  if not IsValid then
    Exit('[Invalid func]');
  Result := LibName + '.';
  if not IsByOrdinal then
    Result := Result + FuncName + ' ';
  Result := Result + OrdinalToString(FuncOrdinal);
end;

function TExportedFunc.MapKey: string;
begin
  if not IsValid then
    Exit('[Invalid func]');
  Result := LibName + '.';
  if not IsByOrdinal then
    Result := Result + FuncName
  else
    Result := Result + OrdinalToString(FuncOrdinal);
end;

function TExportedFunc.NameToString: string;
begin
  if not IsValid then
    Exit('');
  if IsByOrdinal then
    Exit(OrdinalToString(FuncOrdinal));
  Result := FuncName;
end;

end.
