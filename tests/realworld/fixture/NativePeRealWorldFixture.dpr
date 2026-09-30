library NativePeRealWorldFixture;

uses
  Winapi.Windows;

const
  EXCEPTION_MAGIC = $4E504558;
  FixturePadding: array [0 .. 255] of Byte = (
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

function CoTaskMemAlloc(cb: NativeUInt): Pointer; stdcall; external 'ole32.dll';
procedure CoTaskMemFree(pv: Pointer); stdcall; external 'ole32.dll';

function FixtureAdd(A, B: Integer): Integer; stdcall;
begin
  Result := A + B + FixturePadding[0];
end;

function FixtureImportedPid: DWORD; stdcall;
begin
  Result := GetCurrentProcessId;
end;

function FixtureOle32Alloc(Size: NativeUInt): Integer; stdcall;
var
  P: Pointer;
begin
  P := CoTaskMemAlloc(Size);
  if P = nil then
    Exit(0);
  PByte(P)^ := $5A;
  Result := PByte(P)^;
  CoTaskMemFree(P);
end;

function FixtureRaiseAndCatch(Divisor: Integer): Integer; stdcall;
begin
  try
    Result := 100 div Divisor;
  except
    Result := EXCEPTION_MAGIC;
  end;
end;

function FixturePaddingAddress: Pointer; stdcall;
begin
  Result := @FixturePadding[0];
end;

exports
  FixtureAdd,
  FixtureImportedPid,
  FixtureOle32Alloc,
  FixtureRaiseAndCatch,
  FixturePaddingAddress;

begin
end.
