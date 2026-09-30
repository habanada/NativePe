{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.SecurityCookie;

interface

uses
  Winapi.Windows,
  NativePe.Types;

var
  AutoInitSecurityCookie: Boolean = False;

function InitSecurityCookie(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;

implementation

uses
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.LoadConfig,
  NativePe.Logger;

const
  BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;
  DEFAULT_COOKIE_32 = DWORD($BB40E64E);
  DEFAULT_COOKIE_64 = UInt64($00002B992DDFA232);

function BCryptGenRandom(Algorithm: Pointer; Buffer: PByte; BufferSize: ULONG; Flags: ULONG): LongInt; stdcall;
  external 'bcrypt.dll';

function GenerateRandomCookie(Is64B: Boolean): UInt64;
var
  Buf: array [0 .. 7] of Byte;
  Status: LongInt;
  I: Integer;
  Val: UInt64;
begin
  FillChar(Buf, SizeOf(Buf), 0);
  Status := BCryptGenRandom(nil, @Buf[0], SizeOf(Buf), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if Status = 0 then
  begin
    Val := 0;
    for I := 7 downto 0 do
      Val := (Val shl 8) or Buf[I];
  end
  else
  begin
    LogWarning('BCryptGenRandom failed (status: 0x%x), falling back to a weaker seed.', [DWORD(Status)]);
    Val := UInt64(GetTickCount64) xor (UInt64(GetCurrentProcessId) shl 32) xor UInt64(NativeUInt(@Buf));
  end;

  if Is64B then
  begin
    Val := Val and $0000FFFFFFFFFFFF;
    if Val = 0 then
      Val := $1234567812345678;
  end
  else
  begin
    Val := Val and $FFFFFFFF;
    if Val = 0 then
      Val := $12345678;
  end;
  Result := Val;
end;

function InitSecurityCookie(ModulePtr: PByte; ModuleSize: NativeUInt): Boolean;
var
  Is64B: Boolean;
  LdConfigPtr: PByte;
  Ver: TLoadConfigVer;
  CookieVa32: DWORD;
  CookieVa64: UInt64;
  CookiePtr: Pointer;
  NewCookie: UInt64;
begin
  Result := False;
  if (ModulePtr = nil) or (ModuleSize = 0) then
    Exit;

  Is64B := Is64Bit(ModulePtr);
  LdConfigPtr := GetLoadConfigPtr(ModulePtr, ModuleSize);
  if LdConfigPtr = nil then
    Exit(True);

  Ver := GetLoadConfigVersion(ModulePtr, ModuleSize, LdConfigPtr);
  if Ver = LOAD_CONFIG_NONE then
    Exit(True);

  if Is64B then
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, LdConfigPtr, SizeOf(TImageLoadConfigDir64W7)) then
      Exit(True);
    CookieVa64 := PImageLoadConfigDir64W7(LdConfigPtr).SecurityCookie;
    if CookieVa64 = 0 then
      Exit(True);
    CookiePtr := Pointer(NativeUInt(CookieVa64));
    if not ValidatePtr(ModulePtr, ModuleSize, CookiePtr, SizeOf(UInt64)) then
    begin
      LogWarning('SecurityCookie field points outside of the module -- was the module relocated yet?');
      Exit(True);
    end;
    if (PUInt64(CookiePtr)^ = 0) or (PUInt64(CookiePtr)^ = DEFAULT_COOKIE_64) then
    begin
      NewCookie := GenerateRandomCookie(True);
      PUInt64(CookiePtr)^ := NewCookie;
    end;
  end
  else
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, LdConfigPtr, SizeOf(TImageLoadConfigDir32W7)) then
      Exit(True);
    CookieVa32 := PImageLoadConfigDir32W7(LdConfigPtr).SecurityCookie;
    if CookieVa32 = 0 then
      Exit(True);
    CookiePtr := Pointer(NativeUInt(CookieVa32));
    if not ValidatePtr(ModulePtr, ModuleSize, CookiePtr, SizeOf(DWORD)) then
    begin
      LogWarning('SecurityCookie field points outside of the module -- was the module relocated yet?');
      Exit(True);
    end;
    if (PDWORD(CookiePtr)^ = 0) or (PDWORD(CookiePtr)^ = DEFAULT_COOKIE_32) then
    begin
      NewCookie := GenerateRandomCookie(False);
      PDWORD(CookiePtr)^ := DWORD(NewCookie);
    end;
  end;

  Result := True;
end;

end.
