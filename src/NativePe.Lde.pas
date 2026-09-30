{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-FileCopyrightText: 2008-2009 Vyacheslav Patkov
  SPDX-License-Identifier: MIT AND BSD-2-Clause

  This file contains an Object Pascal port of hde64 decoder logic and table data.
  See LICENSE and THIRD-PARTY-NOTICES.md.
}


unit NativePe.Lde;
{$POINTERMATH ON}
{$R-}
{$Q-}

interface

type
  TLdeInstruction = record
    Length: Integer;
    Opcode: Byte;
    Opcode2: Byte;
    HasOpcode2: Boolean;
    HasModRm: Boolean;
    ModRm: Byte;
    HasSib: Boolean;
    Sib: Byte;
    DispSize: Byte;
    Displacement: Int64;
    ImmSize: Byte;
    Immediate: UInt64;
    IsRelativeBranch: Boolean;
    RelBranchOffset: Integer;
    RelBranchSize: Integer;
    IsRipRelative: Boolean;
    RipDispOffset: Integer;
  end;

function LdeDisasm(Code: Pointer; Is64Bit: Boolean; out Instr: TLdeInstruction): Integer;
function LdeGetTrampolineSize(StartAddr: Pointer; MinBytes: Integer; Is64Bit: Boolean): Integer;

implementation

uses
  Winapi.Windows;

const
  C_MODRM   = $01;
  C_IMM8    = $02;
  C_IMM16   = $04;
  C_IMM_P66 = $10;
  C_REL8    = $20;
  C_REL32   = $40;
  C_GROUP   = $80;
  C_ERROR   = $FF;
  DELTA_OPCODES = $4A;

  LDE_TABLE: array [0 .. 528] of Byte = (
    $A5, $AA, $A5, $B8, $A5, $AA, $A5, $AA, $A5, $B8, $A5, $B8, $A5, $B8, $A5,
    $B8, $C0, $C0, $C0, $C0, $C0, $C0, $C0, $C0, $AC, $C0, $CC, $C0, $A1, $A1,
    $A1, $A1, $B1, $A5, $A5, $A6, $C0, $C0, $D7, $DA, $E0, $C0, $E4, $C0, $EA,
    $EA, $E0, $E0, $98, $C8, $EE, $F1, $A5, $D3, $A5, $A5, $A1, $EA, $9E, $C0,
    $C0, $C2, $C0, $E6, $03, $7F, $11, $7F, $01, $7F, $01, $3F, $01, $01, $AB,
    $8B, $90, $64, $5B, $5B, $5B, $5B, $5B, $92, $5B, $5B, $76, $90, $92, $92,
    $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $6A, $73, $90,
    $5B, $52, $52, $52, $52, $5B, $5B, $5B, $5B, $77, $7C, $77, $85, $5B, $5B,
    $70, $5B, $7A, $AF, $76, $76, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B, $5B,
    $5B, $5B, $86, $01, $03, $01, $04, $03, $D5, $03, $D5, $03, $CC, $01, $BC,
    $03, $F0, $03, $03, $04, $00, $50, $50, $50, $50, $FF, $20, $20, $20, $20,
    $01, $01, $01, $01, $C4, $02, $10, $FF, $FF, $FF, $01, $00, $03, $11, $FF,
    $03, $C4, $C6, $C8, $02, $10, $00, $FF, $CC, $01, $01, $01, $00, $00, $00,
    $00, $01, $01, $03, $01, $FF, $FF, $C0, $C2, $10, $11, $02, $03, $01, $01,
    $01, $FF, $FF, $FF, $00, $00, $00, $FF, $00, $00, $FF, $FF, $FF, $FF, $10,
    $10, $10, $10, $02, $10, $00, $00, $C6, $C8, $02, $02, $02, $02, $06, $00,
    $04, $00, $02, $FF, $00, $C0, $C2, $01, $01, $03, $03, $03, $CA, $40, $00,
    $0A, $00, $04, $00, $00, $00, $00, $7F, $00, $33, $01, $00, $00, $00, $00,
    $00, $00, $FF, $BF, $FF, $FF, $00, $00, $00, $00, $07, $00, $00, $FF, $00,
    $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $FF, $FF,
    $00, $00, $00, $BF, $00, $00, $00, $00, $00, $00, $00, $00, $7F, $00, $00,
    $FF, $40, $40, $40, $40, $41, $49, $40, $40, $40, $40, $4C, $42, $40, $40,
    $40, $40, $40, $40, $40, $40, $4F, $44, $53, $40, $40, $40, $44, $57, $43,
    $5C, $40, $60, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40, $40,
    $40, $40, $64, $66, $6E, $6B, $40, $40, $6A, $46, $40, $40, $44, $46, $40,
    $40, $5B, $44, $40, $40, $00, $00, $00, $00, $06, $06, $06, $06, $01, $06,
    $06, $02, $06, $06, $00, $06, $00, $0A, $0A, $00, $00, $00, $02, $07, $07,
    $06, $02, $0D, $06, $06, $06, $0E, $05, $05, $02, $02, $00, $00, $04, $04,
    $04, $04, $05, $06, $06, $06, $00, $00, $00, $0E, $00, $00, $08, $00, $10,
    $00, $18, $00, $20, $00, $28, $00, $30, $00, $80, $01, $82, $01, $86, $00,
    $F6, $CF, $FE, $3F, $AB, $00, $B0, $00, $B1, $00, $B3, $00, $BA, $F8, $BB,
    $00, $C0, $00, $C1, $00, $C7, $BF, $62, $FF, $00, $8D, $FF, $00, $C4, $FF,
    $00, $C5, $FF, $00, $FF, $FF, $EB, $01, $FF, $0E, $12, $08, $00, $13, $09,
    $00, $16, $08, $00, $17, $09, $00, $2B, $09, $00, $AE, $FF, $07, $B2, $FF,
    $00, $B4, $FF, $00, $B5, $FF, $00, $C3, $01, $00, $C7, $FF, $BF, $E7, $08,
    $00, $F0, $02, $00
  );

function LdeDisasm(Code: Pointer; Is64Bit: Boolean; out Instr: TLdeInstruction): Integer;
var
  P, StartP: PByte;
  C: Byte;
  Ht: PByte;
  OpcodeForLookup, CFlags: Byte;
  HasOpcode2: Boolean;
  Opcode2: Byte;
  HasOpSize, HasAddrSize: Boolean;
  RexW: Boolean;
  Op64: Integer;
  ModRm, MMod, MReg, MRm: Byte;
  SibBase: Byte;
  DispSize: Byte;
  T: Word;
  ScanCount: Integer;
  KeepScanning: Boolean;
  HandledImm: Boolean;
begin
  Result := 0;
  FillChar(Instr, SizeOf(Instr), 0);
  if Code = nil then
    Exit;

  StartP := PByte(Code);
  P := StartP;
  Ht := @LDE_TABLE[0];
  HasOpSize := False;
  HasAddrSize := False;
  RexW := False;
  Op64 := 0;
  HasOpcode2 := False;
  Opcode2 := 0;
  DispSize := 0;

  C := 0;
  ScanCount := 16;
  KeepScanning := True;
  while (ScanCount > 0) and KeepScanning do
  begin
    Dec(ScanCount);
    C := P^;
    Inc(P);
    case C of
      $F0, $F2, $F3, $26, $2E, $36, $3E, $64, $65:
        ;
      $66:
        HasOpSize := True;
      $67:
        HasAddrSize := True;
    else
      KeepScanning := False;
    end;
  end;

  if Is64Bit and ((C and $F0) = $40) then
  begin
    RexW := ((C and $0F) shr 3) <> 0;
    if RexW and ((P^ and $F8) = $B8) then
      Inc(Op64);
    C := P^;
    Inc(P);
    if (C and $F0) = $40 then
      Exit;
  end;

  if Is64Bit and ((C = $C4) or (C = $C5) or (C = $62)) then
    Exit;

  Instr.Opcode := C;

  if C = $0F then
  begin
    HasOpcode2 := True;
    Opcode2 := P^;
    Inc(P);
    Inc(Ht, DELTA_OPCODES);
    OpcodeForLookup := Opcode2;
  end
  else
  begin
    if (C >= $A0) and (C <= $A3) then
    begin
      Inc(Op64);
      HasOpSize := HasAddrSize;
    end;
    OpcodeForLookup := C;
  end;
  Instr.Opcode2 := Opcode2;
  Instr.HasOpcode2 := HasOpcode2;

  CFlags := Ht[Ht[OpcodeForLookup div 4] + (OpcodeForLookup mod 4)];
  if CFlags = C_ERROR then
  begin
    CFlags := 0;
    if (OpcodeForLookup and $FD) = $24 then
      Inc(CFlags);
  end;

  if (CFlags and C_GROUP) <> 0 then
  begin
    T := PWord(Ht + (CFlags and $7F))^;
    CFlags := Byte(T);
  end;

  Instr.HasModRm := (CFlags and C_MODRM) <> 0;
  if Instr.HasModRm then
  begin
    ModRm := P^;
    Inc(P);
    Instr.ModRm := ModRm;
    MMod := ModRm shr 6;
    MRm := ModRm and 7;
    MReg := (ModRm and $3F) shr 3;

    C := P^;
    Inc(P);

    if MReg <= 1 then
    begin
      if OpcodeForLookup = $F6 then
        CFlags := CFlags or C_IMM8
      else if OpcodeForLookup = $F7 then
        CFlags := CFlags or C_IMM_P66;
    end;

    DispSize := 0;
    case MMod of
      0:
        if HasAddrSize then
        begin
          if MRm = 6 then
            DispSize := 2;
        end
        else if MRm = 5 then
          DispSize := 4;
      1:
        DispSize := 1;
      2:
        begin
          DispSize := 2;
          if not HasAddrSize then
            DispSize := DispSize shl 1;
        end;
    end;

    Instr.HasSib := (MMod <> 3) and (MRm = 4);
    if Instr.HasSib then
    begin
      Inc(P);
      Instr.Sib := C;
      SibBase := C and 7;
      if (SibBase = 5) and ((MMod and 1) = 0) then
        DispSize := 4;
    end;

    Dec(P);

    if Is64Bit and (MMod = 0) and (MRm = 5) then
    begin
      Instr.IsRipRelative := True;
      Instr.RipDispOffset := Integer(NativeUInt(P) - NativeUInt(StartP));
    end;

    Instr.DispSize := DispSize;
    case DispSize of
      1:
        Instr.Displacement := ShortInt(P^);
      2:
        Instr.Displacement := SmallInt(PWord(P)^);
      4:
        Instr.Displacement := Integer(PCardinal(P)^);
    end;
    Inc(P, DispSize);
  end;

  HandledImm := False;

  if (CFlags and C_IMM_P66) <> 0 then
  begin
    if (CFlags and C_REL32) <> 0 then
    begin
      if HasOpSize then
      begin
        Instr.IsRelativeBranch := True;
        Instr.RelBranchOffset := Integer(NativeUInt(P) - NativeUInt(StartP));
        Instr.RelBranchSize := 2;
        Instr.ImmSize := 2;
        Instr.Immediate := PWord(P)^;
        Inc(P, 2);
      end
      else
      begin
        Instr.IsRelativeBranch := True;
        Instr.RelBranchOffset := Integer(NativeUInt(P) - NativeUInt(StartP));
        Instr.RelBranchSize := 4;
        Instr.ImmSize := 4;
        Instr.Immediate := PCardinal(P)^;
        Inc(P, 4);
      end;
      HandledImm := True;
    end
    else if Op64 <> 0 then
    begin
      Instr.ImmSize := 8;
      Instr.Immediate := PUInt64(P)^;
      Inc(P, 8);
      HandledImm := True;
    end
    else if not HasOpSize then
    begin
      Instr.ImmSize := 4;
      Instr.Immediate := PCardinal(P)^;
      Inc(P, 4);
      HandledImm := True;
    end
    else
    begin
      Instr.ImmSize := 2;
      Instr.Immediate := PWord(P)^;
      Inc(P, 2);
      HandledImm := True;
    end;
  end;

  if (not HandledImm) and ((CFlags and C_IMM16) <> 0) then
  begin
    Instr.ImmSize := 2;
    Instr.Immediate := PWord(P)^;
    Inc(P, 2);
  end;

  if (not HandledImm) and ((CFlags and C_IMM8) <> 0) then
  begin
    Instr.ImmSize := 1;
    Instr.Immediate := P^;
    Inc(P, 1);
  end;

  if not HandledImm then
  begin
    if (CFlags and C_REL32) <> 0 then
    begin
      Instr.IsRelativeBranch := True;
      Instr.RelBranchOffset := Integer(NativeUInt(P) - NativeUInt(StartP));
      Instr.RelBranchSize := 4;
      Instr.ImmSize := 4;
      Instr.Immediate := PCardinal(P)^;
      Inc(P, 4);
    end
    else if (CFlags and C_REL8) <> 0 then
    begin
      Instr.IsRelativeBranch := True;
      Instr.RelBranchOffset := Integer(NativeUInt(P) - NativeUInt(StartP));
      Instr.RelBranchSize := 1;
      Instr.ImmSize := 1;
      Instr.Immediate := P^;
      Inc(P, 1);
    end;
  end;

  Instr.Length := Integer(NativeUInt(P) - NativeUInt(StartP));
  if Instr.Length > 15 then
  begin
    Instr.Length := 0;
    Exit;
  end;
  Result := Instr.Length;
end;

function LdeGetTrampolineSize(StartAddr: Pointer; MinBytes: Integer; Is64Bit: Boolean): Integer;
var
  TotalLen: Integer;
  Instr: TLdeInstruction;
  Curr: PByte;
  Len: Integer;
begin
  Result := 0;
  if (StartAddr = nil) or (MinBytes <= 0) then
    Exit;
  TotalLen := 0;
  Curr := PByte(StartAddr);
  while TotalLen < MinBytes do
  begin
    if IsBadReadPtr(Curr, 16) then
      Exit;
    Len := LdeDisasm(Curr, Is64Bit, Instr);
    if Len <= 0 then
      Exit;
    Inc(TotalLen, Len);
    Inc(Curr, Len);
  end;
  Result := TotalLen;
end;

end.
