program TestLde;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  NativePe.Lde in '..\src\NativePe.Lde.pas';

type
  TCase = record
    Name: string;
    Bytes: array of Byte;
    ExpectLength: Integer;
    ExpectRip: Boolean;
    ExpectRelBranch: Boolean;
  end;

function MakeCase(const Name: string; const Bytes: array of Byte; ExpectLength: Integer;
  ExpectRip: Boolean = False; ExpectRelBranch: Boolean = False): TCase;
var
  I: Integer;
begin
  Result.Name := Name;
  SetLength(Result.Bytes, Length(Bytes));
  for I := 0 to High(Bytes) do
    Result.Bytes[I] := Bytes[I];
  Result.ExpectLength := ExpectLength;
  Result.ExpectRip := ExpectRip;
  Result.ExpectRelBranch := ExpectRelBranch;
end;

function RunCase(const C: TCase): Boolean;
var
  Buf: array [0 .. 31] of Byte;
  Instr: TLdeInstruction;
  Got: Integer;
  I: Integer;
begin
  FillChar(Buf, SizeOf(Buf), $90);
  for I := 0 to High(C.Bytes) do
    Buf[I] := C.Bytes[I];

  Got := LdeDisasm(@Buf[0], True, Instr);
  Result := (Got = C.ExpectLength) and (Instr.IsRipRelative = C.ExpectRip) and
    (Instr.IsRelativeBranch = C.ExpectRelBranch);

  if Result then
    Writeln(Format('  OK   %-55s length=%d', [C.Name, Got]))
  else
    Writeln(Format('  FAIL %-55s length=%d (expected %d) rip=%s (expected %s) rel=%s (expected %s)',
      [C.Name, Got, C.ExpectLength, BoolToStr(Instr.IsRipRelative, True), BoolToStr(C.ExpectRip, True),
      BoolToStr(Instr.IsRelativeBranch, True), BoolToStr(C.ExpectRelBranch, True)]));
end;

var
  Cases: array of TCase;
  I: Integer;
  AllPassed: Boolean;
  TrampSize: Integer;
  NopFunc: array [0 .. 15] of Byte;

begin
  try
    SetLength(Cases, 0);

    Cases := Cases + [MakeCase('NOP', [$90], 1)];
    Cases := Cases + [MakeCase('RET', [$C3], 1)];
    Cases := Cases + [MakeCase('PUSH RBP', [$55], 1)];
    Cases := Cases + [MakeCase('MOV RBP,RSP', [$48, $89, $E5], 3)];
    Cases := Cases + [MakeCase('SUB RSP,imm8', [$48, $83, $EC, $20], 4)];
    Cases := Cases + [MakeCase('CALL rel32', [$E8, $11, $22, $33, $44], 5, False, True)];
    Cases := Cases + [MakeCase('JZ rel8', [$74, $10], 2, False, True)];
    Cases := Cases + [MakeCase('JZ rel32 (0F 84)', [$0F, $84, $11, $22, $33, $44], 6, False, True)];
    Cases := Cases + [MakeCase('MOV [RIP+disp32],RAX', [$48, $89, $05, $11, $22, $33, $44], 7, True)];
    Cases := Cases + [MakeCase('LEA RAX,[RIP+disp32]', [$48, $8D, $05, $11, $22, $33, $44], 7, True)];
    Cases := Cases + [MakeCase('CALL [RIP+disp32] (FF /2)', [$FF, $15, $11, $22, $33, $44], 6, True)];
    Cases := Cases + [MakeCase('MOV RAX,imm64', [$48, $B8, 1, 2, 3, 4, 5, 6, 7, 8], 10)];
    Cases := Cases + [MakeCase('TEST EAX,imm32 (F7 /0)',
      [$F7, $C0, $11, $22, $33, $44], 6)];
    Cases := Cases + [MakeCase('TEST AL,imm8 (F6 /0)', [$F6, $C0, $01], 3)];
    Cases := Cases + [MakeCase('NOT EAX (F7 /2, no immediate)', [$F7, $D0], 2)];
    Cases := Cases + [MakeCase('MOV EAX,[EAX*4+disp32] (SIB, no base)',
      [$8B, $04, $85, 1, 2, 3, 4], 7)];
    Cases := Cases + [MakeCase('MOV AL,[RAX+RBX] (SIB, base present)', [$00, $04, $18], 3)];
    Cases := Cases + [MakeCase('ADD EAX,imm8 (group1, 83 /0)', [$83, $C0, $05], 3)];
    Cases := Cases + [MakeCase('multi-byte NOP (0F 1F 00)', [$0F, $1F, $00], 3)];
    Cases := Cases + [MakeCase('MOV [RIP+disp32],imm32', [$C7, $05, 1, 2, 3, 4, 9, 9, 9, 9], 10, True)];

    AllPassed := True;
    for I := 0 to High(Cases) do
      if not RunCase(Cases[I]) then
        AllPassed := False;

    FillChar(NopFunc, SizeOf(NopFunc), $90);
    NopFunc[0] := $48;
    NopFunc[1] := $83;
    NopFunc[2] := $EC;
    NopFunc[3] := $20;
    NopFunc[4] := $E8;
    NopFunc[5] := $11;
    NopFunc[6] := $22;
    NopFunc[7] := $33;
    NopFunc[8] := $44;

    TrampSize := LdeGetTrampolineSize(@NopFunc[0], 6, True);
    if TrampSize = 9 then
      Writeln(Format('  OK   GetTrampolineSize(min=6) landed on an instruction boundary at %d', [TrampSize]))
    else
    begin
      Writeln(Format('  FAIL GetTrampolineSize(min=6) returned %d, expected 9', [TrampSize]));
      AllPassed := False;
    end;

    if AllPassed then
    begin
      Writeln('PASSED.');
      Halt(0);
    end
    else
    begin
      Writeln('FAILED.');
      Halt(1);
    end;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
