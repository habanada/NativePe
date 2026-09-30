program TestDirectoryEntry;

{$APPTYPE CONSOLE}

// Tests GetDirectoryEntry bounds against NumberOfRvaAndSizes for PE32 and PE32+.
// Undeclared directory indices and indices beyond the standard table must return nil.

uses
  System.SysUtils,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas',
  NativePe.PeHdrsHelper in '..\src\NativePe.PeHdrsHelper.pas';

function Check(const Label_: string; Got: Boolean; Expected: Boolean): Boolean;
begin
  Result := Got = Expected;
  if Result then
    Writeln('[PASS] ', Label_)
  else
    Writeln('[FAIL] ', Label_, ' -- expected ', Expected, ', got ', Got);
end;

// Build the smallest valid PE32 header in a caller-supplied buffer.
// Sets NumberOfRvaAndSizes to NumDirs and populates the first two
// DataDirectory entries with dummy non-zero VAs so GetDirectoryEntry
// does not filter them out via the AllowEmpty=False default.
procedure BuildMinimalPe32(Buf: PByte; BufSize: NativeUInt; NumDirs: DWORD);
var
  Dos: PImageDosHeader;
  Nt: PImageNtHeaders32;
  NtOffset: DWORD;
begin
  FillChar(Buf^, BufSize, 0);
  NtOffset := SizeOf(TImageDosHeader);

  Dos := PImageDosHeader(Buf);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := NtOffset;

  Nt := PImageNtHeaders32(Buf + NtOffset);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_I386;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  Nt.OptionalHeader.NumberOfRvaAndSizes := NumDirs;
  Nt.OptionalHeader.SizeOfImage := DWORD(BufSize);
  // Populate the first two directory entries with dummy VAs.
  if NumDirs > 0 then
    Nt.OptionalHeader.DataDirectory[0].VirtualAddress := $1000;
  if NumDirs > 1 then
    Nt.OptionalHeader.DataDirectory[1].VirtualAddress := $2000;
end;

procedure BuildMinimalPe64(Buf: PByte; BufSize: NativeUInt; NumDirs: DWORD);
var
  Dos: PImageDosHeader;
  Nt: PImageNtHeaders64;
  NtOffset: DWORD;
begin
  FillChar(Buf^, BufSize, 0);
  NtOffset := SizeOf(TImageDosHeader);

  Dos := PImageDosHeader(Buf);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := NtOffset;

  Nt := PImageNtHeaders64(Buf + NtOffset);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_AMD64;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64);
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt.OptionalHeader.NumberOfRvaAndSizes := NumDirs;
  Nt.OptionalHeader.SizeOfImage := DWORD(BufSize);
  if NumDirs > 0 then
    Nt.OptionalHeader.DataDirectory[0].VirtualAddress := $1000;
  if NumDirs > 1 then
    Nt.OptionalHeader.DataDirectory[1].VirtualAddress := $2000;
end;

var
  AllPassed: Boolean;
  BufSize: NativeUInt;
  Buf: PByte;

begin
  try
    AllPassed := True;
    BufSize := SizeOf(TImageDosHeader) + SizeOf(TImageNtHeaders64) + $1000;
    Buf := AllocMem(BufSize);
    try
      // --- PE32 with NumDirs = 2 ---
      BuildMinimalPe32(Buf, BufSize, 2);
      if not Check('PE32 NumDirs=2: index 0 non-nil (AllowEmpty:=True)',
          GetDirectoryEntry(Buf, 0, True) <> nil, True) then AllPassed := False;
      if not Check('PE32 NumDirs=2: index 1 non-nil (AllowEmpty:=True)',
          GetDirectoryEntry(Buf, 1, True) <> nil, True) then AllPassed := False;
      if not Check('PE32 NumDirs=2: index 2 nil',
          GetDirectoryEntry(Buf, 2, True) = nil, True) then AllPassed := False;
      if not Check('PE32 NumDirs=2: index 5 nil',
          GetDirectoryEntry(Buf, 5, True) = nil, True) then AllPassed := False;
      if not Check('PE32 NumDirs=2: index 15 nil',
          GetDirectoryEntry(Buf, 15, True) = nil, True) then AllPassed := False;
      if not Check('PE32 NumDirs=2: index 16 nil (constant guard)',
          GetDirectoryEntry(Buf, 16, True) = nil, True) then AllPassed := False;

      // --- PE64 with NumDirs = 2 ---
      BuildMinimalPe64(Buf, BufSize, 2);
      if not Check('PE64 NumDirs=2: index 0 non-nil (AllowEmpty:=True)',
          GetDirectoryEntry(Buf, 0, True) <> nil, True) then AllPassed := False;
      if not Check('PE64 NumDirs=2: index 1 non-nil (AllowEmpty:=True)',
          GetDirectoryEntry(Buf, 1, True) <> nil, True) then AllPassed := False;
      if not Check('PE64 NumDirs=2: index 2 nil',
          GetDirectoryEntry(Buf, 2, True) = nil, True) then AllPassed := False;
      if not Check('PE64 NumDirs=2: index 5 nil',
          GetDirectoryEntry(Buf, 5, True) = nil, True) then AllPassed := False;

      // --- PE64 with NumDirs = 16 (normal) ---
      BuildMinimalPe64(Buf, BufSize, 16);
      if not Check('PE64 NumDirs=16: index 0 non-nil (AllowEmpty:=True)',
          GetDirectoryEntry(Buf, 0, True) <> nil, True) then AllPassed := False;
      if not Check('PE64 NumDirs=16: index 15 non-nil (AllowEmpty:=True)',
          GetDirectoryEntry(Buf, 15, True) <> nil, True) then AllPassed := False;
      if not Check('PE64 NumDirs=16: index 16 nil (constant guard)',
          GetDirectoryEntry(Buf, 16, True) = nil, True) then AllPassed := False;

      // --- PE64 with NumDirs = 100 (corrupt: clamped to 16) ---
      BuildMinimalPe64(Buf, BufSize, 100);
      if not Check('PE64 NumDirs=100 (corrupt): index 15 non-nil',
          GetDirectoryEntry(Buf, 15, True) <> nil, True) then AllPassed := False;
      if not Check('PE64 NumDirs=100 (corrupt): index 16 nil (clamped)',
          GetDirectoryEntry(Buf, 16, True) = nil, True) then AllPassed := False;

    finally
      FreeMem(Buf);
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
