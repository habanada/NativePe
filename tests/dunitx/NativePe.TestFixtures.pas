unit NativePe.TestFixtures;

interface

uses
  Winapi.Windows,
  System.SysUtils,
  NativePe.Types;

const
  TEST_NT_OFFSET = $80;
  TEST_IMAGE_SIZE = $4000;
  TEST_HEADERS_SIZE = $400;
  TEST_SECTION_ALIGNMENT = $1000;
  TEST_FILE_ALIGNMENT = $200;
  TEST_IMAGE_BASE32 = DWORD($00400000);
  TEST_IMAGE_BASE64 = UInt64($0000000140000000);
  TEST_RAW_SIZE = $1600;

function BytesPtr(var Data: TBytes): PByte;
function BuildMinimalPe32(NumDirs: DWORD = IMAGE_NUMBEROF_DIRECTORY_ENTRIES): TBytes;
function BuildMinimalPe64(NumDirs: DWORD = IMAGE_NUMBEROF_DIRECTORY_ENTRIES): TBytes;
function BuildRichVirtualPe64: TBytes;
function BuildRichRawPe64: TBytes;
function SectionName(Sec: PImageSectionHeader): string;
procedure BuildTruncatedTls64(out Data: TBytes; out DeclaredSize: NativeUInt);
procedure BuildTruncatedImport64(out Data: TBytes; out DeclaredSize: NativeUInt);

implementation



function BytesPtr(var Data: TBytes): PByte;
begin
  if Length(Data) = 0 then
    Exit(nil);
  Result := @Data[0];
end;

procedure SetSectionName(Sec: PImageSectionHeader; const Name: AnsiString);
var
  N: Integer;
begin
  FillChar(Sec.Name, SizeOf(Sec.Name), 0);
  N := Length(Name);
  if N > SizeOf(Sec.Name) then
    N := SizeOf(Sec.Name);
  if N > 0 then
    Move(Name[1], Sec.Name[0], N);
end;

procedure PutAnsiZ(var Data: TBytes; Offset: NativeUInt; const S: AnsiString);
var
  N: Integer;
begin
  N := Length(S);
  if N > 0 then
    Move(S[1], Data[Offset], N);
  Data[Offset + NativeUInt(N)] := 0;
end;

function BuildMinimalPe32(NumDirs: DWORD): TBytes;
var
  P: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeaders32;
begin
  SetLength(Result, $1000);
  FillChar(Result[0], Length(Result), 0);
  P := @Result[0];
  Dos := PImageDosHeader(P);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := TEST_NT_OFFSET;
  Nt := PImageNtHeaders32(P + TEST_NT_OFFSET);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_I386;
  Nt.FileHeader.NumberOfSections := 0;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader32);
  Nt.FileHeader.Characteristics := $0002;
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  Nt.OptionalHeader.AddressOfEntryPoint := $1000;
  Nt.OptionalHeader.BaseOfCode := $1000;
  Nt.OptionalHeader.BaseOfData := $2000;
  Nt.OptionalHeader.ImageBase := TEST_IMAGE_BASE32;
  Nt.OptionalHeader.SectionAlignment := TEST_SECTION_ALIGNMENT;
  Nt.OptionalHeader.FileAlignment := TEST_FILE_ALIGNMENT;
  Nt.OptionalHeader.SizeOfImage := TEST_IMAGE_SIZE;
  Nt.OptionalHeader.SizeOfHeaders := TEST_HEADERS_SIZE;
  Nt.OptionalHeader.Subsystem := 3;
  Nt.OptionalHeader.NumberOfRvaAndSizes := NumDirs;
  if NumDirs > 0 then
    Nt.OptionalHeader.DataDirectory[0].VirtualAddress := $200;
  if NumDirs > 1 then
    Nt.OptionalHeader.DataDirectory[1].VirtualAddress := $220;
end;

function BuildMinimalPe64(NumDirs: DWORD): TBytes;
var
  P: PByte;
  Dos: PImageDosHeader;
  Nt: PImageNtHeaders64;
begin
  SetLength(Result, $1000);
  FillChar(Result[0], Length(Result), 0);
  P := @Result[0];
  Dos := PImageDosHeader(P);
  Dos.e_magic := IMAGE_DOS_SIGNATURE;
  Dos.e_lfanew := TEST_NT_OFFSET;
  Nt := PImageNtHeaders64(P + TEST_NT_OFFSET);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_AMD64;
  Nt.FileHeader.NumberOfSections := 0;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64);
  Nt.FileHeader.Characteristics := $0002;
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt.OptionalHeader.AddressOfEntryPoint := $1000;
  Nt.OptionalHeader.BaseOfCode := $1000;
  Nt.OptionalHeader.ImageBase := TEST_IMAGE_BASE64;
  Nt.OptionalHeader.SectionAlignment := TEST_SECTION_ALIGNMENT;
  Nt.OptionalHeader.FileAlignment := TEST_FILE_ALIGNMENT;
  Nt.OptionalHeader.SizeOfImage := TEST_IMAGE_SIZE;
  Nt.OptionalHeader.SizeOfHeaders := TEST_HEADERS_SIZE;
  Nt.OptionalHeader.Subsystem := 3;
  Nt.OptionalHeader.NumberOfRvaAndSizes := NumDirs;
  if NumDirs > 0 then
    Nt.OptionalHeader.DataDirectory[0].VirtualAddress := $200;
  if NumDirs > 1 then
    Nt.OptionalHeader.DataDirectory[1].VirtualAddress := $220;
end;

function BuildRichVirtualPe64: TBytes;
var
  P: PByte;
  Nt: PImageNtHeaders64;
  Sec: PImageSectionHeader;
  Exp: PImageExportDirectory;
  ResDir: PImageResourceDirectory;
  ResEntry: PImageResourceDirectoryEntry;
  ResData: PImageResourceDataEntry;
  Tls: PImageTlsDirectory64;
  Cor: PImageCor20Header;
  Imp: PImageImportDescriptor;
  Thunk: PImageThunkData64;
  ByName: PImageImportByName;
  Reloc: PImageBaseRelocation;
  RelEntry: PWord;
  I: Integer;
begin
  SetLength(Result, TEST_IMAGE_SIZE);
  FillChar(Result[0], Length(Result), 0);
  P := @Result[0];
  PImageDosHeader(P).e_magic := IMAGE_DOS_SIGNATURE;
  PImageDosHeader(P).e_lfanew := TEST_NT_OFFSET;
  Nt := PImageNtHeaders64(P + TEST_NT_OFFSET);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_AMD64;
  Nt.FileHeader.NumberOfSections := 3;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64);
  Nt.FileHeader.Characteristics := $0002 or IMAGE_FILE_DLL;
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt.OptionalHeader.AddressOfEntryPoint := $1050;
  Nt.OptionalHeader.BaseOfCode := $1000;
  Nt.OptionalHeader.ImageBase := TEST_IMAGE_BASE64;
  Nt.OptionalHeader.SectionAlignment := TEST_SECTION_ALIGNMENT;
  Nt.OptionalHeader.FileAlignment := TEST_FILE_ALIGNMENT;
  Nt.OptionalHeader.SizeOfCode := $400;
  Nt.OptionalHeader.SizeOfInitializedData := $E00;
  Nt.OptionalHeader.SizeOfImage := TEST_IMAGE_SIZE;
  Nt.OptionalHeader.SizeOfHeaders := TEST_HEADERS_SIZE;
  Nt.OptionalHeader.Subsystem := 3;
  Nt.OptionalHeader.DllCharacteristics := $8160;
  Nt.OptionalHeader.NumberOfRvaAndSizes := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

  Sec := PImageSectionHeader(PByte(@Nt.OptionalHeader) + Nt.FileHeader.SizeOfOptionalHeader);
  SetSectionName(Sec, '.text');
  Sec.Misc.VirtualSize := $400;
  Sec.VirtualAddress := $1000;
  Sec.SizeOfRawData := $400;
  Sec.PointerToRawData := $400;
  Sec.Characteristics := IMAGE_SCN_MEM_EXECUTE or IMAGE_SCN_MEM_READ;

  Inc(Sec);
  SetSectionName(Sec, '.rdata');
  Sec.Misc.VirtualSize := $C00;
  Sec.VirtualAddress := $2000;
  Sec.SizeOfRawData := $C00;
  Sec.PointerToRawData := $800;
  Sec.Characteristics := IMAGE_SCN_MEM_READ;

  Inc(Sec);
  SetSectionName(Sec, '.reloc');
  Sec.Misc.VirtualSize := $200;
  Sec.VirtualAddress := $3000;
  Sec.SizeOfRawData := $200;
  Sec.PointerToRawData := $1400;
  Sec.Characteristics := IMAGE_SCN_MEM_READ;

  for I := 0 to $3FF do
    Result[$1000 + I] := Byte(I and $FF);
  Result[$1050] := $C3;
  Result[$1060] := $C3;
  PUInt64(P + $1020)^ := TEST_IMAGE_BASE64 + $1234;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress := $2100;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size := $180;
  Exp := PImageExportDirectory(P + $2100);
  Exp.Name := $2180;
  Exp.Base := 1;
  Exp.NumberOfFunctions := 2;
  Exp.NumberOfNames := 2;
  Exp.AddressOfFunctions := $2200;
  Exp.AddressOfNames := $2220;
  Exp.AddressOfNameOrdinals := $2240;
  PutAnsiZ(Result, $2180, 'fixture64.dll');
  PDWORD(P + $2200)^ := $1050;
  PDWORD(P + $2204)^ := $1060;
  PDWORD(P + $2220)^ := $2260;
  PDWORD(P + $2224)^ := $2270;
  PWord(P + $2240)^ := 0;
  PWord(P + $2242)^ := 1;
  PutAnsiZ(Result, $2260, 'Alpha');
  PutAnsiZ(Result, $2270, 'Beta');

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress := $2300;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size := $100;
  ResDir := PImageResourceDirectory(P + $2300);
  ResDir.NumberOfIdEntries := 1;
  ResEntry := PImageResourceDirectoryEntry(P + $2310);
  ResEntry.NameOrId := 10;
  ResEntry.OffsetToDataOrDirectory := $20;
  ResData := PImageResourceDataEntry(P + $2320);
  ResData.OffsetToData := $2380;
  ResData.Size := 4;
  ResData.CodePage := 1200;
  Result[$2380] := $DE;
  Result[$2381] := $AD;
  Result[$2382] := $BE;
  Result[$2383] := $EF;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress := $2400;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size := SizeOf(TImageTlsDirectory64);
  Tls := PImageTlsDirectory64(P + $2400);
  Tls.AddressOfCallBacks := $2450;
  PUInt64(P + $2450)^ := $11111111;
  PUInt64(P + $2458)^ := $22222222;
  PUInt64(P + $2460)^ := 0;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress := $2500;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size := SizeOf(TImageCor20Header);
  Cor := PImageCor20Header(P + $2500);
  Cor.cb := SizeOf(TImageCor20Header);
  Cor.MajorRuntimeVersion := 4;
  Cor.MetaData.VirtualAddress := $2580;
  Cor.MetaData.Size := $20;
  PDWORD(P + $2580)^ := DOTNET_METADATA_SIGNATURE;

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress := $2600;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size := 2 * SizeOf(TImageImportDescriptor);
  Imp := PImageImportDescriptor(P + $2600);
  Imp.OriginalFirstThunk := $2680;
  Imp.Name := $2640;
  Imp.FirstThunk := $26A0;
  PutAnsiZ(Result, $2640, 'fixturedep.dll');
  Thunk := PImageThunkData64(P + $2680);
  Thunk.AddressOfData := $26C0;
  Inc(Thunk);
  Thunk.Ordinal := IMAGE_ORDINAL_FLAG64 or 7;
  Inc(Thunk);
  Thunk.Func := 0;
  Thunk := PImageThunkData64(P + $26A0);
  Thunk.Func := $1111;
  Inc(Thunk);
  Thunk.Func := $2222;
  Inc(Thunk);
  Thunk.Func := 0;
  ByName := PImageImportByName(P + $26C0);
  ByName.Hint := 42;
  PutAnsiZ(Result, $26C2, 'NamedFunc');

  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress := $3000;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size := 12;
  Reloc := PImageBaseRelocation(P + $3000);
  Reloc.VirtualAddress := $1000;
  Reloc.SizeOfBlock := 12;
  RelEntry := PWord(P + $3008);
  RelEntry^ := Word(($A shl 12) or $20);
  Inc(RelEntry);
  RelEntry^ := 0;
end;

function BuildRichRawPe64: TBytes;
var
  VirtualImage: TBytes;
begin
  VirtualImage := BuildRichVirtualPe64;
  SetLength(Result, TEST_RAW_SIZE);
  FillChar(Result[0], Length(Result), 0);
  Move(VirtualImage[0], Result[0], TEST_HEADERS_SIZE);
  Move(VirtualImage[$1000], Result[$400], $400);
  Move(VirtualImage[$2000], Result[$800], $C00);
  Move(VirtualImage[$3000], Result[$1400], $200);
end;

function SectionName(Sec: PImageSectionHeader): string;
var
  A: AnsiString;
  N: Integer;
begin
  if Sec = nil then
    Exit('');
  N := 0;
  while (N < SizeOf(Sec.Name)) and (Sec.Name[N] <> #0) do
    Inc(N);
  SetLength(A, N);
  if N > 0 then
    Move(Sec.Name[0], A[1], N);
  Result := string(A);
end;

procedure WriteMinimalNtHeaders64(P: PByte; BufferSize: NativeUInt);
var
  Nt: PImageNtHeaders64;
begin
  FillChar(P^, BufferSize, 0);
  PImageDosHeader(P).e_magic := IMAGE_DOS_SIGNATURE;
  PImageDosHeader(P).e_lfanew := 64;
  Nt := PImageNtHeaders64(P + 64);
  Nt.Signature := IMAGE_NT_SIGNATURE;
  Nt.FileHeader.Machine := IMAGE_FILE_MACHINE_AMD64;
  Nt.FileHeader.SizeOfOptionalHeader := SizeOf(TImageOptionalHeader64);
  Nt.OptionalHeader.Magic := IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt.OptionalHeader.SizeOfImage := DWORD(BufferSize);
  Nt.OptionalHeader.SizeOfHeaders := 64 + SizeOf(TImageNtHeaders64);
  Nt.OptionalHeader.NumberOfRvaAndSizes := IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
end;

procedure BuildTruncatedTls64(out Data: TBytes; out DeclaredSize: NativeUInt);
const
  RealSize = 2048;
  TlsRva = 470;
  CallbackRva = 420;
var
  P: PByte;
  Nt: PImageNtHeaders64;
begin
  DeclaredSize := 500;
  SetLength(Data, RealSize);
  P := @Data[0];
  WriteMinimalNtHeaders64(P, RealSize);
  Nt := PImageNtHeaders64(P + 64);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress := TlsRva;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size := SizeOf(TImageTlsDirectory64);
  PUInt64(P + TlsRva + 24)^ := NativeUInt(P) + CallbackRva;
  PUInt64(P + CallbackRva)^ := $0000000140001234;
  PUInt64(P + CallbackRva + 8)^ := 0;
end;

procedure BuildTruncatedImport64(out Data: TBytes; out DeclaredSize: NativeUInt);
const
  RealSize = 2048;
  ImportRva = 300;
  DllNameRva = 350;
  ThunkRva = 495;
var
  P: PByte;
  Nt: PImageNtHeaders64;
  Desc: PImageImportDescriptor;
begin
  DeclaredSize := 500;
  SetLength(Data, RealSize);
  P := @Data[0];
  WriteMinimalNtHeaders64(P, RealSize);
  Nt := PImageNtHeaders64(P + 64);
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress := ImportRva;
  Nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size := 2 * SizeOf(TImageImportDescriptor);
  Desc := PImageImportDescriptor(P + ImportRva);
  Desc.Name := DllNameRva;
  Desc.FirstThunk := ThunkRva;
  PutAnsiZ(Data, DllNameRva, 'a.dll');
end;

end.
