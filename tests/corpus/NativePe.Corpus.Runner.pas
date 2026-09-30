unit NativePe.Corpus.Runner;

interface

function RunCorpusApplication: Integer;

implementation

uses
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  Winapi.Windows,
  NativePe.Types,
  NativePe.BufferUtil,
  NativePe.PeHdrsHelper,
  NativePe.PeLoader,
  NativePe.PeVirtualToRaw,
  NativePe.ImportsLoader,
  NativePe.ExportsLookup,
  NativePe.ResourceParser,
  NativePe.TlsParser,
  NativePe.Relocate,
  NativePe.LoadConfig,
  NativePe.DelayedImports,
  NativePe.Util;

const
  CORPUS_STRICT_IMPORT_DIRECTORY_SIZE = False;
  TLS_CALLBACK_PREVIEW_LIMIT = 64;

type
  TCorpusOutcome = (
    coPass,
    coReject,
    coFail,
    coCrash,
    coTimeout,
    coSkip
  );

  TCorpusResult = record
    FileName: string;
    Outcome: TCorpusOutcome;
    Stage: string;
    MessageText: string;
    FileSize: UInt64;
    Architecture: string;
    ImageBase: UInt64;
    EntryPoint: DWORD;
    SectionCount: NativeUInt;
    DirectoryCount: NativeUInt;
    MapOk: Boolean;
    VirtualSize: UInt64;
    ImportsPresent: Boolean;
    ImportsValid: Boolean;
    ImportsParsed: Boolean;
    ImportCount: NativeUInt;
    DelayImportsPresent: Boolean;
    DelayImportsValid: Boolean;
    DelayImportCount: NativeUInt;
    ExportsPresent: Boolean;
    ExportsParsed: Boolean;
    ExportCount: NativeUInt;
    TlsPresent: Boolean;
    TlsParsed: Boolean;
    TlsCallbackCount: NativeUInt;
    TlsCallbackValidCount: NativeUInt;
    TlsCallbackInvalidCount: NativeUInt;
    TlsCallbackDigest: string;
    TlsCallbackPreview: string;
    TlsCallbackTruncated: Boolean;
    TlsCallbackFirstValidRva: string;
    TlsCallbackLastValidRva: string;
    TlsIndexRva: string;
    TlsRawData: string;
    ResourcesPresent: Boolean;
    ResourcesParsed: Boolean;
    ResourceCount: NativeUInt;
    RelocsPresent: Boolean;
    RelocsValid: Boolean;
    HasRelocs: Boolean;
    RelocFieldCount: NativeUInt;
    ExceptionsPresent: Boolean;
    ExceptionsParsed: Boolean;
    ExceptionCount: NativeUInt;
    ExceptionDigest: string;
    LoadConfigPresent: Boolean;
    LoadConfigParsed: Boolean;
    LoadConfigVersion: Integer;
    LoadConfigSize: DWORD;
    SecurityCookieRva: string;
    IsDotNetImage: Boolean;
    UnmapOk: Boolean;
    RawOutputSize: UInt64;
    RoundTripChecked: Boolean;
    RoundTripEqual: Boolean;
    FirstDiff: Int64;
    LibraryElapsedUs: UInt64;
    CoreElapsedUs: UInt64;
    WorkerElapsedUs: UInt64;
    WallElapsedUs: UInt64;
    ElapsedMs: UInt64;
    ProcessExitCode: DWORD;
  end;

var
  GResourceCount: NativeUInt;

type
  TCorpusRuntimeFunction = packed record
    BeginAddress: DWORD;
    EndAddress: DWORD;
    UnwindInfoAddress: DWORD;
  end;
  PCorpusRuntimeFunction = ^TCorpusRuntimeFunction;

  TCountRelocCallback = class(TRelocBlockCallback)
  private
    FCount: NativeUInt;
  public
    function ProcessRelocField(RelocField: NativeUInt): Boolean; override;
    property Count: NativeUInt read FCount;
  end;

function TCountRelocCallback.ProcessRelocField(RelocField: NativeUInt): Boolean;
begin
  if FCount < High(NativeUInt) then
    Inc(FCount);
  Result := True;
end;

function CountResourceEntry(ModulePtr: PByte; RootDir: PImageResourceDirectoryEntry;
  CurrEntry: PImageResourceDataEntry): Boolean;
begin
  if GResourceCount < High(NativeUInt) then
    Inc(GResourceCount);
  Result := True;
end;

procedure InitCorpusResult(var AResult: TCorpusResult);
begin
  AResult.FileName := '';
  AResult.Outcome := coFail;
  AResult.Stage := '';
  AResult.MessageText := '';
  AResult.FileSize := 0;
  AResult.Architecture := '';
  AResult.ImageBase := 0;
  AResult.EntryPoint := 0;
  AResult.SectionCount := 0;
  AResult.DirectoryCount := 0;
  AResult.MapOk := False;
  AResult.VirtualSize := 0;
  AResult.ImportsPresent := False;
  AResult.ImportsValid := False;
  AResult.ImportsParsed := False;
  AResult.ImportCount := 0;
  AResult.DelayImportsPresent := False;
  AResult.DelayImportsValid := False;
  AResult.DelayImportCount := 0;
  AResult.ExportsPresent := False;
  AResult.ExportsParsed := False;
  AResult.ExportCount := 0;
  AResult.TlsPresent := False;
  AResult.TlsParsed := False;
  AResult.TlsCallbackCount := 0;
  AResult.TlsCallbackValidCount := 0;
  AResult.TlsCallbackInvalidCount := 0;
  AResult.TlsCallbackDigest := '';
  AResult.TlsCallbackPreview := '';
  AResult.TlsCallbackTruncated := False;
  AResult.TlsCallbackFirstValidRva := '';
  AResult.TlsCallbackLastValidRva := '';
  AResult.ResourcesPresent := False;
  AResult.ResourcesParsed := False;
  AResult.ResourceCount := 0;
  AResult.RelocsPresent := False;
  AResult.RelocsValid := False;
  AResult.HasRelocs := False;
  AResult.RelocFieldCount := 0;
  AResult.ExceptionsPresent := False;
  AResult.ExceptionsParsed := False;
  AResult.ExceptionCount := 0;
  AResult.ExceptionDigest := '';
  AResult.LoadConfigPresent := False;
  AResult.LoadConfigParsed := False;
  AResult.LoadConfigVersion := LOAD_CONFIG_NONE;
  AResult.LoadConfigSize := 0;
  AResult.SecurityCookieRva := '';
  AResult.IsDotNetImage := False;
  AResult.UnmapOk := False;
  AResult.RawOutputSize := 0;
  AResult.RoundTripChecked := False;
  AResult.RoundTripEqual := False;
  AResult.FirstDiff := -1;
  AResult.LibraryElapsedUs := 0;
  AResult.CoreElapsedUs := 0;
  AResult.WorkerElapsedUs := 0;
  AResult.WallElapsedUs := 0;
  AResult.ElapsedMs := 0;
  AResult.ProcessExitCode := 0;
end;

function BuildConfiguration: string;
begin
{$IFDEF DEBUG}
  Result := 'Debug';
{$ELSE}
  Result := 'Release';
{$ENDIF}
end;

function BuildOptimized: Boolean;
begin
{$IFOPT O+}
  Result := True;
{$ELSE}
  Result := False;
{$ENDIF}
end;

function OutcomeToText(AOutcome: TCorpusOutcome): string;
begin
  case AOutcome of
    coPass: Result := 'PASS';
    coReject: Result := 'REJECT';
    coFail: Result := 'FAIL';
    coCrash: Result := 'CRASH';
    coTimeout: Result := 'TIMEOUT';
    coSkip: Result := 'SKIP';
  else
    Result := 'FAIL';
  end;
end;

function TextToOutcome(const S: string): TCorpusOutcome;
begin
  if SameText(S, 'PASS') then
    Exit(coPass);
  if SameText(S, 'REJECT') then
    Exit(coReject);
  if SameText(S, 'CRASH') then
    Exit(coCrash);
  if SameText(S, 'TIMEOUT') then
    Exit(coTimeout);
  if SameText(S, 'SKIP') then
    Exit(coSkip);
  Result := coFail;
end;

function BoolToText(Value: Boolean): string;
begin
  if Value then
    Result := '1'
  else
    Result := '0';
end;

function TextToBool(const S: string): Boolean;
begin
  Result := S = '1';
end;

function TextToUInt64(const S: string; DefaultValue: UInt64 = 0): UInt64;
begin
  if not TryStrToUInt64(S, Result) then
    Result := DefaultValue;
end;

function OneLine(const S: string): string;
begin
  Result := StringReplace(S, #13, ' ', [rfReplaceAll]);
  Result := StringReplace(Result, #10, ' ', [rfReplaceAll]);
end;

function TryAddressToRvaWithBases(ImageBase, MappedBase: UInt64; ModuleSize: NativeUInt; Address: UInt64; out Rva: DWORD): Boolean; inline;
var
  Delta: UInt64;
begin
  Rva := 0;
  if Address = 0 then
    Exit(True);
  if Address >= ImageBase then
  begin
    Delta := Address - ImageBase;
    if (Delta < ModuleSize) and (Delta <= High(DWORD)) then
    begin
      Rva := DWORD(Delta);
      Exit(True);
    end;
  end;
  if Address >= MappedBase then
  begin
    Delta := Address - MappedBase;
    if (Delta < ModuleSize) and (Delta <= High(DWORD)) then
    begin
      Rva := DWORD(Delta);
      Exit(True);
    end;
  end;
  if (Address < ModuleSize) and (Address <= High(DWORD)) then
  begin
    Rva := DWORD(Address);
    Exit(True);
  end;
  Result := False;
end;

function AddressToRvaTextWithBases(ImageBase, MappedBase: UInt64; ModuleSize: NativeUInt; Address: UInt64): string; inline;
var
  Rva: DWORD;
begin
  if TryAddressToRvaWithBases(ImageBase, MappedBase, ModuleSize, Address, Rva) then
    Result := '0x' + IntToHex(Rva, 8)
  else
    Result := 'INVALID';
end;

function AddressToRvaText(ModulePtr: PByte; ModuleSize: NativeUInt; Address: UInt64): string;
begin
  Result := AddressToRvaTextWithBases(GetImageBase(ModulePtr), UInt64(NativeUInt(ModulePtr)), ModuleSize, Address);
end;

procedure UpdateTlsDigestByte(var HashA, HashB: UInt64; Value: Byte); inline;
begin
  HashA := ((HashA shl 5) or (HashA shr 59)) xor Value;
  HashB := ((HashB shl 13) or (HashB shr 51)) xor (UInt64(Value) shl 32) xor UInt64(Value);
end;

procedure UpdateTlsDigestToken(var HashA, HashB: UInt64; Valid: Boolean; Rva: DWORD); inline;
begin
  if Valid then
    UpdateTlsDigestByte(HashA, HashB, 1)
  else
    UpdateTlsDigestByte(HashA, HashB, 0);
  UpdateTlsDigestByte(HashA, HashB, Byte(Rva));
  UpdateTlsDigestByte(HashA, HashB, Byte(Rva shr 8));
  UpdateTlsDigestByte(HashA, HashB, Byte(Rva shr 16));
  UpdateTlsDigestByte(HashA, HashB, Byte(Rva shr 24));
end;

function BuildTlsDetails(ModulePtr: PByte; ModuleSize: NativeUInt; Callbacks: TList<UInt64>;
  out IndexRva, RawData, Digest, FirstValidRva, LastValidRva: string;
  out ValidCount, InvalidCount: NativeUInt; out Truncated: Boolean): string;
var
  Tls64: PImageTlsDirectory64;
  Tls32: PImageTlsDirectory32 absolute Tls64;
  StartAddress, EndAddress, IndexAddress: UInt64;
  HashA, HashB, ImageBase, MappedBase: UInt64;
  FirstValid, LastValid, Rva: DWORD;
  HasValid, Valid: Boolean;
  Preview: TStringBuilder;
  I: Integer;
begin
  Result := '';
  IndexRva := '';
  RawData := '';
  Digest := '';
  FirstValidRva := '';
  LastValidRva := '';
  ValidCount := 0;
  InvalidCount := 0;
  Truncated := False;
  Tls64 := PImageTlsDirectory64(GetTypeDirectoryPtr(ModulePtr, IMAGE_DIRECTORY_ENTRY_TLS));
  if Tls64 = nil then
    Exit;
  if Is64Bit(ModulePtr) then
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, Tls64, SizeOf(TImageTlsDirectory64)) then
      Exit;
    StartAddress := Tls64.StartAddressOfRawData;
    EndAddress := Tls64.EndAddressOfRawData;
    IndexAddress := Tls64.AddressOfIndex;
  end
  else
  begin
    if not ValidatePtr(ModulePtr, ModuleSize, Tls32, SizeOf(TImageTlsDirectory32)) then
      Exit;
    StartAddress := Tls32.StartAddressOfRawData;
    EndAddress := Tls32.EndAddressOfRawData;
    IndexAddress := Tls32.AddressOfIndex;
  end;
  ImageBase := GetImageBase(ModulePtr);
  MappedBase := UInt64(NativeUInt(ModulePtr));
  IndexRva := AddressToRvaTextWithBases(ImageBase, MappedBase, ModuleSize, IndexAddress);
  RawData := AddressToRvaTextWithBases(ImageBase, MappedBase, ModuleSize, StartAddress) + '-' +
    AddressToRvaTextWithBases(ImageBase, MappedBase, ModuleSize, EndAddress);
  HashA := $CBF29CE484222325;
  HashB := $6A09E667F3BCC909;
  HasValid := False;
  FirstValid := 0;
  LastValid := 0;
  Preview := TStringBuilder.Create;
  try
    for I := 0 to Callbacks.Count - 1 do
    begin
      Valid := TryAddressToRvaWithBases(ImageBase, MappedBase, ModuleSize, Callbacks[I], Rva);
      if Valid then
      begin
        Inc(ValidCount);
        if not HasValid then
        begin
          FirstValid := Rva;
          HasValid := True;
        end;
        LastValid := Rva;
      end
      else
      begin
        Inc(InvalidCount);
        Rva := 0;
      end;
      UpdateTlsDigestToken(HashA, HashB, Valid, Rva);
      if I < TLS_CALLBACK_PREVIEW_LIMIT then
      begin
        if Preview.Length <> 0 then
          Preview.Append(';');
        if Valid then
          Preview.Append('0x' + IntToHex(Rva, 8))
        else
          Preview.Append('INVALID');
      end;
    end;
    Result := Preview.ToString;
  finally
    Preview.Free;
  end;
  Digest := IntToHex(Int64(HashA), 16) + IntToHex(Int64(HashB), 16);
  Truncated := Callbacks.Count > TLS_CALLBACK_PREVIEW_LIMIT;
  if HasValid then
  begin
    FirstValidRva := '0x' + IntToHex(FirstValid, 8);
    LastValidRva := '0x' + IntToHex(LastValid, 8);
  end;
end;

function ParseExceptionDetails(ModulePtr: PByte; ModuleSize: NativeUInt; out Count: NativeUInt; out Digest: string): Boolean;
var
  Dir: PImageDataDirectory;
  Data: PByte;
  Hash: UInt64;
  I: NativeUInt;
begin
  Result := False;
  Count := 0;
  Digest := '';
  Dir := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
  if Dir = nil then
    Exit(True);
  if (Dir.Size = 0) or ((Dir.Size mod SizeOf(TCorpusRuntimeFunction)) <> 0) then
    Exit;
  Data := PByte(NativeUInt(ModulePtr) + Dir.VirtualAddress);
  if not ValidatePtr(ModulePtr, ModuleSize, Data, Dir.Size) then
    Exit;
  Count := Dir.Size div SizeOf(TCorpusRuntimeFunction);
  Hash := $CBF29CE484222325;
  for I := 0 to Dir.Size - 1 do
  begin
    Hash := ((Hash shl 5) or (Hash shr 59)) xor Data^;
    Inc(Data);
  end;
  Digest := IntToHex(Int64(Hash), 16);
  Result := True;
end;

procedure ReadLoadConfigDetails(ModulePtr: PByte; ModuleSize: NativeUInt; var AResult: TCorpusResult);
var
  Ptr: PByte;
  Cookie: UInt64;
begin
  AResult.LoadConfigPresent := GetDirectoryEntry(ModulePtr, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) <> nil;
  if not AResult.LoadConfigPresent then
    Exit;
  Ptr := GetLoadConfigPtr(ModulePtr, ModuleSize);
  if Ptr = nil then
    Exit;
  AResult.LoadConfigParsed := True;
  AResult.LoadConfigVersion := GetLoadConfigVersion(ModulePtr, ModuleSize, Ptr);
  if ValidatePtr(ModulePtr, ModuleSize, Ptr, SizeOf(DWORD)) then
    AResult.LoadConfigSize := PDWORD(Ptr)^;
  Cookie := 0;
  if Is64Bit(ModulePtr) then
  begin
    if ValidatePtr(ModulePtr, ModuleSize, Ptr, SizeOf(TImageLoadConfigDir64W7)) then
      Cookie := PImageLoadConfigDir64W7(Ptr).SecurityCookie;
  end
  else if ValidatePtr(ModulePtr, ModuleSize, Ptr, SizeOf(TImageLoadConfigDir32W7)) then
    Cookie := PImageLoadConfigDir32W7(Ptr).SecurityCookie;
  AResult.SecurityCookieRva := AddressToRvaText(ModulePtr, ModuleSize, Cookie);
end;

procedure MarkReject(var AResult: TCorpusResult; const AStage, AMessage: string);
begin
  if AResult.Outcome = coPass then
  begin
    AResult.Outcome := coReject;
    AResult.Stage := AStage;
    AResult.MessageText := OneLine(AMessage);
  end
  else if AResult.Outcome = coReject then
    AResult.MessageText := AResult.MessageText + ' | ' + AStage + ': ' + OneLine(AMessage);
end;

function StageMarkerFileName(const ResultFile: string): string;
begin
  Result := ResultFile + '.stage';
end;

procedure WriteStageMarker(const ResultFile, Stage: string);
var
  Lines: TStringList;
begin
  try
    Lines := TStringList.Create;
    try
      Lines.Add(Stage);
      Lines.SaveToFile(StageMarkerFileName(ResultFile), TEncoding.UTF8);
    finally
      Lines.Free;
    end;
  except
  end;
end;

function ReadStageMarker(const ResultFile: string): string;
var
  Lines: TStringList;
begin
  Result := '';
  try
    if not FileExists(StageMarkerFileName(ResultFile)) then
      Exit;
    Lines := TStringList.Create;
    try
      Lines.LoadFromFile(StageMarkerFileName(ResultFile), TEncoding.UTF8);
      if Lines.Count > 0 then
        Result := Trim(Lines[0]);
    finally
      Lines.Free;
    end;
  except
    Result := '';
  end;
end;

function RangeWithin(TotalSize, Offset, FieldSize: NativeUInt): Boolean;
begin
  if Offset > TotalSize then
    Exit(False);
  Result := FieldSize <= TotalSize - Offset;
end;

function IsMzBuffer(Buffer: PByte; BufferSize: NativeUInt): Boolean;
begin
  if Buffer = nil then
    Exit(False);
  if BufferSize < SizeOf(TImageDosHeader) then
    Exit(False);
  Result := PImageDosHeader(Buffer).e_magic = IMAGE_DOS_SIGNATURE;
end;

function ReadRawFile(const FileName: string; out Buffer: TUnalignedBuf;
  out BufferSize: NativeUInt; out ErrorText: string): Boolean;
var
  Stream: TFileStream;
  Size64: Int64;
begin
  Result := False;
  Buffer := nil;
  BufferSize := 0;
  ErrorText := '';
  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      Size64 := Stream.Size;
      if (Size64 < 0) or (UInt64(Size64) > UInt64(High(NativeUInt))) then
      begin
        ErrorText := 'file too large for process address space';
        Exit;
      end;
      BufferSize := NativeUInt(Size64);
      if BufferSize <> 0 then
      begin
        GetMem(Buffer, BufferSize);
        try
          Stream.ReadBuffer(Buffer^, BufferSize);
        except
          FreeMem(Buffer);
          Buffer := nil;
          BufferSize := 0;
          raise;
        end;
      end;
      Result := True;
    finally
      Stream.Free;
    end;
  except
    on E: Exception do
      ErrorText := E.ClassName + ': ' + E.Message;
  end;
end;

function FindFirstDifference(A, B: PByte; Offset, Count: NativeUInt; out Diff: Int64): Boolean;
var
  I: NativeUInt;
begin
  Diff := -1;
  if Count = 0 then
    Exit(False);
  I := 0;
  while I < Count do
  begin
    if PByte(NativeUInt(A) + Offset + I)^ <> PByte(NativeUInt(B) + Offset + I)^ then
    begin
      Diff := Int64(Offset + I);
      Exit(True);
    end;
    Inc(I);
  end;
  Result := False;
end;

function CompareMappedRawRegions(RawBuffer: PByte; RawSize: NativeUInt; RoundTripBuffer: PByte;
  RoundTripSize: NativeUInt; out FirstDiff: Int64; out Detail: string): Boolean;
var
  HdrsSize, FirstRaw: NativeUInt;
  Count, I: NativeUInt;
  Sec: PImageSectionHeader;
  SecOffset, SecSize: NativeUInt;
  LocalDiff: Int64;
begin
  Result := False;
  FirstDiff := -1;
  Detail := '';
  HdrsSize := GetHdrsSize(RawBuffer);
  Count := GetSectionsCount(RawBuffer, RawSize);

  if HdrsSize = 0 then
  begin
    FirstRaw := 0;
    I := 0;
    while I < Count do
    begin
      Sec := GetSectionHdr(RawBuffer, RawSize, I);
      if Sec = nil then
      begin
        Detail := Format('section header %d unavailable during roundtrip compare', [I]);
        Exit;
      end;
      if (Sec.PointerToRawData <> 0) and
         ((FirstRaw = 0) or (NativeUInt(Sec.PointerToRawData) < FirstRaw)) then
        FirstRaw := Sec.PointerToRawData;
      Inc(I);
    end;
    HdrsSize := FirstRaw;
  end;

  if HdrsSize <> 0 then
  begin
    if not RangeWithin(RawSize, 0, HdrsSize) then
    begin
      Detail := 'original header range is invalid';
      Exit;
    end;
    if not RangeWithin(RoundTripSize, 0, HdrsSize) then
    begin
      Detail := Format('roundtrip header range missing: need=0x%x have=0x%x', [HdrsSize, RoundTripSize]);
      Exit;
    end;
    if FindFirstDifference(RawBuffer, RoundTripBuffer, 0, HdrsSize, LocalDiff) then
    begin
      FirstDiff := LocalDiff;
      Detail := Format('header bytes differ at raw offset 0x%x', [FirstDiff]);
      Exit;
    end;
  end;

  I := 0;
  while I < Count do
  begin
    Sec := GetSectionHdr(RawBuffer, RawSize, I);
    if Sec = nil then
    begin
      Detail := Format('section header %d unavailable during roundtrip compare', [I]);
      Exit;
    end;
    SecOffset := Sec.PointerToRawData;
    SecSize := Sec.SizeOfRawData;
    if SecSize <> 0 then
    begin
      if not RangeWithin(RawSize, SecOffset, SecSize) then
      begin
        Detail := Format('original section %d raw range invalid', [I]);
        Exit;
      end;
      if not RangeWithin(RoundTripSize, SecOffset, SecSize) then
      begin
        Detail := Format('roundtrip section %d raw range missing: offset=0x%x size=0x%x output=0x%x',
          [I, SecOffset, SecSize, RoundTripSize]);
        Exit;
      end;
      if FindFirstDifference(RawBuffer, RoundTripBuffer, SecOffset, SecSize, LocalDiff) then
      begin
        FirstDiff := LocalDiff;
        Detail := Format('section %d bytes differ at raw offset 0x%x', [I, FirstDiff]);
        Exit;
      end;
    end;
    Inc(I);
  end;
  Result := True;
end;


function CounterNow: Int64;
begin
  QueryPerformanceCounter(Result);
end;

function CounterElapsedUs(StartCounter: Int64): UInt64;
var
  StopCounter, Frequency, Delta: Int64;
begin
  QueryPerformanceCounter(StopCounter);
  QueryPerformanceFrequency(Frequency);
  Delta := StopCounter - StartCounter;
  if (Delta <= 0) or (Frequency <= 0) then
    Exit(0);
  Result := UInt64((Delta * 1000000) div Frequency);
  if Result = 0 then
    Result := 1;
end;

function CountDelayImports(ModulePtr: PByte; ModuleSize: NativeUInt;
  FirstDesc: PImageDelayloadDescriptor; DirSize: NativeUInt; out Count: NativeUInt): Boolean;
var
  MaxCount, I: NativeUInt;
  Desc: PImageDelayloadDescriptor;
  ImageBase, NameRva: UInt64;
  LibName: PAnsiChar;
begin
  Result := False;
  Count := 0;
  if FirstDesc = nil then
    Exit;
  MaxCount := DirSize div SizeOf(TImageDelayloadDescriptor);
  ImageBase := GetImageBase(ModulePtr);
  I := 0;
  while I < MaxCount do
  begin
    Desc := PImageDelayloadDescriptor(NativeUInt(FirstDesc) + I * SizeOf(TImageDelayloadDescriptor));
    if not ValidatePtr(ModulePtr, ModuleSize, Desc, SizeOf(TImageDelayloadDescriptor)) then
      Exit;
    if Desc.DllNameRVA = 0 then
      Exit(True);
    NameRva := Desc.DllNameRVA;
    if NameRva > ImageBase then
      NameRva := NameRva - ImageBase;
    if NameRva >= ModuleSize then
      Exit;
    LibName := PAnsiChar(NativeUInt(ModulePtr) + NativeUInt(NameRva));
    if not IsValidStringA(ModulePtr, ModuleSize, LibName) then
      Exit;
    Inc(Count);
    Inc(I);
  end;
  Result := MaxCount = 0;
end;

procedure WriteWorkerResult(const FileName: string; const AResult: TCorpusResult);
var
  Lines: TStringList;
begin
  Lines := TStringList.Create;
  try
    Lines.Values['schema'] := '6';
    Lines.Values['outcome'] := OutcomeToText(AResult.Outcome);
    Lines.Values['stage'] := OneLine(AResult.Stage);
    Lines.Values['message'] := OneLine(AResult.MessageText);
    Lines.Values['file_size'] := UIntToStr(AResult.FileSize);
    Lines.Values['architecture'] := AResult.Architecture;
    Lines.Values['image_base'] := UIntToStr(AResult.ImageBase);
    Lines.Values['entry_point'] := UIntToStr(AResult.EntryPoint);
    Lines.Values['sections'] := UIntToStr(AResult.SectionCount);
    Lines.Values['directories'] := UIntToStr(AResult.DirectoryCount);
    Lines.Values['map_ok'] := BoolToText(AResult.MapOk);
    Lines.Values['virtual_size'] := UIntToStr(AResult.VirtualSize);
    Lines.Values['imports_present'] := BoolToText(AResult.ImportsPresent);
    Lines.Values['imports_valid'] := BoolToText(AResult.ImportsValid);
    Lines.Values['imports_parsed'] := BoolToText(AResult.ImportsParsed);
    Lines.Values['imports'] := UIntToStr(AResult.ImportCount);
    Lines.Values['delay_imports_present'] := BoolToText(AResult.DelayImportsPresent);
    Lines.Values['delay_imports_valid'] := BoolToText(AResult.DelayImportsValid);
    Lines.Values['delay_imports'] := UIntToStr(AResult.DelayImportCount);
    Lines.Values['exports_present'] := BoolToText(AResult.ExportsPresent);
    Lines.Values['exports_parsed'] := BoolToText(AResult.ExportsParsed);
    Lines.Values['exports_count'] := UIntToStr(AResult.ExportCount);
    Lines.Values['tls_present'] := BoolToText(AResult.TlsPresent);
    Lines.Values['tls_parsed'] := BoolToText(AResult.TlsParsed);
    Lines.Values['tls_callbacks'] := UIntToStr(AResult.TlsCallbackCount);
    Lines.Values['tls_callbacks_valid'] := UIntToStr(AResult.TlsCallbackValidCount);
    Lines.Values['tls_callbacks_invalid'] := UIntToStr(AResult.TlsCallbackInvalidCount);
    Lines.Values['tls_callback_digest'] := AResult.TlsCallbackDigest;
    Lines.Values['tls_callback_preview'] := AResult.TlsCallbackPreview;
    Lines.Values['tls_callback_truncated'] := BoolToText(AResult.TlsCallbackTruncated);
    Lines.Values['tls_callback_first_valid_rva'] := AResult.TlsCallbackFirstValidRva;
    Lines.Values['tls_callback_last_valid_rva'] := AResult.TlsCallbackLastValidRva;
    Lines.Values['tls_index_rva'] := AResult.TlsIndexRva;
    Lines.Values['tls_raw_data'] := AResult.TlsRawData;
    Lines.Values['resources_present'] := BoolToText(AResult.ResourcesPresent);
    Lines.Values['resources_parsed'] := BoolToText(AResult.ResourcesParsed);
    Lines.Values['resources'] := UIntToStr(AResult.ResourceCount);
    Lines.Values['relocs_present'] := BoolToText(AResult.RelocsPresent);
    Lines.Values['relocs_valid'] := BoolToText(AResult.RelocsValid);
    Lines.Values['has_relocs'] := BoolToText(AResult.HasRelocs);
    Lines.Values['reloc_fields'] := UIntToStr(AResult.RelocFieldCount);
    Lines.Values['exceptions_present'] := BoolToText(AResult.ExceptionsPresent);
    Lines.Values['exceptions_parsed'] := BoolToText(AResult.ExceptionsParsed);
    Lines.Values['exceptions_count'] := UIntToStr(AResult.ExceptionCount);
    Lines.Values['exceptions_digest'] := AResult.ExceptionDigest;
    Lines.Values['load_config_present'] := BoolToText(AResult.LoadConfigPresent);
    Lines.Values['load_config_parsed'] := BoolToText(AResult.LoadConfigParsed);
    Lines.Values['load_config_version'] := IntToStr(AResult.LoadConfigVersion);
    Lines.Values['load_config_size'] := UIntToStr(AResult.LoadConfigSize);
    Lines.Values['security_cookie_rva'] := AResult.SecurityCookieRva;
    Lines.Values['is_dotnet'] := BoolToText(AResult.IsDotNetImage);
    Lines.Values['unmap_ok'] := BoolToText(AResult.UnmapOk);
    Lines.Values['raw_output_size'] := UIntToStr(AResult.RawOutputSize);
    Lines.Values['roundtrip_checked'] := BoolToText(AResult.RoundTripChecked);
    Lines.Values['roundtrip_equal'] := BoolToText(AResult.RoundTripEqual);
    Lines.Values['first_diff'] := IntToStr(AResult.FirstDiff);
    Lines.Values['library_elapsed_us'] := UIntToStr(AResult.LibraryElapsedUs);
    Lines.Values['core_elapsed_us'] := UIntToStr(AResult.CoreElapsedUs);
    Lines.Values['worker_elapsed_us'] := UIntToStr(AResult.WorkerElapsedUs);
    Lines.Values['elapsed_ms'] := UIntToStr(AResult.ElapsedMs);
    Lines.Values['complete'] := '1';
    Lines.SaveToFile(FileName, TEncoding.UTF8);
  finally
    Lines.Free;
  end;
end;

function ReadWorkerResult(const FileName: string; out AResult: TCorpusResult): Boolean;
var
  Lines: TStringList;
begin
  InitCorpusResult(AResult);
  Result := False;
  if not FileExists(FileName) then
    Exit;
  Lines := TStringList.Create;
  try
    Lines.LoadFromFile(FileName, TEncoding.UTF8);
    if (Lines.Values['schema'] <> '6') or (Lines.Values['complete'] <> '1') then
      Exit;
    AResult.Outcome := TextToOutcome(Lines.Values['outcome']);
    AResult.Stage := Lines.Values['stage'];
    AResult.MessageText := Lines.Values['message'];
    AResult.FileSize := TextToUInt64(Lines.Values['file_size']);
    AResult.Architecture := Lines.Values['architecture'];
    AResult.ImageBase := TextToUInt64(Lines.Values['image_base']);
    AResult.EntryPoint := DWORD(TextToUInt64(Lines.Values['entry_point']));
    AResult.SectionCount := NativeUInt(TextToUInt64(Lines.Values['sections']));
    AResult.DirectoryCount := NativeUInt(TextToUInt64(Lines.Values['directories']));
    AResult.MapOk := TextToBool(Lines.Values['map_ok']);
    AResult.VirtualSize := TextToUInt64(Lines.Values['virtual_size']);
    AResult.ImportsPresent := TextToBool(Lines.Values['imports_present']);
    AResult.ImportsValid := TextToBool(Lines.Values['imports_valid']);
    AResult.ImportsParsed := TextToBool(Lines.Values['imports_parsed']);
    AResult.ImportCount := NativeUInt(TextToUInt64(Lines.Values['imports']));
    AResult.DelayImportsPresent := TextToBool(Lines.Values['delay_imports_present']);
    AResult.DelayImportsValid := TextToBool(Lines.Values['delay_imports_valid']);
    AResult.DelayImportCount := NativeUInt(TextToUInt64(Lines.Values['delay_imports']));
    AResult.ExportsPresent := TextToBool(Lines.Values['exports_present']);
    AResult.ExportsParsed := TextToBool(Lines.Values['exports_parsed']);
    AResult.ExportCount := NativeUInt(TextToUInt64(Lines.Values['exports_count']));
    AResult.TlsPresent := TextToBool(Lines.Values['tls_present']);
    AResult.TlsParsed := TextToBool(Lines.Values['tls_parsed']);
    AResult.TlsCallbackCount := NativeUInt(TextToUInt64(Lines.Values['tls_callbacks']));
    AResult.TlsCallbackValidCount := NativeUInt(TextToUInt64(Lines.Values['tls_callbacks_valid']));
    AResult.TlsCallbackInvalidCount := NativeUInt(TextToUInt64(Lines.Values['tls_callbacks_invalid']));
    AResult.TlsCallbackDigest := Lines.Values['tls_callback_digest'];
    AResult.TlsCallbackPreview := Lines.Values['tls_callback_preview'];
    AResult.TlsCallbackTruncated := TextToBool(Lines.Values['tls_callback_truncated']);
    AResult.TlsCallbackFirstValidRva := Lines.Values['tls_callback_first_valid_rva'];
    AResult.TlsCallbackLastValidRva := Lines.Values['tls_callback_last_valid_rva'];
    AResult.TlsIndexRva := Lines.Values['tls_index_rva'];
    AResult.TlsRawData := Lines.Values['tls_raw_data'];
    AResult.ResourcesPresent := TextToBool(Lines.Values['resources_present']);
    AResult.ResourcesParsed := TextToBool(Lines.Values['resources_parsed']);
    AResult.ResourceCount := NativeUInt(TextToUInt64(Lines.Values['resources']));
    AResult.RelocsPresent := TextToBool(Lines.Values['relocs_present']);
    AResult.RelocsValid := TextToBool(Lines.Values['relocs_valid']);
    AResult.HasRelocs := TextToBool(Lines.Values['has_relocs']);
    AResult.RelocFieldCount := NativeUInt(TextToUInt64(Lines.Values['reloc_fields']));
    AResult.ExceptionsPresent := TextToBool(Lines.Values['exceptions_present']);
    AResult.ExceptionsParsed := TextToBool(Lines.Values['exceptions_parsed']);
    AResult.ExceptionCount := NativeUInt(TextToUInt64(Lines.Values['exceptions_count']));
    AResult.ExceptionDigest := Lines.Values['exceptions_digest'];
    AResult.LoadConfigPresent := TextToBool(Lines.Values['load_config_present']);
    AResult.LoadConfigParsed := TextToBool(Lines.Values['load_config_parsed']);
    AResult.LoadConfigVersion := StrToIntDef(Lines.Values['load_config_version'], LOAD_CONFIG_NONE);
    AResult.LoadConfigSize := DWORD(TextToUInt64(Lines.Values['load_config_size']));
    AResult.SecurityCookieRva := Lines.Values['security_cookie_rva'];
    AResult.IsDotNetImage := TextToBool(Lines.Values['is_dotnet']);
    AResult.UnmapOk := TextToBool(Lines.Values['unmap_ok']);
    AResult.RawOutputSize := TextToUInt64(Lines.Values['raw_output_size']);
    AResult.RoundTripChecked := TextToBool(Lines.Values['roundtrip_checked']);
    AResult.RoundTripEqual := TextToBool(Lines.Values['roundtrip_equal']);
    AResult.FirstDiff := StrToInt64Def(Lines.Values['first_diff'], -1);
    AResult.LibraryElapsedUs := TextToUInt64(Lines.Values['library_elapsed_us']);
    AResult.CoreElapsedUs := TextToUInt64(Lines.Values['core_elapsed_us']);
    AResult.WorkerElapsedUs := TextToUInt64(Lines.Values['worker_elapsed_us']);
    AResult.ElapsedMs := TextToUInt64(Lines.Values['elapsed_ms']);
    Result := True;
  finally
    Lines.Free;
  end;
end;

function RunWorker(const InputFile, ResultFile: string): Integer;
var
  R: TCorpusResult;
  WorkerStart, CoreStart, LibraryStart: Int64;
  CoreStarted, LibraryStarted, FatalException: Boolean;
  CurrentStage: string;
  Raw: TUnalignedBuf;
  RawSize: NativeUInt;
  VirtualPe, RoundTrip: TAlignedBuf;
  VirtualSize, RoundTripSize: NativeUInt;
  I: NativeUInt;
  Dir: PImageDataDirectory;
  RoundTripDetail: string;
  Imports: TImportsCollection;
  ExportNames: TList<string>;
  TlsCallbacks: TList<UInt64>;
  RelocCounter: TCountRelocCallback;
  DelaySize: NativeUInt;
  Delayed: PImageDelayloadDescriptor;
  ReadError: string;
begin
  InitCorpusResult(R);
  R.FileName := InputFile;
  WorkerStart := CounterNow;
  CoreStart := 0;
  LibraryStart := 0;
  CoreStarted := False;
  LibraryStarted := False;
  FatalException := False;
  Raw := nil;
  VirtualPe := nil;
  RoundTrip := nil;
  RawSize := 0;
  VirtualSize := 0;
  RoundTripSize := 0;
  CurrentStage := 'load';

  try
    try
      WriteStageMarker(ResultFile, CurrentStage);
      if not ReadRawFile(InputFile, Raw, RawSize, ReadError) then
      begin
        R.Outcome := coFail;
        R.Stage := 'load';
        R.MessageText := ReadError;
        Exit(1);
      end;
      R.FileSize := RawSize;

      CoreStart := CounterNow;
      CoreStarted := True;
      CurrentStage := 'identify';
      WriteStageMarker(ResultFile, CurrentStage);
      if not IsMzBuffer(Raw, RawSize) then
      begin
        R.Outcome := coSkip;
        R.Stage := 'identify';
        R.MessageText := 'not an MZ image';
        Exit(0);
      end;

      R.Outcome := coPass;
      R.Stage := 'map';
      CurrentStage := 'map';
      WriteStageMarker(ResultFile, CurrentStage);
      LibraryStart := CounterNow;
      LibraryStarted := True;
      VirtualPe := LoadPeModule(Raw, RawSize, VirtualSize, False, False);
      R.VirtualSize := VirtualSize;
      if VirtualPe = nil then
      begin
        R.LibraryElapsedUs := CounterElapsedUs(LibraryStart);
        MarkReject(R, 'map', 'LoadPeModule returned nil');
        Exit(0);
      end;
      R.MapOk := True;

      CurrentStage := 'metadata';
      WriteStageMarker(ResultFile, CurrentStage);
      if Is64Bit(VirtualPe) then
        R.Architecture := 'PE64'
      else
        R.Architecture := 'PE32';
      R.ImageBase := GetImageBase(VirtualPe);
      R.EntryPoint := GetEntryPointRva(VirtualPe);
      R.SectionCount := GetSectionsCount(VirtualPe, VirtualSize);

      CurrentStage := 'directories';
      WriteStageMarker(ResultFile, CurrentStage);
      I := 0;
      while I < IMAGE_NUMBEROF_DIRECTORY_ENTRIES do
      begin
        if GetDirectoryEntry(VirtualPe, DWORD(I)) <> nil then
          Inc(R.DirectoryCount);
        Inc(I);
      end;
      R.IsDotNetImage := IsDotNet(VirtualPe, VirtualSize);

      CurrentStage := 'imports';
      WriteStageMarker(ResultFile, CurrentStage);
      Dir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_IMPORT);
      R.ImportsPresent := Dir <> nil;
      if R.ImportsPresent then
      begin
        R.ImportsValid := HasValidImportTable(VirtualPe, VirtualSize, 0, CORPUS_STRICT_IMPORT_DIRECTORY_SIZE);
        if not R.ImportsValid then
          MarkReject(R, 'imports', 'import directory is present but malformed')
        else
        begin
          Imports := TImportsCollection.Create;
          try
            R.ImportsParsed := CollectImports(VirtualPe, VirtualSize, Imports);
            if R.ImportsParsed then
              R.ImportCount := Imports.ThunkToFunc.Count
            else
              MarkReject(R, 'imports', 'CollectImports returned False');
          finally
            Imports.Free;
          end;
        end;
      end;

      CurrentStage := 'delay-imports';
      WriteStageMarker(ResultFile, CurrentStage);
      Dir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
      R.DelayImportsPresent := Dir <> nil;
      if R.DelayImportsPresent then
      begin
        DelaySize := 0;
        Delayed := GetDelayedImps(VirtualPe, VirtualSize, DelaySize);
        R.DelayImportsValid := (Delayed <> nil) and
          CountDelayImports(VirtualPe, VirtualSize, Delayed, DelaySize, R.DelayImportCount);
        if not R.DelayImportsValid then
          MarkReject(R, 'delay-imports', 'delay import directory is present but invalid');
      end;

      CurrentStage := 'exports';
      WriteStageMarker(ResultFile, CurrentStage);
      Dir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_EXPORT);
      R.ExportsPresent := Dir <> nil;
      if R.ExportsPresent then
      begin
        ExportNames := TList<string>.Create;
        try
          R.ExportCount := GetExportedNames(VirtualPe, ExportNames);
          R.ExportsParsed := True;
        finally
          ExportNames.Free;
        end;
      end;

      CurrentStage := 'tls';
      WriteStageMarker(ResultFile, CurrentStage);
      Dir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_TLS);
      R.TlsPresent := Dir <> nil;
      if R.TlsPresent then
      begin
        TlsCallbacks := TList<UInt64>.Create;
        try
          R.TlsCallbackCount := ListTlsCallbacks(VirtualPe, VirtualSize, TlsCallbacks);
          R.TlsCallbackPreview := BuildTlsDetails(VirtualPe, VirtualSize, TlsCallbacks, R.TlsIndexRva, R.TlsRawData,
            R.TlsCallbackDigest, R.TlsCallbackFirstValidRva, R.TlsCallbackLastValidRva, R.TlsCallbackValidCount,
            R.TlsCallbackInvalidCount, R.TlsCallbackTruncated);
          R.TlsParsed := R.TlsIndexRva <> '';
          if not R.TlsParsed then
            MarkReject(R, 'tls', 'tls directory is present but malformed');
        finally
          TlsCallbacks.Free;
        end;
      end;

      CurrentStage := 'exceptions';
      WriteStageMarker(ResultFile, CurrentStage);
      R.ExceptionsPresent := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_EXCEPTION) <> nil;
      if R.ExceptionsPresent then
      begin
        R.ExceptionsParsed := ParseExceptionDetails(VirtualPe, VirtualSize, R.ExceptionCount, R.ExceptionDigest);
        if not R.ExceptionsParsed then
          MarkReject(R, 'exceptions', 'exception directory is present but malformed');
      end;

      CurrentStage := 'load-config';
      WriteStageMarker(ResultFile, CurrentStage);
      ReadLoadConfigDetails(VirtualPe, VirtualSize, R);
      if R.LoadConfigPresent and not R.LoadConfigParsed then
        MarkReject(R, 'load-config', 'load config directory is present but malformed');

      CurrentStage := 'resources';
      WriteStageMarker(ResultFile, CurrentStage);
      Dir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_RESOURCE);
      R.ResourcesPresent := Dir <> nil;
      if R.ResourcesPresent then
      begin
        GResourceCount := 0;
        R.ResourcesParsed := ParseResources(VirtualPe, CountResourceEntry);
        R.ResourceCount := GResourceCount;
        if not R.ResourcesParsed then
          MarkReject(R, 'resources', 'resource directory is present but parsing failed');
      end;

      CurrentStage := 'relocations';
      WriteStageMarker(ResultFile, CurrentStage);
      Dir := GetDirectoryEntry(VirtualPe, IMAGE_DIRECTORY_ENTRY_BASERELOC);
      R.RelocsPresent := Dir <> nil;
      R.HasRelocs := R.RelocsPresent;
      if R.RelocsPresent then
      begin
        R.RelocsValid := HasValidRelocationTable(VirtualPe, VirtualSize);
        if R.RelocsValid then
        begin
          RelocCounter := TCountRelocCallback.Create(Is64Bit(VirtualPe));
          try
            if ProcessRelocationTable(VirtualPe, VirtualSize, RelocCounter) then
              R.RelocFieldCount := RelocCounter.Count;
          finally
            RelocCounter.Free;
          end;
        end;
        if not R.RelocsValid then
          MarkReject(R, 'relocations', 'relocation directory is present but malformed');
      end;

      CurrentStage := 'roundtrip';
      WriteStageMarker(ResultFile, CurrentStage);
      R.RoundTripChecked := True;
      RoundTrip := PeVirtualToRaw(VirtualPe, VirtualSize, GetImageBase(VirtualPe), RoundTripSize, True);
      R.RawOutputSize := RoundTripSize;
      R.LibraryElapsedUs := CounterElapsedUs(LibraryStart);
      if RoundTrip = nil then
      begin
        MarkReject(R, 'roundtrip', 'PeVirtualToRaw returned nil');
        R.RoundTripEqual := False;
      end
      else
      begin
        R.UnmapOk := True;
        CurrentStage := 'roundtrip-compare';
        WriteStageMarker(ResultFile, CurrentStage);
        R.RoundTripEqual := CompareMappedRawRegions(Raw, RawSize, RoundTrip, RoundTripSize,
          R.FirstDiff, RoundTripDetail);
        if not R.RoundTripEqual then
        begin
          if (R.Outcome = coReject) or
             (Pos('range missing:', RoundTripDetail) > 0) or
             (RoundTripDetail = 'original header range is invalid') or
             ((Pos('original section ', RoundTripDetail) = 1) and
              (Pos(' raw range invalid', RoundTripDetail) > 0)) then
            MarkReject(R, 'roundtrip', RoundTripDetail)
          else
          begin
            R.Outcome := coFail;
            R.Stage := 'roundtrip';
            R.MessageText := RoundTripDetail;
          end;
        end;
      end;

      if R.Outcome = coPass then
      begin
        R.Stage := 'complete';
        if R.MessageText = '' then
          R.MessageText := 'all library stages passed'
        else
          R.MessageText := 'all library stages passed | ' + R.MessageText;
      end;
      Result := 0;
    except
      on E: Exception do
      begin
        if E is EExternal then
        begin
          FatalException := True;
          raise;
        end;
        R.Outcome := coFail;
        R.Stage := CurrentStage;
        R.MessageText := E.ClassName + ': ' + E.Message;
        Result := 1;
      end;
    end;
  finally
    if not FatalException then
    begin
      if RoundTrip <> nil then
      begin
        CurrentStage := 'free-roundtrip';
        WriteStageMarker(ResultFile, CurrentStage);
        FreePeBuffer(RoundTrip, RoundTripSize);
      end;
      if VirtualPe <> nil then
      begin
        CurrentStage := 'free-map';
        WriteStageMarker(ResultFile, CurrentStage);
        FreePeBuffer(VirtualPe, VirtualSize);
      end;
      if Raw <> nil then
        FreeMem(Raw);
    end;
    if LibraryStarted and (R.LibraryElapsedUs = 0) then
      R.LibraryElapsedUs := CounterElapsedUs(LibraryStart);
    if CoreStarted then
      R.CoreElapsedUs := CounterElapsedUs(CoreStart);
    R.WorkerElapsedUs := CounterElapsedUs(WorkerStart);
    R.ElapsedMs := R.WorkerElapsedUs div 1000;
    if not FatalException then
    begin
      ForceDirectories(ExtractFileDir(ResultFile));
      WriteWorkerResult(ResultFile, R);
    end;
  end;
end;

function QuoteArg(const S: string): string;
begin
  Result := '"' + StringReplace(S, '"', '""', [rfReplaceAll]) + '"';
end;

function RunWorkerProcess(const InputFile, ResultFile: string; TimeoutMs: DWORD;
  out ExitCode: DWORD; out TimedOut: Boolean; out WallElapsedUs: UInt64): Boolean;
var
  StartupInfo: TStartupInfo;
  ProcessInfo: TProcessInformation;
  CmdLine: string;
  WaitResult: DWORD;
  WallStart: Int64;
begin
  Result := False;
  ExitCode := 0;
  TimedOut := False;
  WallElapsedUs := 0;
  ZeroMemory(@StartupInfo, SizeOf(StartupInfo));
  ZeroMemory(@ProcessInfo, SizeOf(ProcessInfo));
  StartupInfo.cb := SizeOf(StartupInfo);

  CmdLine := QuoteArg(ParamStr(0)) + ' --worker ' + QuoteArg(InputFile) + ' ' + QuoteArg(ResultFile);
  UniqueString(CmdLine);
  WallStart := CounterNow;
  if not CreateProcess(nil, PChar(CmdLine), nil, nil, False, CREATE_NO_WINDOW, nil, nil,
    StartupInfo, ProcessInfo) then
  begin
    WallElapsedUs := CounterElapsedUs(WallStart);
    Exit;
  end;
  try
    WaitResult := WaitForSingleObject(ProcessInfo.hProcess, TimeoutMs);
    if WaitResult = WAIT_TIMEOUT then
    begin
      TimedOut := True;
      TerminateProcess(ProcessInfo.hProcess, $DEAD);
      WaitForSingleObject(ProcessInfo.hProcess, 5000);
    end;
    GetExitCodeProcess(ProcessInfo.hProcess, ExitCode);
    WallElapsedUs := CounterElapsedUs(WallStart);
    Result := True;
  finally
    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
  end;
end;

procedure EnumerateFiles(const Root: string; Files: TStrings);
var
  Search: TSearchRec;
  BasePath, FullPath: string;
begin
  BasePath := IncludeTrailingPathDelimiter(Root);
  if FindFirst(BasePath + '*', faAnyFile, Search) <> 0 then
    Exit;
  try
    repeat
      if (Search.Name = '.') or (Search.Name = '..') then
        Continue;
      FullPath := BasePath + Search.Name;
      if (Search.Attr and faDirectory) <> 0 then
      begin
        if (Length(Search.Name) > 0) and (Search.Name[1] = '.') then
          Continue;

        if (Search.FindData.dwFileAttributes and FILE_ATTRIBUTE_REPARSE_POINT) = 0 then
          EnumerateFiles(FullPath, Files);
      end
      else
        Files.Add(FullPath);
    until FindNext(Search) <> 0;
  finally
    System.SysUtils.FindClose(Search);
  end;
end;

function GetPathFileSize(const FileName: string; out FileSize: Int64): Boolean;
var
  Search: TSearchRec;
begin
  FileSize := 0;
  Result := FindFirst(FileName, faAnyFile, Search) = 0;
  if not Result then
    Exit;
  try
    FileSize := Search.Size;
  finally
    System.SysUtils.FindClose(Search);
  end;
end;

function MakeRelativePath(const Root, FileName: string): string;
var
  Prefix: string;
begin
  Prefix := IncludeTrailingPathDelimiter(ExpandFileName(Root));
  Result := ExpandFileName(FileName);
  if SameText(Copy(Result, 1, Length(Prefix)), Prefix) then
    Delete(Result, 1, Length(Prefix));
end;

function IsAllowedCorpusRootName(const Name: string): Boolean;
begin
  Result := SameText(Name, 'System32') or
            SameText(Name, 'SysWOW64') or
            SameText(Name, 'bintests-master') or
            SameText(Name, 'pocs-master');
end;

function HasNamedCorpusRoots(const Root: string): Boolean;
begin
  Result := DirectoryExists(IncludeTrailingPathDelimiter(Root) + 'System32') or
            DirectoryExists(IncludeTrailingPathDelimiter(Root) + 'SysWOW64') or
            DirectoryExists(IncludeTrailingPathDelimiter(Root) + 'bintests-master') or
            DirectoryExists(IncludeTrailingPathDelimiter(Root) + 'pocs-master');
end;

function IsAllowedCorpusPath(const Root, FileName: string): Boolean;
var
  RelativeName, RootName: string;
  SepPos: Integer;
begin
  RelativeName := MakeRelativePath(Root, FileName);
  SepPos := Pos(PathDelim, RelativeName);
  if SepPos = 0 then
    RootName := RelativeName
  else
    RootName := Copy(RelativeName, 1, SepPos - 1);
  Result := IsAllowedCorpusRootName(RootName);
end;

procedure EnumerateCorpusFiles(const Root: string; Files: TStrings);
var
  BasePath, SubDir: string;
  Names: array[0..3] of string;
  I: Integer;
begin
  if not HasNamedCorpusRoots(Root) then
  begin
    EnumerateFiles(Root, Files);
    Exit;
  end;

  Names[0] := 'System32';
  Names[1] := 'SysWOW64';
  Names[2] := 'bintests-master';
  Names[3] := 'pocs-master';
  BasePath := IncludeTrailingPathDelimiter(Root);

  I := Low(Names);
  while I <= High(Names) do
  begin
    SubDir := BasePath + Names[I];
    if DirectoryExists(SubDir) then
      EnumerateFiles(SubDir, Files);
    Inc(I);
  end;
end;

function LoadCorpusFileList(const Root, ListFile: string; Files: TStrings): Boolean;
var
  Lines, Seen: TStringList;
  I: Integer;
  RelativeName, FullName, RootPrefix: string;
  RestrictToCorpusRoots: Boolean;
begin
  Result := False;
  if not FileExists(ListFile) then
    Exit;

  RootPrefix := IncludeTrailingPathDelimiter(ExpandFileName(Root));
  RestrictToCorpusRoots := HasNamedCorpusRoots(Root);
  Lines := TStringList.Create;
  Seen := TStringList.Create;
  try
    Seen.Sorted := True;
    Seen.CaseSensitive := False;
    Seen.Duplicates := dupIgnore;
    Lines.LoadFromFile(ListFile, TEncoding.UTF8);
    I := 0;
    while I < Lines.Count do
    begin
      RelativeName := Trim(Lines[I]);
      if RelativeName <> '' then
      begin
        RelativeName := StringReplace(RelativeName, '/', PathDelim, [rfReplaceAll]);
        FullName := ExpandFileName(RootPrefix + RelativeName);
        if SameText(Copy(FullName, 1, Length(RootPrefix)), RootPrefix) and
           ((not RestrictToCorpusRoots) or IsAllowedCorpusPath(Root, FullName)) and
           (Seen.IndexOf(FullName) < 0) then
        begin
          Seen.Add(FullName);
          Files.Add(FullName);
        end;
      end;
      Inc(I);
    end;
    Result := True;
  finally
    Seen.Free;
    Lines.Free;
  end;
end;

function CsvEscape(const S: string): string;
begin
  Result := '"' + StringReplace(S, '"', '""', [rfReplaceAll]) + '"';
end;

function JsonEscape(const S: string): string;
var
  I: Integer;
  C: Char;
begin
  Result := '';
  I := 1;
  while I <= Length(S) do
  begin
    C := S[I];
    case C of
      '"': Result := Result + '\"';
      '\': Result := Result + '\\';
      #8: Result := Result + '\b';
      #9: Result := Result + '\t';
      #10: Result := Result + '\n';
      #12: Result := Result + '\f';
      #13: Result := Result + '\r';
    else
      if Ord(C) < 32 then
        Result := Result + '\u' + IntToHex(Ord(C), 4)
      else
        Result := Result + C;
    end;
    Inc(I);
  end;
end;

procedure SaveReports(const Results: TList<TCorpusResult>; const Root, ResultsDir, Stamp: string;
  out LogPath, CsvPath, JsonPath: string);
var
  LogLines, CsvLines, JsonLines: TStringList;
  R: TCorpusResult;
  I: Integer;
  PassCount, RejectCount, FailCount, CrashCount, TimeoutCount, SkipCount: Integer;
  Line: string;
begin
  ForceDirectories(ResultsDir);
  LogPath := IncludeTrailingPathDelimiter(ResultsDir) + 'NativePeCorpus-' + Stamp + '.log';
  CsvPath := IncludeTrailingPathDelimiter(ResultsDir) + 'NativePeCorpus-' + Stamp + '.csv';
  JsonPath := IncludeTrailingPathDelimiter(ResultsDir) + 'NativePeCorpus-' + Stamp + '.json';

  LogLines := TStringList.Create;
  CsvLines := TStringList.Create;
  JsonLines := TStringList.Create;
  try
    PassCount := 0;
    RejectCount := 0;
    FailCount := 0;
    CrashCount := 0;
    TimeoutCount := 0;
    SkipCount := 0;

    LogLines.Add('NativePe Corpus Differential Probe v6');
    LogLines.Add('Root=' + Root);
    LogLines.Add('Generated=' + DateTimeToStr(Now));
    if CORPUS_STRICT_IMPORT_DIRECTORY_SIZE then
      LogLines.Add('ImportValidationMode=StrictDirectorySize')
    else
      LogLines.Add('ImportValidationMode=CompatibleNullTerminated');
    LogLines.Add('');

    CsvLines.Add('outcome,file,stage,message,fileSize,architecture,imageBase,entryPoint,sections,directories,mapOk,virtualSize,importsPresent,importsValid,importsParsed,imports,delayImportsPresent,delayImportsValid,delayImports,exportsPresent,exportsParsed,exports,tlsPresent,tlsParsed,tlsCallbacks,tlsCallbacksValid,tlsCallbacksInvalid,tlsCallbackDigest,tlsCallbackPreview,tlsCallbackTruncated,tlsCallbackFirstValidRva,tlsCallbackLastValidRva,tlsIndexRva,tlsRawData,resourcesPresent,resourcesParsed,resources,relocsPresent,relocsValid,relocFields,exceptionsPresent,exceptionsParsed,exceptionsCount,exceptionsDigest,loadConfigPresent,loadConfigParsed,loadConfigVersion,loadConfigSize,securityCookieRva,isDotNet,unmapOk,rawOutputSize,roundTripChecked,roundTripEqual,firstDiff,libraryElapsedUs,coreElapsedUs,workerElapsedUs,wallElapsedUs,elapsedMs,processExitCode');

    JsonLines.Add('{');
    JsonLines.Add('  "schemaVersion": 6,');
    JsonLines.Add('  "harness": "NativePe",');
    JsonLines.Add('  "buildConfig": "' + BuildConfiguration + '",');
    JsonLines.Add('  "optimized": ' + LowerCase(BoolToStr(BuildOptimized, True)) + ',');
    JsonLines.Add('  "processBits": ' + IntToStr(SizeOf(Pointer) * 8) + ',');
    JsonLines.Add('  "timerUnit": "microseconds",');
    if CORPUS_STRICT_IMPORT_DIRECTORY_SIZE then
      JsonLines.Add('  "importValidationMode": "strict-directory-size",')
    else
      JsonLines.Add('  "importValidationMode": "compatible-null-terminated",');
    JsonLines.Add('  "timingModel": "library=direct LoadPeModule through PeVirtualToRaw return excluding roundtrip compare; core=post-read library probe; worker=worker entry through cleanup; wall=CreateProcess through worker exit",');
    JsonLines.Add('  "root": "' + JsonEscape(Root) + '",');
    JsonLines.Add('  "generated": "' + JsonEscape(FormatDateTime('yyyy-mm-dd"T"hh:nn:ss', Now)) + '",');
    JsonLines.Add('  "results": [');

    I := 0;
    while I < Results.Count do
    begin
      R := Results[I];
      case R.Outcome of
        coPass: Inc(PassCount);
        coReject: Inc(RejectCount);
        coFail: Inc(FailCount);
        coCrash: Inc(CrashCount);
        coTimeout: Inc(TimeoutCount);
        coSkip: Inc(SkipCount);
      end;

      Line := OutcomeToText(R.Outcome) + '  ' + R.FileName;
      if R.Stage <> '' then
        Line := Line + '  stage=' + R.Stage;
      if R.MessageText <> '' then
        Line := Line + '  ' + R.MessageText;
      Line := Line + '  imports=' + UIntToStr(R.ImportCount) +
        ' exports=' + UIntToStr(R.ExportCount) +
        ' tls=' + UIntToStr(R.TlsCallbackCount) +
        ' resources=' + UIntToStr(R.ResourceCount);
      if R.RelocsValid then
        Line := Line + ' relocs=valid'
      else if R.RelocsPresent then
        Line := Line + ' relocs=invalid'
      else
        Line := Line + ' relocs=absent';
      LogLines.Add(Line);

      CsvLines.Add(
        CsvEscape(OutcomeToText(R.Outcome)) + ',' +
        CsvEscape(R.FileName) + ',' +
        CsvEscape(R.Stage) + ',' +
        CsvEscape(R.MessageText) + ',' +
        UIntToStr(R.FileSize) + ',' +
        CsvEscape(R.Architecture) + ',' +
        CsvEscape('0x' + IntToHex(Int64(R.ImageBase), 16)) + ',' +
        CsvEscape('0x' + IntToHex(R.EntryPoint, 8)) + ',' +
        UIntToStr(R.SectionCount) + ',' +
        UIntToStr(R.DirectoryCount) + ',' +
        LowerCase(BoolToStr(R.MapOk, True)) + ',' +
        UIntToStr(R.VirtualSize) + ',' +
        LowerCase(BoolToStr(R.ImportsPresent, True)) + ',' +
        LowerCase(BoolToStr(R.ImportsValid, True)) + ',' +
        LowerCase(BoolToStr(R.ImportsParsed, True)) + ',' +
        UIntToStr(R.ImportCount) + ',' +
        LowerCase(BoolToStr(R.DelayImportsPresent, True)) + ',' +
        LowerCase(BoolToStr(R.DelayImportsValid, True)) + ',' +
        UIntToStr(R.DelayImportCount) + ',' +
        LowerCase(BoolToStr(R.ExportsPresent, True)) + ',' +
        LowerCase(BoolToStr(R.ExportsParsed, True)) + ',' +
        UIntToStr(R.ExportCount) + ',' +
        LowerCase(BoolToStr(R.TlsPresent, True)) + ',' +
        LowerCase(BoolToStr(R.TlsParsed, True)) + ',' +
        UIntToStr(R.TlsCallbackCount) + ',' +
        UIntToStr(R.TlsCallbackValidCount) + ',' +
        UIntToStr(R.TlsCallbackInvalidCount) + ',' +
        CsvEscape(R.TlsCallbackDigest) + ',' +
        CsvEscape(R.TlsCallbackPreview) + ',' +
        LowerCase(BoolToStr(R.TlsCallbackTruncated, True)) + ',' +
        CsvEscape(R.TlsCallbackFirstValidRva) + ',' +
        CsvEscape(R.TlsCallbackLastValidRva) + ',' +
        CsvEscape(R.TlsIndexRva) + ',' +
        CsvEscape(R.TlsRawData) + ',' +
        LowerCase(BoolToStr(R.ResourcesPresent, True)) + ',' +
        LowerCase(BoolToStr(R.ResourcesParsed, True)) + ',' +
        UIntToStr(R.ResourceCount) + ',' +
        LowerCase(BoolToStr(R.RelocsPresent, True)) + ',' +
        LowerCase(BoolToStr(R.RelocsValid, True)) + ',' +
        UIntToStr(R.RelocFieldCount) + ',' +
        LowerCase(BoolToStr(R.ExceptionsPresent, True)) + ',' +
        LowerCase(BoolToStr(R.ExceptionsParsed, True)) + ',' +
        UIntToStr(R.ExceptionCount) + ',' +
        CsvEscape(R.ExceptionDigest) + ',' +
        LowerCase(BoolToStr(R.LoadConfigPresent, True)) + ',' +
        LowerCase(BoolToStr(R.LoadConfigParsed, True)) + ',' +
        IntToStr(R.LoadConfigVersion) + ',' +
        UIntToStr(R.LoadConfigSize) + ',' +
        CsvEscape(R.SecurityCookieRva) + ',' +
        LowerCase(BoolToStr(R.IsDotNetImage, True)) + ',' +
        LowerCase(BoolToStr(R.UnmapOk, True)) + ',' +
        UIntToStr(R.RawOutputSize) + ',' +
        LowerCase(BoolToStr(R.RoundTripChecked, True)) + ',' +
        LowerCase(BoolToStr(R.RoundTripEqual, True)) + ',' +
        IntToStr(R.FirstDiff) + ',' +
        UIntToStr(R.LibraryElapsedUs) + ',' +
        UIntToStr(R.CoreElapsedUs) + ',' +
        UIntToStr(R.WorkerElapsedUs) + ',' +
        UIntToStr(R.WallElapsedUs) + ',' +
        UIntToStr(R.ElapsedMs) + ',' +
        UIntToStr(R.ProcessExitCode)
      );

      JsonLines.Add('    {');
      JsonLines.Add('      "outcome": "' + JsonEscape(OutcomeToText(R.Outcome)) + '",');
      JsonLines.Add('      "file": "' + JsonEscape(R.FileName) + '",');
      JsonLines.Add('      "stage": "' + JsonEscape(R.Stage) + '",');
      JsonLines.Add('      "message": "' + JsonEscape(R.MessageText) + '",');
      JsonLines.Add('      "fileSize": ' + UIntToStr(R.FileSize) + ',');
      JsonLines.Add('      "architecture": "' + JsonEscape(R.Architecture) + '",');
      JsonLines.Add('      "imageBase": "0x' + IntToHex(Int64(R.ImageBase), 16) + '",');
      JsonLines.Add('      "entryPoint": "0x' + IntToHex(R.EntryPoint, 8) + '",');
      JsonLines.Add('      "sections": ' + UIntToStr(R.SectionCount) + ',');
      JsonLines.Add('      "directories": ' + UIntToStr(R.DirectoryCount) + ',');
      JsonLines.Add('      "mapOk": ' + LowerCase(BoolToStr(R.MapOk, True)) + ',');
      JsonLines.Add('      "virtualSize": ' + UIntToStr(R.VirtualSize) + ',');
      JsonLines.Add('      "importsPresent": ' + LowerCase(BoolToStr(R.ImportsPresent, True)) + ',');
      JsonLines.Add('      "importsValid": ' + LowerCase(BoolToStr(R.ImportsValid, True)) + ',');
      JsonLines.Add('      "importsParsed": ' + LowerCase(BoolToStr(R.ImportsParsed, True)) + ',');
      JsonLines.Add('      "imports": ' + UIntToStr(R.ImportCount) + ',');
      JsonLines.Add('      "delayImportsPresent": ' + LowerCase(BoolToStr(R.DelayImportsPresent, True)) + ',');
      JsonLines.Add('      "delayImportsValid": ' + LowerCase(BoolToStr(R.DelayImportsValid, True)) + ',');
      JsonLines.Add('      "delayImports": ' + UIntToStr(R.DelayImportCount) + ',');
      JsonLines.Add('      "exportsPresent": ' + LowerCase(BoolToStr(R.ExportsPresent, True)) + ',');
      JsonLines.Add('      "exportsParsed": ' + LowerCase(BoolToStr(R.ExportsParsed, True)) + ',');
      JsonLines.Add('      "exports": ' + UIntToStr(R.ExportCount) + ',');
      JsonLines.Add('      "tlsPresent": ' + LowerCase(BoolToStr(R.TlsPresent, True)) + ',');
      JsonLines.Add('      "tlsParsed": ' + LowerCase(BoolToStr(R.TlsParsed, True)) + ',');
      JsonLines.Add('      "tlsCallbacks": ' + UIntToStr(R.TlsCallbackCount) + ',');
      JsonLines.Add('      "tlsCallbacksValid": ' + UIntToStr(R.TlsCallbackValidCount) + ',');
      JsonLines.Add('      "tlsCallbacksInvalid": ' + UIntToStr(R.TlsCallbackInvalidCount) + ',');
      JsonLines.Add('      "tlsCallbackDigest": "' + JsonEscape(R.TlsCallbackDigest) + '",');
      JsonLines.Add('      "tlsCallbackPreview": "' + JsonEscape(R.TlsCallbackPreview) + '",');
      JsonLines.Add('      "tlsCallbackTruncated": ' + LowerCase(BoolToStr(R.TlsCallbackTruncated, True)) + ',');
      JsonLines.Add('      "tlsCallbackFirstValidRva": "' + JsonEscape(R.TlsCallbackFirstValidRva) + '",');
      JsonLines.Add('      "tlsCallbackLastValidRva": "' + JsonEscape(R.TlsCallbackLastValidRva) + '",');
      JsonLines.Add('      "tlsIndexRva": "' + JsonEscape(R.TlsIndexRva) + '",');
      JsonLines.Add('      "tlsRawData": "' + JsonEscape(R.TlsRawData) + '",');
      JsonLines.Add('      "resourcesPresent": ' + LowerCase(BoolToStr(R.ResourcesPresent, True)) + ',');
      JsonLines.Add('      "resourcesParsed": ' + LowerCase(BoolToStr(R.ResourcesParsed, True)) + ',');
      JsonLines.Add('      "resources": ' + UIntToStr(R.ResourceCount) + ',');
      JsonLines.Add('      "relocsPresent": ' + LowerCase(BoolToStr(R.RelocsPresent, True)) + ',');
      JsonLines.Add('      "relocsValid": ' + LowerCase(BoolToStr(R.RelocsValid, True)) + ',');
      JsonLines.Add('      "hasRelocs": ' + LowerCase(BoolToStr(R.HasRelocs, True)) + ',');
      JsonLines.Add('      "relocFields": ' + UIntToStr(R.RelocFieldCount) + ',');
      JsonLines.Add('      "exceptionsPresent": ' + LowerCase(BoolToStr(R.ExceptionsPresent, True)) + ',');
      JsonLines.Add('      "exceptionsParsed": ' + LowerCase(BoolToStr(R.ExceptionsParsed, True)) + ',');
      JsonLines.Add('      "exceptionsCount": ' + UIntToStr(R.ExceptionCount) + ',');
      JsonLines.Add('      "exceptionsDigest": "' + JsonEscape(R.ExceptionDigest) + '",');
      JsonLines.Add('      "loadConfigPresent": ' + LowerCase(BoolToStr(R.LoadConfigPresent, True)) + ',');
      JsonLines.Add('      "loadConfigParsed": ' + LowerCase(BoolToStr(R.LoadConfigParsed, True)) + ',');
      JsonLines.Add('      "loadConfigVersion": ' + IntToStr(R.LoadConfigVersion) + ',');
      JsonLines.Add('      "loadConfigSize": ' + UIntToStr(R.LoadConfigSize) + ',');
      JsonLines.Add('      "securityCookieRva": "' + JsonEscape(R.SecurityCookieRva) + '",');
      JsonLines.Add('      "isDotNet": ' + LowerCase(BoolToStr(R.IsDotNetImage, True)) + ',');
      JsonLines.Add('      "unmapOk": ' + LowerCase(BoolToStr(R.UnmapOk, True)) + ',');
      JsonLines.Add('      "rawOutputSize": ' + UIntToStr(R.RawOutputSize) + ',');
      JsonLines.Add('      "roundTripChecked": ' + LowerCase(BoolToStr(R.RoundTripChecked, True)) + ',');
      JsonLines.Add('      "roundTripEqual": ' + LowerCase(BoolToStr(R.RoundTripEqual, True)) + ',');
      JsonLines.Add('      "firstDiff": ' + IntToStr(R.FirstDiff) + ',');
      JsonLines.Add('      "libraryElapsedUs": ' + UIntToStr(R.LibraryElapsedUs) + ',');
      JsonLines.Add('      "coreElapsedUs": ' + UIntToStr(R.CoreElapsedUs) + ',');
      JsonLines.Add('      "workerElapsedUs": ' + UIntToStr(R.WorkerElapsedUs) + ',');
      JsonLines.Add('      "wallElapsedUs": ' + UIntToStr(R.WallElapsedUs) + ',');
      JsonLines.Add('      "elapsedMs": ' + UIntToStr(R.ElapsedMs) + ',');
      JsonLines.Add('      "processExitCode": ' + UIntToStr(R.ProcessExitCode));
      if I + 1 < Results.Count then
        JsonLines.Add('    },')
      else
        JsonLines.Add('    }');
      Inc(I);
    end;

    JsonLines.Add('  ],');
    JsonLines.Add('  "summary": {');
    JsonLines.Add('    "files": ' + IntToStr(Results.Count) + ',');
    JsonLines.Add('    "passed": ' + IntToStr(PassCount) + ',');
    JsonLines.Add('    "rejected": ' + IntToStr(RejectCount) + ',');
    JsonLines.Add('    "failed": ' + IntToStr(FailCount) + ',');
    JsonLines.Add('    "crashed": ' + IntToStr(CrashCount) + ',');
    JsonLines.Add('    "timedOut": ' + IntToStr(TimeoutCount) + ',');
    JsonLines.Add('    "skipped": ' + IntToStr(SkipCount));
    JsonLines.Add('  }');
    JsonLines.Add('}');

    LogLines.Add('');
    LogLines.Add('Files=' + IntToStr(Results.Count));
    LogLines.Add('Passed=' + IntToStr(PassCount));
    LogLines.Add('Rejected=' + IntToStr(RejectCount));
    LogLines.Add('Failed=' + IntToStr(FailCount));
    LogLines.Add('Crashed=' + IntToStr(CrashCount));
    LogLines.Add('TimedOut=' + IntToStr(TimeoutCount));
    LogLines.Add('Skipped=' + IntToStr(SkipCount));

    LogLines.SaveToFile(LogPath, TEncoding.UTF8);
    CsvLines.SaveToFile(CsvPath, TEncoding.UTF8);
    JsonLines.SaveToFile(JsonPath, TEncoding.UTF8);
  finally
    JsonLines.Free;
    CsvLines.Free;
    LogLines.Free;
  end;
end;

function GetArgValue(const Name, DefaultValue: string): string;
var
  I: Integer;
begin
  Result := DefaultValue;
  I := 1;
  while I <= ParamCount do
  begin
    if SameText(ParamStr(I), Name) and (I < ParamCount) then
      Exit(ParamStr(I + 1));
    Inc(I);
  end;
end;

function HasArg(const Name: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  I := 1;
  while I <= ParamCount do
  begin
    if SameText(ParamStr(I), Name) then
      Exit(True);
    Inc(I);
  end;
end;

function RunSupervisor: Integer;
var
  ExeDir, DefaultRoot, DefaultResults: string;
  RootDir, ResultsDir, Stamp, TempDir, ListFile: string;
  Files: TStringList;
  Results: TList<TCorpusResult>;
  R: TCorpusResult;
  I: Integer;
  TimeoutMs: DWORD;
  MaxMb, MaxBytes: Int64;
  CurrentSize: Int64;
  WorkerResultPath: string;
  WorkerExitCode: DWORD;
  WorkerWallElapsedUs: UInt64;
  TimedOut, Started: Boolean;
  LogPath, CsvPath, JsonPath: string;
  HardFailures: Integer;
  AllSubDirs: Boolean;
begin
  Result := 2;
  ExeDir := ExtractFilePath(ParamStr(0));
  DefaultRoot := ExpandFileName(ExeDir + '..\..\..\tests\corpus\samples');
  DefaultResults := ExpandFileName(ExeDir + '..\..\..\test-results\corpus');
  RootDir := ExpandFileName(GetArgValue('--root', DefaultRoot));
  ResultsDir := ExpandFileName(GetArgValue('--results', DefaultResults));
  ListFile := GetArgValue('--list', '');
  if ListFile <> '' then
    ListFile := ExpandFileName(ListFile);
  TimeoutMs := DWORD(StrToIntDef(GetArgValue('--timeout-ms', '15000'), 15000));
  MaxMb := StrToInt64Def(GetArgValue('--max-mb', '512'), 512);
  AllSubDirs := HasArg('--all-subdirs');
  if MaxMb < 1 then
    MaxMb := 1;
  MaxBytes := MaxMb * 1024 * 1024;

  if not DirectoryExists(RootDir) then
  begin
    Writeln('Corpus directory not found: ' + RootDir);
    Exit(2);
  end;

  Files := TStringList.Create;
  Results := TList<TCorpusResult>.Create;
  try
    Files.Sorted := ListFile = '';
    Files.Duplicates := dupIgnore;
    if ListFile <> '' then
    begin
      if not LoadCorpusFileList(RootDir, ListFile, Files) then
      begin
        Writeln('Corpus file list not found: ' + ListFile);
        Exit(2);
      end;
    end
    else if AllSubDirs then
      EnumerateFiles(RootDir, Files)
    else
      EnumerateCorpusFiles(RootDir, Files);

    Stamp := FormatDateTime('yyyymmdd-hhnnss-zzz', Now);
    ForceDirectories(ResultsDir);
    TempDir := IncludeTrailingPathDelimiter(ResultsDir) + 'tmp-' + Stamp;
    ForceDirectories(TempDir);

    Writeln('NativePe Corpus Test');
    Writeln('Root: ' + RootDir);
    if ListFile <> '' then
      Writeln('List: ' + ListFile);
    Writeln('Files: ' + IntToStr(Files.Count));
    Writeln('Timeout per file: ' + UIntToStr(TimeoutMs) + ' ms');
    Writeln('Maximum file size: ' + IntToStr(MaxMb) + ' MB');
    Writeln('');

    I := 0;
    while I < Files.Count do
    begin
      InitCorpusResult(R);
      R.FileName := MakeRelativePath(RootDir, Files[I]);

      if not FileExists(Files[I]) then
      begin
        R.Outcome := coSkip;
        R.Stage := 'input';
        R.MessageText := 'file no longer exists';
        Results.Add(R);
        Writeln(Format('[%d/%d] SKIP %s', [I + 1, Files.Count, R.FileName]));
        Inc(I);
        Continue;
      end;

      CurrentSize := 0;
      if not GetPathFileSize(Files[I], CurrentSize) then
      begin
        R.Outcome := coFail;
        R.Stage := 'size';
        R.MessageText := 'file size query failed';
        Results.Add(R);
        Writeln(Format('[%d/%d] FAIL %s', [I + 1, Files.Count, R.FileName]));
        Inc(I);
        Continue;
      end;

      if CurrentSize > MaxBytes then
      begin
        R.Outcome := coSkip;
        R.Stage := 'size';
        R.MessageText := 'file exceeds --max-mb limit';
        R.FileSize := UInt64(CurrentSize);
        Results.Add(R);
        Writeln(Format('[%d/%d] SKIP %s', [I + 1, Files.Count, R.FileName]));
        Inc(I);
        Continue;
      end;

      WorkerResultPath := IncludeTrailingPathDelimiter(TempDir) + Format('worker-%.8d.txt', [I]);
      System.SysUtils.DeleteFile(WorkerResultPath);
      System.SysUtils.DeleteFile(StageMarkerFileName(WorkerResultPath));
      Started := RunWorkerProcess(Files[I], WorkerResultPath, TimeoutMs, WorkerExitCode, TimedOut,
        WorkerWallElapsedUs);

      if not Started then
      begin
        R.Outcome := coFail;
        R.Stage := 'spawn';
        R.MessageText := 'CreateProcess failed: ' + SysErrorMessage(GetLastError);
        R.WallElapsedUs := WorkerWallElapsedUs;
      end
      else if TimedOut then
      begin
        R.Outcome := coTimeout;
        R.Stage := ReadStageMarker(WorkerResultPath);
        if R.Stage = '' then
          R.Stage := 'worker';
        R.MessageText := 'worker exceeded timeout';
        R.ProcessExitCode := WorkerExitCode;
        R.WallElapsedUs := WorkerWallElapsedUs;
      end
      else if ReadWorkerResult(WorkerResultPath, R) then
      begin
        R.FileName := MakeRelativePath(RootDir, Files[I]);
        R.ProcessExitCode := WorkerExitCode;
        R.WallElapsedUs := WorkerWallElapsedUs;
      end
      else
      begin
        R.FileName := MakeRelativePath(RootDir, Files[I]);
        R.FileSize := UInt64(CurrentSize);
        if WorkerExitCode = 0 then
        begin
          R.Outcome := coFail;
          R.MessageText := 'worker exited without a valid result';
        end
        else
        begin
          R.Outcome := coCrash;
          R.MessageText := 'worker terminated before writing a result';
        end;
        R.Stage := ReadStageMarker(WorkerResultPath);
        if R.Stage = '' then
          R.Stage := 'worker';
        R.ProcessExitCode := WorkerExitCode;
        R.WallElapsedUs := WorkerWallElapsedUs;
      end;

      Results.Add(R);
      Writeln(Format('[%d/%d] %s %s', [I + 1, Files.Count, OutcomeToText(R.Outcome), R.FileName]));
      System.SysUtils.DeleteFile(WorkerResultPath);
      System.SysUtils.DeleteFile(StageMarkerFileName(WorkerResultPath));
      Inc(I);
    end;

    RemoveDir(TempDir);
    SaveReports(Results, RootDir, ResultsDir, Stamp, LogPath, CsvPath, JsonPath);

    HardFailures := 0;
    I := 0;
    while I < Results.Count do
    begin
      if Results[I].Outcome in [coFail, coCrash, coTimeout] then
        Inc(HardFailures);
      Inc(I);
    end;

    Writeln('');
    Writeln('Log : ' + LogPath);
    Writeln('CSV : ' + CsvPath);
    Writeln('JSON: ' + JsonPath);
    Writeln('Hard failures: ' + IntToStr(HardFailures));

    if HardFailures = 0 then
      Result := 0
    else
      Result := 1;
  finally
    Results.Free;
    Files.Free;
  end;
end;

function RunCorpusApplication: Integer;
begin
  if (ParamCount >= 3) and SameText(ParamStr(1), '--worker') then
    Result := RunWorker(ParamStr(2), ParamStr(3))
  else
    Result := RunSupervisor;
end;

end.
