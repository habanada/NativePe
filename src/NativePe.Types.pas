{
  SPDX-FileCopyrightText: 2026 Selahattin Erkoc
  SPDX-License-Identifier: MIT

  See LICENSE.
}
unit NativePe.Types;

interface

uses
  Winapi.Windows;

const
  IMAGE_DOS_SIGNATURE = $5A4D;
  IMAGE_NT_SIGNATURE = DWORD($00004550);
  IMAGE_NT_OPTIONAL_HDR32_MAGIC = $10B;
  IMAGE_NT_OPTIONAL_HDR64_MAGIC = $20B;
  IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
  IMAGE_SIZEOF_SECTION_HEADER = 40;
  IMAGE_SIZEOF_BASE_RELOCATION = 8;

  IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
  IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
  IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
  IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
  IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
  IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
  IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
  IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
  IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
  IMAGE_DIRECTORY_ENTRY_TLS = 9;
  IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
  IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
  IMAGE_DIRECTORY_ENTRY_IAT = 12;
  IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
  IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

  IMAGE_FILE_DLL = $2000;
  IMAGE_SCN_MEM_EXECUTE = DWORD($20000000);
  IMAGE_SCN_MEM_READ = DWORD($40000000);
  IMAGE_SCN_MEM_WRITE = DWORD($80000000);

  IMAGE_ORDINAL_FLAG32 = DWORD($80000000);
  IMAGE_ORDINAL_FLAG64 = UInt64($8000000000000000);

  PE_PAGE_SIZE = $1000;

  DOTNET_METADATA_SIGNATURE = DWORD($424A5342);

type
  TImageDosHeader = packed record
    e_magic: Word;
    e_cblp: Word;
    e_cp: Word;
    e_crlc: Word;
    e_cparhdr: Word;
    e_minalloc: Word;
    e_maxalloc: Word;
    e_ss: Word;
    e_sp: Word;
    e_csum: Word;
    e_ip: Word;
    e_cs: Word;
    e_lfarlc: Word;
    e_ovno: Word;
    e_res: array [0 .. 3] of Word;
    e_oemid: Word;
    e_oeminfo: Word;
    e_res2: array [0 .. 9] of Word;
    e_lfanew: LongInt;
  end;
  PImageDosHeader = ^TImageDosHeader;

  TImageFileHeader = packed record
    Machine: Word;
    NumberOfSections: Word;
    TimeDateStamp: DWORD;
    PointerToSymbolTable: DWORD;
    NumberOfSymbols: DWORD;
    SizeOfOptionalHeader: Word;
    Characteristics: Word;
  end;
  PImageFileHeader = ^TImageFileHeader;

  TImageDataDirectory = packed record
    VirtualAddress: DWORD;
    Size: DWORD;
  end;
  PImageDataDirectory = ^TImageDataDirectory;
  TImageDataDirectories = array [0 .. IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1] of TImageDataDirectory;

  TImageOptionalHeader32 = packed record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    BaseOfData: DWORD;
    ImageBase: DWORD;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: DWORD;
    SizeOfStackCommit: DWORD;
    SizeOfHeapReserve: DWORD;
    SizeOfHeapCommit: DWORD;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: TImageDataDirectories;
  end;
  PImageOptionalHeader32 = ^TImageOptionalHeader32;

  TImageOptionalHeader64 = packed record
    Magic: Word;
    MajorLinkerVersion: Byte;
    MinorLinkerVersion: Byte;
    SizeOfCode: DWORD;
    SizeOfInitializedData: DWORD;
    SizeOfUninitializedData: DWORD;
    AddressOfEntryPoint: DWORD;
    BaseOfCode: DWORD;
    ImageBase: UInt64;
    SectionAlignment: DWORD;
    FileAlignment: DWORD;
    MajorOperatingSystemVersion: Word;
    MinorOperatingSystemVersion: Word;
    MajorImageVersion: Word;
    MinorImageVersion: Word;
    MajorSubsystemVersion: Word;
    MinorSubsystemVersion: Word;
    Win32VersionValue: DWORD;
    SizeOfImage: DWORD;
    SizeOfHeaders: DWORD;
    CheckSum: DWORD;
    Subsystem: Word;
    DllCharacteristics: Word;
    SizeOfStackReserve: UInt64;
    SizeOfStackCommit: UInt64;
    SizeOfHeapReserve: UInt64;
    SizeOfHeapCommit: UInt64;
    LoaderFlags: DWORD;
    NumberOfRvaAndSizes: DWORD;
    DataDirectory: TImageDataDirectories;
  end;
  PImageOptionalHeader64 = ^TImageOptionalHeader64;

  TImageNtHeaders32 = packed record
    Signature: DWORD;
    FileHeader: TImageFileHeader;
    OptionalHeader: TImageOptionalHeader32;
  end;
  PImageNtHeaders32 = ^TImageNtHeaders32;

  TImageNtHeaders64 = packed record
    Signature: DWORD;
    FileHeader: TImageFileHeader;
    OptionalHeader: TImageOptionalHeader64;
  end;
  PImageNtHeaders64 = ^TImageNtHeaders64;

  TImageSectionMisc = packed record
    case Integer of
      0: (PhysicalAddress: DWORD);
      1: (VirtualSize: DWORD);
  end;

  TImageSectionHeader = packed record
    Name: array [0 .. 7] of AnsiChar;
    Misc: TImageSectionMisc;
    VirtualAddress: DWORD;
    SizeOfRawData: DWORD;
    PointerToRawData: DWORD;
    PointerToRelocations: DWORD;
    PointerToLinenumbers: DWORD;
    NumberOfRelocations: Word;
    NumberOfLinenumbers: Word;
    Characteristics: DWORD;
  end;
  PImageSectionHeader = ^TImageSectionHeader;

  TImageImportDescriptor = packed record
    OriginalFirstThunk: DWORD;
    TimeDateStamp: DWORD;
    ForwarderChain: DWORD;
    Name: DWORD;
    FirstThunk: DWORD;
  end;
  PImageImportDescriptor = ^TImageImportDescriptor;

  TImageThunkData32 = packed record
    case Integer of
      0: (ForwarderString: DWORD);
      1: (Func: DWORD);
      2: (Ordinal: DWORD);
      3: (AddressOfData: DWORD);
  end;
  PImageThunkData32 = ^TImageThunkData32;

  TImageThunkData64 = packed record
    case Integer of
      0: (ForwarderString: UInt64);
      1: (Func: UInt64);
      2: (Ordinal: UInt64);
      3: (AddressOfData: UInt64);
  end;
  PImageThunkData64 = ^TImageThunkData64;

  TImageImportByName = packed record
    Hint: Word;
    Name: array [0 .. 0] of AnsiChar;
  end;
  PImageImportByName = ^TImageImportByName;

  TImageExportDirectory = packed record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    Name: DWORD;
    Base: DWORD;
    NumberOfFunctions: DWORD;
    NumberOfNames: DWORD;
    AddressOfFunctions: DWORD;
    AddressOfNames: DWORD;
    AddressOfNameOrdinals: DWORD;
  end;
  PImageExportDirectory = ^TImageExportDirectory;

  TImageBaseRelocation = packed record
    VirtualAddress: DWORD;
    SizeOfBlock: DWORD;
  end;
  PImageBaseRelocation = ^TImageBaseRelocation;

  TImageTlsDirectory32 = packed record
    StartAddressOfRawData: DWORD;
    EndAddressOfRawData: DWORD;
    AddressOfIndex: DWORD;
    AddressOfCallBacks: DWORD;
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;
  PImageTlsDirectory32 = ^TImageTlsDirectory32;

  TImageTlsDirectory64 = packed record
    StartAddressOfRawData: UInt64;
    EndAddressOfRawData: UInt64;
    AddressOfIndex: UInt64;
    AddressOfCallBacks: UInt64;
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;
  PImageTlsDirectory64 = ^TImageTlsDirectory64;

  TImageCor20Header = packed record
    cb: DWORD;
    MajorRuntimeVersion: Word;
    MinorRuntimeVersion: Word;
    MetaData: TImageDataDirectory;
    Flags: DWORD;
    EntryPointToken: DWORD;
    Resources: TImageDataDirectory;
    StrongNameSignature: TImageDataDirectory;
    CodeManagerTable: TImageDataDirectory;
    VTableFixups: TImageDataDirectory;
    ExportAddressTableJumps: TImageDataDirectory;
    ManagedNativeHeader: TImageDataDirectory;
  end;
  PImageCor20Header = ^TImageCor20Header;

  PImageResourceDirectory = ^TImageResourceDirectory;
  TImageResourceDirectory = packed record
    Characteristics: DWORD;
    TimeDateStamp: DWORD;
    MajorVersion: Word;
    MinorVersion: Word;
    NumberOfNamedEntries: Word;
    NumberOfIdEntries: Word;
  end;

  PImageResourceDirectoryEntry = ^TImageResourceDirectoryEntry;
  TImageResourceDirectoryEntry = packed record
    NameOrId: DWORD;
    OffsetToDataOrDirectory: DWORD;
    function Id: Word; inline;
    function NameIsString: Boolean; inline;
    function NameOffset: DWORD; inline;
    function OffsetToData: DWORD; inline;
    function OffsetToDirectory: DWORD; inline;
    function DataIsDirectory: Boolean; inline;
  end;

  PImageResourceDataEntry = ^TImageResourceDataEntry;
  TImageResourceDataEntry = packed record
    OffsetToData: DWORD;
    Size: DWORD;
    CodePage: DWORD;
    Reserved: DWORD;
  end;

  TImageDelayloadDescriptor = packed record
    AllAttributes: DWORD;
    DllNameRVA: DWORD;
    ModuleHandleRVA: DWORD;
    ImportAddressTableRVA: DWORD;
    ImportNameTableRVA: DWORD;
    BoundImportAddressTableRVA: DWORD;
    UnloadInformationTableRVA: DWORD;
    TimeDateStamp: DWORD;
  end;
  PImageDelayloadDescriptor = ^TImageDelayloadDescriptor;

  TBaseRelocationEntry = packed record
    OffsetAndType: Word;
    function Offset: Word; inline;
    function RelocType: Word; inline;
  end;
  PBaseRelocationEntry = ^TBaseRelocationEntry;

  TListEntry = record
    Flink: Pointer;
    Blink: Pointer;
  end;
  PListEntry = ^TListEntry;

  TUnicodeString = record
    Length: Word;
    MaximumLength: Word;
    Buffer: PWideChar;
  end;
  PUnicodeString = ^TUnicodeString;

  PPebLdrData = ^TPebLdrData;
  TPebLdrData = record
    Length: DWORD;
    Initialized: Boolean;
    SsHandle: THandle;
    InLoadOrderModuleList: TListEntry;
    InMemoryOrderModuleList: TListEntry;
    InInitializationOrderModuleList: TListEntry;
    EntryInProgress: Pointer;
  end;

  PLdrDataTableEntry = ^TLdrDataTableEntry;
  TLdrDataTableEntry = record
    InLoadOrderLinks: TListEntry;
    InMemoryOrderLinks: TListEntry;
    InInitializationOrderLinks: TListEntry;
    DllBase: Pointer;
    EntryPoint: Pointer;
    SizeOfImage: DWORD;
    FullDllName: TUnicodeString;
    BaseDllName: TUnicodeString;
    Flags: DWORD;
    LoadCount: Word;
    TlsIndex: Word;
    HashLinks: TListEntry;
    SectionPointer: Pointer;
    CheckSum: DWORD;
    TimeDateStamp: DWORD;
    LoadedImports: Pointer;
    EntryPointActivationContext: Pointer;
    PatchInformation: Pointer;
    Unknown1: Pointer;
    Unknown2: Pointer;
    Unknown3: Pointer;
  end;

  PPeb = ^TPeb;
  TPeb = record
    InheritedAddressSpace: Byte;
    ReadImageFileExecOptions: Byte;
    BeingDebugged: Byte;
    BitField: Byte;
    Mutant: THandle;
    ImageBaseAddress: Pointer;
    Ldr: PPebLdrData;
    ProcessParameters: Pointer;
    SubSystemData: Pointer;
    ProcessHeap: Pointer;
    FastPebLock: PRTLCriticalSection;
    AtlThunkSListPtr: Pointer;
    IFEOKey: Pointer;
    CrossProcessFlags: DWORD;
    KernelCallbackTable: Pointer;
    SystemReserved: DWORD;
    AtlThunkSListPtr32: DWORD;
    ApiSetMap: Pointer;
    TlsExpansionCounter: Pointer;
    TlsBitmap: Pointer;
    TlsBitmapBits: array [0 .. 1] of DWORD;
    ReadOnlySharedMemoryBase: Pointer;
    SharedData: Pointer;
    ReadOnlyStaticServerData: Pointer;
    AnsiCodePageData: Pointer;
    OemCodePageData: Pointer;
    UnicodeCaseTableData: Pointer;
    NumberOfProcessors: DWORD;
    NtGlobalFlag: DWORD;
    CriticalSectionTimeout: Int64;
    HeapSegmentReserve: Pointer;
    HeapSegmentCommit: Pointer;
    HeapDeCommitTotalFreeThreshold: Pointer;
    HeapDeCommitFreeBlockThreshold: Pointer;
    NumberOfHeaps: DWORD;
    MaximumNumberOfHeaps: DWORD;
    ProcessHeaps: Pointer;
    GdiSharedHandleTable: Pointer;
    ProcessStarterHelper: Pointer;
    GdiDCAttributeList: Pointer;
    LoaderLock: PRTLCriticalSection;
  end;

  PProcessBasicInformation = ^TProcessBasicInformation;
  TProcessBasicInformation = record
    Reserved1: Pointer;
    PebBaseAddress: PPeb;
    Reserved2: array [0 .. 1] of Pointer;
    UniqueProcessId: NativeUInt;
    Reserved3: Pointer;
  end;

implementation

function TBaseRelocationEntry.Offset: Word;
begin
  Result := OffsetAndType and $0FFF;
end;

function TBaseRelocationEntry.RelocType: Word;
begin
  Result := (OffsetAndType shr 12) and $000F;
end;

function TImageResourceDirectoryEntry.Id: Word;
begin
  Result := Word(NameOrId and $FFFF);
end;

function TImageResourceDirectoryEntry.NameIsString: Boolean;
begin
  Result := (NameOrId shr 31) and 1 <> 0;
end;

function TImageResourceDirectoryEntry.NameOffset: DWORD;
begin
  Result := NameOrId and $7FFFFFFF;
end;

function TImageResourceDirectoryEntry.OffsetToData: DWORD;
begin
  Result := OffsetToDataOrDirectory;
end;

function TImageResourceDirectoryEntry.OffsetToDirectory: DWORD;
begin
  Result := OffsetToDataOrDirectory and $7FFFFFFF;
end;

function TImageResourceDirectoryEntry.DataIsDirectory: Boolean;
begin
  Result := (OffsetToDataOrDirectory shr 31) and 1 <> 0;
end;

end.
