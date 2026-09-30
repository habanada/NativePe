program NativePeProcessDumpTarget;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Winapi.Windows,
  Winapi.ActiveX;

function OleCLSIDFromString(lpsz: PWideChar; out pclsid: TGUID): HRESULT; stdcall; external 'ole32.dll' name 'CLSIDFromString';
function OleCreateStreamOnHGlobal(hGlobal: HGLOBAL; fDeleteOnRelease: BOOL; out ppstm: IStream): HRESULT; stdcall; external 'ole32.dll' name 'CreateStreamOnHGlobal';
function OleCoTaskMemAlloc(cb: NativeUInt): Pointer; stdcall; external 'ole32.dll' name 'CoTaskMemAlloc';
procedure OleCoTaskMemFree(pv: Pointer); stdcall; external 'ole32.dll' name 'CoTaskMemFree';
function OleCoInitializeEx(pvReserved: Pointer; coInit: DWORD): HRESULT; stdcall; external 'ole32.dll' name 'CoInitializeEx';
procedure OleCoUninitialize; stdcall; external 'ole32.dll' name 'CoUninitialize';
function OleCoCreateInstance(const rclsid: TGUID; pUnkOuter: Pointer; dwClsContext: DWORD;
  const riid: TGUID; out ppv: Pointer): HRESULT; stdcall; external 'ole32.dll' name 'CoCreateInstance';

const
  COINIT_MULTITHREADED = 0;
  CLSCTX_INPROC_SERVER = 1;

var
  Clsid, Iid: TGUID;
  Stream: IStream;
  P: Pointer;
  Obj: Pointer;
  Hr: HRESULT;
begin
  FillChar(Clsid, SizeOf(Clsid), 0);
  FillChar(Iid, SizeOf(Iid), 0);
  Hr := OleCoInitializeEx(nil, COINIT_MULTITHREADED);
  OleCLSIDFromString('{00000000-0000-0000-C000-000000000046}', Clsid);
  OleCreateStreamOnHGlobal(0, True, Stream);
  P := OleCoTaskMemAlloc(64);
  if P <> nil then
  begin
    PByte(P)^ := $5A;
    OleCoTaskMemFree(P);
  end;
  Obj := nil;
  OleCoCreateInstance(Clsid, nil, CLSCTX_INPROC_SERVER, Iid, Obj);
  Writeln('PID=', GetCurrentProcessId);
  Writeln('BITS=', SizeOf(Pointer) * 8);
  Writeln('COM=', Hr);
  Flush(Output);
  Sleep(INFINITE);
  if Hr >= 0 then
    OleCoUninitialize;
end.
