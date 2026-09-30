program TestThreadSafeHooks;

{$APPTYPE CONSOLE}

uses
  System.SysUtils,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas',
  NativePe.PeHdrsHelper in '..\src\NativePe.PeHdrsHelper.pas',
  NativePe.ExportedFunc in '..\src\NativePe.ExportedFunc.pas',
  NativePe.FunctionResolver in '..\src\NativePe.FunctionResolver.pas',
  NativePe.PebLookup in '..\src\NativePe.PebLookup.pas',
  NativePe.ExportsLookup in '..\src\NativePe.ExportsLookup.pas',
  NativePe.Hooks in '..\src\NativePe.Hooks.pas';

// Tests thread-safe hook patching by suspending other threads while a patch is written.
// Thread IDs are collected before suspension so no array allocation is required while
// threads are suspended. The test verifies freeze/resume behavior and ThreadSafe patching.

var
  FailCount: Integer;

procedure Check(const Name: string; Pass: Boolean);
begin
  if Pass then
    Writeln(Format('  OK   %s', [Name]))
  else
  begin
    Writeln(Format('  FAIL %s', [Name]));
    Inc(FailCount);
  end;
end;

procedure TestSuspendWithoutExplicitWorker;
var
  Ids: TArray<DWORD>;
  Count, I: Integer;
  Ok, ValidIds: Boolean;
begin
  Writeln('-- SuspendOtherThreads / ResumeOtherThreads: no explicit worker thread --');
  Ok := SuspendOtherThreads(Ids, Count);
  Check('snapshot succeeds without an explicit worker thread', Ok);
  ValidIds := (Count >= 0) and (Count <= Length(Ids));
  if ValidIds then
    for I := 0 to Count - 1 do
      if Ids[I] = GetCurrentThreadId then
      begin
        ValidIds := False;
        Break;
      end;
  Check('only other threads are reported as suspended', ValidIds);
  ResumeOtherThreads(Ids, Count);
end;

var
  Counter: Integer;
  StopFlag: Boolean;

function WorkerThreadProc(Param: Pointer): DWORD; stdcall;
begin
  while not StopFlag do
  begin
    InterlockedIncrement(Counter);
    Sleep(1);
  end;
  Result := 0;
end;

procedure TestSuspendFreezesARealThread;
var
  hThread: THandle;
  ThreadId: DWORD;
  Ids: TArray<DWORD>;
  Count: Integer;
  Before, After: Integer;
begin
  Writeln('-- SuspendOtherThreads: actually freezes a running background thread --');
  Counter := 0;
  StopFlag := False;
  hThread := CreateThread(nil, 0, @WorkerThreadProc, nil, 0, ThreadId);
  if hThread = 0 then
  begin
    Check('could not create the background worker thread (environment issue, not a library bug)', False);
    Exit;
  end;
  try
    Sleep(50); // let it actually start counting
    Check('background thread found by SuspendOtherThreads', SuspendOtherThreads(Ids, Count) and (Count >= 1));

    Before := Counter;
    Sleep(200);
    After := Counter;
    Check('counter did not advance while the thread was suspended', Before = After);

    ResumeOtherThreads(Ids, Count);
    Sleep(50);
    Before := Counter;
    Sleep(100);
    After := Counter;
    Check('counter advances again after resuming', After > Before);
  finally
    StopFlag := True;
    WaitForSingleObject(hThread, 2000);
    CloseHandle(hThread);
  end;
end;

procedure TestThreadSafePatchIsIdenticalToNormalPatch;
const
  BufSize = 32;
var
  BufA, BufB: Pointer;
  FakeTarget: Pointer;
  ResA, ResB: NativeUInt;
begin
  Writeln('-- RedirectToLocal: ThreadSafe=True writes exactly the same bytes as ThreadSafe=False --');
  BufA := VirtualAlloc(nil, BufSize, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  BufB := VirtualAlloc(nil, BufSize, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (BufA = nil) or (BufB = nil) then
  begin
    Check('could not allocate executable test buffers', False);
    Exit;
  end;
  try
    FillChar(BufA^, BufSize, $90);
    FillChar(BufB^, BufSize, $90);
    FakeTarget := Pointer(NativeUInt($0000000140001000));

    ResA := RedirectToLocal(BufA, FakeTarget, nil, False);
    ResB := RedirectToLocal(BufB, FakeTarget, nil, True);

    Check('both patches report the same patched size', ResA = ResB);
    Check('both patches wrote byte-identical hook stubs', CompareMem(BufA, BufB, BufSize));
  finally
    if BufA <> nil then
      VirtualFree(BufA, 0, MEM_RELEASE);
    if BufB <> nil then
      VirtualFree(BufB, 0, MEM_RELEASE);
  end;
end;

procedure TestBackwardCompatibleDefaults;
var
  Backup: TPatchBackup;
  Buf: Pointer;
  FakeTarget: Pointer;
begin
  Writeln('-- Existing call sites without a ThreadSafe argument still compile and behave the same --');
  Buf := VirtualAlloc(nil, 16, MEM_COMMIT or MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if Buf = nil then
  begin
    Check('could not allocate executable test buffer', False);
    Exit;
  end;
  Backup := TPatchBackup.Create;
  try
    FillChar(Buf^, 16, $90);
    FakeTarget := Pointer(NativeUInt($0000000140002000));
    RedirectToLocal(Buf, FakeTarget, Backup);
    Check('backup was captured by the 3-argument call', Backup.IsBackup);
    Check('applying the backup with no ThreadSafe argument still works', Backup.ApplyBackup);
  finally
    Backup.Free;
    if Buf <> nil then
      VirtualFree(Buf, 0, MEM_RELEASE);
  end;
end;

begin
  try
    FailCount := 0;

    TestSuspendWithoutExplicitWorker;
    TestSuspendFreezesARealThread;
    TestThreadSafePatchIsIdenticalToNormalPatch;
    TestBackwardCompatibleDefaults;

    if FailCount = 0 then
    begin
      Writeln('PASSED.');
      Halt(0);
    end
    else
    begin
      Writeln(Format('FAILED (%d check(s)).', [FailCount]));
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
