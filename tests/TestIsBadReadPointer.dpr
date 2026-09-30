program TestIsBadReadPointer;

{$APPTYPE CONSOLE}

// Regression tests for IsBadReadPointer using VirtualQuery through IsMemAccessible.
// Covers readable memory, invalid addresses, PAGE_NOACCESS, and PAGE_READONLY.

uses
  System.SysUtils,
  Winapi.Windows,
  NativePe.Types in '..\src\NativePe.Types.pas',
  NativePe.Logger in '..\src\NativePe.Logger.pas',
  NativePe.BufferUtil in '..\src\NativePe.BufferUtil.pas',
  NativePe.Util in '..\src\NativePe.Util.pas';

function Check(const Label_: string; Got: Boolean; Expected: Boolean): Boolean;
begin
  Result := Got = Expected;
  if Result then
    Writeln('[PASS] ', Label_)
  else
    Writeln('[FAIL] ', Label_, ' -- expected ', Expected, ', got ', Got);
end;

var
  AllPassed: Boolean;
  StackVar: Integer;
  Page: Pointer;
  OldProtect: DWORD;

begin
  try
    AllPassed := True;
    StackVar := 42;

    if not Check('Stack variable is readable (IsBadReadPointer = False)',
        IsBadReadPointer(@StackVar, SizeOf(StackVar)), False) then
      AllPassed := False;

    if not Check('nil is not readable (IsBadReadPointer = True)',
        IsBadReadPointer(nil, 1), True) then
      AllPassed := False;

    if not Check('Address 1 is not readable (IsBadReadPointer = True)',
        IsBadReadPointer(Pointer(1), 1), True) then
      AllPassed := False;

    Page := VirtualAlloc(nil, 4096, MEM_COMMIT or MEM_RESERVE, PAGE_NOACCESS);
    if Page = nil then
    begin
      Writeln('[SKIP] VirtualAlloc failed; skipping PAGE_NOACCESS test');
    end
    else
    begin
      try
        if not Check('PAGE_NOACCESS page is not readable (IsBadReadPointer = True)',
            IsBadReadPointer(Page, 4096), True) then
          AllPassed := False;

        OldProtect := 0;
        if VirtualProtect(Page, 4096, PAGE_READONLY, OldProtect) then
        begin
          if not Check('PAGE_READONLY page is readable (IsBadReadPointer = False)',
              IsBadReadPointer(Page, 4096), False) then
            AllPassed := False;
        end
        else
          Writeln('[SKIP] VirtualProtect failed; skipping PAGE_READONLY test');
      finally
        VirtualFree(Page, 0, MEM_RELEASE);
      end;
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
