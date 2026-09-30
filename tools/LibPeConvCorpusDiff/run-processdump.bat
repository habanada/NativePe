@echo off
setlocal

set "ROOT=%~dp0"
set "PID=%~1"
set "EXE=%ROOT%build\Release\LibPeConvProcessDump.exe"

if "%PID%"=="" (
  echo Usage:
  echo   run-processdump.bat ^<pid^> [extra args...]
  exit /b 2
)

if not exist "%EXE%" (
  echo LibPeConvProcessDump.exe not found:
  echo   %EXE%
  exit /b 2
)

"%EXE%" --pid %PID% %2 %3 %4 %5

exit /b %ERRORLEVEL%
