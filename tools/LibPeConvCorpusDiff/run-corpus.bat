@echo off
setlocal

set "ROOT=%~dp0"
set "EXE=%ROOT%build\Release\LibPeConvCorpus.exe"
set "CORPUS=E:\PE-Corpus"
set "RESULTS=%ROOT%results"

if not exist "%EXE%" (
  echo LibPeConvCorpus.exe not found:
  echo   %EXE%
  exit /b 2
)

if not exist "%CORPUS%" (
  echo Corpus directory not found:
  echo   %CORPUS%
  exit /b 2
)

if not exist "%RESULTS%" mkdir "%RESULTS%"

"%EXE%" ^
  --root "%CORPUS%" ^
  --include-root "." ^
  --results "%RESULTS%" ^
  --timeout-ms 15000 ^
  --max-mb 512

exit /b %ERRORLEVEL%
