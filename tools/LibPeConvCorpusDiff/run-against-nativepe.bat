@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0"
set "EXE=%ROOT%build\Release\LibPeConvCorpus.exe"
set "NATIVE_JSON=%~1"
set "RESULTS=%~2"

if "%NATIVE_JSON%"=="" (
  echo Usage:
  echo   run-against-nativepe.bat "path\to\NativePeCorpus-....json" ["results-dir"]
  exit /b 2
)

if "%RESULTS%"=="" set "RESULTS=%ROOT%results"

if not exist "%EXE%" (
  echo LibPeConvCorpus.exe not found:
  echo   %EXE%
  exit /b 2
)

if not exist "%NATIVE_JSON%" (
  echo NativePe JSON not found:
  echo   %NATIVE_JSON%
  exit /b 2
)

if not exist "%RESULTS%" mkdir "%RESULTS%"

set "LIST=%RESULTS%\nativepe-file-list.txt"
set "ROOTFILE=%RESULTS%\nativepe-root.txt"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$j = Get-Content -LiteralPath '%NATIVE_JSON%' -Raw | ConvertFrom-Json; " ^
  "$allowed = @('System32\','SysWOW64\','bintests-master\','pocs-master\'); " ^
  "$files = @($j.results.file | Where-Object { $p = $_; @($allowed | Where-Object { $p.StartsWith($_,[System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 }); " ^
  "$enc = New-Object System.Text.UTF8Encoding($false); " ^
  "[System.IO.File]::WriteAllLines('%LIST%', $files, $enc); " ^
  "[System.IO.File]::WriteAllText('%ROOTFILE%', [string]$j.root, $enc)"
if errorlevel 1 exit /b %errorlevel%

set /p CORPUS=<"%ROOTFILE%"

echo Corpus root:
echo   %CORPUS%
echo.
echo File list:
echo   %LIST%
echo.
echo Running libpeconv against the filtered NativePe file list...

"%EXE%" ^
  --root "%CORPUS%" ^
  --list "%LIST%" ^
  --results "%RESULTS%" ^
  --timeout-ms 15000 ^
  --max-mb 512

set "RUN_RC=%ERRORLEVEL%"

set "LIB_JSON="
for /f "delims=" %%F in ('dir /b /a-d /o-d "%RESULTS%\LibPeConvCorpus-*.json" 2^>nul') do (
  if not defined LIB_JSON set "LIB_JSON=%RESULTS%\%%F"
)

if not defined LIB_JSON (
  echo No libpeconv JSON report found.
  exit /b 2
)

echo.
echo Comparing:
echo   NativePe : %NATIVE_JSON%
echo   libpeconv: %LIB_JSON%
echo.

powershell -NoProfile -ExecutionPolicy Bypass ^
  -File "%ROOT%Compare-NativePe.ps1" ^
  -NativePeJson "%NATIVE_JSON%" ^
  -LibPeConvJson "%LIB_JSON%" ^
  -OutputDir "%RESULTS%"

set "CMP_RC=%ERRORLEVEL%"

if not "%RUN_RC%"=="0" exit /b %RUN_RC%
exit /b %CMP_RC%
