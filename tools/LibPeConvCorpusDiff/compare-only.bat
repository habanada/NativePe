@echo off
setlocal

set "ROOT=%~dp0"
set "NATIVE_JSON=%~1"
set "LIB_JSON=%~2"
set "RESULTS=%~3"

if "%NATIVE_JSON%"=="" goto usage
if "%LIB_JSON%"=="" goto usage
if "%RESULTS%"=="" set "RESULTS=%ROOT%results"

if not exist "%RESULTS%" mkdir "%RESULTS%"

powershell -NoProfile -ExecutionPolicy Bypass ^
  -File "%ROOT%Compare-NativePe.ps1" ^
  -NativePeJson "%NATIVE_JSON%" ^
  -LibPeConvJson "%LIB_JSON%" ^
  -OutputDir "%RESULTS%"

exit /b %ERRORLEVEL%

:usage
echo Usage:
echo   compare-only.bat "NativePeCorpus.json" "LibPeConvCorpus.json" ["results-dir"]
exit /b 2
