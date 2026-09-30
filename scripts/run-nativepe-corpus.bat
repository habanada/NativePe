@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ROOT=%~dp0.."
set "PLATFORM="
set "CONFIG="
set "CORPUS=E:\PE-Corpus"
set "TIMEOUT_MS=15000"
set "MAX_MB=512"

if "%~1"=="" goto interactive
if /I "%~1"=="Debug" goto legacy
if /I "%~1"=="Release" goto legacy

set "PLATFORM=%~1"
set "CONFIG=%~2"
if not "%~3"=="" set "CORPUS=%~3"
goto validate

:legacy
set "PLATFORM=Win64"
set "CONFIG=%~1"
if not "%~2"=="" set "CORPUS=%~2"
goto validate

:interactive
call :select_platform || exit /b 2
call :select_config || exit /b 2

:validate
call :normalize_platform || exit /b 2
call :normalize_config || exit /b 2
set "CORPUS=%CORPUS:"=%"

if not exist "%CORPUS%" (
  echo.
  echo ERROR: Corpus root not found:
  echo   %CORPUS%
  exit /b 2
)

set "EXE=%ROOT%\bin\%PLATFORM%\%CONFIG%\NativePeCorpusTest.exe"
set "RESULTS=%ROOT%\test-results\corpus\%PLATFORM%\%CONFIG%"

if not exist "%EXE%" (
  echo.
  echo ERROR: NativePeCorpusTest.exe not found:
  echo   %EXE%
  echo Build NativePeCorpusTest for %PLATFORM% %CONFIG% first.
  exit /b 2
)

if not exist "%RESULTS%" mkdir "%RESULTS%"

echo.
echo NativePe Corpus Test
echo --------------------
echo Platform : %PLATFORM%
echo Config   : %CONFIG%
echo Corpus   : %CORPUS%
echo Results  : %RESULTS%
echo Timeout  : %TIMEOUT_MS% ms
echo Max size : %MAX_MB% MB
echo Scan     : complete directory tree

echo.
"%EXE%" --root "%CORPUS%" --results "%RESULTS%" --timeout-ms "%TIMEOUT_MS%" --max-mb "%MAX_MB%" --all-subdirs
set "RC=%ERRORLEVEL%"
echo.
echo Exit code: %RC%
echo Results  : %RESULTS%
exit /b %RC%

:select_platform
echo.
echo Select platform:
echo   1. Win32
echo   2. Win64
choice /C 12 /N /M "Selection [1-2]: "
if errorlevel 2 (set "PLATFORM=Win64") else set "PLATFORM=Win32"
exit /b 0

:select_config
echo.
echo Select build configuration:
echo   1. Debug
echo   2. Release
choice /C 12 /N /M "Selection [1-2]: "
if errorlevel 2 (set "CONFIG=Release") else set "CONFIG=Debug"
exit /b 0

:normalize_platform
if /I "%PLATFORM%"=="32" set "PLATFORM=Win32"
if /I "%PLATFORM%"=="64" set "PLATFORM=Win64"
if /I "%PLATFORM%"=="Win32" exit /b 0
if /I "%PLATFORM%"=="Win64" exit /b 0
echo ERROR: Invalid platform "%PLATFORM%". Use Win32 or Win64.
exit /b 1

:normalize_config
if /I "%CONFIG%"=="Debug" set "CONFIG=Debug"
if /I "%CONFIG%"=="Release" set "CONFIG=Release"
if "%CONFIG%"=="Debug" exit /b 0
if "%CONFIG%"=="Release" exit /b 0
echo ERROR: Invalid configuration "%CONFIG%". Use Debug or Release.
exit /b 1
