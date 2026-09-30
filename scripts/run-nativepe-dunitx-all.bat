@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ROOT=%~dp0.."
set "PLATFORM=%~1"
if not defined PLATFORM (
  echo.
  echo Select platform:
  echo   1. Win32
  echo   2. Win64
  choice /C 12 /N /M "Selection [1-2]: "
  if errorlevel 2 (set "PLATFORM=Win64") else set "PLATFORM=Win32"
)
if /I "%PLATFORM%"=="32" set "PLATFORM=Win32"
if /I "%PLATFORM%"=="64" set "PLATFORM=Win64"
if /I not "%PLATFORM%"=="Win32" if /I not "%PLATFORM%"=="Win64" (
  echo ERROR: Invalid platform "%PLATFORM%". Use Win32 or Win64.
  exit /b 2
)

call "%~dp0run-nativepe-dunitx.bat" "%PLATFORM%" Debug all
set "DEBUG_RC=%ERRORLEVEL%"
if not "%DEBUG_RC%"=="0" exit /b %DEBUG_RC%
call "%~dp0run-nativepe-dunitx.bat" "%PLATFORM%" Release all
exit /b %ERRORLEVEL%
