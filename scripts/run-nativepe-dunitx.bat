@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "ROOT=%~dp0.."
set "PLATFORM="
set "CONFIG="
set "PRESET="
set "FILTER_ARGS="
set "FILTER_DESC=All tests"
set "VERIFY_FIXTURES=1"
set "EXTRA_ARGS="
set "INTERACTIVE=0"

if "%~1"=="" (
  set "INTERACTIVE=1"
  goto interactive
)

if /I "%~1"=="Debug" goto legacy
if /I "%~1"=="Release" goto legacy

set "PLATFORM=%~1"
set "CONFIG=%~2"
set "PRESET=%~3"
shift
shift
shift
call :collect_extra %*
goto configure

:legacy
set "PLATFORM=Win64"
set "CONFIG=%~1"
set "PRESET=all"
shift
call :collect_extra %*
goto configure

:interactive
call :select_platform || exit /b 2
call :select_config || exit /b 2
call :select_tests || exit /b 2
set "EXTRA_INPUT="
set /p "EXTRA_INPUT=Additional DUnitX arguments [none]: "
if defined EXTRA_INPUT set "EXTRA_ARGS=%EXTRA_INPUT%"

:configure
call :normalize_platform || exit /b 2
call :normalize_config || exit /b 2
if not defined PRESET set "PRESET=all"
call :apply_preset "%PRESET%" || exit /b 2

set "EXE=%ROOT%\bin\%PLATFORM%\%CONFIG%\NativePeDUnitX.exe"
set "RESULTS=%ROOT%\test-results\dunitx\%PLATFORM%\%CONFIG%"
set "NATIVEPE_LIBPECONV_FIXTURES=%ROOT%\tests\dunitx\fixtures\libpeconv"
set "NATIVEPE_DUNITX_XML=%RESULTS%\NativePeDUnitX.xml"
set "LOG=%RESULTS%\NativePeDUnitX.log"

if not exist "%EXE%" (
  echo.
  echo ERROR: NativePeDUnitX.exe not found:
  echo   %EXE%
  echo Build NativePeDUnitX for %PLATFORM% %CONFIG% first.
  exit /b 2
)

if "%VERIFY_FIXTURES%"=="1" call :verify_fixtures || exit /b 1
if not exist "%RESULTS%" mkdir "%RESULTS%"

echo.
echo NativePe DUnitX
echo ---------------
echo Platform : %PLATFORM%
echo Config   : %CONFIG%
echo Tests    : %FILTER_DESC%
echo XML      : %NATIVEPE_DUNITX_XML%
echo Log      : %LOG%
if defined EXTRA_ARGS echo Extra    : %EXTRA_ARGS%
echo.

if defined FILTER_ARGS (
  if defined EXTRA_ARGS (
    "%EXE%" %FILTER_ARGS% %EXTRA_ARGS% > "%LOG%" 2>&1
  ) else (
    "%EXE%" %FILTER_ARGS% > "%LOG%" 2>&1
  )
) else (
  if defined EXTRA_ARGS (
    "%EXE%" %EXTRA_ARGS% > "%LOG%" 2>&1
  ) else (
    "%EXE%" > "%LOG%" 2>&1
  )
)
set "RC=%ERRORLEVEL%"
type "%LOG%"
echo.
echo Exit code: %RC%
echo XML      : %NATIVEPE_DUNITX_XML%
echo Log      : %LOG%
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

:select_tests
echo.
echo Select tests:
echo   1. All tests
echo   2. Core
echo   3. Coverage
echo   4. PE
echo   5. Robustness
echo   6. Windows integration
echo   7. LibPeConv and fidelity
echo   8. Custom fixture or full test name
echo   9. Run-list file
echo  10. Raw DUnitX arguments
echo  11. Show DUnitX help
set "TEST_SELECTION="
set /p "TEST_SELECTION=Selection [1-11]: "
if "%TEST_SELECTION%"=="1" (set "PRESET=all" & exit /b 0)
if "%TEST_SELECTION%"=="2" (set "PRESET=core" & exit /b 0)
if "%TEST_SELECTION%"=="3" (set "PRESET=coverage" & exit /b 0)
if "%TEST_SELECTION%"=="4" (set "PRESET=pe" & exit /b 0)
if "%TEST_SELECTION%"=="5" (set "PRESET=robustness" & exit /b 0)
if "%TEST_SELECTION%"=="6" (set "PRESET=windows" & exit /b 0)
if "%TEST_SELECTION%"=="7" (set "PRESET=libpeconv" & exit /b 0)
if "%TEST_SELECTION%"=="8" goto custom_run
if "%TEST_SELECTION%"=="9" goto run_list
if "%TEST_SELECTION%"=="10" goto raw_args
if "%TEST_SELECTION%"=="11" goto help_mode
echo ERROR: Invalid selection.
exit /b 1

:custom_run
set "CUSTOM_RUN="
set /p "CUSTOM_RUN=Fixture or full test name: "
if not defined CUSTOM_RUN exit /b 1
set "PRESET=%CUSTOM_RUN%"
exit /b 0

:run_list
set "RUNLIST="
set /p "RUNLIST=Run-list file path: "
set "RUNLIST=%RUNLIST:"=%"
if not exist "%RUNLIST%" (
  echo ERROR: Run-list file not found: %RUNLIST%
  exit /b 1
)
set "PRESET=runlist:%RUNLIST%"
exit /b 0

:raw_args
set "RAW_ARGS="
set /p "RAW_ARGS=DUnitX arguments: "
if not defined RAW_ARGS exit /b 1
set "PRESET=raw:%RAW_ARGS%"
exit /b 0

:help_mode
set "PRESET=help"
exit /b 0

:apply_preset
set "VALUE=%~1"
set "FILTER_ARGS="
set "VERIFY_FIXTURES=0"
if /I "%VALUE%"=="all" (set "FILTER_DESC=All tests" & set "VERIFY_FIXTURES=1" & exit /b 0)
if /I "%VALUE%"=="core" (set "FILTER_ARGS=--run:NativePe.Core" & set "FILTER_DESC=NativePe.Core" & exit /b 0)
if /I "%VALUE%"=="coverage" (set "FILTER_ARGS=--run:NativePe.Coverage" & set "FILTER_DESC=NativePe.Coverage" & exit /b 0)
if /I "%VALUE%"=="pe" (set "FILTER_ARGS=--run:NativePe.Pe" & set "FILTER_DESC=NativePe.Pe" & exit /b 0)
if /I "%VALUE%"=="robustness" (set "FILTER_ARGS=--run:NativePe.Robustness" & set "FILTER_DESC=NativePe.Robustness" & exit /b 0)
if /I "%VALUE%"=="windows" (set "FILTER_ARGS=--run:NativePe.Windows" & set "FILTER_DESC=NativePe.Windows" & exit /b 0)
if /I "%VALUE%"=="libpeconv" (set "FILTER_ARGS=--run:NativePe.LibPeConv" & set "FILTER_DESC=NativePe.LibPeConv" & set "VERIFY_FIXTURES=1" & exit /b 0)
if /I "%VALUE%"=="help" (
  set "EXE=%ROOT%\bin\%PLATFORM%\%CONFIG%\NativePeDUnitX.exe"
  if not exist "%EXE%" (echo ERROR: NativePeDUnitX.exe not found: %EXE% & exit /b 2)
  "%EXE%" --h
  exit /b 2
)
if /I "%VALUE:~0,8%"=="runlist:" (
  set "RUNLIST_VALUE=%VALUE:~8%"
  if not exist "%RUNLIST_VALUE%" (echo ERROR: Run-list file not found: %RUNLIST_VALUE% & exit /b 2)
  set FILTER_ARGS=--runlist:"%RUNLIST_VALUE%"
  set "FILTER_DESC=Run list: %RUNLIST_VALUE%"
  exit /b 0
)
if /I "%VALUE:~0,4%"=="raw:" (
  set "FILTER_ARGS=%VALUE:~4%"
  set "FILTER_DESC=Raw DUnitX arguments"
  exit /b 0
)
set "FILTER_ARGS=--run:%VALUE%"
set "FILTER_DESC=%VALUE%"
if /I not "%VALUE:NativePe.LibPeConv=%"=="%VALUE%" set "VERIFY_FIXTURES=1"
exit /b 0

:verify_fixtures
set "FIX=%ROOT%\tests\dunitx\fixtures\libpeconv"
if not exist "%FIX%" (
  echo ERROR: Missing fixture directory:
  echo   %FIX%
  exit /b 1
)
call :check_hash "greek_to_me.bin" "a3eb21f603efb6731d3493be3427a33982a427f1b630214136531aba1746e540" || exit /b 1
call :check_hash "payload.dll" "2fbca35e033a0bd34b43ebbbb023bb98e6ac4063f9bb7800dd0f45b8bfe9a3e0" || exit /b 1
call :check_hash "test_case3_32.exe" "fe71c9d21eaa67f9aad31df6ca60e5c6c99f77494ac7c15b9963ba954983c459" || exit /b 1
call :check_hash "test_case3_64.exe" "8994981a704ff7647470080798142fa44a89049ce67706f6bd73ad10ae8c38cf" || exit /b 1
call :check_hash "shellc32.bin" "8a36e3d8fad5933d5877f962296f3970fb9304355f643dd6caa7c5579da0ce98" || exit /b 1
call :check_hash "shellc64.bin" "6c1ca77e7f94ad5e83b4515be597a7ef166ccce38905ae230e059a995adc6d15" || exit /b 1
echo libpeconv fixture hashes: OK
exit /b 0

:check_hash
set "HASH_FILE=%FIX%\%~1"
set "HASH_EXPECTED=%~2"
if not exist "%HASH_FILE%" (
  echo ERROR: Missing fixture: %HASH_FILE%
  exit /b 1
)
set "HASH_ACTUAL="
for /f "usebackq delims=" %%H in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%HASH_FILE%').Hash.ToLowerInvariant()"`) do set "HASH_ACTUAL=%%H"
if not defined HASH_ACTUAL (
  echo ERROR: Cannot calculate SHA256: %HASH_FILE%
  exit /b 1
)
if /I not "%HASH_ACTUAL%"=="%HASH_EXPECTED%" (
  echo ERROR: SHA256 mismatch: %~1
  echo Expected: %HASH_EXPECTED%
  echo Actual  : %HASH_ACTUAL%
  exit /b 1
)
echo OK %~1
exit /b 0

:collect_extra
set "EXTRA_ARGS=%*"
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
