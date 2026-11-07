@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul 2>&1
title netwatch build
cd /d "%~dp0"

rem =====================================================================
rem  build.bat - полная сборка netwatch под Windows (cmd, UTF-8)
rem
rem  Делает:
rem    1. проверка Python 3 (py -3 / python) + запуск self-tests;
rem    2. поиск C-компилятора: gcc (MinGW-w64), clang, zig, MSVC cl.exe
rem       (при необходимости сам поднимает VS Developer Command Prompt);
rem    3. компиляция nwaccel.c -> nwaccel.exe (-O2, ws2_32/iphlpapi);
rem    4. smoke-тест ядра: nwaccel.exe ping 127.0.0.1;
rem    5. python netwatch.py accel - проверка интеграции ядра;
rem    6. (опция --exe) "компост" из всего этого: PyInstaller onefile
rem       -> dist\netwatch.exe; если PyInstaller недоступен - fallback:
rem       netwatch.cmd (обёртка над python) + copy бинарей в dist\.
rem
rem  Флаги:
rem    --no-exe     пропустить шаг 6 (только C-ядро и тесты) [по умолчанию]
rem    --exe        собрать standalone netwatch.exe (PyInstaller)
rem    --skip-tests не запускать python-тесты (selftest)
rem    --clean      перед сборкой удалить артефакты (nwaccel.exe, build/, dist/)
rem    --help       эта справка
rem =====================================================================

set "RC=0"
set "JOBS="
set "PY="
set "CC_NAME="
set "CC_CMD="
set "BUILD_EXE=0"
set "SKIP_TESTS=0"
set "DO_CLEAN=0"

:parse
if "%~1"=="" goto :parsed
if /i "%~1"=="--exe"        set "BUILD_EXE=1" & shift & goto :parse
if /i "%~1"=="--no-exe"     set "BUILD_EXE=0" & shift & goto :parse
if /i "%~1"=="--skip-tests" set "SKIP_TESTS=1" & shift & goto :parse
if /i "%~1"=="--clean"      set "DO_CLEAN=1"   & shift & goto :parse
if /i "%~1"=="-h"           goto :usage
if /i "%~1"=="--help"       goto :usage
echo [!] Неизвестный флаг: %~1  (--help для справки)
set "RC=2" & goto :finish
:parsed

if "%DO_CLEAN%"=="1" (
    echo [*] Clean: удаляю артефакты...
    if exist nwaccel.exe    del /q nwaccel.exe    2>nul
    if exist nwaccel        del /q nwaccel        2>nul
    if exist build          rd /s /q build
    if exist dist           rd /s /q dist
    for /d %%D in ("%TEMP%\netwatch-build-.*") do rd /s /q "%%~fD" 2>nul
)

call :hr
echo  netwatch builder v1.0  ^|  cwd: %CD%
call :hr

rem ---------------------------------------------------------- [1/6] Python
echo.
echo [1/6] Python
call :find_py
if not defined PY (
    echo  [X] Python 3 не найден ^(проверены py -3 и python^).
    echo      Поставь: https://www.python.org/downloads/ ^(галка "Add to PATH"^)
    set "RC=1" & goto :finish
)
echo  [OK] %PY%
%PY% -c "import sys; print('       Python', sys.version.split()[0], '|', sys.executable)" 2>nul

if "%SKIP_TESTS%"=="0" (
    %PY% -m py_compile netwatch.py nwaccel.py nw_probes.py 2>nul
    if errorlevel 1 ( echo  [X] Синтаксические ошибки в исходниках.[& set "RC=1" & goto :finish )
    echo  [..] self-tests:
    %PY% netwatch.py selftest
    if errorlevel 1 ( echo  [X] Тесты провалены.[& set "RC=1" & goto :finish )
    echo  [OK] Тесты зелёные.
)

rem --------------------------------------------------- [2/6] C-компилятор
echo.
echo [2/6] Поиск C-компилятора
where gcc >nul 2>&1 && ( set "CC_NAME=gcc"  & set "CC_CMD=gcc"   & goto :cc_found )
where clang >nul 2>&1 && ( set "CC_NAME=clang" & set "CC_CMD=clang -pthread" & goto :cc_found )
where cc >nul 2>&1     && ( set "CC_NAME=cc"    & set "CC_CMD=cc"    & goto :cc_found )
where zig >nul 2>&1    && ( set "CC_NAME=zig cc" & set "CC_CMD=zig cc -pthread" & set "JOBS=%TEMP%\netwatch-build-%RANDOM%" ) & goto :cc_found_prep
where cl >nul 2>&1     && ( set "CC_NAME=MSVC cl" & set "CC_CMD=cl"  & goto :cc_found )
rem cl есть, но вне Developer Prompt - пробуем поднять его через vswhere/VsDevCmd
call :try_msvc
if defined CC_NAME goto :cc_found_prep
echo  [X] Компилятор не найден: gcc / clang / zig / cl ^(MSVC^).
echo      Варианты:
echo        - WSL:  wsl -e bash -c "gcc -O2 -pthread -o nwaccel nwaccel.c"
echo        - MinGW-w64: winget install --id=BrechtSanders.MinGW-w64
echo        - Zig ^(один exe, без установки^):  winget install zig.zig
echo        - Visual Studio Build Tools ^(Workload "C++ Build Tools"^)
echo      Без ядра netwatch работает на pure-Python фолбэке - это не критично.
set "RC_C=1"
goto :cc_skip

:cc_found_prep
if defined JOBS if not exist "%JOBS%" mkdir "%JOBS%" >nul 2>&1
:cc_found_prep_done
:cc_found
echo  [OK] %CC_NAME%  (%CC_CMD%)

rem ---------------------------------------------------- [3/6] nwaccel.exe
echo.
echo [3/6] Компиляция nwaccel.c -^> nwaccel.exe
if not exist nwaccel.c (
    echo  [X] Нет исходника nwaccel.c рядом с build.bat
    set "RC_C=1" & goto :cc_skip
)
set "BIN=nwaccel.exe"
if "%CC_NAME%"=="MSVC cl" set "BIN=nwaccel.exe"
if "%CC_NAME%"=="gcc"         "%CC_CMD%" -O2 -Wall -o nwaccel.exe nwaccel.c -lws2_32 -liphlpapi -liphlpapi -luser32 2>nul
if "%CC_NAME%"=="gcc" if not exist nwaccel.exe "%CC_CMD%" -O2 -Wall -o nwaccel.exe nwaccel.c -lwsock32 -lws2_32
if "%CC_NAME%"=="cc"          "%CC_CMD%" -O2 -Wall -o nwaccel.exe nwaccel.c -lws2_32 -liphlpapi
if "%CC_NAME%"=="clang"       "%CC_CMD%" -O2 -Wall -target x86_64-pc-windows-gnu -o nwaccel.exe nwaccel.c -lws2_32 -liphlpapi
if "%CC_NAME%"=="zig cc"      "%CC_CMD%" -O2 -target x86_64-windows-gnu -ofmt=c -o nul 2>nul & "%CC_CMD%" -O2 -o nwaccel.exe nwaccel.c -lws2_32 -liphlpapi
if "%CC_NAME%"=="MSVC cl"     "%CC_CMD%" /nologo /O2 /W3 /DNDEBUG /Fe:nwaccel.exe nwaccel.c /link ws2_32.lib iphlpapi.lib
if not exist nwaccel.exe (
    echo  [X] Сборка не удалась - см. вывод компилятора выше.
    echo      Пробуй другой компилятор или WSL.
    set "RC_C=1" & goto :cc_skip
)
for %%F in (nwaccel.exe) do echo  [OK] nwaccel.exe ^(%%~zF байт^)

rem ------------------------------------------------------ [4/6] smoke-test
echo.
echo [4/6] Smoke-тест ядра
"%BIN%" ping 127.0.0.1 --count 5 --interval 20
if errorlevel 1 (
    echo  [!] Ядро собралось, но ping-loop не прошёл ^(raw-ICMP на Windows
    echo      требует админ-прав - DNS-batch при этом всё равно работает^).
) else (
    echo  [OK] Ping-loop жив.
)

rem ----------------------------------------------- [5/6] Интеграция ядра
echo.
echo [5/6] python netwatch.py accel
%PY% netwatch.py accel
if errorlevel 1 echo  [!] accel-статус не "ready" - смотри вывод выше.

:cc_skip
if defined RC_C if "%RC%"=="0" set "RC=%RC_C%"

rem ------------------------------------------------------- [6/6] netwatch.exe
echo.
echo [6/6] Standalone бинарь
if "%BUILD_EXE%"=="0" (
    echo  [skip] По умолчанию пропускается. Ключ --exe соберёт dist\netwatch.exe
    echo         через PyInstaller ^(или fallback-обёртку netwatch.cmd в dist\^).
    goto :summary
)
%PY% -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    %PY% -m pip show pyinstaller >nul 2>&1
    if errorlevel 1 (
        echo  [..] Ставлю PyInstaller в isolated venv...
        call :make_venv || ( echo  [X] venv не поднялся - делаю fallback-обёртку. & goto :fallback_exe )
    )
)
call :run_pyinstaller && goto :summary
echo  [X] PyInstaller-сборка упала - перехожу на fallback-обёртку.

:fallback_exe
if not exist dist mkdir dist
>dist\netwatch.cmd (
echo @echo off
echo setlocal
echo cd /d "%%~dp0"
echo where pythonw >nul 2^>^&1 ^&^& ^( pythonw "%%~dp0netwatch.py" %%* ^& exit /b %%errorlevel%% ^)
echo python "%%~dp0netwatch.py" %%*
echo exit /b %%errorlevel%%
)
copy /y netwatch.py nwaccel.py nw_probes.py nwaccel.toml dist\ >nul 2>&1
if exist nwaccel.exe copy /y nwaccel.exe dist\ >nul 2>&1
echo  [OK] Fallback: dist\netwatch.cmd + исходники в dist\ ^(нужен Python в PATH^).
set "NOTE=fallback-wrapper"

:summary
call :hr
echo  Итог:
if exist nwaccel.exe ( echo    C-ядро      : [OK] nwaccel.exe  ) else ( echo    C-ядро      : [нет] pure-Python фолбэк активен )
if exist dist\netwatch.exe ( echo    Бинарь      : [OK] dist\netwatch.exe ) else if exist dist\netwatch.cmd ( echo    Бинарь      : [OK] dist\netwatch.cmd \(обёртка\) ) else ( echo    Бинарь      : [-] не собирался \(--exe\) )
echo    Запуск      : netwatch.py --c-core -t example.com 8.8.8.8
echo    Справка     : python netwatch.py --help ^| python netwatch.py accel
call :hr
if "%RC%"=="0" ( echo  Готово. Всё собрано и проверено. ) else ( echo  Готово с предупреждениями \(RC=%RC%^\). )
endlocal & exit /b %RC%

rem ================================================================ helpers
:usage
echo usage: build.bat [--exe] [--skip-tests] [--clean] [--help]
echo   --exe         собрать standalone dist\netwatch.exe через PyInstaller
echo   --skip-tests  не запускать python self-tests
echo   --clean       удалить артефакты перед сборкой
endlocal & exit /b 0

:find_py
set "PY="
py -3 -V >nul 2>&1 && set "PY=py -3" & exit /b 0
python -V >nul 2>&1 && set "PY=python" & exit /b 0
exit /b 1

:try_msvc
rem ищет VsDevCmd.bat через vswhere и вызывает нас рекурсивно внутри dev-cmd
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 1
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSINST=%%i"
if not defined VSINST exit /b 1
if exist "%VSINST%\Common7\Tools\VsDevCmd.bat" (
    echo  [..] Найден Visual Studio: поднимаю Developer Command Prompt...
    call "%VSINST%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
    where cl >nul 2>&1 && ( set "CC_NAME=MSVC cl" & set "CC_CMD=cl" )
)
exit /b 0

:make_venv
set "JOBS=%TEMP%\netwatch-build-%RANDOM%"
mkdir "%JOBS%" >nul 2>&1
%PY% -m venv "%JOBS%\venv" >nul 2>&1 || exit /b 1
"%JOBS%\venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check pyinstaller >nul 2>&1 || exit /b 1
set "PYI=%JOBS%\venv\Scripts\python.exe -m PyInstaller"
exit /b 0

:run_pyinstaller
if not defined PYI set "PYI=%PY% -m PyInstaller"
%PYI% --noconfirm --clean --onefile ^
  --name netwatch ^
  --add-data "nwaccel.c;." ^
  --add-data "netwatch.toml;." ^
  --hidden-import nwaccel --hidden-import nw_probes ^
  netwatch.py || exit /b 1
if defined JOBS rd /s /q "%JOBS%" 2>nul
if exist nwaccel.exe copy /y nwaccel.exe dist\ >nul 2>&1
echo  [OK] dist\netwatch.exe собран ^(nwaccel.exe рядом - ядро подхватится автоматически^).
exit /b 0

:hr
echo ---------------------------------------------------------------------
exit /b 0
