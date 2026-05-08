@echo off
title KeyGen Builder
color 0A

cd /d "%~dp0"

set "CARGO_BIN=%USERPROFILE%\.cargo\bin"
if exist "%CARGO_BIN%\cargo.exe" set "PATH=%CARGO_BIN%;%PATH%"

where cargo >nul 2>nul
if not %errorlevel%==0 (
    echo.
    echo  [ERROR] cargo not found! Run rustup-init.exe first.
    echo.
    pause
    exit /b 1
)

if not exist data mkdir data
if not exist Release mkdir Release
if not exist Release\data mkdir Release\data

set "TARGET_X64=x86_64-pc-windows-msvc"
set "TARGET_X86=i686-pc-windows-msvc"

:menu
cls
echo.
echo   [1] Build All
echo   [2] Build KeyGen.exe
echo   [3] Build Native Loaders (32-bit)
echo   [4] Build Native Loaders (64-bit)
echo   [5] Build .NET Loaders (32-bit)
echo   [6] Build .NET Loaders (64-bit)
echo   [7] Install Rust targets (i686 + x86_64)
echo.
set /p "choice=  Select: "

if "%choice%"=="1" goto buildall
if "%choice%"=="2" goto keygen
if "%choice%"=="3" goto loaders32
if "%choice%"=="4" goto loaders64
if "%choice%"=="5" goto net32
if "%choice%"=="6" goto net64
if "%choice%"=="7" goto installtargets
goto menu

:installtargets
echo.
echo  [*] Installing rustup targets...
rustup target add %TARGET_X64%
rustup target add %TARGET_X86%
goto done

:buildall
call :do_keygen
call :do_loaders32
call :do_loaders64
call :do_net32
call :do_net64
call :do_copy_map
goto done

:keygen
call :do_keygen
goto done

:loaders32
call :do_loaders32
goto done

:loaders64
call :do_loaders64
goto done

:net32
call :do_net32
goto done

:net64
call :do_net64
goto done

:do_keygen
echo.
echo  [*] Building KeyGen.exe...
cargo build --release -p keygen
if not %errorlevel%==0 (echo  [FAIL] KeyGen.exe & exit /b 1)
copy /Y target\release\KeyGen.exe Release\KeyGen.exe >nul
echo  [OK] Release\KeyGen.exe
exit /b 0

:do_loaders32
echo.
echo  [*] Building S32.dll (Native 32-bit)...
cargo build --release -p stub --target %TARGET_X86%
if not %errorlevel%==0 (echo  [FAIL] S32.dll & exit /b 1)
copy /Y target\%TARGET_X86%\release\S.exe Release\S32.dll >nul
echo  [OK] Release\S32.dll

echo  [*] Building S32U.dll (Native 32-bit UAC)...
cargo build --release -p stub --target %TARGET_X86% --features uac
if not %errorlevel%==0 (echo  [SKIP] S32U.dll & exit /b 0)
copy /Y target\%TARGET_X86%\release\S.exe Release\S32U.dll >nul
echo  [OK] Release\S32U.dll
exit /b 0

:do_loaders64
echo.
echo  [*] Building S64.dll (Native 64-bit)...
cargo build --release -p stub --target %TARGET_X64%
if not %errorlevel%==0 (echo  [FAIL] S64.dll & exit /b 1)
copy /Y target\%TARGET_X64%\release\S.exe Release\S64.dll >nul
echo  [OK] Release\S64.dll

echo  [*] Building S64U.dll (Native 64-bit UAC)...
cargo build --release -p stub --target %TARGET_X64% --features uac
if not %errorlevel%==0 (echo  [SKIP] S64U.dll & exit /b 0)
copy /Y target\%TARGET_X64%\release\S.exe Release\S64U.dll >nul
echo  [OK] Release\S64U.dll
exit /b 0

:do_net32
echo.
echo  [*] Building N32.dll (.NET 32-bit)...
cargo build --release -p stub --target %TARGET_X86% --features dotnet
if not %errorlevel%==0 (echo  [FAIL] N32.dll & exit /b 1)
copy /Y target\%TARGET_X86%\release\S.exe Release\N32.dll >nul
echo  [OK] Release\N32.dll

echo  [*] Building N32U.dll (.NET 32-bit UAC)...
cargo build --release -p stub --target %TARGET_X86% --features dotnet,uac
if not %errorlevel%==0 (echo  [SKIP] N32U.dll & exit /b 0)
copy /Y target\%TARGET_X86%\release\S.exe Release\N32U.dll >nul
echo  [OK] Release\N32U.dll
exit /b 0

:do_net64
echo.
echo  [*] Building N64.dll (.NET 64-bit)...
cargo build --release -p stub --target %TARGET_X64% --features dotnet
if not %errorlevel%==0 (echo  [FAIL] N64.dll & exit /b 1)
copy /Y target\%TARGET_X64%\release\S.exe Release\N64.dll >nul
echo  [OK] Release\N64.dll

echo  [*] Building N64U.dll (.NET 64-bit UAC)...
cargo build --release -p stub --target %TARGET_X64% --features dotnet,uac
if not %errorlevel%==0 (echo  [SKIP] N64U.dll & exit /b 0)
copy /Y target\%TARGET_X64%\release\S.exe Release\N64U.dll >nul
echo  [OK] Release\N64U.dll
exit /b 0

:do_copy_map
if exist data\map.dat (
    copy /Y data\map.dat Release\data\map.dat >nul
)
exit /b 0

:done
echo.
echo   Build Completed
echo.
pause
goto menu
