@echo off
cd /d "%~dp0"

set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"

if not exist %ISCC% (
    echo ERROR: Inno Setup not found at %ISCC%
    echo Download and install it from: https://jrsoftware.org/isdl.php
    pause
    exit /b 1
)

if not exist "dist\WinEventPro.exe" (
    echo ERROR: dist\WinEventPro.exe not found.
    echo Run build.bat first.
    pause
    exit /b 1
)

echo Building installer...
%ISCC% WinEventPro.iss
if errorlevel 1 (
    echo ERROR: Installer build failed.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Done!
echo  Installer: installer\WinEventPro_Setup_v1.0.0.exe
echo ============================================
pause
