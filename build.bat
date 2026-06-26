@echo off
cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo ERROR: Virtual environment not found.
    echo Please run run.bat first to set up the environment.
    pause
    exit /b 1
)

echo Installing PyInstaller...
venv\Scripts\pip install pyinstaller --quiet

echo.
echo Building WinEventPro.exe...

if exist "WinEventPro.ico" (
    venv\Scripts\pyinstaller ^
        --onefile ^
        --windowed ^
        --name WinEventPro ^
        --icon WinEventPro.ico ^
        --uac-admin ^
        --hidden-import win32timezone ^
        --hidden-import win32api ^
        --hidden-import win32con ^
        --hidden-import win32security ^
        --hidden-import win32evtlog ^
        --hidden-import win32evtlogutil ^
        --hidden-import pywintypes ^
        wineventpro.py
) else (
    echo NOTE: No WinEventPro.ico found - building without custom icon.
    echo       Place WinEventPro.ico in this folder and re-run to add an icon.
    venv\Scripts\pyinstaller ^
        --onefile ^
        --windowed ^
        --name WinEventPro ^
        --uac-admin ^
        --hidden-import win32timezone ^
        --hidden-import win32api ^
        --hidden-import win32con ^
        --hidden-import win32security ^
        --hidden-import win32evtlog ^
        --hidden-import win32evtlogutil ^
        --hidden-import pywintypes ^
        wineventpro.py
)

if errorlevel 1 (
    echo.
    echo ERROR: Build failed. See output above.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  Build complete!
echo  Executable: dist\WinEventPro.exe
echo ============================================
pause
