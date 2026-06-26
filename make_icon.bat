@echo off
cd /d "%~dp0"

if not exist "icon.png" (
    echo ERROR: icon.png not found in this folder.
    echo Place your icon PNG here as "icon.png" then re-run.
    pause
    exit /b 1
)

echo Installing Pillow for icon conversion...
venv\Scripts\pip install pillow --quiet

echo Converting icon.png to WinEventPro.ico...
venv\Scripts\python -c "from PIL import Image; img = Image.open('icon.png').convert('RGBA'); img.save('WinEventPro.ico', format='ICO', sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])"

if errorlevel 1 (
    echo ERROR: Conversion failed.
    pause
    exit /b 1
)

echo Done! WinEventPro.ico created.
echo You can now run build.bat to build the exe with this icon.
pause
