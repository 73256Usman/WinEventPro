@echo off
cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to create venv.
        echo Make sure Python 3.12 is installed and on your PATH.
        pause
        exit /b 1
    )

    echo Installing dependencies...
    venv\Scripts\pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo ERROR: Failed to install dependencies.
        pause
        exit /b 1
    )

    echo Running pywin32 post-install setup...
    venv\Scripts\python venv\Scripts\pywin32_postinstall.py -install 2>nul
    echo Setup complete.
    echo.
)

echo Launching WinEventPro...
venv\Scripts\python wineventpro.py
if errorlevel 1 (
    echo.
    echo ERROR: App crashed or failed to start. See error above.
    pause
)
