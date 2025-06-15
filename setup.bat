@echo off
echo Setting up AGIS-Terminus environment...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Create virtual environment if it doesn't exist
if not exist terminus_venv (
    echo Creating virtual environment...
    python -m venv terminus_venv
)

REM Activate virtual environment
echo Activating virtual environment...
call terminus_venv\Scripts\activate

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo Installing requirements...
pip install -r requirements.txt

echo.
echo Setup complete! The virtual environment is now activated.
echo You can run AGIS-Terminus with: python agis_terminus.py
echo.
echo To deactivate the virtual environment, type: deactivate
echo.

pause 