@echo off
echo Publishing AGIS-Terminus to GitHub...

REM Initialize git repository if not already initialized
if not exist .git (
    echo Initializing git repository...
    git init
)

REM Add all files
echo Adding files to git...
git add .

REM Create initial commit
echo Creating initial commit...
git commit -m "Initial commit: AGIS-Terminus AI agent"

REM Add remote if not already added
git remote -v | findstr "origin" >nul
if errorlevel 1 (
    echo Adding remote repository...
    git remote add origin https://github.com/Dark-753/aiagent.git
)

REM Push to GitHub
echo Pushing to GitHub...
git push -u origin main

echo.
echo If you get an error about the main branch, try:
echo git branch -M main
echo git push -u origin main
echo.

pause 