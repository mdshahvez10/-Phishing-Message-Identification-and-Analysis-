@echo off
TITLE PhishGuard - Desktop GUI Launcher
cd /d "%~dp0"

:: Auto-detect Python interpreter with full Tkinter and ML library support
set "PY_EXE="
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
) else if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
) else (
    set "PY_EXE=python"
)

echo ===============================================================================
echo    Launching PhishGuard Desktop Graphical User Interface (GUI)...
echo ===============================================================================
echo Python runtime: %PY_EXE%
echo.

"%PY_EXE%" main.py --gui

if errorlevel 1 (
    echo.
    echo [!] An error occurred while running the GUI.
    pause
)
