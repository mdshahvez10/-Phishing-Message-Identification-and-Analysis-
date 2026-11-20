@echo off
TITLE PhishGuard - Procedural ML Training Pipeline
cd /d "%~dp0"

:: Auto-detect Python interpreter with scikit-learn and ML library support
set "PY_EXE="
if exist "%LOCALAPPDATA%\Programs\Python\Python310\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
) else if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" (
    set "PY_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
) else (
    set "PY_EXE=python"
)

echo ===============================================================================
echo    Launching Procedural Machine Learning Training Pipeline...
echo ===============================================================================
echo Active Python: %PY_EXE%
echo.

"%PY_EXE%" procedural_train.py --dataset combined --max-features 8000

if errorlevel 1 (
    echo.
    echo [!] Procedural training encountered an error.
    pause
) else (
    echo.
    echo [*] Press any key to exit...
    pause >nul
)
