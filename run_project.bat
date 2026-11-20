@echo off
TITLE Phishing Message Identification and Analysis - CNS PBL Project
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

CLS
echo ===============================================================================
echo    PHISHING MESSAGE IDENTIFICATION AND ANALYSIS (CNS TOPIC 5)
echo    Cryptography and Network Security Project-Based Learning Activity
echo ===============================================================================
echo.
echo Active Python: %PY_EXE%
echo.
echo Please choose an execution mode:
echo   [1] Run Command-Line Interface (CLI Evaluation & Metrics)
echo   [2] Launch Desktop GUI (Tkinter Application)
echo   [3] Launch Local Web Dashboard (Browser-based on http://localhost:8080)
echo   [4] Regenerate Visual Charts in results/ folder
echo   [5] Open Printable Project Report (PROJECT_REPORT.html)
echo   [6] Open Presentation Slides (PRESENTATION_SLIDES.html)
echo   [7] Exit
echo.
set /p choice="Enter choice [1-7]: "

if "%choice%"=="1" (
    echo.
    echo [*] Running CLI Evaluation...
    "%PY_EXE%" main.py --cli
    pause
    goto end
)
if "%choice%"=="2" (
    echo.
    echo [*] Launching Desktop GUI...
    "%PY_EXE%" main.py --gui
    if errorlevel 1 pause
    goto end
)
if "%choice%"=="3" (
    echo.
    echo [*] Starting Local Web Dashboard on http://localhost:8080...
    start http://localhost:8080
    "%PY_EXE%" main.py --web
    goto end
)
if "%choice%"=="4" (
    echo.
    echo [*] Regenerating academic plots...
    "%PY_EXE%" main.py --charts
    pause
    goto end
)
if "%choice%"=="5" (
    start PROJECT_REPORT.html
    goto end
)
if "%choice%"=="6" (
    start PRESENTATION_SLIDES.html
    goto end
)
if "%choice%"=="7" (
    exit
)

:end
