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
echo   [1] Run Command-Line Interface (CLI Evaluation and Metrics)
echo   [2] Launch Desktop GUI (Tkinter Application with Big Data Evaluator)
echo   [3] Launch Local Web Dashboard (Browser-based on http://localhost:8080)
echo   [4] Run Large Dataset Batch Evaluation (CLI Mode)
echo   [5] Retrain Large ML Model on data/email_text.csv
echo   [6] Regenerate Visual Charts in results/ folder
echo   [7] Open Printable Project Report (PROJECT_REPORT.html)
echo   [8] Open Presentation Slides (PRESENTATION_SLIDES.html)
echo   [9] Exit
echo.
set /p choice="Enter choice [1-9]: "

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
    echo [*] Running Large Dataset Batch Evaluation...
    "%PY_EXE%" main.py --batch data/Nazario_5.csv --samples 500
    pause
    goto end
)
if "%choice%"=="5" (
    echo.
    echo [*] Running Procedural ML Training Pipeline...
    "%PY_EXE%" procedural_train.py --dataset combined --max-features 8000
    pause
    goto end
)
if "%choice%"=="6" (
    echo.
    echo [*] Regenerating academic plots...
    "%PY_EXE%" main.py --charts
    pause
    goto end
)
if "%choice%"=="7" (
    start PROJECT_REPORT.html
    goto end
)
if "%choice%"=="8" (
    start PRESENTATION_SLIDES.html
    goto end
)
if "%choice%"=="9" (
    exit
)

:end
