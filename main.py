"""
main.py
Unified Entry Point for Phishing Message Identification and Analysis.
Project-Based Learning (PBL) Assignment - Cryptography and Network Security.

Usage:
  python main.py             # Runs CLI evaluation and generates charts
  python main.py --cli       # Runs CLI evaluation
  python main.py --gui       # Launches Desktop Tkinter GUI
  python main.py --web       # Launches Local Web Dashboard (http://localhost:8080)
  python main.py --charts    # Regenerates all academic figures
"""

import sys
import os
import subprocess

# Force UTF-8 on Windows consoles to prevent charmap UnicodeEncodeErrors
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Detect and immediately redirect away from LibreOffice's bundled Python
def _find_working_python():
    candidates = [
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python310\python.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python313\python.exe"),
        r"C:\Users\hp\AppData\Local\Programs\Python\Python310\python.exe",
        r"C:\Users\hp\AppData\Local\Programs\Python\Python313\python.exe",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.path.abspath(c).lower() != os.path.abspath(sys.executable).lower():
            return c
    return None

if "libreoffice" in sys.executable.lower():
    _real_py = _find_working_python()
    if _real_py and len(sys.argv) > 0 and os.path.exists(sys.argv[0]):
        # Clean environment variables so Python 3.10 doesn't inherit LibreOffice's sys.path/PYTHONHOME
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        clean_env["PYTHONIOENCODING"] = "utf-8"
        sys.exit(subprocess.call([_real_py, os.path.abspath(sys.argv[0])] + sys.argv[1:], env=clean_env))

import argparse
import tempfile

# Set Matplotlib temporary config dir to prevent warning
os.environ["MPLCONFIGDIR"] = os.path.join(tempfile.gettempdir(), "matplotlib_cns_pbl")

def main():
    parser = argparse.ArgumentParser(
        description="Phishing Message Identification and Analysis (CNS Topic 5 PBL Project)"
    )
    parser.add_argument("--cli", action="store_true", help="Run comprehensive CLI evaluation")
    parser.add_argument("--gui", action="store_true", help="Launch Desktop Tkinter GUI")
    parser.add_argument("--web", action="store_true", help="Launch Local Web Dashboard on port 8080")
    parser.add_argument("--port", type=int, default=8080, help="Port for web dashboard (default: 8080)")
    parser.add_argument("--charts", action="store_true", help="Regenerate all visual evaluation plots")
    parser.add_argument("--batch", type=str, metavar="CSV_FILE", help="Run batch evaluation on a large dataset CSV")
    parser.add_argument("--samples", type=int, default=None, help="Sample size for batch evaluation")
    parser.add_argument("--train-model", action="store_true", help="Train and serialize high-accuracy model on data/email_text.csv")

    args = parser.parse_args()

    if args.gui:
        try:
            import tkinter
            from phish_analyzer.gui import launch_gui
            print("[*] Launching PhishGuard Desktop GUI...")
            launch_gui()
        except ImportError as e:
            # Check if another Python has tkinter
            _py = _find_working_python()
            if _py:
                print(f"[*] Re-launching GUI with supported Python interpreter: {_py}")
                sys.exit(subprocess.call([_py, __file__, "--gui"]))
            print(f"[!] Unable to launch GUI: {e}")
            print("[*] Falling back to CLI evaluation...")
            from phish_analyzer.cli import run_cli_evaluation
            run_cli_evaluation()
        except Exception as e:
            print(f"[!] Error in Desktop GUI: {e}")
            print("[*] Falling back to CLI evaluation...")
            from phish_analyzer.cli import run_cli_evaluation
            run_cli_evaluation()
    elif args.web:
        from phish_analyzer.web_app import launch_web_server
        launch_web_server(port=args.port)
    elif args.batch:
        from phish_analyzer.batch_evaluator import BatchEvaluator
        print(f"[*] Running Batch Evaluation on: {args.batch}")
        ev = BatchEvaluator()
        res = ev.evaluate_csv(args.batch, max_rows=args.samples)
        m = res["metrics"]
        cm = res["confusion_matrix"]
        print("\n" + "=" * 60)
        print("           BATCH DATASET EVALUATION RESULTS          ")
        print("=" * 60)
        print(f"  • Total Evaluated : {res['total_evaluated']:,}")
        print(f"  • Accuracy        : {m['accuracy']}%")
        print(f"  • Precision       : {m['precision']}%")
        print(f"  • Recall          : {m['recall']}%")
        print(f"  • F1-Score        : {m['f1_score']}%")
        print(f"  • ROC-AUC         : {m['roc_auc']}%")
        print(f"  • False Positives : {cm['fp']} (FPR: {m['fpr']}%)")
        print(f"  • False Negatives : {cm['fn']} (FNR: {m['fnr']}%)")
        print("=" * 60)
    elif args.train_model:
        from train_large_model import train_and_export_model
        train_and_export_model()
    elif args.charts:
        from phish_analyzer.comparison import DiscrepancyAnalyzer
        from phish_analyzer.visualizer import ProjectVisualizer
        print("[*] Regenerating visual charts...")
        comp = DiscrepancyAnalyzer().run_comparative_analysis()
        vis = ProjectVisualizer()
        paths = vis.generate_all(comp)
        for name, p in paths.items():
            print(f"  [+] Saved: {p}")
        print("[✓] All charts generated successfully.")
    else:
        # Default behavior: run CLI evaluation and chart generation
        from phish_analyzer.cli import run_cli_evaluation
        run_cli_evaluation()

if __name__ == "__main__":
    main()
