"""
cli.py
Command-Line Interface (CLI) for Phishing Identification and Analysis.
Provides formatted terminal reports, evaluation metrics, and discrepancy breakdowns.
"""

import os
import sys
import json
from typing import Dict, Any

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from phish_analyzer.dataset import TEN_FICTIONAL_EMAILS
from phish_analyzer.comparison import DiscrepancyAnalyzer
from phish_analyzer.visualizer import ProjectVisualizer
from phish_analyzer.detector import PhishingDetector

def print_banner():
    banner = """
================================================================================
   PHISHING MESSAGE IDENTIFICATION AND ANALYSIS (CNS PROJECT - TOPIC 5)
   Cryptography & Network Security | Academic Project Implementation
================================================================================
"""
    print(banner)

def run_cli_evaluation(export_json: bool = True):
    print_banner()
    analyzer = DiscrepancyAnalyzer()
    print("[*] Running comparative analysis on the 10 fictional email test cases...\n")
    results = analyzer.run_comparative_analysis()

    # Table of 10 emails
    print("=" * 110)
    print(f"{'ID':<4} | {'Scenario Title':<28} | {'Actual':<10} | {'AI Label':<10} | {'Student Checklist':<17} | {'Audit Status'}")
    print("-" * 110)

    for r in results["records"]:
        status = "⚠️ CORRECTED" if r["is_discrepancy"] else "✓ MATCH"
        print(f"#{r['id']:<3} | {r['title'][:28]:<28} | {r['ground_truth']:<10} | {r['ai_initial_label']:<10} | {r['student_label']:<17} | {status}")

    print("=" * 110)
    print()

    # Discrepancies and Student Corrections
    print("--------------------------------------------------------------------------------")
    print(f"[*] DISCREPANCY AUDIT & AI CORRECTION LOG ({results['discrepancy_count']} discrepancies found and corrected)")
    print("--------------------------------------------------------------------------------")
    for d in results["discrepancies"]:
        print(f"\n[Case #{d['id']}] {d['title']}")
        print(f"  • Ground Truth Label     : {d['ground_truth']}")
        print(f"  • AI Model Prediction    : {d['ai_prediction']}")
        print(f"  • Student Corrected Label: {d['student_correction']}")
        print(f"  • Classification Type    : {d['error_type']}")
        print(f"  • Detailed Explanation   : {d['detailed_explanation']}")

    print("\n" + "=" * 110)
    print("PERFORMANCE METRICS SUMMARY")
    print("=" * 110)
    ai_m = results["ai_metrics"]
    st_m = results["student_metrics"]

    print(f"{'Metric':<25} | {'AI Model (Baseline)':<22} | {'Student Checklist (Independent)':<25}")
    print("-" * 80)
    print(f"{'Accuracy':<25} | {ai_m['accuracy']:>18}% | {st_m['accuracy']:>25}%")
    print(f"{'Precision':<25} | {ai_m['precision']:>18}% | {st_m['precision']:>25}%")
    print(f"{'Recall (Sensitivity)':<25} | {ai_m['recall']:>18}% | {st_m['recall']:>25}%")
    print(f"{'F1-Score':<25} | {ai_m['f1_score']:>18}% | {st_m['f1_score']:>25}%")
    print(f"{'True Positives (TP)':<25} | {ai_m['tp']:>19}  | {st_m['tp']:>26} ")
    print(f"{'True Negatives (TN)':<25} | {ai_m['tn']:>19}  | {st_m['tn']:>26} ")
    print(f"{'False Positives (FP)':<25} | {ai_m['fp']:>19}  | {st_m['fp']:>26} ")
    print(f"{'False Negatives (FN)':<25} | {ai_m['fn']:>19}  | {st_m['fn']:>26} ")
    print("=" * 80)

    # Generate charts
    print("\n[*] Generating high-resolution academic charts in 'results/' folder...")
    vis = ProjectVisualizer()
    saved_plots = vis.generate_all(results)
    for key, path in saved_plots.items():
        print(f"  [+] Saved {key} -> {path}")

    # Export json
    if export_json:
        os.makedirs("results", exist_ok=True)
        out_json = os.path.join("results", "evaluation_results.json")
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Full evaluation dataset and audit log exported to: {out_json}")

    print("\n[✓] Evaluation completed successfully.\n")

if __name__ == "__main__":
    run_cli_evaluation()
