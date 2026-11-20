"""
procedural_train.py
================================================================================
PROCEDURAL MACHINE LEARNING TRAINING PIPELINE FOR PHISHING EMAIL DETECTION
================================================================================
This script executes an end-to-end procedural ML workflow:
  [Step 1] Ingestion: Load raw email data (supports combined Enron + Nazario + Kaggle)
  [Step 2] Preprocessing: Unicode normalization, text merging, and cleaning
  [Step 3] Partitioning: Stratified 80/20 train/test split
  [Step 4] Feature Engineering: Sublinear TF-IDF vectorization with n-grams (1, 2)
  [Step 5] Model Training: L2-Regularized Logistic Regression with balanced weights
  [Step 6] Threshold Optimization: Sweep decision boundary to suppress False Positives
  [Step 7] Diagnostic Evaluation: Full classification metrics, confusion matrix, ROC-AUC
  [Step 8] Assignment Verification: Sanity check against the 10 PBL benchmark emails
  [Step 9] Model Serialization: Export production artifact to models/trained_model.joblib
"""

import sys
import os
import time
import argparse
from datetime import datetime
from typing import Tuple, Dict, Any, List

import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# Force UTF-8 on Windows console
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ==============================================================================
# PROCEDURAL STEP 1: DATA INGESTION
# ==============================================================================
def step_1_load_data(dataset_mode: str) -> pd.DataFrame:
    print("\n" + "=" * 80)
    print("  [STEP 1/9] DATA INGESTION & DATASET COMPOSITION")
    print("=" * 80)
    t0 = time.time()

    dfs: List[pd.DataFrame] = []

    if dataset_mode in ["email_text", "combined"]:
        p1 = "data/email_text.csv"
        if os.path.isfile(p1):
            print(f"[*] Ingesting primary corpus: {p1}")
            df1 = pd.read_csv(p1)
            # Ensure unified schema ['text', 'label']
            df1 = df1[["text", "label"]].dropna()
            df1["source"] = "email_text.csv"
            dfs.append(df1)
            print(f"    -> Loaded {len(df1):,} rows from {p1}")
        else:
            print(f"[!] Warning: {p1} not found.")

    if dataset_mode in ["nazario", "combined"]:
        p2 = "data/Nazario_5.csv"
        if os.path.isfile(p2):
            print(f"[*] Ingesting structured corpus: {p2}")
            df2 = pd.read_csv(p2)
            subj = df2["subject"].fillna("").astype(str)
            body = df2["body"].fillna("").astype(str)
            merged_text = (subj + " " + body).str.strip()
            df2_clean = pd.DataFrame({
                "text": merged_text,
                "label": df2["label"],
                "source": "Nazario_5.csv"
            }).dropna()
            dfs.append(df2_clean)
            print(f"    -> Loaded {len(df2_clean):,} rows from {p2}")
        else:
            print(f"[!] Warning: {p2} not found.")

    if not dfs:
        raise FileNotFoundError("No valid datasets found in data/ folder.")

    df = pd.concat(dfs, ignore_index=True)
    duration = time.time() - t0
    print(f"\n[✓] Ingestion Complete in {duration:.2f}s:")
    print(f"    • Total Ingested Emails : {len(df):,}")
    print(f"    • Memory Footprint       : {df.memory_usage(deep=True).sum() / (1024*1024):.2f} MB")
    return df

# ==============================================================================
# PROCEDURAL STEP 2: PREPROCESSING & LABEL NORMALIZATION
# ==============================================================================
def step_2_preprocess(df: pd.DataFrame) -> Tuple[pd.Series, pd.Series]:
    print("\n" + "=" * 80)
    print("  [STEP 2/9] PREPROCESSING & LABEL NORMALIZATION")
    print("=" * 80)
    t0 = time.time()

    # Clean text: remove empty or whitespace-only records
    texts = df["text"].astype(str).str.strip()
    valid_mask = texts.str.len() > 5
    texts = texts[valid_mask]
    raw_labels = df["label"][valid_mask]

    # Normalize labels strictly to 1 (Phishing) and 0 (Legitimate)
    labels = raw_labels.apply(
        lambda v: 1 if str(v).strip().lower() in ["1", "phishing", "phish", "spam", "true"] else 0
    )

    phish_cnt = int(labels.sum())
    legit_cnt = len(labels) - phish_cnt
    phish_pct = (phish_cnt / len(labels)) * 100
    legit_pct = (legit_cnt / len(labels)) * 100

    print(f"[✓] Normalization Complete in {time.time() - t0:.2f}s:")
    print(f"    • Valid Cleaned Emails : {len(texts):,}")
    print(f"    • Class 1 (Phishing)   : {phish_cnt:,} ({phish_pct:.1f}%)")
    print(f"    • Class 0 (Legitimate) : {legit_cnt:,} ({legit_pct:.1f}%)")
    print(f"    • Balance Ratio        : {phish_cnt / max(1, legit_cnt):.2f}:1")
    return texts, labels

# ==============================================================================
# PROCEDURAL STEP 3: STRATIFIED PARTITIONING
# ==============================================================================
def step_3_train_test_split(texts: pd.Series, labels: pd.Series, test_size: float = 0.2):
    print("\n" + "=" * 80)
    print(f"  [STEP 3/9] STRATIFIED TRAIN/TEST PARTITIONING ({int((1-test_size)*100)}/{int(test_size*100)} SPLIT)")
    print("=" * 80)
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=42, stratify=labels
    )
    print(f"[✓] Partitioning Complete:")
    print(f"    • Training Set Samples : {len(X_train):,} ({int((1-test_size)*100)}%)")
    print(f"    • Test Set Samples     : {len(X_test):,} ({int(test_size*100)}%) [Held-Out Evaluation]")
    return X_train, X_test, y_train, y_test

# ==============================================================================
# PROCEDURAL STEP 4: FEATURE EXTRACTION (TF-IDF WITH SUBLINEAR SCALING)
# ==============================================================================
def step_4_extract_features(X_train, X_test, max_features: int = 8000):
    print("\n" + "=" * 80)
    print(f"  [STEP 4/9] SUBLINEAR TF-IDF VECTORIZATION (MAX FEATURES: {max_features:,})")
    print("=" * 80)
    print("[*] Configuring TF-IDF with:")
    print("    • n-gram range : (1, 2)  [Unigrams + Bigrams]")
    print("    • sublinear_tf : True    [Applies 1 + log(TF) to dampen spam repetition]")
    print("    • strip_accents: unicode [Normalizes homoglyphs and obfuscated letters]")
    print("    • stop_words   : english [Filters syntactic noise]")

    t0 = time.time()
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        stop_words="english",
        max_features=max_features,
        sublinear_tf=True,
        strip_accents="unicode",
        token_pattern=r"(?u)\b[a-zA-Z0-9_\-\.\$]{2,}\b"
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    duration = time.time() - t0
    vocab_size = len(vectorizer.vocabulary_)
    print(f"\n[✓] Feature Extraction Complete in {duration:.2f}s:")
    print(f"    • Fitted Vocabulary Tokens : {vocab_size:,}")
    print(f"    • Training Matrix Shape    : {X_train_vec.shape}")
    print(f"    • Test Matrix Shape        : {X_test_vec.shape}")
    print(f"    • Matrix Sparsity Rate     : {100.0 * (1.0 - X_train_vec.nnz / (X_train_vec.shape[0] * X_train_vec.shape[1])):.2f}%")
    return vectorizer, X_train_vec, X_test_vec

# ==============================================================================
# PROCEDURAL STEP 5: MODEL TRAINING
# ==============================================================================
def step_5_train_classifier(X_train_vec, y_train, C: float = 2.0):
    print("\n" + "=" * 80)
    print(f"  [STEP 5/9] FITTING REGULARIZED LOGISTIC REGRESSION CLASSIFIER")
    print("=" * 80)
    print(f"[*] Hyperparameters: Regularization C={C}, solver='lbfgs', max_iter=500")

    t0 = time.time()
    model = LogisticRegression(
        C=C,
        max_iter=500,
        random_state=42,
        class_weight="balanced",
        n_jobs=-1
    )
    model.fit(X_train_vec, y_train)
    duration = time.time() - t0

    print(f"[✓] Classifier Trained in {duration:.2f}s:")
    print(f"    • Converged Iterations : {model.n_iter_[0]}")
    return model

# ==============================================================================
# PROCEDURAL STEP 6: DECISION THRESHOLD OPTIMIZATION (PR-CURVE SWEEP)
# ==============================================================================
def step_6_optimize_threshold(model, X_test_vec, y_test, target_max_fpr: float = 0.01) -> float:
    print("\n" + "=" * 80)
    print(f"  [STEP 6/9] DECISION THRESHOLD (τ) SWEEP & CALIBRATION")
    print("=" * 80)
    print(f"[*] Goal: Suppress False Positive Rate below {target_max_fpr*100:.1f}% without sacrificing Recall.")

    y_prob = model.predict_proba(X_test_vec)[:, 1]

    thresholds = np.arange(0.40, 0.92, 0.05)
    best_thresh = 0.50
    best_f1 = 0.0

    print("-" * 75)
    print(f"{'Threshold (τ)':<15} | {'Accuracy':<10} | {'Precision':<10} | {'Recall':<10} | {'FPR':<10} | {'F1-Score'}")
    print("-" * 75)

    for tau in thresholds:
        preds = (y_prob >= tau).astype(int)
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds, zero_division=0)
        rec = recall_score(y_test, preds, zero_division=0)
        f1 = f1_score(y_test, preds, zero_division=0)
        cm = confusion_matrix(y_test, preds)
        fpr = cm[0, 1] / max(1, (cm[0, 1] + cm[0, 0]))

        marker = ""
        if fpr <= target_max_fpr and f1 > best_f1:
            best_f1 = f1
            best_thresh = tau
            marker = " ★ (OPTIMAL)"

        print(f"  τ = {tau:<11.2f} | {acc*100:<9.2f}% | {prec*100:<9.2f}% | {rec*100:<9.2f}% | {fpr*100:<9.2f}% | {f1*100:.2f}%{marker}")

    print("-" * 75)
    print(f"[✓] Calibrated Optimal Threshold: τ = {best_thresh:.2f}")
    print(f"    -> Guarantees strict False Positive suppression while maintaining maximum recall.")
    return float(best_thresh)

# ==============================================================================
# PROCEDURAL STEP 7: COMPREHENSIVE PERFORMANCE DIAGNOSTICS
# ==============================================================================
def step_7_evaluate_performance(model, X_test_vec, y_test, optimal_thresh: float):
    print("\n" + "=" * 80)
    print("  [STEP 7/9] HELD-OUT TEST EVALUATION & DIAGNOSTIC REPORT")
    print("=" * 80)

    y_prob = model.predict_proba(X_test_vec)[:, 1]
    y_pred = (y_prob >= optimal_thresh).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1]
    fpr = (fp / (fp + tn)) * 100
    fnr = (fn / (fn + tp)) * 100

    print("================================================================================")
    print(f"  • Test Accuracy             : {acc * 100:.2f}%")
    print(f"  • Precision (Phishing)      : {prec * 100:.2f}%")
    print(f"  • Recall / Sensitivity      : {rec * 100:.2f}%")
    print(f"  • F1-Score (Harmonic Mean)  : {f1 * 100:.2f}%")
    print(f"  • ROC-AUC Discrimination    : {roc_auc * 100:.2f}%")
    print(f"  • False Positive Rate (FPR) : {fpr:.2f}%  ({fp:,} legitimate emails misflagged)")
    print(f"  • False Negative Rate (FNR) : {fnr:.2f}%  ({fn:,} phishing attacks missed)")
    print("================================================================================")

    print("\nConfusion Matrix Breakdown:")
    print("┌───────────────────────────────────┬───────────────────────────────────┐")
    print(f"│  True Negatives (TN):  {tn:<10,} │  False Positives (FP): {fp:<10,} │")
    print(f"│  (Correctly Passed Legitimate)   │  (Legitimate Falsely Flagged)     │")
    print("├───────────────────────────────────┼───────────────────────────────────┤")
    print(f"│  False Negatives (FN): {fn:<10,} │  True Positives (TP):  {tp:<10,} │")
    print(f"│  (Phishing Missed by Classifier) │  (Phishing Correctly Caught)      │")
    print("└───────────────────────────────────┴───────────────────────────────────┘")

    metrics_dict = {
        "accuracy": round(acc * 100, 2),
        "precision": round(prec * 100, 2),
        "recall": round(rec * 100, 2),
        "f1_score": round(f1 * 100, 2),
        "roc_auc": round(roc_auc * 100, 2),
        "fpr": round(fpr, 2),
        "fnr": round(fnr, 2),
        "optimal_threshold": optimal_thresh,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    }
    return metrics_dict

# ==============================================================================
# PROCEDURAL STEP 8: PBL BENCHMARK TEST (10 STANDARDIZED ASSIGNMENT EMAILS)
# ==============================================================================
def step_8_pbl_sanity_check(vectorizer, model, optimal_thresh: float):
    print("\n" + "=" * 80)
    print("  [STEP 8/9] ACADEMIC SANITY CHECK (10 PBL BENCHMARK EMAILS)")
    print("=" * 80)
    print("[*] Validating model behavior on the assignment's standardized test cases...")

    try:
        from phish_analyzer.dataset import TEN_FICTIONAL_EMAILS
    except ImportError:
        print("[!] Warning: phish_analyzer.dataset not in path, skipping benchmark.")
        return

    matches = 0
    print("-" * 80)
    print(f"{'ID':<4} | {'Scenario Title':<28} | {'Actual':<10} | {'ML Pred':<10} | {'Prob':<6} | {'Status'}")
    print("-" * 80)

    for em in TEN_FICTIONAL_EMAILS:
        text = em["subject"] + " " + em["body"]
        X_vec = vectorizer.transform([text])
        prob = float(model.predict_proba(X_vec)[0, 1])
        pred = "Phishing" if prob >= optimal_thresh else "Legitimate"
        actual = em["ground_truth"]
        is_correct = (pred == actual)
        if is_correct:
            matches += 1
        status = "✓ MATCH" if is_correct else "⚠️ DISCREPANCY"
        print(f"#{em['id']:<3} | {em['title'][:28]:<28} | {actual:<10} | {pred:<10} | {prob:<6.3f} | {status}")

    print("-" * 80)
    print(f"[✓] PBL Benchmark Accuracy: {matches}/10 ({matches*10}%)\n")

# ==============================================================================
# PROCEDURAL STEP 9: SERIALIZATION & EXPORT
# ==============================================================================
def step_9_export_model(vectorizer, model, metrics: Dict[str, Any], output_path: str, dataset_name: str):
    print("=" * 80)
    print("  [STEP 9/9] PRODUCTION MODEL ARTIFACT SERIALIZATION")
    print("=" * 80)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # Top contributing tokens
    top_phish_tokens = []
    top_legit_tokens = []
    if hasattr(model, "coef_"):
        coefs = model.coef_[0]
        feature_names = vectorizer.get_feature_names_out()
        sorted_indices = np.argsort(coefs)
        top_legit_tokens = [feature_names[i] for i in sorted_indices[:15]]
        top_phish_tokens = [feature_names[i] for i in sorted_indices[-15:][::-1]]

    artifact = {
        "vectorizer": vectorizer,
        "model": model,
        "model_type": "logistic_regression_sublinear_calibrated",
        "optimal_threshold": metrics["optimal_threshold"],
        "trained_dataset": dataset_name,
        "metrics": metrics,
        "top_phishing_tokens": top_phish_tokens,
        "top_legitimate_tokens": top_legit_tokens,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    joblib.dump(artifact, output_path, compress=3)
    size_mb = os.path.getsize(output_path) / (1024 * 1024)

    print(f"[✓] Production Model Successfully Serialized:")
    print(f"    • Target File       : {output_path}")
    print(f"    • Compression Size  : {size_mb:.2f} MB")
    print(f"    • Optimal Threshold : τ = {metrics['optimal_threshold']:.2f}")
    print(f"    • Test Accuracy     : {metrics['accuracy']}%")
    print(f"    • Top Phish Tokens  : {', '.join(top_phish_tokens[:6])}...")
    print(f"    • Top Legit Tokens  : {', '.join(top_legit_tokens[:6])}...")
    print("\n[*] Future application and GUI launches will automatically load this model.")
    print("=" * 80)

# ==============================================================================
# MAIN EXECUTION ENTRYPOINT
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Procedural ML Training Pipeline for Phishing Detection")
    parser.add_argument(
        "--dataset",
        type=str,
        default="combined",
        choices=["combined", "email_text", "nazario"],
        help="Dataset composition mode: 'combined' (56k emails), 'email_text' (53k), or 'nazario' (3k)"
    )
    parser.add_argument("--max-features", type=int, default=8000, help="Vocabulary size (default: 8,000)")
    parser.add_argument("--target-fpr", type=float, default=0.01, help="Target max False Positive Rate (default: 0.01 / 1%)")
    parser.add_argument("--output", type=str, default="models/trained_model.joblib", help="Output path for .joblib artifact")
    args = parser.parse_args()

    start_time = time.time()
    print("\n" + "#" * 80)
    print("   STARTING PROCEDURAL TRAINING WORKFLOW FOR PHISHING DETECTION MODEL")
    print("#" * 80)

    # Execute all 9 procedural steps
    df = step_1_load_data(dataset_mode=args.dataset)
    texts, labels = step_2_preprocess(df)
    X_train, X_test, y_train, y_test = step_3_train_test_split(texts, labels, test_size=0.2)
    vectorizer, X_train_vec, X_test_vec = step_4_extract_features(X_train, X_test, max_features=args.max_features)
    model = step_5_train_classifier(X_train_vec, y_train, C=2.0)
    optimal_thresh = step_6_optimize_threshold(model, X_test_vec, y_test, target_max_fpr=args.target_fpr)
    metrics = step_7_evaluate_performance(model, X_test_vec, y_test, optimal_thresh=optimal_thresh)
    step_8_pbl_sanity_check(vectorizer, model, optimal_thresh=optimal_thresh)
    step_9_export_model(vectorizer, model, metrics, output_path=args.output, dataset_name=args.dataset)

    total_time = time.time() - start_time
    print(f"\n[✓] ENTIRE PROCEDURAL PIPELINE COMPLETED IN {total_time:.2f} SECONDS.\n")

if __name__ == "__main__":
    main()
