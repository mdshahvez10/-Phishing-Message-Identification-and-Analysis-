"""
train_large_model.py
Offline Machine Learning Training Pipeline for Large Phishing Datasets.
Trains TF-IDF n-gram vectorizer + Logistic Regression / Naive Bayes classifier
on large datasets (e.g. data/email_text.csv or data/Nazario_5.csv) and serializes the model.
"""

import sys
import os
import time
import argparse
import joblib
from datetime import datetime

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report

def train_and_export_model(
    dataset_path: str = "data/email_text.csv",
    output_path: str = "models/trained_model.joblib",
    max_features: int = 5000,
    model_type: str = "logistic_regression",
    test_size: float = 0.2
):
    print("=" * 75)
    print("   OFFLINE ML TRAINING PIPELINE FOR LARGE PHISHING DATASET")
    print("=" * 75)
    print(f"[*] Input Dataset : {dataset_path}")
    print(f"[*] Output Target : {output_path}")
    print(f"[*] Model Type    : {model_type}")
    print(f"[*] Max Features  : {max_features}")
    print(f"[*] Test Split    : {int(test_size * 100)}%\n")

    if not os.path.isfile(dataset_path):
        print(f"[!] Error: Dataset not found at {dataset_path}")
        return False

    # 1. Load Dataset
    print("[1/5] Loading dataset into memory...")
    t0 = time.time()
    df = pd.read_csv(dataset_path)
    load_time = time.time() - t0
    print(f"  [+] Loaded {len(df):,} records in {load_time:.2f}s")

    # Detect text and label columns
    if "text" in df.columns:
        texts = df["text"].fillna("").astype(str)
    elif "subject" in df.columns and "body" in df.columns:
        texts = (df["subject"].fillna("") + " " + df["body"].fillna("")).astype(str)
    elif "body" in df.columns:
        texts = df["body"].fillna("").astype(str)
    else:
        print("[!] Error: Could not identify email text column ('text' or 'subject'/'body').")
        return False

    if "label" not in df.columns:
        print("[!] Error: 'label' column is missing from dataset.")
        return False

    # Normalize labels
    labels = df["label"].apply(lambda v: 1 if str(v).strip().lower() in ["1", "phishing", "phish", "spam", "true"] else 0)
    phish_count = int(labels.sum())
    legit_count = len(labels) - phish_count
    print(f"  [+] Distribution: {phish_count:,} Phishing (1) | {legit_count:,} Legitimate (0)")

    # 2. Train/Test Split
    print("\n[2/5] Creating stratified train/test split...")
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=42, stratify=labels
    )
    print(f"  [+] Training set: {len(X_train):,} samples | Test set: {len(X_test):,} samples")

    # 3. Feature Extraction (TF-IDF)
    print("\n[3/5] Vectorizing text with TF-IDF (n-grams: 1 to 2)...")
    t_vec = time.time()
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        stop_words="english",
        max_features=max_features,
        token_pattern=r"(?u)\b[a-zA-Z0-9_\-\.\$]{2,}\b"
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"  [+] Vectorization completed in {time.time() - t_vec:.2f}s (Vocabulary: {len(vectorizer.vocabulary_):,} tokens)")

    # 4. Model Training
    print(f"\n[4/5] Fitting {model_type} classifier...")
    t_train = time.time()
    if model_type == "naive_bayes":
        model = MultinomialNB(alpha=0.1)
    else:
        model = LogisticRegression(C=1.5, max_iter=400, random_state=42, n_jobs=-1)

    model.fit(X_train_vec, y_train)
    fit_duration = time.time() - t_train
    print(f"  [+] Model trained in {fit_duration:.2f}s")

    # 5. Evaluation
    print("\n[5/5] Evaluating test performance...")
    y_pred = model.predict(X_test_vec)
    y_prob = model.predict_proba(X_test_vec)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 60)
    print("              MODEL EVALUATION METRICS               ")
    print("=" * 60)
    print(f"  • Test Accuracy : {acc * 100:.2f}%")
    print(f"  • Precision     : {prec * 100:.2f}%")
    print(f"  • Recall        : {rec * 100:.2f}%")
    print(f"  • F1-Score      : {f1 * 100:.2f}%")
    print(f"  • ROC-AUC Score : {roc_auc * 100:.2f}%")
    print("=" * 60)
    print("Confusion Matrix:")
    print(f"  True Negatives (TN): {cm[0, 0]:<6} | False Positives (FP): {cm[0, 1]:<6}")
    print(f"  False Negatives (FN): {cm[1, 0]:<6} | True Positives (TP): {cm[1, 1]:<6}")
    print("=" * 60)

    # Save artifact
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    payload = {
        "vectorizer": vectorizer,
        "model": model,
        "model_type": model_type,
        "trained_dataset": os.path.basename(dataset_path),
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics": {
            "accuracy": round(acc * 100, 2),
            "precision": round(prec * 100, 2),
            "recall": round(rec * 100, 2),
            "f1_score": round(f1 * 100, 2),
            "roc_auc": round(roc_auc * 100, 2)
        },
        "training_time_sec": round(fit_duration, 2),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    joblib.dump(payload, output_path, compress=3)
    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"\n[✓] High-accuracy model successfully serialized to: {output_path} ({file_size_mb:.2f} MB)")
    print("[*] Future application launches will load this model instantly without retraining.\n")
    return True

def main():
    parser = argparse.ArgumentParser(description="Train and serialize a high-accuracy phishing ML model.")
    parser.add_argument("--dataset", type=str, default="data/email_text.csv", help="Path to CSV dataset")
    parser.add_argument("--output", type=str, default="models/trained_model.joblib", help="Target .joblib file path")
    parser.add_argument("--max-features", type=int, default=5000, help="Maximum vocabulary features")
    parser.add_argument("--model-type", type=str, default="logistic_regression", choices=["logistic_regression", "naive_bayes"])
    args = parser.parse_args()

    train_and_export_model(
        dataset_path=args.dataset,
        output_path=args.output,
        max_features=args.max_features,
        model_type=args.model_type
    )

if __name__ == "__main__":
    main()
