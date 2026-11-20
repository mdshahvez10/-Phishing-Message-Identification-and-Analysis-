"""
batch_evaluator.py
High-throughput batch evaluation engine for large phishing and email datasets.
Handles schema normalization, link extraction, ML inference, and metric calculations.
"""

import os
import re
import ast
import email.utils
from typing import Dict, Any, List, Optional, Callable
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score

from phish_analyzer.detector import PhishingDetector
from phish_analyzer.ml_model import PhishingMLClassifier

URL_REGEX = re.compile(r'https?://[^\s<>"\'\)]+')

def extract_urls_from_row(row: pd.Series) -> List[str]:
    """Safely extracts URL list from either a serialized list string or email body."""
    raw_urls = row.get("urls")
    if isinstance(raw_urls, str) and raw_urls.strip().startswith("["):
        try:
            parsed = ast.literal_eval(raw_urls)
            if isinstance(parsed, list):
                return [str(u) for u in parsed]
        except Exception:
            pass
    # Fallback to regex on body / text
    body = str(row.get("body", row.get("text", "")))
    return URL_REGEX.findall(body)

def normalize_label(val: Any) -> int:
    """Normalizes various label formats (1/0, 'phishing'/'legitimate', 'spam'/'ham') to 1 or 0."""
    if pd.isnull(val):
        return 0
    if isinstance(val, (int, np.integer, float, np.floating)):
        return 1 if int(val) == 1 else 0
    s = str(val).strip().lower()
    if s in ["1", "phishing", "phish", "spam", "true", "malicious", "attack"]:
        return 1
    return 0

class BatchEvaluator:
    """Evaluates CSV email datasets against the ML classifier and heuristic rule engine."""

    def __init__(self, ml_classifier: Optional[PhishingMLClassifier] = None):
        self.ml_classifier = ml_classifier or PhishingMLClassifier()
        self.detector = PhishingDetector()

    def evaluate_csv(
        self,
        csv_path: str,
        max_rows: Optional[int] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Loads a CSV dataset, runs evaluation, and computes comprehensive statistics.
        """
        if not os.path.isfile(csv_path):
            raise FileNotFoundError(f"Dataset file not found: {csv_path}")

        # Read CSV
        df = pd.read_csv(csv_path)
        total_rows = len(df)
        if total_rows == 0:
            raise ValueError("The provided CSV file contains no records.")

        cols = set(df.columns)
        has_text_col = "text" in cols
        has_body_col = "body" in cols
        has_subject_col = "subject" in cols
        has_sender_col = "sender" in cols
        has_label_col = "label" in cols
        if not has_label_col:
            raise ValueError("Dataset must contain a 'label' column.")

        # If max_rows requested, take a representative stratified sample
        if max_rows and max_rows < total_rows:
            try:
                # Group by label to ensure balanced evaluation
                half = max_rows // 2
                sampled = []
                for _, group in df.groupby("label"):
                    n = min(len(group), half)
                    sampled.append(group.sample(n=n, random_state=42))
                df = pd.concat(sampled).sample(frac=1.0, random_state=42).reset_index(drop=True)
            except Exception:
                df = df.head(max_rows)
            total_rows = len(df)

        records: List[Dict[str, Any]] = []
        y_true: List[int] = []
        y_pred: List[int] = []
        y_prob: List[float] = []

        step_interval = max(1, total_rows // 20)

        for idx, (_, row) in enumerate(df.iterrows()):
            # Construct text payload
            if has_text_col and pd.notnull(row["text"]):
                full_text = str(row["text"])
                subject = full_text[:60] + "..."
                body = full_text
            else:
                subj_str = str(row["subject"]) if has_subject_col and pd.notnull(row["subject"]) else ""
                body_str = str(row["body"]) if has_body_col and pd.notnull(row["body"]) else ""
                full_text = (subj_str + " " + body_str).strip()
                subject = subj_str if subj_str else (body_str[:60] + "...")
                body = body_str

            ground_truth = normalize_label(row["label"])
            y_true.append(ground_truth)

            # ML Prediction
            ml_res = self.ml_classifier.predict(full_text)
            pred_class = 1 if ml_res["prediction"] == "Phishing" else 0
            prob = ml_res["phishing_probability"]
            y_pred.append(pred_class)
            y_prob.append(prob)

            # Heuristic Rule prediction if sender or urls are present
            heuristic_res = None
            if has_sender_col or "urls" in cols:
                sender_raw = str(row["sender"]) if has_sender_col and pd.notnull(row["sender"]) else ""
                s_name, s_email = email.utils.parseaddr(sender_raw)
                links = extract_urls_from_row(row)

                email_obj = {
                    "sender_name": s_name,
                    "sender_email": s_email,
                    "reply_to": s_email,
                    "subject": subject,
                    "body": body,
                    "links": links,
                    "attachments": [],
                    "received_spf": "None",
                    "dkim_signature": "None"
                }
                heuristic_res = self.detector.analyze(email_obj)

            status = "CORRECT"
            if pred_class == 1 and ground_truth == 0:
                status = "FALSE_POSITIVE"
            elif pred_class == 0 and ground_truth == 1:
                status = "FALSE_NEGATIVE"

            records.append({
                "id": idx + 1,
                "subject": subject[:70],
                "ground_truth": "Phishing" if ground_truth == 1 else "Legitimate",
                "ml_prediction": ml_res["prediction"],
                "ml_probability": round(prob, 3),
                "status": status,
                "heuristic_score": heuristic_res["risk_score"] if heuristic_res else None,
                "heuristic_class": heuristic_res["classification"] if heuristic_res else None,
                "top_features": [f[0] for f in ml_res.get("contributing_features", [])[:3]]
            })

            if progress_callback and (idx % step_interval == 0 or idx == total_rows - 1):
                progress_callback(idx + 1, total_rows)

        # Compute Metrics
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        try:
            auc = roc_auc_score(y_true, y_prob)
        except Exception:
            auc = 0.5

        cm = confusion_matrix(y_true, y_pred)
        if cm.shape == (2, 2):
            tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
        else:
            tn, fp, fn, tp = 0, 0, 0, 0

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        return {
            "dataset_path": csv_path,
            "total_evaluated": total_rows,
            "metrics": {
                "accuracy": round(acc * 100, 2),
                "precision": round(prec * 100, 2),
                "recall": round(rec * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "roc_auc": round(auc * 100, 2),
                "fpr": round(fpr * 100, 2),
                "fnr": round(fnr * 100, 2)
            },
            "confusion_matrix": {
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp
            },
            "records": records
        }
