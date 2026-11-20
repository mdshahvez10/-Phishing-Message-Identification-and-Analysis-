"""
comparison.py
Independent Verification and AI Output Correction Engine.
Directly implements the PBL requirement:
"Independently label the examples using a predefined checklist; compare and correct the AI classifications."
"""

from typing import Dict, Any, List
from phish_analyzer.dataset import TEN_FICTIONAL_EMAILS
from phish_analyzer.checklist import VerificationChecklist
from phish_analyzer.detector import PhishingDetector

class DiscrepancyAnalyzer:
    """
    Analyzes the consensus and divergence between automated AI classification
    and the student's independent verification checklist.
    """

    def __init__(self):
        self.checklist = VerificationChecklist()
        self.detector = PhishingDetector()

    def run_comparative_analysis(self) -> Dict[str, Any]:
        """
        Processes all 10 fictional emails, computes metrics for both AI and Student Checklist,
        and isolates corrected discrepancies.
        """
        records: List[Dict[str, Any]] = []
        discrepancies: List[Dict[str, Any]] = []

        # Metric counters
        ai_tp = ai_fp = ai_tn = ai_fn = 0
        student_tp = student_fp = student_tn = student_fn = 0

        for email in TEN_FICTIONAL_EMAILS:
            ground_truth = email["ground_truth"]
            ai_label = email["ai_initial_label"]
            
            # Run student checklist
            chk_result = self.checklist.evaluate_email(email)
            student_label = chk_result["student_label"]

            # Run heuristic detector
            det_result = self.detector.analyze(email)

            # AI metrics
            if ground_truth == "Phishing" and ai_label == "Phishing":
                ai_tp += 1
            elif ground_truth == "Legitimate" and ai_label == "Phishing":
                ai_fp += 1
            elif ground_truth == "Legitimate" and ai_label == "Legitimate":
                ai_tn += 1
            elif ground_truth == "Phishing" and ai_label == "Legitimate":
                ai_fn += 1

            # Student metrics
            if ground_truth == "Phishing" and student_label == "Phishing":
                student_tp += 1
            elif ground_truth == "Legitimate" and student_label == "Phishing":
                student_fp += 1
            elif ground_truth == "Legitimate" and student_label == "Legitimate":
                student_tn += 1
            elif ground_truth == "Phishing" and student_label == "Legitimate":
                student_fn += 1

            is_discrepancy = (ai_label != student_label) or (ai_label != ground_truth)
            
            rec = {
                "id": email["id"],
                "title": email["title"],
                "ground_truth": ground_truth,
                "ai_initial_label": ai_label,
                "ai_confidence": email["ai_confidence"],
                "student_checklist_score": chk_result["checklist_score"],
                "student_label": student_label,
                "heuristic_score": det_result["risk_score"],
                "heuristic_label": det_result["classification"],
                "is_discrepancy": is_discrepancy,
                "discrepancy_note": email["discrepancy_note"],
                "safe_response": email["safe_response"],
                "key_indicators": email["key_indicators"]
            }
            records.append(rec)

            if is_discrepancy:
                discrepancies.append({
                    "id": email["id"],
                    "title": email["title"],
                    "ground_truth": ground_truth,
                    "ai_prediction": ai_label,
                    "student_correction": student_label,
                    "error_type": "False Negative (AI missed attack)" if ai_label == "Legitimate" else "False Positive (AI flagged benign email)",
                    "detailed_explanation": email["discrepancy_note"]
                })

        # Calculate metrics
        def calc_stats(tp, fp, tn, fn):
            total = tp + fp + tn + fn
            acc = (tp + tn) / total if total > 0 else 0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
            return {
                "tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "accuracy": round(acc * 100, 2),
                "precision": round(prec * 100, 2),
                "recall": round(rec * 100, 2),
                "f1_score": round(f1 * 100, 2)
            }

        ai_metrics = calc_stats(ai_tp, ai_fp, ai_tn, ai_fn)
        student_metrics = calc_stats(student_tp, student_fp, student_tn, student_fn)

        return {
            "records": records,
            "discrepancies": discrepancies,
            "ai_metrics": ai_metrics,
            "student_metrics": student_metrics,
            "total_emails": len(TEN_FICTIONAL_EMAILS),
            "discrepancy_count": len(discrepancies)
        }
