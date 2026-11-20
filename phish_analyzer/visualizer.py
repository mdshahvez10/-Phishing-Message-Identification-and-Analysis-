"""
visualizer.py
Generates visual charts and performance figures for the PBL project:
1. Confusion matrices (AI Model vs Student Checklist).
2. Indicator frequency distribution across phishing attacks.
3. Comparative evaluation metric bars (Accuracy, Precision, Recall, F1).
4. Threat score distribution per test email.
"""

import os
from typing import Dict, Any
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for generating figures cleanly
import matplotlib.pyplot as plt
import numpy as np

class ProjectVisualizer:
    """
    Produces publication-grade figures saved to the results/ directory.
    """

    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        # Style configuration
        plt.rcParams["font.sans-serif"] = "DejaVu Sans"
        plt.rcParams["axes.edgecolor"] = "#cccccc"
        plt.rcParams["axes.linewidth"] = 0.8

    def plot_confusion_matrices(self, ai_metrics: Dict[str, Any], student_metrics: Dict[str, Any]) -> str:
        """Generates side-by-side confusion matrices for AI and Student Checklist."""
        fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), dpi=200)

        # AI Matrix
        ai_mat = np.array([[ai_metrics["tp"], ai_metrics["fn"]],
                           [ai_metrics["fp"], ai_metrics["tn"]]])
        
        # Student Matrix
        stud_mat = np.array([[student_metrics["tp"], student_metrics["fn"]],
                             [student_metrics["fp"], student_metrics["tn"]]])

        labels = [["True Phishing (TP)", "False Legit (FN)"],
                  ["False Phishing (FP)", "True Legit (TN)"]]

        for ax, mat, title, color_theme in zip(
            axes, 
            [ai_mat, stud_mat], 
            [f"AI Model Alone\n(Accuracy: {ai_metrics['accuracy']}%)", 
             f"Student Checklist Verification\n(Accuracy: {student_metrics['accuracy']}%)"],
            [plt.cm.Oranges, plt.cm.Blues]
        ):
            cax = ax.matshow(mat, cmap=color_theme, alpha=0.75)
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, f"{mat[i, j]}\n({labels[i][j]})", 
                            ha="center", va="center", color="#111111", fontsize=10, fontweight="bold")
            
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(["Predicted Phish", "Predicted Legit"], fontsize=9)
            ax.set_yticklabels(["Actual Phish", "Actual Legit"], fontsize=9)
            ax.set_title(title, fontsize=11, fontweight="bold", pad=12)

        plt.suptitle("PBL Activity 5: Confusion Matrix Comparison (AI vs Human Verification)", fontsize=13, fontweight="bold", y=1.02)
        plt.tight_layout()
        out_path = os.path.join(self.output_dir, "confusion_matrix.png")
        plt.savefig(out_path, bbox_inches="tight")
        plt.close()
        return out_path

    def plot_metric_comparison(self, ai_metrics: Dict[str, Any], student_metrics: Dict[str, Any]) -> str:
        """Generates bar chart comparing Accuracy, Precision, Recall, and F1."""
        metrics = ["Accuracy", "Precision", "Recall", "F1 Score"]
        ai_vals = [ai_metrics["accuracy"], ai_metrics["precision"], ai_metrics["recall"], ai_metrics["f1_score"]]
        stud_vals = [student_metrics["accuracy"], student_metrics["precision"], student_metrics["recall"], student_metrics["f1_score"]]

        x = np.arange(len(metrics))
        width = 0.35

        fig, ax = plt.subplots(figsize=(8, 4.5), dpi=200)
        rects1 = ax.bar(x - width/2, ai_vals, width, label="AI Model (Baseline)", color="#f28e2b", edgecolor="#b05b00")
        rects2 = ax.bar(x + width/2, stud_vals, width, label="Student Checklist (Independent)", color="#4e79a7", edgecolor="#24446b")

        ax.set_ylabel("Score (%)", fontsize=10, fontweight="bold")
        ax.set_title("Detection Performance Metrics: AI Model vs. Student Verification", fontsize=12, fontweight="bold", pad=12)
        ax.set_xticks(x)
        ax.set_xticklabels(metrics, fontsize=10, fontweight="bold")
        ax.set_ylim(0, 115)
        ax.legend(frameon=True, facecolor="#ffffff", edgecolor="#cccccc")
        ax.grid(axis="y", linestyle="--", alpha=0.5)

        # Value labels on top of bars
        for rect in rects1:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, fontweight="bold")
        for rect in rects2:
            h = rect.get_height()
            ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=8, fontweight="bold")

        out_path = os.path.join(self.output_dir, "metric_comparison.png")
        plt.tight_layout()
        plt.savefig(out_path, bbox_inches="tight")
        plt.close()
        return out_path

    def plot_indicator_distribution(self) -> str:
        """Visualizes prevalence of suspicious phishing indicators across the test corpus."""
        indicators = [
            "SPF Failure / SoftFail",
            "DKIM Missing or Invalid",
            "Urgency / Fear Coercion",
            "Credential / Asset Solicitation",
            "Typosquatting / Lookalike Domain",
            "Direct IP / Insecure HTTP Link",
            "Macro / Executable Attachment",
            "Free Webmail Impersonation (BEC)"
        ]
        counts = [4, 4, 4, 3, 3, 2, 1, 1]

        fig, ax = plt.subplots(figsize=(9, 4.8), dpi=200)
        y_pos = np.arange(len(indicators))
        colors = plt.cm.viridis(np.linspace(0.3, 0.85, len(indicators)))

        bars = ax.barh(y_pos, counts, color=colors, edgecolor="#333333", height=0.6)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(indicators, fontsize=9, fontweight="bold")
        ax.invert_yaxis()
        ax.set_xlabel("Detection Count (out of 5 Phishing Emails)", fontsize=10, fontweight="bold")
        ax.set_title("Prevalence of Suspicious Indicators in Fictional Phishing Dataset", fontsize=12, fontweight="bold", pad=12)
        ax.set_xlim(0, 5.5)
        ax.grid(axis="x", linestyle="--", alpha=0.5)

        for bar in bars:
            w = bar.get_width()
            pct = int((w / 5.0) * 100)
            ax.text(w + 0.1, bar.get_y() + bar.get_height()/2, f"{w} ({pct}%)", va="center", ha="left", fontsize=9, fontweight="bold")

        out_path = os.path.join(self.output_dir, "indicator_distribution.png")
        plt.tight_layout()
        plt.savefig(out_path, bbox_inches="tight")
        plt.close()
        return out_path

    def plot_email_risk_scores(self, records: list) -> str:
        """Generates a comparison bar chart of risk scores across all 10 emails."""
        ids = [f"E{r['id']}: {r['ground_truth'][:1]}" for r in records]
        scores = [r["student_checklist_score"] for r in records]
        colors = ["#d95f02" if r["ground_truth"] == "Phishing" else "#2ca02c" for r in records]

        fig, ax = plt.subplots(figsize=(10, 4.5), dpi=200)
        bars = ax.bar(ids, scores, color=colors, edgecolor="#222222", width=0.55)
        ax.axhline(35, color="red", linestyle="--", linewidth=1.2, label="Phishing Threshold (Score = 35)")
        ax.set_ylabel("Checklist Threat Score (0 - 100)", fontsize=10, fontweight="bold")
        ax.set_title("Individual Threat Risk Score across 10 Fictional Emails", fontsize=12, fontweight="bold", pad=12)
        ax.set_ylim(0, 110)
        ax.grid(axis="y", linestyle=":", alpha=0.6)
        ax.legend(loc="upper right", frameon=True)

        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 2, f"{h}", ha="center", va="bottom", fontsize=8, fontweight="bold")

        out_path = os.path.join(self.output_dir, "risk_score_distribution.png")
        plt.tight_layout()
        plt.savefig(out_path, bbox_inches="tight")
        plt.close()
        return out_path

    def generate_all(self, comparison_data: Dict[str, Any]) -> Dict[str, str]:
        """Generates all figures and returns their filepaths."""
        paths = {}
        paths["confusion_matrix"] = self.plot_confusion_matrices(
            comparison_data["ai_metrics"], comparison_data["student_metrics"]
        )
        paths["metric_comparison"] = self.plot_metric_comparison(
            comparison_data["ai_metrics"], comparison_data["student_metrics"]
        )
        paths["indicator_distribution"] = self.plot_indicator_distribution()
        paths["risk_score_distribution"] = self.plot_email_risk_scores(
            comparison_data["records"]
        )
        return paths
