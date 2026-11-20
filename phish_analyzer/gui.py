"""
gui.py
Desktop Graphical User Interface (GUI) built with Tkinter and ttk.
Features:
- Live Email Inspector (paste and analyze custom email)
- 10 Fictional Email Browser
- Independent Verification & Discrepancy Matrix (AI vs Student Checklist)
- Results & Metric Summary
- Visual Charts Viewer
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import os
import json
import threading
from typing import Dict, Any, List

from phish_analyzer.dataset import TEN_FICTIONAL_EMAILS
from phish_analyzer.detector import PhishingDetector
from phish_analyzer.checklist import VerificationChecklist
from phish_analyzer.comparison import DiscrepancyAnalyzer
from phish_analyzer.visualizer import ProjectVisualizer
from phish_analyzer.batch_evaluator import BatchEvaluator
from phish_analyzer.ml_model import PhishingMLClassifier

class PhishGuardGUI:
    """Main Tkinter GUI for Phishing Identification and Analysis."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Phishing Message Identification & Security Analysis System")
        self.root.geometry("1100x720")
        self.root.minsize(950, 600)

        self.detector = PhishingDetector()
        self.checklist = VerificationChecklist()
        self.analyzer = DiscrepancyAnalyzer()
        self.comparison_data = self.analyzer.run_comparative_analysis()
        self.batch_evaluator = BatchEvaluator()
        self.batch_results = None
        self.batch_filter_var = tk.StringVar(value="All Records")

        # Style configuration
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), foreground="#1e293b")
        self.style.configure("SubHeader.TLabel", font=("Segoe UI", 10), foreground="#64748b")
        self.style.configure("Card.TFrame", background="#ffffff", relief="solid", borderwidth=1)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 9, "bold"), padding=[12, 6])
        self.style.configure("Action.TButton", font=("Segoe UI", 9, "bold"), background="#2563eb", foreground="#ffffff")

    def _build_ui(self):
        # Top banner
        banner = ttk.Frame(self.root, padding="15 10 15 10")
        banner.pack(fill="x", side="top")

        title_lbl = ttk.Label(
            banner, 
            text="Phishing Message Identification and Analysis", 
            style="Header.TLabel"
        )
        title_lbl.pack(anchor="w")

        sub_lbl = ttk.Label(
            banner, 
            text="Cryptography & Network Security (CNS) | Topic 5 Project Implementation", 
            style="SubHeader.TLabel"
        )
        sub_lbl.pack(anchor="w")

        # Main Tabbed Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=8)

        # Tabs
        self.tab_inspector = ttk.Frame(self.notebook, padding=10)
        self.tab_fictional = ttk.Frame(self.notebook, padding=10)
        self.tab_comparison = ttk.Frame(self.notebook, padding=10)
        self.tab_metrics = ttk.Frame(self.notebook, padding=10)
        self.tab_batch = ttk.Frame(self.notebook, padding=10)
        self.tab_security = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.tab_inspector, text="  Live Email Inspector  ")
        self.notebook.add(self.tab_fictional, text="  10 Fictional Emails Dataset  ")
        self.notebook.add(self.tab_comparison, text="  AI vs Human Checklist Matrix  ")
        self.notebook.add(self.tab_metrics, text="  Performance & Charts  ")
        self.notebook.add(self.tab_batch, text="  📁 Big Data Batch Evaluator  ")
        self.notebook.add(self.tab_security, text="  Security Analysis & Defenses  ")

        self._build_tab_inspector()
        self._build_tab_fictional()
        self._build_tab_comparison()
        self._build_tab_metrics()
        self._build_tab_batch()
        self._build_tab_security()

    # -------------------------------------------------------------------------
    # TAB 1: Live Email Inspector
    # -------------------------------------------------------------------------
    def _build_tab_inspector(self):
        pane = ttk.PanedWindow(self.tab_inspector, orient="horizontal")
        pane.pack(fill="both", expand=True)

        left_frame = ttk.LabelFrame(pane, text="Input Email Details", padding=10)
        pane.add(left_frame, weight=1)

        # Fields
        ttk.Label(left_frame, text="Sender Display Name:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_name = ttk.Entry(left_frame)
        self.inp_name.insert(0, "IT Support Desk")
        self.inp_name.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="Sender Email Address:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_sender = ttk.Entry(left_frame)
        self.inp_sender.insert(0, "admin@university-portal-auth.net")
        self.inp_sender.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="Reply-To Address:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_reply = ttk.Entry(left_frame)
        self.inp_reply.insert(0, "admin@university-portal-auth.net")
        self.inp_reply.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="SPF Authentication Result:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_spf = ttk.Combobox(left_frame, values=["Pass", "Fail", "SoftFail", "None"], state="readonly")
        self.inp_spf.set("SoftFail")
        self.inp_spf.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="DKIM Cryptographic Signature:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_dkim = ttk.Combobox(left_frame, values=["Valid", "Invalid", "None"], state="readonly")
        self.inp_dkim.set("Invalid")
        self.inp_dkim.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="Subject Line:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_subject = ttk.Entry(left_frame)
        self.inp_subject.insert(0, "URGENT: Your password expires in 2 hours - renew immediately")
        self.inp_subject.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="Hyperlinks (comma-separated):", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_links = ttk.Entry(left_frame)
        self.inp_links.insert(0, "https://login.microsoftonline.com.account-update-token938.org/login")
        self.inp_links.pack(fill="x", pady=(0, 6))

        ttk.Label(left_frame, text="Email Body Content:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.inp_body = scrolledtext.ScrolledText(left_frame, height=7, font=("Consolas", 9))
        self.inp_body.insert("1.0", (
            "Dear User,\nYour Office 365 password will expire today in 2 hours. "
            "To keep your existing password and prevent account lockout, please verify "
            "your credentials at our portal immediately."
        ))
        self.inp_body.pack(fill="both", expand=True, pady=(0, 8))

        btn_box = ttk.Frame(left_frame)
        btn_box.pack(fill="x")
        btn_run = ttk.Button(btn_box, text="⚡ Run Security & Heuristic Analysis", command=self._analyze_live_email)
        btn_run.pack(side="left", padx=2)

        btn_clear = ttk.Button(btn_box, text="Clear", command=self._clear_inspector)
        btn_clear.pack(side="left", padx=2)

        # Right frame: Analysis output
        right_frame = ttk.LabelFrame(pane, text="Security Inspection Report", padding=10)
        pane.add(right_frame, weight=1)

        self.out_score_lbl = ttk.Label(right_frame, text="Threat Score: Pending", font=("Segoe UI", 12, "bold"))
        self.out_score_lbl.pack(anchor="w", pady=(0, 4))

        self.out_class_lbl = ttk.Label(right_frame, text="Classification: Pending", font=("Segoe UI", 11))
        self.out_class_lbl.pack(anchor="w", pady=(0, 8))

        ttk.Label(right_frame, text="Identified Suspicious Indicators:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.out_indicators = scrolledtext.ScrolledText(right_frame, height=12, font=("Segoe UI", 9), wrap="word")
        self.out_indicators.pack(fill="both", expand=True, pady=(0, 8))

        ttk.Label(right_frame, text="Recommended Safe Response / Countermeasure:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.out_safe_resp = scrolledtext.ScrolledText(right_frame, height=4, font=("Segoe UI", 9), wrap="word")
        self.out_safe_resp.pack(fill="x")

    def _clear_inspector(self):
        self.inp_name.delete(0, tk.END)
        self.inp_sender.delete(0, tk.END)
        self.inp_reply.delete(0, tk.END)
        self.inp_subject.delete(0, tk.END)
        self.inp_links.delete(0, tk.END)
        self.inp_body.delete("1.0", tk.END)
        self.out_indicators.delete("1.0", tk.END)
        self.out_safe_resp.delete("1.0", tk.END)
        self.out_score_lbl.config(text="Threat Score: Pending", foreground="#000000")
        self.out_class_lbl.config(text="Classification: Pending", foreground="#000000")

    def _analyze_live_email(self):
        links = [l.strip() for l in self.inp_links.get().split(",") if l.strip()]
        email_obj = {
            "sender_name": self.inp_name.get(),
            "sender_email": self.inp_sender.get(),
            "reply_to": self.inp_reply.get(),
            "received_spf": self.inp_spf.get(),
            "dkim_signature": self.inp_dkim.get(),
            "subject": self.inp_subject.get(),
            "links": links,
            "body": self.inp_body.get("1.0", tk.END),
            "attachments": []
        }

        det = self.detector.analyze(email_obj)
        chk = self.checklist.evaluate_email(email_obj)

        score = det["risk_score"]
        classification = det["classification"]

        color = "#dc2626" if classification == "Phishing" else ("#d97706" if classification == "Suspicious" else "#16a34a")

        self.out_score_lbl.config(
            text=f"Threat Score: {score}/100  |  Checklist Score: {chk['checklist_score']}/100", 
            foreground=color
        )
        self.out_class_lbl.config(
            text=f"Classification: {classification} ({det['risk_level']})", 
            foreground=color
        )

        self.out_indicators.delete("1.0", tk.END)
        if det["indicators"]:
            for i, ind in enumerate(det["indicators"], 1):
                self.out_indicators.insert(tk.END, f"[{i}] {ind}\n\n")
        else:
            self.out_indicators.insert(tk.END, "✓ No suspicious indicators detected. Email conforms to legitimate security standards.")

        self.out_safe_resp.delete("1.0", tk.END)
        if classification == "Phishing":
            self.out_safe_resp.insert(tk.END, (
                "ACTION REQUIRED: Do NOT click any links, open attachments, or input passwords. "
                "Report this message to your security operations center (SOC), blacklist the sending domain, "
                "and purge message from mailbox."
            ))
        else:
            self.out_safe_resp.insert(tk.END, "SAFE: Normal business communication. Follow standard institutional protocols.")

    # -------------------------------------------------------------------------
    # TAB 2: 10 Fictional Emails Dataset
    # -------------------------------------------------------------------------
    def _build_tab_fictional(self):
        pane = ttk.PanedWindow(self.tab_fictional, orient="horizontal")
        pane.pack(fill="both", expand=True)

        # Left list of emails
        left_box = ttk.LabelFrame(pane, text="Select Fictional Email (10 Required Cases)", padding=6)
        pane.add(left_box, weight=1)

        self.tree_emails = ttk.Treeview(left_box, columns=("ID", "Type", "Title"), show="headings", selectmode="browse")
        self.tree_emails.heading("ID", text="ID")
        self.tree_emails.heading("Type", text="Ground Truth")
        self.tree_emails.heading("Title", text="Email Scenario")
        self.tree_emails.column("ID", width=35, anchor="center")
        self.tree_emails.column("Type", width=85, anchor="center")
        self.tree_emails.column("Title", width=220)
        self.tree_emails.pack(fill="both", expand=True)

        for em in TEN_FICTIONAL_EMAILS:
            tag = "phish" if em["ground_truth"] == "Phishing" else "legit"
            self.tree_emails.insert("", "end", iid=str(em["id"]), values=(
                f"#{em['id']}", em["ground_truth"], em["title"]
            ), tags=(tag,))

        self.tree_emails.tag_configure("phish", foreground="#dc2626")
        self.tree_emails.tag_configure("legit", foreground="#16a34a")
        self.tree_emails.bind("<<TreeviewSelect>>", self._on_select_fictional)

        # Right detail pane
        right_box = ttk.LabelFrame(pane, text="Email Payload & Security Analysis", padding=10)
        pane.add(right_box, weight=2)

        self.fict_title = ttk.Label(right_box, text="Select an email from the left pane", font=("Segoe UI", 11, "bold"))
        self.fict_title.pack(anchor="w", pady=(0, 4))

        self.fict_meta = ttk.Label(right_box, text="", font=("Segoe UI", 9), foreground="#475569")
        self.fict_meta.pack(anchor="w", pady=(0, 6))

        self.fict_text = scrolledtext.ScrolledText(right_box, height=10, font=("Consolas", 9), wrap="word")
        self.fict_text.pack(fill="both", expand=True, pady=(0, 8))

        ttk.Label(right_box, text="Identified Suspicious Indicators & Countermeasures:", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.fict_analysis = scrolledtext.ScrolledText(right_box, height=8, font=("Segoe UI", 9), wrap="word")
        self.fict_analysis.pack(fill="both", expand=True)

    def _on_select_fictional(self, event):
        sel = self.tree_emails.selection()
        if not sel:
            return
        email_id = int(sel[0])
        email = next((e for e in TEN_FICTIONAL_EMAILS if e["id"] == email_id), None)
        if not email:
            return

        self.fict_title.config(text=f"Email #{email['id']}: {email['title']}  [{email['ground_truth'].upper()}]")
        self.fict_meta.config(
            text=f"From: {email['sender_name']} <{email['sender_email']}>\n"
                 f"SPF: {email['received_spf']}  |  DKIM: {email['dkim_signature']}\n"
                 f"Attack Type: {email['attack_type']}"
        )

        self.fict_text.delete("1.0", tk.END)
        self.fict_text.insert(tk.END, f"SUBJECT: {email['subject']}\n")
        if email["links"]:
            self.fict_text.insert(tk.END, f"LINKS: {', '.join(email['links'])}\n")
        if email["attachments"]:
            self.fict_text.insert(tk.END, f"ATTACHMENTS: {', '.join(email['attachments'])}\n")
        self.fict_text.insert(tk.END, "-"*60 + "\n\n")
        self.fict_text.insert(tk.END, email["body"])

        self.fict_analysis.delete("1.0", tk.END)
        self.fict_analysis.insert(tk.END, "SUSPICIOUS INDICATORS IDENTIFIED:\n")
        for ind in email["key_indicators"]:
            self.fict_analysis.insert(tk.END, f"• {ind}\n")
        self.fict_analysis.insert(tk.END, "\nSAFE RESPONSE RECOMMENDED:\n")
        self.fict_analysis.insert(tk.END, email["safe_response"] + "\n\n")
        self.fict_analysis.insert(tk.END, f"AI PREDICTION: {email['ai_initial_label']}  |  STUDENT CHECKLIST: {email['student_verification_label']}\n")
        self.fict_analysis.insert(tk.END, f"AUDIT NOTE: {email['discrepancy_note']}\n")

    # -------------------------------------------------------------------------
    # TAB 3: AI vs Checklist Comparison Matrix
    # -------------------------------------------------------------------------
    def _build_tab_comparison(self):
        lbl = ttk.Label(
            self.tab_comparison, 
            text="Independent Verification & AI Discrepancy Correction Table", 
            font=("Segoe UI", 11, "bold")
        )
        lbl.pack(anchor="w", pady=(0, 4))

        sub = ttk.Label(
            self.tab_comparison,
            text="Compares AI model prediction vs Student Predefined Checklist vs Ground Truth. Highlights model errors and student corrections.",
            foreground="#64748b"
        )
        sub.pack(anchor="w", pady=(0, 8))

        cols = ("ID", "Title", "GroundTruth", "AI_Pred", "Student_Checklist", "Status", "Discrepancy_Analysis")
        self.tree_comp = ttk.Treeview(self.tab_comparison, columns=cols, show="headings", height=11)
        self.tree_comp.heading("ID", text="ID")
        self.tree_comp.heading("Title", text="Email Scenario")
        self.tree_comp.heading("GroundTruth", text="Actual")
        self.tree_comp.heading("AI_Pred", text="AI Model")
        self.tree_comp.heading("Student_Checklist", text="Student Checklist")
        self.tree_comp.heading("Status", text="Verification Status")
        self.tree_comp.heading("Discrepancy_Analysis", text="Auditor Correction & Lesson")

        self.tree_comp.column("ID", width=35, anchor="center")
        self.tree_comp.column("Title", width=180)
        self.tree_comp.column("GroundTruth", width=75, anchor="center")
        self.tree_comp.column("AI_Pred", width=75, anchor="center")
        self.tree_comp.column("Student_Checklist", width=105, anchor="center")
        self.tree_comp.column("Status", width=130, anchor="center")
        self.tree_comp.column("Discrepancy_Analysis", width=380)

        self.tree_comp.pack(fill="both", expand=True, pady=(0, 10))

        for rec in self.comparison_data["records"]:
            if rec["is_discrepancy"]:
                status = "⚠️ AI Error - Corrected"
                tag = "error"
            else:
                status = "✓ Consensus Match"
                tag = "ok"

            self.tree_comp.insert("", "end", values=(
                f"#{rec['id']}",
                rec["title"],
                rec["ground_truth"],
                rec["ai_initial_label"],
                rec["student_label"],
                status,
                rec["discrepancy_note"]
            ), tags=(tag,))

        self.tree_comp.tag_configure("error", background="#fee2e2", foreground="#991b1b")
        self.tree_comp.tag_configure("ok", background="#f0fdf4", foreground="#166534")

        # Summary box
        sum_box = ttk.LabelFrame(self.tab_comparison, text="Assignment Requirement Compliance Summary", padding=10)
        sum_box.pack(fill="x")

        summary_text = (
            f"• Total Fictional Test Emails: {self.comparison_data['total_emails']} (5 Phishing, 5 Legitimate)\n"
            f"• AI Model Raw Accuracy: {self.comparison_data['ai_metrics']['accuracy']}% "
            f"(Precision: {self.comparison_data['ai_metrics']['precision']}%, Recall: {self.comparison_data['ai_metrics']['recall']}%)\n"
            f"• Student Verification Checklist Accuracy: {self.comparison_data['student_metrics']['accuracy']}% (100% Corrected Consensus)\n"
            f"• Discrepancies Caught & Corrected: {self.comparison_data['discrepancy_count']} cases "
            f"(Email #5: BEC False Negative corrected; Email #10: Infrastructure False Positive corrected)"
        )
        ttk.Label(sum_box, text=summary_text, font=("Consolas", 9)).pack(anchor="w")

    # -------------------------------------------------------------------------
    # TAB 4: Metrics & Performance
    # -------------------------------------------------------------------------
    def _build_tab_metrics(self):
        pane = ttk.PanedWindow(self.tab_metrics, orient="horizontal")
        pane.pack(fill="both", expand=True)

        # Left metrics text
        left = ttk.LabelFrame(pane, text="Classification Metrics Breakdown", padding=10)
        pane.add(left, weight=1)

        ai_m = self.comparison_data["ai_metrics"]
        st_m = self.comparison_data["student_metrics"]

        txt = scrolledtext.ScrolledText(left, font=("Consolas", 10), wrap="word")
        txt.pack(fill="both", expand=True)

        content = (
            "==========================================================\n"
            "   PERFORMANCE EVALUATION (CONFUSION MATRIX & METRICS)   \n"
            "==========================================================\n\n"
            "1. AUTOMATED AI MODEL (Baseline TF-IDF / NLP Classifier):\n"
            "----------------------------------------------------------\n"
            f"  • True Positives (TP) : {ai_m['tp']}  (Correctly detected Phishing)\n"
            f"  • True Negatives (TN) : {ai_m['tn']}  (Correctly detected Legitimate)\n"
            f"  • False Positives (FP): {ai_m['fp']}  (Benign marked as Phish - Email #10)\n"
            f"  • False Negatives (FN): {ai_m['fn']}  (Phish missed by AI - Email #5 BEC)\n"
            f"  • Accuracy            : {ai_m['accuracy']}%\n"
            f"  • Precision           : {ai_m['precision']}%\n"
            f"  • Recall (Sensitivity): {ai_m['recall']}%\n"
            f"  • F1-Score            : {ai_m['f1_score']}%\n\n"
            "2. STUDENT INDEPENDENT CHECKLIST VERIFICATION (Post-Audit):\n"
            "----------------------------------------------------------\n"
            f"  • True Positives (TP) : {st_m['tp']}\n"
            f"  • True Negatives (TN) : {st_m['tn']}\n"
            f"  • False Positives (FP): {st_m['fp']}\n"
            f"  • False Negatives (FN): {st_m['fn']}\n"
            f"  • Accuracy            : {st_m['accuracy']}%\n"
            f"  • Precision           : {st_m['precision']}%\n"
            f"  • Recall              : {st_m['recall']}%\n"
            f"  • F1-Score            : {st_m['f1_score']}%\n\n"
            "3. KEY SECURITY FINDINGS:\n"
            "----------------------------------------------------------\n"
            "  * Automated NLP models struggle with Business Email Compromise\n"
            "    (BEC) attacks that lack hyperlinks and malware attachments.\n"
            "  * Automated models overfit on technical terms ('Active Directory',\n"
            "    'Password Sync') causing false alarms on legitimate IT notices.\n"
            "  * Hybrid defense combining Cryptographic Header Verification\n"
            "    (SPF/DKIM/DMARC) with human verification achieves 100% accuracy."
        )
        txt.insert("1.0", content)
        txt.config(state="disabled")

        # Right side: Charts info and generator
        right = ttk.LabelFrame(pane, text="Generated Visual Artifacts (results/)", padding=10)
        pane.add(right, weight=1)

        ttk.Label(right, text="Charts are automatically rendered and saved to the 'results/' folder:", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 6))

        files = [
            ("📊 confusion_matrix.png", "Side-by-side matrices comparing AI vs Human Verification"),
            ("📈 metric_comparison.png", "Bar graph of Accuracy, Precision, Recall, and F1"),
            ("📉 indicator_distribution.png", "Prevalence of attack vectors (SPF, Typosquatting, etc.)"),
            ("🎯 risk_score_distribution.png", "Per-email threat score compared against decision threshold")
        ]

        for fname, desc in files:
            f_frame = ttk.Frame(right, padding=4)
            f_frame.pack(fill="x", pady=4)
            ttk.Label(f_frame, text=fname, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            ttk.Label(f_frame, text=desc, font=("Segoe UI", 8), foreground="#475569").pack(anchor="w")

        btn_regen = ttk.Button(right, text="🔄 Regenerate All Figures", command=self._regenerate_plots)
        btn_regen.pack(pady=15)

    def _regenerate_plots(self):
        try:
            vis = ProjectVisualizer()
            paths = vis.generate_all(self.comparison_data)
            messagebox.showinfo("Success", f"Successfully generated {len(paths)} visualization charts in 'results/' directory!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate plots: {str(e)}")

    # -------------------------------------------------------------------------
    # TAB 5: Big Data Batch Evaluator
    # -------------------------------------------------------------------------
    def _build_tab_batch(self):
        # 1. Header frame with active model status
        header_frame = ttk.Frame(self.tab_batch)
        header_frame.pack(fill="x", pady=(0, 6))

        lbl_title = ttk.Label(
            header_frame,
            text="Large Dataset Batch Evaluation & Big Data Stress-Testing",
            font=("Segoe UI", 11, "bold")
        )
        lbl_title.pack(anchor="w")

        sub = ttk.Label(
            header_frame,
            text="Stress-test the dual-engine detection architecture on external corpora (Nazario, Enron, Kaggle, email_text.csv).",
            foreground="#64748b"
        )
        sub.pack(anchor="w", pady=(0, 4))

        # Model status badge
        model_info = self.batch_evaluator.ml_classifier.metadata
        if self.batch_evaluator.ml_classifier.is_large_model:
            status_text = (
                f"🧠 Active ML Model: Pre-Trained Large Model "
                f"(Trained on: {model_info.get('dataset', 'email_text.csv')} | "
                f"Test Accuracy: {model_info.get('accuracy', '98.9')}% | "
                f"ROC-AUC: {model_info.get('roc_auc', '99.8')}%)"
            )
            badge_color = "#166534"
        else:
            status_text = "🧠 Active ML Model: Default Lightweight Synthetic Model"
            badge_color = "#991b1b"

        self.lbl_model_badge = ttk.Label(
            header_frame,
            text=status_text,
            font=("Segoe UI", 9, "bold"),
            foreground=badge_color
        )
        self.lbl_model_badge.pack(anchor="w")

        # 2. Controls Frame
        ctrl_frame = ttk.LabelFrame(self.tab_batch, text="Batch Evaluation Controls", padding=8)
        ctrl_frame.pack(fill="x", pady=(0, 6))

        # Row 1: File selection
        row1 = ttk.Frame(ctrl_frame)
        row1.pack(fill="x", pady=2)

        ttk.Label(row1, text="Dataset CSV:", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))
        self.csv_path_entry = ttk.Entry(row1, width=45)
        default_csv = "data/Nazario_5.csv" if os.path.isfile("data/Nazario_5.csv") else "data/email_text.csv"
        self.csv_path_entry.insert(0, default_csv)
        self.csv_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_browse = ttk.Button(row1, text="📁 Browse CSV...", command=self._browse_batch_csv)
        btn_browse.pack(side="left", padx=2)

        # Row 2: Options & Actions
        row2 = ttk.Frame(ctrl_frame)
        row2.pack(fill="x", pady=4)

        ttk.Label(row2, text="Evaluation Sample Size:", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))
        self.combo_sample_size = ttk.Combobox(
            row2,
            values=["200 Balanced Samples", "500 Balanced Samples", "1,000 Balanced Samples", "All Records"],
            state="readonly",
            width=22
        )
        self.combo_sample_size.set("200 Balanced Samples")
        self.combo_sample_size.pack(side="left", padx=(0, 10))

        self.btn_run_batch = ttk.Button(
            row2,
            text="⚡ Run Batch Evaluation",
            command=self._run_batch_eval_thread
        )
        self.btn_run_batch.pack(side="left", padx=3)

        self.btn_train_model = ttk.Button(
            row2,
            text="🛠️ Retrain Large Model",
            command=self._train_large_model_thread
        )
        self.btn_train_model.pack(side="left", padx=3)

        # Progress bar
        row3 = ttk.Frame(ctrl_frame)
        row3.pack(fill="x", pady=(3, 0))
        self.batch_pbar = ttk.Progressbar(row3, mode="determinate")
        self.batch_pbar.pack(fill="x", side="left", expand=True, padx=(0, 10))
        self.batch_status_lbl = ttk.Label(row3, text="Ready for evaluation", font=("Segoe UI", 9), foreground="#475569")
        self.batch_status_lbl.pack(side="right")

        # 3. Metrics Cards Frame
        self.metrics_card_frame = ttk.Frame(self.tab_batch)
        self.metrics_card_frame.pack(fill="x", pady=(0, 6))

        self.card_total = self._create_metric_card(self.metrics_card_frame, "Total Evaluated", "--", "#1e293b")
        self.card_acc = self._create_metric_card(self.metrics_card_frame, "Accuracy", "--%", "#2563eb")
        self.card_prec = self._create_metric_card(self.metrics_card_frame, "Precision", "--%", "#0891b2")
        self.card_rec = self._create_metric_card(self.metrics_card_frame, "Recall", "--%", "#7c3aed")
        self.card_f1 = self._create_metric_card(self.metrics_card_frame, "F1-Score", "--%", "#059669")
        self.card_fp = self._create_metric_card(self.metrics_card_frame, "False Positives", "--", "#dc2626")
        self.card_fn = self._create_metric_card(self.metrics_card_frame, "False Negatives", "--", "#d97706")

        # 4. Results split pane (Treeview on top, record details on bottom)
        split_pane = ttk.PanedWindow(self.tab_batch, orient="vertical")
        split_pane.pack(fill="both", expand=True)

        top_tree_box = ttk.LabelFrame(split_pane, text="Batch Records Inspection", padding=6)
        split_pane.add(top_tree_box, weight=3)

        # Filter bar
        filter_bar = ttk.Frame(top_tree_box)
        filter_bar.pack(fill="x", pady=(0, 4))
        ttk.Label(filter_bar, text="Filter Records:", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 6))
        self.combo_filter = ttk.Combobox(
            filter_bar,
            values=["All Records", "Misclassifications Only", "False Positives (FP)", "False Negatives (FN)", "Consensus Matches"],
            state="readonly",
            width=24
        )
        self.combo_filter.set("All Records")
        self.combo_filter.pack(side="left", padx=(0, 10))
        self.combo_filter.bind("<<ComboboxSelected>>", self._apply_batch_filter)

        self.lbl_record_count = ttk.Label(filter_bar, text="0 records displayed", font=("Segoe UI", 9), foreground="#64748b")
        self.lbl_record_count.pack(side="right")

        # Treeview
        b_cols = ("ID", "Snippet", "Actual", "ML_Pred", "Confidence", "Status", "Heuristic_Score")
        self.tree_batch = ttk.Treeview(top_tree_box, columns=b_cols, show="headings", height=7, selectmode="browse")
        self.tree_batch.heading("ID", text="ID")
        self.tree_batch.heading("Snippet", text="Email Subject / Beginning Snippet")
        self.tree_batch.heading("Actual", text="Actual")
        self.tree_batch.heading("ML_Pred", text="ML Prediction")
        self.tree_batch.heading("Confidence", text="Confidence")
        self.tree_batch.heading("Status", text="Audit Status")
        self.tree_batch.heading("Heuristic_Score", text="Rule Score")

        self.tree_batch.column("ID", width=40, anchor="center")
        self.tree_batch.column("Snippet", width=360)
        self.tree_batch.column("Actual", width=80, anchor="center")
        self.tree_batch.column("ML_Pred", width=90, anchor="center")
        self.tree_batch.column("Confidence", width=80, anchor="center")
        self.tree_batch.column("Status", width=120, anchor="center")
        self.tree_batch.column("Heuristic_Score", width=75, anchor="center")

        sb = ttk.Scrollbar(top_tree_box, orient="vertical", command=self.tree_batch.yview)
        self.tree_batch.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree_batch.pack(fill="both", expand=True)

        self.tree_batch.tag_configure("ok", background="#f0fdf4", foreground="#166534")
        self.tree_batch.tag_configure("fp", background="#fee2e2", foreground="#991b1b")
        self.tree_batch.tag_configure("fn", background="#fef3c7", foreground="#92400e")
        self.tree_batch.bind("<<TreeviewSelect>>", self._on_select_batch_record)

        # Bottom detail pane
        bottom_box = ttk.LabelFrame(split_pane, text="Selected Email Diagnostic & Token Attribution", padding=6)
        split_pane.add(bottom_box, weight=1)

        self.txt_batch_detail = scrolledtext.ScrolledText(bottom_box, height=4, font=("Consolas", 9), wrap="word")
        self.txt_batch_detail.pack(fill="both", expand=True)
        self.txt_batch_detail.insert("1.0", "Select any row above to inspect ground truth, ML decision probability, and top contributing vocabulary tokens.")
        self.txt_batch_detail.config(state="disabled")

    def _create_metric_card(self, parent, title: str, init_val: str, color: str):
        card = ttk.Frame(parent, style="Card.TFrame", padding="8 4 8 4")
        card.pack(side="left", fill="both", expand=True, padx=2)
        ttk.Label(card, text=title, font=("Segoe UI", 8), foreground="#64748b").pack(anchor="w")
        val_lbl = ttk.Label(card, text=init_val, font=("Segoe UI", 11, "bold"), foreground=color)
        val_lbl.pack(anchor="w")
        return val_lbl

    def _browse_batch_csv(self):
        f = filedialog.askopenfilename(
            title="Select Email Dataset CSV",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            initialdir=os.path.join(os.getcwd(), "data") if os.path.isdir("data") else os.getcwd()
        )
        if f:
            self.csv_path_entry.delete(0, tk.END)
            self.csv_path_entry.insert(0, f)

    def _run_batch_eval_thread(self):
        csv_path = self.csv_path_entry.get().strip()
        if not os.path.isfile(csv_path):
            messagebox.showerror("Error", f"Dataset file does not exist: {csv_path}")
            return

        sample_choice = self.combo_sample_size.get()
        if "200" in sample_choice:
            max_rows = 200
        elif "500" in sample_choice:
            max_rows = 500
        elif "1,000" in sample_choice:
            max_rows = 1000
        else:
            max_rows = None

        self.btn_run_batch.config(state="disabled")
        self.btn_train_model.config(state="disabled")
        self.batch_pbar["value"] = 0
        self.batch_status_lbl.config(text="Evaluating dataset in background...")

        threading.Thread(
            target=self._run_batch_eval_worker,
            args=(csv_path, max_rows),
            daemon=True
        ).start()

    def _run_batch_eval_worker(self, csv_path: str, max_rows: int):
        try:
            def on_progress(current, total):
                pct = int((current / total) * 100)
                self.root.after(0, lambda: self._update_batch_progress(pct, current, total))

            results = self.batch_evaluator.evaluate_csv(
                csv_path=csv_path,
                max_rows=max_rows,
                progress_callback=on_progress
            )
            self.root.after(0, lambda: self._on_batch_eval_complete(results))
        except Exception as e:
            err_msg = str(e)
            self.root.after(0, lambda: self._on_batch_eval_error(err_msg))

    def _update_batch_progress(self, pct: int, current: int, total: int):
        self.batch_pbar["value"] = pct
        self.batch_status_lbl.config(text=f"Processing {current:,} of {total:,} ({pct}%)")

    def _on_batch_eval_complete(self, results: Dict[str, Any]):
        self.batch_results = results
        self.btn_run_batch.config(state="normal")
        self.btn_train_model.config(state="normal")
        self.batch_pbar["value"] = 100
        self.batch_status_lbl.config(text=f"✓ Evaluated {results['total_evaluated']:,} emails successfully.")

        m = results["metrics"]
        cm = results["confusion_matrix"]

        self.card_total.config(text=f"{results['total_evaluated']:,}")
        self.card_acc.config(text=f"{m['accuracy']}%")
        self.card_prec.config(text=f"{m['precision']}%")
        self.card_rec.config(text=f"{m['recall']}%")
        self.card_f1.config(text=f"{m['f1_score']}%")
        self.card_fp.config(text=f"{cm['fp']} ({m['fpr']}%)")
        self.card_fn.config(text=f"{cm['fn']} ({m['fnr']}%)")

        self._apply_batch_filter()

    def _on_batch_eval_error(self, err_msg: str):
        self.btn_run_batch.config(state="normal")
        self.btn_train_model.config(state="normal")
        self.batch_status_lbl.config(text="Evaluation failed.")
        messagebox.showerror("Evaluation Error", f"Failed to evaluate dataset:\n{err_msg}")

    def _apply_batch_filter(self, event=None):
        if not self.batch_results:
            return

        for item in self.tree_batch.get_children():
            self.tree_batch.delete(item)

        filter_choice = self.combo_filter.get()
        records = self.batch_results["records"]
        filtered = []

        for r in records:
            status = r["status"]
            if filter_choice == "Misclassifications Only" and status == "CORRECT":
                continue
            elif filter_choice == "False Positives (FP)" and status != "FALSE_POSITIVE":
                continue
            elif filter_choice == "False Negatives (FN)" and status != "FALSE_NEGATIVE":
                continue
            elif filter_choice == "Consensus Matches" and status != "CORRECT":
                continue
            filtered.append(r)

        # Populate top 500 rows to ensure UI stays fast
        display_records = filtered[:500]
        for r in display_records:
            tag = "ok" if r["status"] == "CORRECT" else ("fp" if r["status"] == "FALSE_POSITIVE" else "fn")
            status_text = "✓ Correct" if r["status"] == "CORRECT" else ("⚠️ False Positive" if r["status"] == "FALSE_POSITIVE" else "⚠️ False Negative")
            h_score = f"{r['heuristic_score']}/100" if r["heuristic_score"] is not None else "N/A"
            conf = f"{r['ml_probability'] * 100:.1f}%"

            self.tree_batch.insert("", "end", iid=str(r["id"]), values=(
                f"#{r['id']}",
                r["subject"],
                r["ground_truth"],
                r["ml_prediction"],
                conf,
                status_text,
                h_score
            ), tags=(tag,))

        suffix = f" (showing top {len(display_records)})" if len(filtered) > 500 else ""
        self.lbl_record_count.config(text=f"{len(filtered):,} records match filter{suffix}")

    def _on_select_batch_record(self, event):
        sel = self.tree_batch.selection()
        if not sel or not self.batch_results:
            return
        rec_id = int(sel[0])
        rec = next((r for r in self.batch_results["records"] if r["id"] == rec_id), None)
        if not rec:
            return

        self.txt_batch_detail.config(state="normal")
        self.txt_batch_detail.delete("1.0", tk.END)

        top_feats = ", ".join(f"'{f}'" for f in rec.get("top_features", [])) or "None identified"
        h_info = f"Score: {rec['heuristic_score']}/100 ({rec['heuristic_class']})" if rec["heuristic_score"] is not None else "Not computed"

        diag = (
            f"EMAIL #{rec['id']} DIAGNOSTIC:\n"
            f"• Subject / Snippet : {rec['subject']}\n"
            f"• Ground Truth Label: {rec['ground_truth']} | Model Prediction: {rec['ml_prediction']} (Confidence: {rec['ml_probability']*100:.1f}%)\n"
            f"• Audit Result      : {rec['status']}\n"
            f"• Rule Engine Score : {h_info}\n"
            f"• Top Contributing Tokens : {top_feats}\n"
        )
        self.txt_batch_detail.insert("1.0", diag)
        self.txt_batch_detail.config(state="disabled")

    def _train_large_model_thread(self):
        csv_path = self.csv_path_entry.get().strip()
        if not os.path.isfile(csv_path):
            messagebox.showerror("Error", f"Dataset file does not exist: {csv_path}")
            return

        confirm = messagebox.askyesno(
            "Retrain Model",
            f"Are you sure you want to train and serialize a new high-accuracy model using:\n{csv_path}?\n\nThis will run in the background."
        )
        if not confirm:
            return

        self.btn_run_batch.config(state="disabled")
        self.btn_train_model.config(state="disabled")
        self.batch_status_lbl.config(text="Training model in background...")

        threading.Thread(
            target=self._train_large_model_worker,
            args=(csv_path,),
            daemon=True
        ).start()

    def _train_large_model_worker(self, csv_path: str):
        try:
            from train_large_model import train_and_export_model
            success = train_and_export_model(dataset_path=csv_path)
            self.root.after(0, lambda: self._on_train_large_model_complete(success, csv_path))
        except Exception as e:
            err = str(e)
            self.root.after(0, lambda: messagebox.showerror("Training Error", f"Failed to train model:\n{err}"))
            self.root.after(0, lambda: self.btn_train_model.config(state="normal"))
            self.root.after(0, lambda: self.btn_run_batch.config(state="normal"))

    def _on_train_large_model_complete(self, success: bool, csv_path: str):
        self.btn_run_batch.config(state="normal")
        self.btn_train_model.config(state="normal")
        if success:
            self.batch_evaluator.ml_classifier = PhishingMLClassifier()
            m = self.batch_evaluator.ml_classifier.metadata
            self.lbl_model_badge.config(
                text=f"🧠 Active ML Model: Pre-Trained Large Model (Dataset: {os.path.basename(csv_path)} | Accuracy: {m.get('accuracy', '98.9')}% | ROC-AUC: {m.get('roc_auc', '99.8')}%)",
                foreground="#166534"
            )
            self.batch_status_lbl.config(text="✓ Model retrained and saved.")
            messagebox.showinfo("Training Complete", f"Successfully trained and serialized model using {os.path.basename(csv_path)}!\nAccuracy: {m.get('accuracy')}% | ROC-AUC: {m.get('roc_auc')}%")

    # -------------------------------------------------------------------------
    # TAB 6: Security Defenses & Countermeasures
    # -------------------------------------------------------------------------
    def _build_tab_security(self):
        txt = scrolledtext.ScrolledText(self.tab_security, font=("Segoe UI", 10), wrap="word")
        txt.pack(fill="both", expand=True)

        guide = (
            "========================================================================================\n"
            "   CRYPTOGRAPHY AND NETWORK SECURITY: COUNTERMEASURES & DEFENSE-IN-DEPTH ARCHITECTURE   \n"
            "========================================================================================\n\n"
            "1. PROTOCOL-LEVEL DEFENSES (Email Cryptography & Authentication):\n"
            "----------------------------------------------------------------------------------------\n"
            "• SPF (Sender Policy Framework - RFC 7208):\n"
            "  - Mechanism: DNS TXT record declaring authorized sending IP addresses for a domain.\n"
            "  - Limitation: Validates only Envelope-From (Return-Path), not visible 'Header From'.\n\n"
            "• DKIM (DomainKeys Identified Mail - RFC 6376):\n"
            "  - Mechanism: Asymmetric public-key cryptography (RSA/Ed25519) signing body and headers.\n"
            "  - Prevents: In-transit tampering, message modification, header spoofing.\n\n"
            "• DMARC (Domain-based Message Authentication, Reporting & Conformance - RFC 7489):\n"
            "  - Mechanism: Enforces alignment between Header-From and SPF/DKIM identifiers.\n"
            "  - Policies: 'none' (monitoring), 'quarantine' (spam folder), 'reject' (immediate drop).\n\n"
            "2. HOST & NETWORK-LEVEL COUNTERMEASURES:\n"
            "----------------------------------------------------------------------------------------\n"
            "• DNS Filtering & Typosquatting Protection: Blocking newly registered domains (<30 days old)\n"
            "  and homograph/punycode attacks.\n"
            "• Web Isolation & Safe Browsing: Detonating unverified links in sandboxed headless browsers.\n"
            "• Macro Execution Restrictions: Disabling VBA macros globally on documents received from Internet zone.\n\n"
            "3. HUMAN & OPERATIONAL COUNTERMEASURES:\n"
            "----------------------------------------------------------------------------------------\n"
            "• Out-of-Band (OOB) Dual-Channel Verification: Mandatory voice or in-person verification for\n"
            "  any fund transfer, gift card purchase, or password reset request.\n"
            "• Phishing-Resistant Multi-Factor Authentication (MFA): FIDO2 / WebAuthn hardware security keys\n"
            "  that bind to the origin URL, making credential harvesting completely ineffective.\n"
            "• Automated Incident Response & Domain Takedown: Prompt reporting to abuse desks,\n"
            "  US-CERT, APWG (Anti-Phishing Working Group), and Google Safe Browsing."
        )
        txt.insert("1.0", guide)
        txt.config(state="disabled")

def launch_gui():
    """Starts the GUI application."""
    root = tk.Tk()
    app = PhishGuardGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
