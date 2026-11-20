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
from tkinter import ttk, messagebox, scrolledtext
import os
import json
from typing import Dict, Any

from phish_analyzer.dataset import TEN_FICTIONAL_EMAILS
from phish_analyzer.detector import PhishingDetector
from phish_analyzer.checklist import VerificationChecklist
from phish_analyzer.comparison import DiscrepancyAnalyzer
from phish_analyzer.visualizer import ProjectVisualizer

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
        self.tab_security = ttk.Frame(self.notebook, padding=10)

        self.notebook.add(self.tab_inspector, text="  Live Email Inspector  ")
        self.notebook.add(self.tab_fictional, text="  10 Fictional Emails Dataset  ")
        self.notebook.add(self.tab_comparison, text="  AI vs Human Checklist Matrix  ")
        self.notebook.add(self.tab_metrics, text="  Performance & Charts  ")
        self.notebook.add(self.tab_security, text="  Security Analysis & Defenses  ")

        self._build_tab_inspector()
        self._build_tab_fictional()
        self._build_tab_comparison()
        self._build_tab_metrics()
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
    # TAB 5: Security Defenses & Countermeasures
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
