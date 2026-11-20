# Phishing Message Identification and Analysis
### Cryptography and Network Security — Project-Based Learning (PBL) Assignment
**Activity 5:** Network Attacks and Countermeasures  
**Due Date:** 23/11/2026 | **Max Marks:** 10  
**Group Size:** 3 Students

---

## 🌟 Project Overview
This project provides an end-to-end cybersecurity solution for **Phishing Message Identification and Analysis**. It simulates real-world attack vectors, evaluates email cryptographic authentication protocols (SPF, DKIM, DMARC), benchmarks an automated AI/NLP model against an independent 7-point human verification checklist, and formulates defensive countermeasures.

---

## 🚀 Key Features

1. **Dual-Engine Detection Pipeline:**
   - **Engine 1 (Heuristic & Cryptographic):** Inspects SPF authorization, DKIM asymmetric signatures, sender vs. Reply-To mismatch, lookalike domain typosquatting, deceptive subdomains, raw IP hosts, insecure HTTP, and macro-enabled (`.xlsm`) attachments.
   - **Engine 2 (NLP & Machine Learning):** Employs TF-IDF n-gram vectorization with Logistic Regression / Naive Bayes models to evaluate vocabulary probabilities and top predictive tokens.
2. **Standardized 10 Fictional Emails Dataset:**
   - 5 diverse phishing scenarios (Banking credential theft, Office 365 subdomain spoofing, HR macro ransomware dropper, Courier delivery typosquatting, and Business Email Compromise / Executive BEC).
   - 5 legitimate communications (University registration notice, Bank statement with zero links, GitHub security advisory, Amazon receipt, and Campus IT server maintenance).
3. **Independent Verification & AI Discrepancy Matrix:**
   - Evaluates the 10 emails against an independent 7-checkpoint human checklist.
   - Unmasks **two critical AI errors**: a False Negative on link-free BEC fraud (Email #5) and a False Positive on IT maintenance notices (Email #10).
   - Demonstrates how human verification achieves **100% accuracy** over baseline AI's **80% accuracy**.
4. **Three User Interfaces:**
   - **Command Line Interface (CLI):** Formatted ASCII tables, metric outputs, and automatic chart generation.
   - **Desktop GUI:** Built with Tkinter with live email inspection, email browser, comparison matrix, and chart viewer.
   - **Local Web Dashboard:** Zero-dependency web server (`http://localhost:8080`) built with Python's standard library.
5. **Academic Deliverables Included:**
   - Full Academic Project Report ([PROJECT_REPORT.md](PROJECT_REPORT.md) & printable [PROJECT_REPORT.html](PROJECT_REPORT.html)).
   - Interactive 5-7 minute Slide Deck ([PRESENTATION_SLIDES.html](PRESENTATION_SLIDES.html)) with speaker script ([PRESENTATION_SCRIPT.md](PRESENTATION_SCRIPT.md)).
   - Viva-Voce preparation guide with 25+ questions & answers ([VIVA_VOCE_GUIDE.md](VIVA_VOCE_GUIDE.md)).
   - Publication-quality figures in `results/`.

---

## 📁 Repository Structure

```
c:\Users\wakar\Documents\Downloads\project\
│
├── PBL assignment.pdf             # Original university assignment specification
├── README.md                      # Project documentation and guide
├── requirements.txt               # Dependencies (scikit-learn, matplotlib, pandas, etc.)
├── run_project.bat                # 1-Click launcher script for Windows
├── main.py                        # Unified command line entrypoint
│
├── phish_analyzer/                # Core Python package
│   ├── __init__.py
│   ├── dataset.py                 # 10 fictional emails + expanded NLP training corpus
│   ├── detector.py                # Heuristic & cryptographic rule engine
│   ├── ml_model.py                # Scikit-learn TF-IDF + Logistic Regression/Naive Bayes
│   ├── checklist.py               # Predefined 7-point independent audit checklist
│   ├── comparison.py              # Discrepancy detector and metric calculator
│   ├── visualizer.py              # Publication-grade chart generator (Matplotlib)
│   ├── gui.py                     # Tkinter desktop user interface
│   └── web_app.py                 # Local Web Dashboard (standard library http.server)
│
├── results/                       # Generated visual artifacts & data
│   ├── confusion_matrix.png       # AI vs Student Checklist confusion matrices
│   ├── metric_comparison.png      # Accuracy, Precision, Recall, F1-Score bar chart
│   ├── indicator_distribution.png # Prevalence of phishing attack vectors
│   ├── risk_score_distribution.png# Threat scores across all 10 test emails
│   └── evaluation_results.json    # Complete JSON dataset with audit logs
│
├── PROJECT_REPORT.md              # Complete formal academic project report
├── PROJECT_REPORT.html            # Beautiful printable/convertible HTML report
├── PRESENTATION_SLIDES.html       # Fullscreen 5-7 minute slide deck (browser-based)
├── PRESENTATION_SCRIPT.md         # Slide-by-slide speaker notes for group of 3
└── VIVA_VOCE_GUIDE.md             # 25+ technical Q&A for faculty viva
```

---

## ⚡ Quick Start & Execution

### 1. Run via Windows 1-Click Launcher
- **Direct GUI Launcher:** Double-click `launch_gui.bat` in File Explorer to directly open the Desktop GUI (includes new Big Data Batch Evaluator tab).
- **Main Menu Launcher:** Double-click `run_project.bat` in File Explorer, or select an option from the menu:
- `[1]` Run CLI Evaluation
- `[2]` Launch Desktop GUI (with Big Data Batch Evaluator)
- `[3]` Launch Local Web Dashboard (`http://localhost:8080`)
- `[4]` Run Large Dataset Batch Evaluation (CLI Mode on `data/Nazario_5.csv`)
- `[5]` Retrain Large ML Model on `data/email_text.csv`
- `[6]` Regenerate Charts in `results/`
- `[7]` Open Printable Report (`PROJECT_REPORT.html`)
- `[8]` Open Presentation Slides (`PRESENTATION_SLIDES.html`)
- `[9]` Exit

### 2. Run via Command Line

```powershell
# Run CLI evaluation (prints comparison table, metrics, and generates charts)
python main.py --cli

# Launch the Tkinter Desktop GUI (with Big Data Batch Evaluator)
python main.py --gui

# Run Large Dataset Batch Evaluation from CLI
python main.py --batch data/Nazario_5.csv --samples 500

# Retrain and serialize high-accuracy model on 53k emails
python train_large_model.py --dataset data/email_text.csv

# Launch the Local Web Dashboard
python main.py --web
# Open browser at: http://localhost:8080

# Regenerate all visual charts
python main.py --charts
```

---

## 📊 Summary of Results

| Metric | Automated AI Model (Baseline) | Student Verification Checklist (Independent) |
| :--- | :---: | :---: |
| **Accuracy** | 80.0% | **100.0%** |
| **Precision** | 80.0% | **100.0%** |
| **Recall (Sensitivity)** | 80.0% | **100.0%** |
| **F1-Score** | 80.0% | **100.0%** |
| **False Positives (FP)** | 1 (Email #10 - IT Maintenance) | **0** |
| **False Negatives (FN)** | 1 (Email #5 - BEC Dean Fraud) | **0** |

---

## 🛡️ Mandatory AI Usage Declaration

1. **AI Tools Used:** DeepMind Gemini (via Antigravity) and Python Scikit-Learn.
2. **Purpose:** Synthesis of realistic scenario templates, baseline NLP modeling, and modular software scaffolding.
3. **Verification & Modification:** Students audited all RFC 5322 headers, unmasked AI failure modes on BEC and IT maintenance notices, built a 7-factor checklist to overrule AI misclassifications, and verified all code execution.
4. **Student Learnings:** Statistical AI filters are vulnerable to context blindness; cryptographic validation (DKIM/SPF) and human contextual verification are vital for cyber defense.
