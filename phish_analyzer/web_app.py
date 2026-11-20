"""
web_app.py
Lightweight Local Web Dashboard for Phishing Message Identification and Analysis.
Built using Python's standard library http.server (zero third-party web framework dependencies).
Ideal for demonstrations and demo video recording.
"""

import http.server
import socketserver
import json
import urllib.parse
import os
from typing import Dict, Any

from phish_analyzer.dataset import TEN_FICTIONAL_EMAILS
from phish_analyzer.detector import PhishingDetector
from phish_analyzer.checklist import VerificationChecklist
from phish_analyzer.comparison import DiscrepancyAnalyzer

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Message Identification & Security Analysis</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --danger: #dc2626;
            --success: #16a34a;
            --warning: #d97706;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: white;
            padding: 28px 32px;
            border-radius: 14px;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        header h1 { font-size: 26px; font-weight: 700; margin-bottom: 6px; }
        header p { color: #94a3b8; font-size: 14px; }
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            margin-top: 8px;
        }
        .badge-academic { background: #3b82f6; color: white; }
        .tabs {
            display: flex;
            gap: 8px;
            border-bottom: 2px solid var(--border);
            margin-bottom: 20px;
        }
        .tab-btn {
            background: none;
            border: none;
            padding: 10px 18px;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-muted);
            cursor: pointer;
            border-radius: 6px 6px 0 0;
            transition: all 0.2s;
        }
        .tab-btn.active {
            color: var(--primary);
            border-bottom: 3px solid var(--primary);
            background: #eff6ff;
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 22px;
            border: 1px solid var(--border);
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
            margin-bottom: 20px;
        }
        .card h2 { font-size: 18px; font-weight: 700; margin-bottom: 14px; color: #1e293b; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 4px; color: #334155; }
        input, select, textarea {
            width: 100%;
            padding: 9px 12px;
            border: 1px solid #cbd5e1;
            border-radius: 6px;
            font-size: 14px;
            margin-bottom: 12px;
            font-family: inherit;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
        }
        button.btn-primary {
            background: var(--primary);
            color: white;
            border: none;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
        }
        button.btn-primary:hover { background: var(--primary-dark); }
        .report-box {
            background: #f1f5f9;
            border-radius: 8px;
            padding: 16px;
            border-left: 4px solid var(--primary);
            margin-top: 10px;
        }
        .score-pill {
            font-size: 20px;
            font-weight: 800;
            display: inline-block;
            margin-bottom: 8px;
        }
        .table-responsive { overflow-x: auto; }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th, td {
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { background: #f8fafc; font-weight: 600; color: #475569; }
        tr:hover { background: #f8fafc; }
        .status-pill {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
        }
        .pill-phish { background: #fee2e2; color: #991b1b; }
        .pill-legit { background: #dcfce7; color: #166534; }
        .pill-warn { background: #fef3c7; color: #92400e; }
        .metric-card {
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            text-align: center;
        }
        .metric-val { font-size: 28px; font-weight: 800; color: var(--primary); }
        .metric-lbl { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px; }
        .email-item {
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px;
            margin-bottom: 12px;
            background: #ffffff;
            cursor: pointer;
            transition: all 0.2s;
        }
        .email-item:hover { border-color: var(--primary); box-shadow: 0 2px 6px rgba(0,0,0,0.05); }
        .email-meta { font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
        .email-body-box {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 12px;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            margin: 10px 0;
        }
        ul.indicator-list { list-style: none; margin-top: 8px; }
        ul.indicator-list li {
            padding: 6px 10px;
            background: #fef2f2;
            border-left: 3px solid #ef4444;
            margin-bottom: 6px;
            font-size: 12px;
            border-radius: 0 4px 4px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Phishing Message Identification & Analysis</h1>
            <p>Subject: Cryptography & Network Security | Activity 5 Implementation</p>
            <span class="badge badge-academic">PBL Practical Assignment</span>
        </header>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('tab-inspector')">Live Email Inspector</button>
            <button class="tab-btn" onclick="switchTab('tab-dataset')">10 Fictional Emails Dataset</button>
            <button class="tab-btn" onclick="switchTab('tab-matrix')">AI vs Student Checklist Matrix</button>
            <button class="tab-btn" onclick="switchTab('tab-metrics')">Metrics & Verification</button>
            <button class="tab-btn" onclick="switchTab('tab-countermeasures')">Security Countermeasures</button>
        </div>

        <!-- TAB 1: Live Inspector -->
        <div id="tab-inspector" class="tab-content active">
            <div class="grid-2">
                <div class="card">
                    <h2>Inspect Any Message</h2>
                    <label>Sender Display Name</label>
                    <input type="text" id="live-name" value="Bank Customer Support">

                    <label>Sender Email Address</label>
                    <input type="text" id="live-sender" value="security@chase-account-update.com">

                    <label>SPF Result</label>
                    <select id="live-spf">
                        <option value="Fail" selected>Fail (Unauthorized IP)</option>
                        <option value="SoftFail">SoftFail</option>
                        <option value="Pass">Pass</option>
                        <option value="None">None</option>
                    </select>

                    <label>DKIM Cryptographic Signature</label>
                    <select id="live-dkim">
                        <option value="None" selected>None (Missing)</option>
                        <option value="Invalid">Invalid (Tampered)</option>
                        <option value="Valid">Valid</option>
                    </select>

                    <label>Subject</label>
                    <input type="text" id="live-subject" value="URGENT: Suspended Account - Verify within 24 hours">

                    <label>Embedded Links (comma separated)</label>
                    <input type="text" id="live-links" value="http://login-chase-account-verify.xyz/login.php">

                    <label>Email Body</label>
                    <textarea id="live-body" rows="4">Dear Valued Customer, We detected an unauthorized attempt. Verify your login credentials and card PIN immediately or your account will be closed.</textarea>

                    <button class="btn-primary" onclick="runAnalysis()">⚡ Analyze Phishing Indicators</button>
                </div>

                <div class="card">
                    <h2>Live Threat Analysis Report</h2>
                    <div id="result-box" class="report-box">
                        <div id="res-score" class="score-pill" style="color: var(--danger);">Threat Score: 92/100</div>
                        <div id="res-status" style="font-weight: 700; margin-bottom: 10px;">Classification: Phishing (Critical Threat)</div>
                        <p style="font-size: 13px; font-weight: 600; margin-bottom: 6px;">Suspicious Indicators Detected:</p>
                        <ul id="res-indicators" class="indicator-list">
                            <li>Sender domain 'chase-account-update.com' is a lookalike domain, not authentic 'chase.com'</li>
                            <li>SPF check explicitly Failed</li>
                            <li>No cryptographic DKIM signature present</li>
                            <li>Severe fear-inducing language ('URGENT', 'within 24 hours')</li>
                            <li>Hyperlink points to insecure HTTP protocol on suspicious TLD (.xyz)</li>
                        </ul>
                        <p style="font-size: 13px; font-weight: 600; margin-top: 12px; margin-bottom: 4px;">Recommended Response:</p>
                        <p id="res-safe" style="font-size: 12px; color: #334155;">Do not click link. Report domain to security operations center and blackhole domain on DNS.</p>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: 10 Fictional Emails Dataset -->
        <div id="tab-dataset" class="tab-content">
            <div class="card">
                <h2>The 10 Fictional Emails (Assignment Requirement)</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                    Five realistic phishing scenarios (credential harvesting, typosquatting, malware attachment, smishing/delivery, and BEC executive impersonation)
                    and five legitimate organizational notifications (university registrar, authentic bank statement, GitHub dependabot alert, Amazon shipment receipt, and campus IT maintenance).
                </p>
                <div id="email-list-container">
                    <!-- Loaded dynamically via JavaScript -->
                </div>
            </div>
        </div>

        <!-- TAB 3: AI vs Student Checklist Matrix -->
        <div id="tab-matrix" class="tab-content">
            <div class="card">
                <h2>Independent Verification & AI Discrepancy Matrix</h2>
                <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
                    Required by Syllabus: "Independently label the examples using a predefined checklist; compare and correct the AI classifications."
                </p>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Scenario Title</th>
                                <th>Ground Truth</th>
                                <th>AI Model</th>
                                <th>Student Checklist</th>
                                <th>Verification Status</th>
                                <th>Discrepancy & Correction Analysis</th>
                            </tr>
                        </thead>
                        <tbody id="matrix-tbody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB 4: Metrics -->
        <div id="tab-metrics" class="tab-content">
            <div class="grid-4">
                <div class="metric-card">
                    <div class="metric-val" id="m-ai-acc">80.0%</div>
                    <div class="metric-lbl">AI Model Raw Accuracy</div>
                </div>
                <div class="metric-card">
                    <div class="metric-val" id="m-st-acc" style="color: var(--success);">100.0%</div>
                    <div class="metric-lbl">Human Checklist Accuracy</div>
                </div>
                <div class="metric-card">
                    <div class="metric-val" id="m-disc-count" style="color: var(--warning);">2</div>
                    <div class="metric-lbl">Discrepancies Caught</div>
                </div>
                <div class="metric-card">
                    <div class="metric-val" id="m-total">10</div>
                    <div class="metric-lbl">Total Scenarios Audited</div>
                </div>
            </div>

            <div class="card">
                <h2>Comparison of Detection Metrics</h2>
                <table style="margin-bottom: 20px;">
                    <thead>
                        <tr>
                            <th>Performance Metric</th>
                            <th>AI Model (Baseline)</th>
                            <th>Student Verification Checklist</th>
                            <th>Security Interpretation</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong>Accuracy</strong></td>
                            <td>80.0%</td>
                            <td><strong style="color: var(--success);">100.0%</strong></td>
                            <td>Checklist corrected both AI errors (1 False Negative, 1 False Positive).</td>
                        </tr>
                        <tr>
                            <td><strong>Precision</strong></td>
                            <td>80.0%</td>
                            <td><strong style="color: var(--success);">100.0%</strong></td>
                            <td>No false alarms after student checklist review.</td>
                        </tr>
                        <tr>
                            <td><strong>Recall (Sensitivity)</strong></td>
                            <td>80.0%</td>
                            <td><strong style="color: var(--success);">100.0%</strong></td>
                            <td>Zero missed attacks after human context evaluation.</td>
                        </tr>
                        <tr>
                            <td><strong>F1-Score</strong></td>
                            <td>80.0%</td>
                            <td><strong style="color: var(--success);">100.0%</strong></td>
                            <td>Harmonic mean indicates optimal hybrid security posture.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TAB 5: Countermeasures -->
        <div id="tab-countermeasures" class="tab-content">
            <div class="card">
                <h2>Network & Cryptographic Countermeasures</h2>
                <div style="font-size: 14px; line-height: 1.7; color: #334155;">
                    <h3 style="color: #1e293b; margin: 12px 0 6px;">1. Cryptographic Authentication Frameworks</h3>
                    <p>• <strong>Sender Policy Framework (SPF):</strong> Validates return-path IP against authorized host list published in DNS TXT records.</p>
                    <p>• <strong>DomainKeys Identified Mail (DKIM):</strong> Employs public-key cryptography (asymmetric signing) to compute a cryptographic digest of header fields and body content, guaranteeing message integrity.</p>
                    <p>• <strong>DMARC Alignment:</strong> Enforces that the visible 'From' domain matches the authenticated SPF and DKIM domains, preventing display name / domain impersonation.</p>
                    
                    <h3 style="color: #1e293b; margin: 16px 0 6px;">2. Social Engineering & BEC Countermeasures</h3>
                    <p>• <strong>Out-of-Band (OOB) Verification:</strong> Establishing an independent secondary channel (voice call to known office phone) before approving fund transfers or sensitive credential updates.</p>
                    <p>• <strong>FIDO2 / WebAuthn Hardware Keys:</strong> Hardware-bound authentication tokens that resist credential harvesting because credentials cannot be proxied to an attacker's fake domain.</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        const emailsData = %EMAILS_JSON%;
        const comparisonData = %COMPARISON_JSON%;

        function switchTab(tabId) {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        }

        // Render dataset list
        const listContainer = document.getElementById('email-list-container');
        emailsData.forEach(em => {
            const isPhish = em.ground_truth === 'Phishing';
            const pillClass = isPhish ? 'pill-phish' : 'pill-legit';
            const item = document.createElement('div');
            item.className = 'email-item';
            item.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <strong style="font-size: 15px;">#${em.id} ${em.title}</strong>
                    <span class="status-pill ${pillClass}">${em.ground_truth.toUpperCase()}</span>
                </div>
                <div class="email-meta">
                    From: ${em.sender_name} &lt;${em.sender_email}&gt; | SPF: ${em.received_spf} | DKIM: ${em.dkim_signature}
                </div>
                <div style="font-size: 13px; font-weight: 600; color: #1e293b;">Subject: ${em.subject}</div>
                <div class="email-body-box">${em.body}</div>
                <div style="font-size: 12px; margin-top: 6px;">
                    <strong>Suspicious Indicators:</strong>
                    <ul class="indicator-list">
                        ${em.key_indicators.map(i => `<li>${i}</li>`).join('')}
                    </ul>
                </div>
                <div style="font-size: 12px; margin-top: 8px; color: #166534; background: #f0fdf4; padding: 8px; border-radius: 4px;">
                    <strong>Safe Response:</strong> ${em.safe_response}
                </div>
            `;
            listContainer.appendChild(item);
        });

        // Render matrix
        const tbody = document.getElementById('matrix-tbody');
        comparisonData.records.forEach(r => {
            const tr = document.createElement('tr');
            const statusClass = r.is_discrepancy ? 'pill-warn' : 'pill-legit';
            const statusText = r.is_discrepancy ? '⚠️ AI Error (Corrected)' : '✓ Consensus Match';
            tr.innerHTML = `
                <td><strong>#${r.id}</strong></td>
                <td>${r.title}</td>
                <td><span class="status-pill ${r.ground_truth === 'Phishing' ? 'pill-phish' : 'pill-legit'}">${r.ground_truth}</span></td>
                <td>${r.ai_initial_label}</td>
                <td><strong>${r.student_label}</strong></td>
                <td><span class="status-pill ${statusClass}">${statusText}</span></td>
                <td style="font-size: 12px; color: #334155;">${r.discrepancy_note}</td>
            `;
            tbody.appendChild(tr);
        });

        async function runAnalysis() {
            const payload = {
                sender_name: document.getElementById('live-name').value,
                sender_email: document.getElementById('live-sender').value,
                reply_to: document.getElementById('live-sender').value,
                received_spf: document.getElementById('live-spf').value,
                dkim_signature: document.getElementById('live-dkim').value,
                subject: document.getElementById('live-subject').value,
                links: document.getElementById('live-links').value.split(',').map(s => s.trim()).filter(Boolean),
                body: document.getElementById('live-body').value,
                attachments: []
            };

            try {
                const resp = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const res = await resp.json();

                const isPhish = res.classification === 'Phishing';
                document.getElementById('res-score').textContent = `Threat Score: ${res.risk_score}/100`;
                document.getElementById('res-score').style.color = isPhish ? 'var(--danger)' : 'var(--success)';
                document.getElementById('res-status').textContent = `Classification: ${res.classification} (${res.risk_level})`;
                document.getElementById('res-status').style.color = isPhish ? 'var(--danger)' : 'var(--success)';

                const indUl = document.getElementById('res-indicators');
                indUl.innerHTML = '';
                if (res.indicators.length > 0) {
                    res.indicators.forEach(i => {
                        const li = document.createElement('li');
                        li.textContent = i;
                        indUl.appendChild(li);
                    });
                } else {
                    indUl.innerHTML = '<li style="background:#f0fdf4; border-color:#22c55e; color:#166534;">✓ No suspicious indicators found. Conforms to authentic security standards.</li>';
                }

                document.getElementById('res-safe').textContent = isPhish
                    ? 'Do NOT click links, open attachments, or input credentials. Report to security operations center immediately.'
                    : 'Legitimate business communication. Safe to proceed through standard portal.';
            } catch (err) {
                alert('Analysis error: ' + err);
            }
        }
    </script>
</body>
</html>
"""

class PhishRequestHandler(http.server.BaseHTTPRequestHandler):
    detector = PhishingDetector()
    checklist = VerificationChecklist()
    analyzer = DiscrepancyAnalyzer()

    def do_GET(self):
        if self.path in ["/", "/index.html"]:
            comp_data = self.analyzer.run_comparative_analysis()
            html = HTML_TEMPLATE.replace("%EMAILS_JSON%", json.dumps(TEN_FICTIONAL_EMAILS))
            html = html.replace("%COMPARISON_JSON%", json.dumps(comp_data))
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode("utf-8"))
        elif self.path.startswith("/results/"):
            # Serve result image files if requested
            rel_path = self.path.lstrip("/")
            if os.path.exists(rel_path):
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.end_headers()
                with open(rel_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/analyze":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)
            email_data = json.loads(body_bytes.decode("utf-8"))

            det_res = self.detector.analyze(email_data)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(det_res).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress noisy console logs
        return

def launch_web_server(port: int = 8080):
    handler = PhishRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"[*] Local Web Dashboard running at: http://localhost:{port}")
        print("[*] Press Ctrl+C to terminate the web server.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Web server terminated.")

if __name__ == "__main__":
    launch_web_server()
