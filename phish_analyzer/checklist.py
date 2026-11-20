"""
checklist.py
Predefined Independent Verification Checklist (Mandated by Syllabus).
Used by students to independently audit emails, compute risk indicators,
and detect/correct AI misclassifications.
"""

from typing import Dict, Any, List

class VerificationChecklist:
    """
    Standard 7-Point Security Audit Checklist.
    Each checkpoint awards risk points and notes specific findings.
    """

    CHECKPOINTS = [
        {
            "id": "CHK_1",
            "name": "Sender Identity & SPF Authentication",
            "weight": 20,
            "description": "Verifies sender domain matches claimed entity and passes SPF authorization."
        },
        {
            "id": "CHK_2",
            "name": "Cryptographic Integrity (DKIM Signature)",
            "weight": 15,
            "description": "Verifies message possesses a valid cryptographic DKIM signature."
        },
        {
            "id": "CHK_3",
            "name": "URL & Hyperlink Destination Inspection",
            "weight": 20,
            "description": "Analyzes protocol (HTTP vs HTTPS), direct IP links, and typosquatting/subdomain deception."
        },
        {
            "id": "CHK_4",
            "name": "Psychological Urgency & Coercive Pressure",
            "weight": 15,
            "description": "Checks for artificial deadlines (e.g., 2h, 24h) and fear-inducing threats."
        },
        {
            "id": "CHK_5",
            "name": "Solicitation of Credentials or Financial Assets",
            "weight": 15,
            "description": "Examines whether email requests passwords, PINs, OTPs, wire transfers, or gift cards."
        },
        {
            "id": "CHK_6",
            "name": "Payload & Attachment Vulnerability",
            "weight": 10,
            "description": "Screens for macro-enabled (.xlsm) or executable attachments."
        },
        {
            "id": "CHK_7",
            "name": "Out-of-Band Verification Suppression & Context",
            "weight": 5,
            "description": "Detects excuses preventing phone/in-person verification ('in a meeting', 'no calls')."
        }
    ]

    def evaluate_email(self, email: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the 7-factor checklist on an email, returning detailed score and itemized breakdown.
        """
        findings: List[Dict[str, Any]] = []
        total_risk_score = 0

        sender = email.get("sender_email", "")
        spf = email.get("received_spf", "")
        dkim = email.get("dkim_signature", "")
        links = email.get("links", [])
        body = email.get("body", "")
        subject = email.get("subject", "")
        attachments = email.get("attachments", [])
        sender_name = email.get("sender_name", "")

        # 1. Sender Identity & SPF
        chk1_flagged = False
        chk1_notes = "Sender domain is authorized and authenticated."
        if "fail" in spf.lower():
            chk1_flagged = True
            chk1_notes = "FAIL: Sender IP address is not authorized under domain SPF record."
        elif "softfail" in spf.lower():
            chk1_flagged = True
            chk1_notes = "SOFTFAIL: SPF record does not explicitly permit sending IP."
        elif "gmail.com" in sender and any(t in sender_name.lower() for t in ["dean", "ceo", "director", "admin"]):
            chk1_flagged = True
            chk1_notes = "SUSPICIOUS: Authority figure using free commercial Gmail account."
        
        score1 = 20 if chk1_flagged else 0
        total_risk_score += score1
        findings.append({"id": "CHK_1", "name": "Sender Identity & SPF", "flagged": chk1_flagged, "points": score1, "notes": chk1_notes})

        # 2. DKIM Cryptographic Integrity
        chk2_flagged = False
        chk2_notes = "Valid DKIM cryptographic signature verified."
        if dkim.lower() in ["none", "missing"]:
            chk2_flagged = True
            chk2_notes = "FAIL: No cryptographic DKIM signature found on email."
        elif "invalid" in dkim.lower():
            chk2_flagged = True
            chk2_notes = "CRITICAL FAIL: DKIM signature verification failed (tampering detected)."

        score2 = 15 if chk2_flagged else 0
        total_risk_score += score2
        findings.append({"id": "CHK_2", "name": "Cryptographic Integrity (DKIM)", "flagged": chk2_flagged, "points": score2, "notes": chk2_notes})

        # 3. URL Inspection
        chk3_flagged = False
        chk3_notes = "URLs point to authentic HTTPS domain or no external links present."
        for l in links:
            if "http://" in l:
                chk3_flagged = True
                chk3_notes = "FAIL: Hyperlink utilizes unencrypted HTTP protocol."
                break
            if any(char.isdigit() for char in l.split("/")[2].split(".")[0]): # IP or lookalike
                if sum(c.isdigit() for c in l.split("/")[2]) > 6:
                    chk3_flagged = True
                    chk3_notes = "CRITICAL FAIL: Hyperlink uses raw numeric IP address."
                    break
            if any(tld in l for tld in [".xyz", ".info", ".top"]):
                chk3_flagged = True
                chk3_notes = "SUSPICIOUS: Hyperlink uses high-risk / cheap TLD."
                break
            if "account-update" in l or "portal-auth" in l:
                chk3_flagged = True
                chk3_notes = "FAIL: Subdomain spoofing detected in target URL."
                break

        score3 = 20 if chk3_flagged else 0
        total_risk_score += score3
        findings.append({"id": "CHK_3", "name": "URL Destination Inspection", "flagged": chk3_flagged, "points": score3, "notes": chk3_notes})

        # 4. Psychological Urgency
        chk4_flagged = False
        chk4_notes = "Message tone is informative, regular, and non-coercive."
        urgent_words = ["urgent", "action required", "suspended", "expires in 2 hours", "immediate", "within 24 hours"]
        if any(w in subject.lower() or w in body.lower() for w in urgent_words):
            chk4_flagged = True
            chk4_notes = "SUSPICIOUS: Coercive urgency, impending suspension or short deadline detected."

        score4 = 15 if chk4_flagged else 0
        total_risk_score += score4
        findings.append({"id": "CHK_4", "name": "Psychological Urgency & Fear", "flagged": chk4_flagged, "points": score4, "notes": chk4_notes})

        # 5. Data & Credential Solicitation
        chk5_flagged = False
        chk5_notes = "No sensitive passwords, PINs, or financial transactions solicited."
        if any(term in body.lower() for term in ["pin", "credentials", "direct deposit", "gift voucher", "gift cards", "wire transfer", "keep current password"]):
            chk5_flagged = True
            chk5_notes = "CRITICAL: Solicits sensitive authentication tokens, banking details, or financial funds."

        score5 = 15 if chk5_flagged else 0
        total_risk_score += score5
        findings.append({"id": "CHK_5", "name": "Credential / Asset Solicitation", "flagged": chk5_flagged, "points": score5, "notes": chk5_notes})

        # 6. Attachment Threat
        chk6_flagged = False
        chk6_notes = "No dangerous attachment formats or macros requested."
        if attachments:
            for a in attachments:
                if any(a.lower().endswith(ext) for ext in [".xlsm", ".exe", ".vbs", ".scr", ".zip"]):
                    chk6_flagged = True
                    chk6_notes = f"CRITICAL: Macro-enabled or executable payload attachment detected ('{a}')."
                    break
        if "enable content" in body.lower() or "enable macro" in body.lower():
            chk6_flagged = True
            chk6_notes = "CRITICAL: Explicit instruction instructing recipient to enable malicious macros."

        score6 = 10 if chk6_flagged else 0
        total_risk_score += score6
        findings.append({"id": "CHK_6", "name": "Payload & Attachment Safety", "flagged": chk6_flagged, "points": score6, "notes": chk6_notes})

        # 7. Out-of-band Verification Suppression
        chk7_flagged = False
        chk7_notes = "No suppression of communication; standard channels open."
        if "cannot take" in body.lower() or "in an all-day" in body.lower():
            chk7_flagged = True
            chk7_notes = "SUSPICIOUS: Excuses offered to prevent phone or in-person verification (BEC tactic)."

        score7 = 5 if chk7_flagged else 0
        total_risk_score += score7
        findings.append({"id": "CHK_7", "name": "Verification Suppression", "flagged": chk7_flagged, "points": score7, "notes": chk7_notes})

        # Final Checklist Classification
        student_label = "Phishing" if total_risk_score >= 35 else "Legitimate"

        return {
            "checklist_score": total_risk_score,
            "student_label": student_label,
            "checkpoints_evaluated": findings,
            "flags_raised": sum(1 for f in findings if f["flagged"])
        }
