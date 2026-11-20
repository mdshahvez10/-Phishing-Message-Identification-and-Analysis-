"""
detector.py
Rule-Based and Heuristic Cybersecurity Analysis Engine for Phishing Detection.
Examines cryptographic email headers, URL patterns, domain authenticity,
attachment threats, and social engineering language patterns.
"""

import re
from urllib.parse import urlparse
from typing import Dict, Any, List

class PhishingDetector:
    """
    Heuristic and Security Rule Engine for evaluating email threats.
    Provides detailed indicator breakdowns and security risk scoring.
    """

    # Urgency & Fear trigger patterns
    URGENCY_PATTERNS = [
        r"\burgent\b", r"\bimmediate(ly)?\b", r"\baction required\b", r"\bsuspended\b",
        r"\bterminated\b", r"\bwithin \d+ hours?\b", r"\bexpires in\b", r"\bclosure\b",
        r"\brestricted\b", r"\blimited\b", r"\blockout\b", r"\bunauthorized\b",
        r"\bpenalty\b", r"\bconfidential\b", r"\bas soon as possible\b"
    ]

    # Sensitive data solicitation
    CREDENTIAL_PATTERNS = [
        r"\bpassword\b", r"\blogin\b", r"\bpin\b", r"\bcredit card\b", r"\bssn\b",
        r"\bverify your identity\b", r"\brenew.*token\b", r"\bdirect deposit\b",
        r"\bgift cards?\b", r"\bwire transfer\b", r"\bbanking details\b",
        r"\bcard credentials\b", r"\bone-time (code|password|security)\b", r"\botp\b"
    ]

    # Impersonal salutations
    GENERIC_GREETINGS = [
        r"^dear (valued )?customer", r"^dear team member", r"^customer notification",
        r"^attention (campus )?user", r"^hello staff and students", r"^dear user"
    ]

    # High-risk TLDs and typosquatting signals
    SUSPICIOUS_TLDS = {".xyz", ".top", ".info", ".online", ".work", ".click", ".buzz", ".live"}
    DANGEROUS_EXTENSIONS = {".exe", ".scr", ".bat", ".vbs", ".cmd", ".ps1", ".xlsm", ".docm", ".jar", ".iso"}

    # Known legitimate institutional / tech / banking domains
    OFFICIAL_DOMAINS = {
        "chase.com", "university.edu", "github.com", "amazon.com", "microsoft.com",
        "google.com", "apple.com", "paypal.com", "fedex.com"
    }

    def analyze(self, email: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs comprehensive security heuristics on an email object.
        Returns a rich dictionary containing scores, indicators, and recommendations.
        """
        indicators: List[str] = []
        score = 0

        sender = email.get("sender_email", "").strip()
        reply_to = email.get("reply_to", "").strip()
        sender_name = email.get("sender_name", "").strip()
        subject = email.get("subject", "").strip()
        body = email.get("body", "").strip()
        links = email.get("links", [])
        attachments = email.get("attachments", [])
        spf = email.get("received_spf", "")
        dkim = email.get("dkim_signature", "")

        # -------------------------------------------------------------
        # 1. Email Header & Cryptographic Authentication Checks
        # -------------------------------------------------------------
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
        reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""

        # SPF Inspection
        if "fail" in spf.lower():
            score += 25
            indicators.append(f"SPF Authentication FAILED: Sender IP is not authorized to transmit for '{sender_domain}'")
        elif "softfail" in spf.lower():
            score += 15
            indicators.append(f"SPF Authentication SOFTFAIL: Domain owner does not fully authorize the sending host")

        # DKIM Inspection
        if dkim.lower() in ["none", "missing"]:
            score += 15
            indicators.append("DKIM Signature Missing: Email lacks cryptographic signature to verify message integrity")
        elif "invalid" in dkim.lower():
            score += 30
            indicators.append("DKIM Signature INVALID: Message payload or headers were tampered with during transit")

        # Sender vs Reply-To Mismatch
        if reply_domain and sender_domain and reply_domain != sender_domain:
            score += 20
            indicators.append(f"Sender / Reply-To Domain Mismatch: Sender '{sender_domain}' routes replies to '{reply_domain}'")

        # Free Webmail Impersonation (e.g. Dean / Exec using Gmail)
        free_webmail_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"]
        if sender_domain in free_webmail_providers:
            executive_keywords = ["dean", "ceo", "president", "director", "professor", "prof.", "admin", "it support"]
            if any(k in sender_name.lower() or k in subject.lower() for k in executive_keywords):
                score += 35
                indicators.append(f"Executive Impersonation (BEC): Free webmail provider '{sender_domain}' used with authority title '{sender_name}'")

        # Lookalike Domain / Brand Typosquatting
        for brand in ["chase", "fedex", "amazon", "microsoft", "paypal", "university"]:
            if brand in sender_domain and sender_domain not in self.OFFICIAL_DOMAINS:
                # e.g. chase-account-update.com or fedx
                score += 30
                indicators.append(f"Lookalike / Spoofed Sender Domain: '{sender_domain}' mimics legitimate brand '{brand}'")

        # -------------------------------------------------------------
        # 2. URL & Hyperlink Analysis
        # -------------------------------------------------------------
        for link in links:
            parsed = urlparse(link)
            host = parsed.netloc.lower()

            # Raw IP address used in URL
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", host):
                score += 35
                indicators.append(f"Suspicious Direct IP URL: Link '{link}' uses a raw IP address ({host}) instead of a domain")

            # Unencrypted HTTP used for credentials or banking
            if parsed.scheme == "http":
                score += 20
                indicators.append(f"Insecure HTTP Protocol: Link '{link}' uses unencrypted HTTP communication")

            # High-risk TLD
            for tld in self.SUSPICIOUS_TLDS:
                if host.endswith(tld):
                    score += 20
                    indicators.append(f"Suspicious Top-Level Domain (TLD): Link uses high-risk TLD '{tld}' in '{host}'")

            # Subdomain deception / multi-level domain spoofing
            # e.g., login.microsoftonline.com.account-update.org
            subdomain_parts = host.split(".")
            if len(subdomain_parts) >= 4:
                for brand in ["microsoftonline", "chase", "paypal", "google", "apple"]:
                    if brand in subdomain_parts[:-2]:  # brand is in prefix, not apex domain
                        score += 30
                        indicators.append(f"Subdomain Spoofing Detected: Brand name '{brand}' embedded in misleading subdomain of '{host}'")

        # -------------------------------------------------------------
        # 3. Attachment Analysis
        # -------------------------------------------------------------
        for att in attachments:
            ext = "." + att.split(".")[-1].lower() if "." in att else ""
            if ext in self.DANGEROUS_EXTENSIONS:
                score += 40
                indicators.append(f"Dangerous Attachment: '{att}' has executable or macro-enabled extension '{ext}'")

        if re.search(r"\benable (content|macros?)\b", body, re.IGNORECASE):
            score += 35
            indicators.append("Malicious Macro Lure: Email explicitly instructs user to 'enable macros' or 'enable content'")

        # -------------------------------------------------------------
        # 4. Social Engineering & Natural Language Analysis
        # -------------------------------------------------------------
        # Urgency Triggers
        found_urgency = []
        for pat in self.URGENCY_PATTERNS:
            if re.search(pat, subject, re.IGNORECASE) or re.search(pat, body, re.IGNORECASE):
                found_urgency.append(pat.replace(r"\b", "").replace(r"\d+", "N"))
        if found_urgency:
            urgency_score = min(25, len(set(found_urgency)) * 8)
            score += urgency_score
            indicators.append(f"Psychological Urgency & Fear Triggers: Detected keywords {list(set(found_urgency))[:4]}")

        # Credential / Asset Solicitation
        found_cred = []
        for pat in self.CREDENTIAL_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                found_cred.append(pat.replace(r"\b", ""))
        if found_cred:
            cred_score = min(30, len(set(found_cred)) * 10)
            score += cred_score
            indicators.append(f"Sensitive Data Solicitation: Solicits {list(set(found_cred))[:4]}")

        # Impersonal Greeting
        for greeting_pat in self.GENERIC_GREETINGS:
            if re.search(greeting_pat, body.strip(), re.IGNORECASE | re.MULTILINE):
                score += 10
                indicators.append("Generic Salutation: Impersonal greeting used instead of recipient's verified name")
                break

        # Out-of-band communication suppression
        if re.search(r"cannot (take|answer) (phone )?calls?|in an? (all-day )?meeting", body, re.IGNORECASE):
            score += 25
            indicators.append("Verification Suppression: Explicitly discourages out-of-band telephone verification")

        # -------------------------------------------------------------
        # 5. Legitimate Mitigation Factors
        # -------------------------------------------------------------
        # If SPF Pass, DKIM Valid, and matches verified domain with no bad links:
        if "pass" in spf.lower() and "valid" in dkim.lower() and sender_domain in self.OFFICIAL_DOMAINS:
            score = max(0, score - 35)

        # Explicit anti-phishing advice in email (legitimate bank standard)
        if re.search(r"will never (email or call|ask for your password|ask for otp)", body, re.IGNORECASE):
            score = max(0, score - 30)

        # "No user intervention required" (operational IT notification)
        if re.search(r"no user intervention is required", body, re.IGNORECASE):
            score = max(0, score - 25)

        # Bound score between 0 and 100
        score = max(0, min(100, score))

        # Risk level determination
        if score >= 70:
            risk_level = "Critical Threat"
            classification = "Phishing"
        elif score >= 45:
            risk_level = "High Suspicion"
            classification = "Phishing"
        elif score >= 25:
            risk_level = "Medium (Caution)"
            classification = "Suspicious"
        else:
            risk_level = "Low (Safe)"
            classification = "Legitimate"

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "classification": classification,
            "is_phishing": classification in ["Phishing", "Suspicious"],
            "indicator_count": len(indicators),
            "indicators": indicators,
            "sender_domain": sender_domain,
            "reply_domain": reply_domain
        }
