# VIVA-VOCE EXAMINATION PREPARATION GUIDE
## Subject: Cryptography and Network Security
### Activity 5: Phishing Message Identification and Analysis

This guide contains **25 essential Viva-Voce questions and comprehensive technical answers** designed to prepare students for viva examinations by faculty and external examiners.

---

## Category 1: Cryptographic Principles & Email Authentication

### Q1: What is the fundamental role of cryptography in securing email communications?
**Answer:**  
Standard email protocols (SMTP, RFC 5321 / RFC 5322) were designed without built-in security; any sender can forge the visible `From:` header. Cryptography provides:
1. **Authentication & Non-Repudiation:** Verifying the true identity of the transmitting entity using asymmetric digital signatures (DKIM).
2. **Message Integrity:** Ensuring that the email headers and body have not been altered in transit via cryptographic hash functions (SHA-256).
3. **Confidentiality:** Encrypting email transit over TLS (STARTTLS) and payload encryption via S/MIME or OpenPGP.

---

### Q2: Explain the working mechanism of DKIM (DomainKeys Identified Mail - RFC 6376).
**Answer:**  
DKIM uses **asymmetric public-key cryptography** (typically RSA-2048 or Ed25519):
1. **Signing (Sender MTA):** The sending mail server computes a cryptographic hash (SHA-256) of specified header fields and the email body. It then encrypts this hash using the domain's **private key**, attaching the resulting signature in the `DKIM-Signature` header.
2. **Verification (Recipient MTA):** The receiving server extracts the `d=` (domain) and `s=` (selector) tags from the header, queries the sender's DNS for the corresponding public key (`selector._domainkey.domain.com`), and decrypts the signature. If the decrypted hash matches the freshly computed hash of the received message, the signature is **VALID** (guaranteeing authenticity and integrity).

---

### Q3: What is SPF (Sender Policy Framework - RFC 7208), and what is its main cryptographic limitation?
**Answer:**  
- **Mechanism:** SPF allows a domain owner to publish a list of authorized IP addresses / CIDR ranges in a DNS TXT record (e.g. `v=spf1 ip4:198.51.100.0/24 -all`). The receiving MTA checks whether the client IP connecting via SMTP matches this list.
- **Limitation:** SPF only validates the **Envelope Sender** (`MAIL FROM` / Return-Path), NOT the human-visible RFC 5322 `From:` header displayed in email clients. Therefore, an attacker can pass SPF using their own rogue domain while displaying a forged bank or university brand in the `From:` line.

---

### Q4: How does DMARC (RFC 7489) solve the limitations of SPF and DKIM?
**Answer:**  
DMARC solves the disconnect between technical authentication and user display by requiring **Identifier Alignment**:
1. The domain in the visible `From:` header must match (or align with) the domain verified by SPF and/or DKIM.
2. If alignment fails, the receiving MTA applies the domain owner's published DMARC policy:
   - `p=none`: Monitor and report only.
   - `p=quarantine`: Send failed messages to Spam/Junk folder.
   - `p=reject`: Completely drop/reject the message at SMTP connection time.

---

### Q5: What is the difference between encryption and digital signatures?
**Answer:**  
- **Encryption** transforms plaintext into ciphertext using a public key (asymmetric) or shared secret key (symmetric) to achieve **confidentiality** (preventing unauthorized reading).
- **Digital Signatures** encrypt a cryptographic message digest using the sender's **private key** to achieve **authenticity, integrity, and non-repudiation** (proving who sent it and that it was not modified).

---

## Category 2: Phishing Vectors & Attack Mechanisms

### Q6: What is Typosquatting / Lookalike Domain spoofing, and how did your project demonstrate it?
**Answer:**  
Typosquatting involves registering domain names that are visually or phonetically similar to established brands (e.g., omitting letters, substituting letters, or using deceptive TLDs).  
*Project Demonstration:*
- In **Email #4**, the attacker registered `fedx-express-tracking.com` (omitting the 'e' in `fedex`).
- In **Email #1**, the attacker registered `chase-account-update.com` with a cheap `.xyz` TLD rather than authentic `chase.com`.

---

### Q7: Explain Subdomain Spoofing and how attackers exploit DNS hierarchy.
**Answer:**  
DNS domain names are read from right to left (Top-Level Domain $\rightarrow$ Apex Domain $\rightarrow$ Subdomain). Attackers create confusing subdomains on an apex domain they own:
- Example from **Email #2**: `https://login.microsoftonline.com.account-update-token938.org/login`
- Victims see `login.microsoftonline.com` and assume it is official Microsoft. However, the actual apex domain controlling the destination server is `account-update-token938.org`.

---

### Q8: What is Business Email Compromise (BEC), and why is it so difficult for automated filters to detect?
**Answer:**  
BEC (Executive Fraud / Spear Phishing) is a targeted social engineering attack where attackers impersonate an executive, dean, or trusted vendor to request urgent fund transfers or gift card purchases.  
*Why automated filters fail:*
1. **No Technical Payload:** BEC emails contain **no hyperlinks** and **no malicious file attachments**.
2. **Valid Authentication:** Attackers frequently send from genuine commercial webmail (e.g. Gmail) with valid SPF and DKIM signatures.
3. The attack relies purely on psychological authority and urgency.

---

### Q9: How do macro-enabled Office documents (.xlsm, .docm) compromise a system?
**Answer:**  
Macro-enabled documents contain embedded Visual Basic for Applications (VBA) code. When a user is tricked into clicking "Enable Content / Enable Macros", the VBA script executes with the permissions of the current user, often invoking PowerShell or Windows API calls (`WScript.Shell`, `URLDownloadToFile`) to download and detonate a Trojan dropper or ransomware payload. Demonstrated in our **Email #3**.

---

### Q10: Why do attackers use raw numerical IP addresses in phishing URLs?
**Answer:**  
Using raw IPs (e.g., `http://185.220.101.45/...` in **Email #4**) allows attackers to bypass domain-based reputation blocklists, avoid domain registration fees/WHOIS identification, and circumvent newly registered domain filters.

---

## Category 3: Project-Specific Implementation & AI Evaluation

### Q11: Explain the Dual-Engine Architecture implemented in your project.
**Answer:**  
Our Python system utilizes two independent analytical pipelines:
1. **Heuristic & Cryptographic Engine (`detector.py`):** Uses deterministic cybersecurity rules to inspect SPF/DKIM headers, evaluate URL protocol (HTTP vs HTTPS), calculate typosquatting distances, detect subdomain spoofing, and flag dangerous file extensions.
2. **NLP Machine Learning Engine (`ml_model.py`):** Uses TF-IDF vectorization (unigrams + bigrams) and Scikit-Learn classifiers (Logistic Regression / Naive Bayes) to assign a statistical threat probability based on vocabulary patterns.

---

### Q12: Why did the automated AI model generate a False Negative on Email #5 (Dean BEC Request)?
**Answer:**  
The AI model evaluated the email as Legitimate (64% confidence) because:
- The email originated from a legitimate Google mail server with passing SPF and valid DKIM.
- It contained zero URLs and zero attachments.
- The language was polite and grammatically correct.  
*How our checklist corrected it:* Our student checklist flagged **CHK-1** (Dean using a commercial `@gmail.com` address instead of official university email), **CHK-5** (urgent gift card solicitation), and **CHK-7** (pretext excuse: "in an all-day meeting, cannot take calls").

---

### Q13: Why did the automated AI model generate a False Positive on Email #10 (Campus IT Server Maintenance)?
**Answer:**  
The AI model predicted Phishing with a 71% risk score because it overweighted security and administrative keywords: *"Password Sync"*, *"Active Directory"*, *"VPN endpoints"*, and *"login difficulties"*. Because these tokens frequently appear in credential harvesting attacks, the statistical model triggered a false alarm.  
*How our checklist corrected it:* Our checklist verified that the email explicitly stated **"No user intervention is required"**, possessed valid cryptographic signatures from `university.edu`, pointed to an authentic status sub-domain, and provided internal campus phone extensions.

---

### Q14: Explain the 7 checkpoints in your Predefined Security Audit Checklist.
**Answer:**  
1. **CHK-1 (20 pts):** Sender Identity & SPF authorization.
2. **CHK-2 (15 pts):** DKIM cryptographic integrity validation.
3. **CHK-3 (20 pts):** URL destination inspection (HTTPS, raw IP, subdomain spoofing).
4. **CHK-4 (15 pts):** Psychological urgency, threats of account closure, and short deadlines.
5. **CHK-5 (15 pts):** Credential, PIN, OTP, wire transfer, or gift card solicitation.
6. **CHK-6 (10 pts):** Weaponized attachments (`.xlsm`, `.exe`) and macro enablement lures.
7. **CHK-7 (5 pts):** Suppression of out-of-band communication (excuses preventing phone calls).  
*Decision Threshold:* Cumulative score $\ge 35$ designates Phishing.

---

### Q15: What were the final statistical performance metrics of the AI model vs the Student Checklist?
**Answer:**  
- **Automated AI Baseline:**
  - True Positives (TP): 4 | True Negatives (TN): 4
  - False Positives (FP): 1 (Email #10) | False Negatives (FN): 1 (Email #5)
  - Accuracy: **80.0%** | Precision: **80.0%** | Recall: **80.0%** | F1-Score: **80.0%**
- **Student Independent Verification Checklist:**
  - TP: 5 | TN: 5 | FP: 0 | FN: 0
  - Accuracy: **100.0%** | Precision: **100.0%** | Recall: **100.0%** | F1-Score: **100.0%**

---

### Q16: How did you calculate Precision, Recall, and F1-Score?
**Answer:**  
$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{4}{4 + 1} = 80.0\%$$
$$\text{Recall (Sensitivity)} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{4}{4 + 1} = 80.0\%$$
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 2 \times \frac{0.8 \times 0.8}{0.8 + 0.8} = 80.0\%$$

---

## Category 4: Defensive Strategies & Countermeasures

### Q17: What is Phishing-Resistant MFA, and why does FIDO2 / WebAuthn succeed where SMS/TOTP fails?
**Answer:**  
SMS OTPs and authenticator apps (TOTP) can be intercepted using automated reverse-proxy tools (e.g. Evilginx), which capture both credentials and session cookies in real time.  
**FIDO2 / WebAuthn hardware security keys** use **Origin Binding**:
- During registration, the key generates an asymmetric key pair bound strictly to the browser's current Fully Qualified Domain Name (FQDN).
- If a user visits `login-chase-account-verify.xyz`, the security key will refuse to provide an authentication assertion because the domain does not match `chase.com`. Hence, credential theft is mathematically impossible.

---

### Q18: What is Out-of-Band (OOB) Verification?
**Answer:**  
Out-of-Band verification is a protocol requiring confirmation through a secondary, physically separate communication channel. For example, before executing a wire transfer requested via email, the finance team must call the executive on their known, pre-registered telephone number or verify in person.

---

### Q19: What should an end-user do immediately upon receiving a suspicious email?
**Answer:**  
1. **Do not click links** or download/open attachments.
2. **Do not reply** to the sender (which confirms active mailbox status).
3. **Inspect the headers** or report the email using the client's "Report Phishing" button.
4. **Forward the raw email with full headers** to the corporate security team (`abuse@domain.com` or SOC).
5. If credentials were submitted, immediately reset passwords and revoke active sessions.

---

### Q20: What is DNSSEC, and how does it protect email security?
**Answer:**  
DNS Security Extensions (DNSSEC) add cryptographic digital signatures to DNS records using public-key cryptography. This prevents attackers from poisoning DNS caches or spoofing DNS TXT records for SPF, DKIM public keys, and DMARC policies.

---

## Category 5: Assignment-Specific Questions

### Q21: What AI tools did your group use, and for what purpose?
**Answer:**  
We used Gemini (via the Antigravity developer environment) to assist in drafting realistic email scenario templates and structuring code modules, and Scikit-Learn for training baseline NLP classification models (`TfidfVectorizer` and `LogisticRegression`).

---

### Q22: How did your group verify and modify the AI outputs?
**Answer:**  
We manually reviewed all 10 generated emails against RFC 5322 specifications, validated that real cryptographic parameters (SPF IP ranges, DKIM selectors) were accurately formatted, identified two critical misclassifications in the AI baseline (Cases #5 and #10), and engineered our 7-point checklist to correct them to 100% ground-truth accuracy.

---

### Q23: What was the primary lesson learned from using AI in this project?
**Answer:**  
AI models excel at detecting generic keyword patterns, but they lack human contextual reasoning and are blind to subtle social engineering attacks (like BEC) that lack technical payloads. Automated AI filters must always be combined with cryptographic verification (SPF/DKIM/DMARC) and human-in-the-loop oversight.

---

### Q24: What interfaces are available to run your project?
**Answer:**  
Our project supports three execution modes:
1. `python main.py --cli`: Complete command-line evaluation with formatted ASCII tables and metric summaries.
2. `python main.py --gui`: Full-featured desktop Tkinter GUI with interactive email inspection and chart viewer.
3. `python main.py --web`: Local Web Dashboard (`http://localhost:8080`) built with zero third-party web framework dependencies.

---

### Q25: What future enhancements could be added to this system?
**Answer:**  
1. Direct ingestion and parsing of live `.eml` and RFC 822 raw email files with automatic DNS resolver integration.
2. Computer vision analysis to inspect screenshots of hyperlinked landing pages for brand logo theft.
3. Transformer-based models (such as BERT or RoBERTa) fine-tuned for semantic Business Email Compromise detection.
