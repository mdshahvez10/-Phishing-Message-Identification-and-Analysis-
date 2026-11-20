"""
dataset.py
Dataset definition for Phishing Message Identification and Analysis.
Contains:
1. The 10 Fictional Emails (5 Phishing, 5 Legitimate) required by the PBL assignment.
2. Expanded training corpus for the NLP / ML classifier.
"""

from typing import List, Dict, Any

TEN_FICTIONAL_EMAILS: List[Dict[str, Any]] = [
    {
        "id": 1,
        "title": "Bank Security Alert - Suspended Account",
        "sender_name": "Chase Security Alert",
        "sender_email": "security@chase-account-update.com",
        "reply_to": "verify-support@chase-resolution-desk.net",
        "received_spf": "Fail (IP 194.26.29.112 not authorized for chase.com)",
        "dkim_signature": "None",
        "subject": "URGENT: Your online banking access has been suspended due to 3 unauthorized attempts",
        "body": (
            "Dear Valued Customer,\n\n"
            "We detected suspicious login activity on your Chase Online Banking account from an unrecognized "
            "device in Moscow, Russia. To protect your funds, we have temporarily restricted your access.\n\n"
            "You MUST verify your identity within 24 hours to prevent permanent account closure. "
            "Click the link below to confirm your login credentials and card security PIN:\n\n"
            "http://login-chase-account-verify.xyz/auth/login.php?client_id=98321\n\n"
            "Failure to complete verification will result in immediate termination of banking privileges.\n\n"
            "Sincerely,\nChase Fraud Prevention Team"
        ),
        "links": ["http://login-chase-account-verify.xyz/auth/login.php?client_id=98321"],
        "attachments": [],
        "ground_truth": "Phishing",
        "attack_type": "Credential Harvesting & Urgency Phishing",
        "student_checklist_score": 92,  # 0-100 risk score
        "student_verification_label": "Phishing",
        "ai_initial_label": "Phishing",
        "ai_confidence": 0.98,
        "discrepancy_note": "Consensus match. Both AI and Checklist identified severe urgency, mismatched domain, and unencrypted HTTP link.",
        "key_indicators": [
            "Sender domain 'chase-account-update.com' is a lookalike domain, not the authentic 'chase.com'",
            "Reply-to points to an external unverified domain 'chase-resolution-desk.net'",
            "SPF check explicitly Failed (unauthorized sending IP)",
            "No cryptographic DKIM signature present",
            "Severe fear-inducing language: 'URGENT', 'within 24 hours', 'permanent account closure'",
            "Hyperlink points to insecure HTTP protocol on suspicious TLD (.xyz)",
            "Directly solicits sensitive credentials (login credentials + PIN)",
            "Generic greeting ('Dear Valued Customer') instead of user's name or last 4 digits of account"
        ],
        "safe_response": (
            "Do NOT click the link or provide any credentials. Mark as Phishing in email client, "
            "forward to abuse@chase.com, and report the malicious domain to Google Safe Browsing / Netcraft."
        )
    },
    {
        "id": 2,
        "title": "Corporate Office 365 Password Expiry",
        "sender_name": "IT Helpdesk Admin",
        "sender_email": "admin@university-portal-auth.net",
        "reply_to": "admin@university-portal-auth.net",
        "received_spf": "SoftFail (domain owner does not authorize IP)",
        "dkim_signature": "Invalid",
        "subject": "Action Required: Your Office 365 password expires in 2 hours",
        "body": (
            "Hello Staff and Students,\n\n"
            "Your institutional Microsoft Office 365 password will expire today in approximately 2 hours. "
            "To retain your existing password and prevent disruption of your email, Teams, and OneDrive access, "
            "please renew your authentication token immediately.\n\n"
            "Keep Current Password Here:\n"
            "https://login.microsoftonline.com.account-update-token938.org/login\n\n"
            "Note: Passwords left unrenewed will be locked automatically by the directory service.\n\n"
            "IT Systems and Infrastructure Office"
        ),
        "links": ["https://login.microsoftonline.com.account-update-token938.org/login"],
        "attachments": [],
        "ground_truth": "Phishing",
        "attack_type": "Subdomain Spoofing & Spear Phishing",
        "student_checklist_score": 88,
        "student_verification_label": "Phishing",
        "ai_initial_label": "Phishing",
        "ai_confidence": 0.94,
        "discrepancy_note": "Consensus match. AI detected password-related urgency keywords, checklist caught deceptive subdomain hierarchy.",
        "key_indicators": [
            "Subdomain spoofing: 'login.microsoftonline.com' is merely a subdomain of attacker-controlled 'account-update-token938.org'",
            "Sender domain 'university-portal-auth.net' is external and unaffiliated with the institution's real domain",
            "Artificial deadline pressure ('expires in 2 hours') designed to bypass rational scrutiny",
            "Promises an impossible action: enterprise directories never allow 'keeping existing expired password' by clicking an external link",
            "DKIM signature verification failed"
        ],
        "safe_response": (
            "Never click password expiration links in emails. If password reset is needed, navigate manually "
            "to the official institution portal (e.g. portal.university.edu). Report email to campus CISO / SOC."
        )
    },
    {
        "id": 3,
        "title": "HR Payroll & Q4 Bonus Revision",
        "sender_name": "Human Resources & Payroll",
        "sender_email": "hr-payroll@corporate-benefits365.info",
        "reply_to": "payroll-queries@corporate-benefits365.info",
        "received_spf": "Fail",
        "dkim_signature": "None",
        "subject": "Confidential: Updated Q4 Incentive Bonus and Direct Deposit Adjustment Form",
        "body": (
            "Dear Team Member,\n\n"
            "Management has approved an updated Q4 performance incentive structure. All eligible employees "
            "must review the revised payout schedule and confirm their direct deposit banking details.\n\n"
            "Please open the attached spreadsheet, enable content macros to calculate your entitlement, and return "
            "the signed schedule before the payroll cutoff at 5:00 PM today.\n\n"
            "Attachment: Q4_Bonus_Payout_Schedule_2026.xlsm\n\n"
            "Warm regards,\nCorporate Human Resources & Compensation Department"
        ),
        "links": [],
        "attachments": ["Q4_Bonus_Payout_Schedule_2026.xlsm"],
        "ground_truth": "Phishing",
        "attack_type": "Malicious Attachment (Macro-enabled Malware / Ransomware Stager)",
        "student_checklist_score": 95,
        "student_verification_label": "Phishing",
        "ai_initial_label": "Phishing",
        "ai_confidence": 0.91,
        "discrepancy_note": "Consensus match. Email contains financial bait paired with a dangerous macro-enabled (.xlsm) attachment.",
        "key_indicators": [
            "Delivery of a macro-enabled Office document (.xlsm) used as a traditional vector for Trojan droppers",
            "Explicit instruction to 'enable content macros', which executes arbitrary VBA code upon opening",
            "Generic greeting ('Dear Team Member') lacking employee name or ID",
            "External domain 'corporate-benefits365.info' used instead of legitimate company domain",
            "Manufactured time sensitivity ('cutoff at 5:00 PM today') combined with financial greed bait"
        ],
        "safe_response": (
            "Do NOT download or open the attachment. Do NOT enable macros under any circumstances. "
            "Submit the file directly to IT Security for sandbox detonation and block the sender domain on the email gateway."
        )
    },
    {
        "id": 4,
        "title": "Courier Package Delivery Exception",
        "sender_name": "FedEx Express Logistics",
        "sender_email": "notifications@fedx-express-tracking.com",
        "reply_to": "no-reply@fedx-express-tracking.com",
        "received_spf": "SoftFail",
        "dkim_signature": "None",
        "subject": "Delivery Exception: Package #FX-928104 could not be delivered - fee required",
        "body": (
            "Customer Notification,\n\n"
            "Your shipment #FX-928104 could not be delivered on 20/11/2026 because the destination address was "
            "incomplete and custom handling fee of $1.99 remains outstanding.\n\n"
            "To update your street address and settle the $1.99 dispatch surcharge, visit our tracking portal:\n\n"
            "http://185.220.101.45/fedex/track.html?pkg=FX928104\n\n"
            "Packages held for more than 48 hours will be returned to the sender at your expense.\n\n"
            "FedEx Customer Service"
        ),
        "links": ["http://185.220.101.45/fedex/track.html?pkg=FX928104"],
        "attachments": [],
        "ground_truth": "Phishing",
        "attack_type": "Typosquatting & Direct IP URL Phishing",
        "student_checklist_score": 96,
        "student_verification_label": "Phishing",
        "ai_initial_label": "Phishing",
        "ai_confidence": 0.97,
        "discrepancy_note": "Consensus match. Highly characteristic typosquatting ('fedx' omitting 'e') and raw IP link.",
        "key_indicators": [
            "Typosquatting in domain name: 'fedx' instead of the genuine brand name 'fedex'",
            "Hyperlink points directly to a raw numerical IPv4 address ('185.220.101.45') rather than a registered domain",
            "Unencrypted HTTP protocol used for financial transaction page",
            "Micro-charge scam pattern: small monetary charge ($1.99) designed to lower victim skepticism while stealing credit card details",
            "Impersonal salutation ('Customer Notification')"
        ],
        "safe_response": (
            "Do not navigate to raw IP links. Verify tracking numbers only on the official www.fedex.com website. "
            "Block IP address at corporate perimeter firewall."
        )
    },
    {
        "id": 5,
        "title": "Dean / Executive Wire Request (BEC)",
        "sender_name": "Prof. Arthur Pendelton (Dean of Engineering)",
        "sender_email": "dean.arthur.pendelton.edu@gmail.com",
        "reply_to": "dean.arthur.pendelton.edu@gmail.com",
        "received_spf": "Pass (for gmail.com, but unauthorized for university)",
        "dkim_signature": "Valid (signed by google.com)",
        "subject": "Urgent and confidential request - are you at your desk?",
        "body": (
            "Hi,\n\n"
            "I am currently in an all-day executive board meeting and cannot take phone calls. "
            "I need an urgent confidential favor from you regarding department conference gift vouchers for our visiting speakers.\n\n"
            "Are you available right now? Please respond back to my email as soon as possible so I can share the purchase details.\n\n"
            "Best,\n"
            "Prof. Arthur Pendelton\n"
            "Dean of Engineering, Academic Affairs"
        ),
        "links": [],
        "attachments": [],
        "ground_truth": "Phishing",
        "attack_type": "Business Email Compromise (BEC) / Executive Impersonation",
        "student_checklist_score": 82,
        "student_verification_label": "Phishing",
        "ai_initial_label": "Legitimate",  # AI MISCLASSIFICATION! Key learning for PBL assignment!
        "ai_confidence": 0.64,
        "discrepancy_note": (
            "DISCREPANCY IDENTIFIED & CORRECTED: Standard AI/NLP model misclassified this as 'Legitimate' "
            "(or very low confidence phishing) because the email has valid Gmail SPF/DKIM, contains no malicious links, "
            "and has no malware attachments. However, the student's Predefined Checklist flagged it as Phishing because "
            "a university dean is using a free commercial Gmail account to solicit urgent, confidential financial favors "
            "while claiming inability to take phone calls—classic BEC social engineering."
        ),
        "key_indicators": [
            "Free webmail address (gmail.com) used to impersonate university leadership instead of official '@university.edu'",
            "Display name spoofing leveraging authority / Dean position",
            "Preemptive excuse against out-of-band verification ('in an all-day board meeting, cannot take phone calls')",
            "Urgent call to action seeking gift cards / vouchers (hallmark of BEC fraud)",
            "No technical malware payload or links, bypassing naive automated signature scanners"
        ],
        "safe_response": (
            "Verify identity via known out-of-band phone number or internal office extension. "
            "Do not purchase gift cards or execute wire requests based on email instructions. Report to SOC for BEC investigation."
        )
    },
    {
        "id": 6,
        "title": "University Course Add/Drop Schedule Notice",
        "sender_name": "Office of the Academic Registrar",
        "sender_email": "registrar@university.edu",
        "reply_to": "registrar@university.edu",
        "received_spf": "Pass (IP 198.51.100.4 matches university.edu SPF record)",
        "dkim_signature": "Valid (d=university.edu)",
        "subject": "Academic Calendar Notice: Fall Semester Add/Drop Deadline - November 30",
        "body": (
            "Dear Student Community,\n\n"
            "This is a formal reminder from the Office of the Academic Registrar regarding the upcoming course "
            "registration deadline for the current academic session.\n\n"
            "The final day to add or drop elective courses without academic penalty is Friday, November 30, at 11:59 PM.\n\n"
            "You may review your current course roster and advisor notes directly through the official student portal:\n"
            "https://portal.university.edu/academics/registration\n\n"
            "If you have academic advising questions, please visit the Registrar's Office in Room 204, Administration Building, "
            "or contact your assigned faculty mentor.\n\n"
            "Regards,\nOffice of the Academic Registrar\nUniversity Administration"
        ),
        "links": ["https://portal.university.edu/academics/registration"],
        "attachments": [],
        "ground_truth": "Legitimate",
        "attack_type": "N/A (Legitimate Academic Notice)",
        "student_checklist_score": 10,
        "student_verification_label": "Legitimate",
        "ai_initial_label": "Legitimate",
        "ai_confidence": 0.96,
        "discrepancy_note": "Consensus match. Authentic domain, valid SPF and DKIM signatures, HTTPS link matching verified institutional domain.",
        "key_indicators": [
            "Cryptographic DKIM signature matches the sender domain 'university.edu'",
            "Sender email matches SPF authorized IP range",
            "Hyperlink points strictly to verified institutional domain under secure HTTPS",
            "Provides verifiable physical campus office location and established advisory channels",
            "No threats of account deletion or solicitation of credentials"
        ],
        "safe_response": "Legitimate notice. Safe to read and follow normal academic procedures through standard portal."
    },
    {
        "id": 7,
        "title": "Bank Monthly Electronic Statement",
        "sender_name": "Chase Online Customer Care",
        "sender_email": "no-reply@chase.com",
        "reply_to": "no-reply@chase.com",
        "received_spf": "Pass (mail.chase.com SPF record)",
        "dkim_signature": "Valid (d=chase.com)",
        "subject": "Your monthly account statement is now available online",
        "body": (
            "Hello Customer,\n\n"
            "Your electronic statement for checking account ending in ...4912 is ready for viewing.\n\n"
            "For security reasons, we do not include account numbers or statement attachments in emails. "
            "To view your statement, please open your official Chase Mobile app or visit chase.com in your web browser "
            "and sign in to your secure account dashboard.\n\n"
            "SECURITY REMINDER: Chase will never email or call asking for your password, PIN, or one-time security codes. "
            "Never disclose these codes to anyone.\n\n"
            "Thank you for banking with Chase."
        ),
        "links": [],
        "attachments": [],
        "ground_truth": "Legitimate",
        "attack_type": "N/A (Legitimate Banking Communication)",
        "student_checklist_score": 8,
        "student_verification_label": "Legitimate",
        "ai_initial_label": "Legitimate",
        "ai_confidence": 0.95,
        "discrepancy_note": "Consensus match. Authentic bank communication following strict anti-phishing guidelines (no embedded links, explicit security advisory).",
        "key_indicators": [
            "Valid SPF and DKIM signatures from authentic 'chase.com'",
            "Deliberately contains NO hyperlinks to prevent credential harvesting",
            "Advises customers to navigate independently to the verified website or mobile app",
            "Includes proactive anti-phishing security advisory warning against sharing OTPs or passwords",
            "References partial verified account identifier (...4912)"
        ],
        "safe_response": "Legitimate communication. Customers should sign in directly via bookmarks or mobile banking application."
    },
    {
        "id": 8,
        "title": "GitHub Security Dependabot Alert",
        "sender_name": "GitHub Notifications",
        "sender_email": "notifications@github.com",
        "reply_to": "support@github.com",
        "received_spf": "Pass (IP 192.30.252.206 matches github.com)",
        "dkim_signature": "Valid (d=github.com)",
        "subject": "[GitHub] Security advisory: Moderate severity vulnerability in cryptography package",
        "body": (
            "Hi developer,\n\n"
            "Dependabot has detected a security vulnerability in one of your project repository dependencies:\n\n"
            "Repository: user-workspace/crypto-network-lab\n"
            "Vulnerable package: cryptography (< 42.0.5)\n"
            "Ecosystem: pip\n"
            "Severity: Moderate (CVE-2024-26130)\n\n"
            "A pull request has been automatically generated to upgrade the affected package to a patched version:\n"
            "https://github.com/user-workspace/crypto-network-lab/pull/14\n\n"
            "You can review the pull request, run your automated CI/CD test suite, and merge the security fix.\n\n"
            "The GitHub Security Team"
        ),
        "links": ["https://github.com/user-workspace/crypto-network-lab/pull/14"],
        "attachments": [],
        "ground_truth": "Legitimate",
        "attack_type": "N/A (Legitimate Security Notification)",
        "student_checklist_score": 12,
        "student_verification_label": "Legitimate",
        "ai_initial_label": "Legitimate",
        "ai_confidence": 0.93,
        "discrepancy_note": "Consensus match. Authentic technical notification with valid cryptographic signatures and exact GitHub repository URL.",
        "key_indicators": [
            "Authentic domain with cryptographically valid DKIM signature from github.com",
            "Specific context provided (exact repository name and CVE-2024-26130 identifier)",
            "Hyperlink points to genuine, encrypted https://github.com path",
            "Does not solicit passwords, personal information, or financial transactions",
            "Standard technical tone appropriate for software dependency management"
        ],
        "safe_response": "Legitimate notification. Review the pull request directly on GitHub and merge once testing is complete."
    },
    {
        "id": 9,
        "title": "E-Commerce Order Shipment Confirmation",
        "sender_name": "Amazon Orders",
        "sender_email": "shipment-tracking@amazon.com",
        "reply_to": "shipment-tracking@amazon.com",
        "received_spf": "Pass (amazonses.com authorized for amazon.com)",
        "dkim_signature": "Valid (d=amazon.com)",
        "subject": "Shipped: 'Cryptography and Network Security Principles and Practice 8th Edition'",
        "body": (
            "Hi Student,\n\n"
            "Good news! Your order #114-8291048-2940129 has been dispatched.\n\n"
            "Items in shipment:\n"
            "- Cryptography and Network Security: Principles and Practice (Paperback) - Qty: 1\n\n"
            "Estimated Delivery Date: Monday, November 23, 2026\n"
            "Carrier: Amazon Logistics (Tracking ID: TBA92841029100)\n\n"
            "Track your package or manage order settings at:\n"
            "https://www.amazon.com/gp/your-account/order-history\n\n"
            "Thank you for shopping with Amazon."
        ),
        "links": ["https://www.amazon.com/gp/your-account/order-history"],
        "attachments": [],
        "ground_truth": "Legitimate",
        "attack_type": "N/A (Legitimate Order Confirmation)",
        "student_checklist_score": 9,
        "student_verification_label": "Legitimate",
        "ai_initial_label": "Legitimate",
        "ai_confidence": 0.97,
        "discrepancy_note": "Consensus match. Authentic e-commerce receipt with verified DKIM, matching Amazon domain, and zero credential solicitation.",
        "key_indicators": [
            "Sender domain 'amazon.com' verified by DKIM and SPF authentication",
            "Order ID matches standard 17-digit Amazon format",
            "Hyperlink points directly to authenticated 'https://www.amazon.com' account history",
            "No urgent requests for credit card re-verification or suspicious fees",
            "Clean layout without spelling or grammar errors"
        ],
        "safe_response": "Legitimate order receipt. User can check delivery status through their standard account page."
    },
    {
        "id": 10,
        "title": "Campus IT Maintenance and Credential Sync Notice",
        "sender_name": "Campus IT Infrastructure",
        "sender_email": "it-service@university.edu",
        "reply_to": "it-helpdesk@university.edu",
        "received_spf": "Pass (IP 198.51.100.12 authorized for university.edu)",
        "dkim_signature": "Valid (d=university.edu)",
        "subject": "System Notice: Scheduled Central Server Maintenance & Password Sync on Nov 22",
        "body": (
            "Attention Campus Network Users,\n\n"
            "The University Computing Center will be conducting routine infrastructure maintenance and Active Directory "
            "synchronization on Sunday, November 22, between 02:00 AM and 04:00 AM.\n\n"
            "During this maintenance window, access to Wi-Fi authentication, VPN endpoints, and library databases may "
            "experience intermittent interruptions. No user intervention is required. All user accounts and active passwords "
            "will be automatically synchronized across the central cluster.\n\n"
            "Status updates will be posted to the internal systems board:\n"
            "https://status.university.edu/incident/202611-maintenance\n\n"
            "If you experience login difficulties after 06:00 AM on Sunday, please call the IT Helpdesk at ext. 4357.\n\n"
            "Campus Information Technology Division"
        ),
        "links": ["https://status.university.edu/incident/202611-maintenance"],
        "attachments": [],
        "ground_truth": "Legitimate",
        "attack_type": "N/A (Legitimate Infrastructure Notice)",
        "student_checklist_score": 15,
        "student_verification_label": "Legitimate",
        "ai_initial_label": "Phishing",  # AI FALSE POSITIVE! Key learning for PBL assignment!
        "ai_confidence": 0.71,
        "discrepancy_note": (
            "DISCREPANCY IDENTIFIED & CORRECTED: Standard AI model generated a FALSE POSITIVE, incorrectly labeling "
            "this email as 'Phishing' (71% risk). The AI overweighted keywords such as 'Password Sync', 'Active Directory', "
            "'VPN endpoints', and 'login difficulties'. The student's Predefined Checklist correctly overruled the AI: "
            "the email explicitly clarifies 'No user intervention is required', has valid institutional SPF/DKIM, points to "
            "an authentic institutional sub-domain (status.university.edu), and provides internal telephone extensions."
        ),
        "key_indicators": [
            "Authentic campus domain 'university.edu' with passing SPF and DKIM",
            "Explicitly states that 'No user intervention is required' (no action or credential handover requested)",
            "Predictable maintenance window during off-peak hours (Sunday 2:00-4:00 AM)",
            "Hyperlink leads strictly to institutional status monitor under HTTPS",
            "Provides legitimate internal campus telephone extension (ext. 4357)"
        ],
        "safe_response": "Legitimate operational notice. Note the maintenance window; no action required."
    }
]

# Additional synthetic balanced corpus for ML training (50 legitimate, 50 phishing scenarios)
EXPANDED_TRAINING_CORPUS: List[Dict[str, Any]] = [
    # Phishing patterns
    {"text": "URGENT: Your PayPal account has been limited. Confirm your card identity now or lose your funds.", "label": "Phishing"},
    {"text": "Netflix billing failure. We were unable to process your payment. Update payment details immediately.", "label": "Phishing"},
    {"text": "IRS Tax Refund Notification: You are eligible for a refund of $1,250. Click here to claim your direct deposit.", "label": "Phishing"},
    {"text": "Apple ID locked due to security reasons. Verify your login credentials to unlock your device.", "label": "Phishing"},
    {"text": "Action Required: Suspicious login from Firefox in Beijing. Click to change your account password.", "label": "Phishing"},
    {"text": "DocuSign: You have received a confidential document for electronic signature. Click here to review.", "label": "Phishing"},
    {"text": "Dropbox storage quota exceeded. Upgrade now or all your stored files will be deleted within 12 hours.", "label": "Phishing"},
    {"text": "Wells Fargo Alert: Wire transfer of $4,500 pending. If this was not you, cancel the transaction immediately.", "label": "Phishing"},
    {"text": "Steam Community: Claim free $50 gift wallet code by logging in with your gaming profile here.", "label": "Phishing"},
    {"text": "HR Notice: Open the attached macro spreadsheet to review new employee compensation restructuring.", "label": "Phishing"},
    {"text": "Your DHL parcel is held at the sorting depot. Pay outstanding clearance tax of $2.50 to release shipment.", "label": "Phishing"},
    {"text": "Internal IT Alert: Webmail server quota full. Click here to re-validate your email quota and avoid deletion.", "label": "Phishing"},
    {"text": "Coinbase security: Unauthorized withdrawal detected. Click the link to lock your crypto wallet instantly.", "label": "Phishing"},
    {"text": "Immediate Wire Transfer needed: I am currently travelling overseas without phone access. Send funds to this vendor.", "label": "Phishing"},
    {"text": "Instagram Copyright Violation: Your account will be disabled in 24 hours. Appeal the copyright strike here.", "label": "Phishing"},
    {"text": "Google Workspace: Your subscription is expiring. Enter credit card details to retain business email access.", "label": "Phishing"},
    {"text": "Zoom meeting recording ready: Download the attached executable archive to view corporate meeting notes.", "label": "Phishing"},
    {"text": "Geek Squad Renewal: $399 auto-debited from your checking account. Call our cancellation desk immediately.", "label": "Phishing"},
    {"text": "Walmart Gift Card Reward: You have been selected as a lucky winner of a $500 gift coupon. Claim now.", "label": "Phishing"},
    {"text": "LinkedIn: Someone has viewed your profile 14 times today. Sign in here to unlock recruiter visibility.", "label": "Phishing"},
    {"text": "Facebook Security: Your page has violated community standards. Submit identity proof within 48 hours.", "label": "Phishing"},
    {"text": "Spotify Premium: Payment method declined. Update credit card credentials to avoid service cancellation.", "label": "Phishing"},
    {"text": "Bank of America: Security token expired. Verify your online ID and passcode to regain account access.", "label": "Phishing"},
    {"text": "USPS Redelivery: Carrier attempted delivery but no one was home. Reschedule and pay address verification fee.", "label": "Phishing"},
    {"text": "CEO Urgent Directive: Buy 5 Apple gift cards for regional conference attendees and email me back the codes.", "label": "Phishing"},
    {"text": "ATT Wireless: We could not process your autopay bill. Confirm billing details to avoid mobile disconnection.", "label": "Phishing"},
    {"text": "Microsoft Security Center: Trojan virus detected on your system. Call toll-free number for remote assistance.", "label": "Phishing"},
    {"text": "E-ZPass Toll Violation: Unpaid toll notice. Download the attached PDF to avoid legal prosecution.", "label": "Phishing"},
    {"text": "Citibank: New payee added to your account. If you did not make this change, click here to reverse immediately.", "label": "Phishing"},
    {"text": "University IT Service: Storage quota reached 99%. Follow link to upgrade mailbox limit.", "label": "Phishing"},

    # Legitimate patterns
    {"text": "Your weekly digest from GitHub: 4 pull requests merged and 2 issues closed across your watched repos.", "label": "Legitimate"},
    {"text": "Order confirmation: Thank you for your purchase of wireless headphones. View receipt on amazon.com.", "label": "Legitimate"},
    {"text": "Campus Library notice: The book 'Computer Networks' is due in 3 days. Renew online or return to desk.", "label": "Legitimate"},
    {"text": "Monthly e-statement is ready. Log in to your online banking app to review your balance and transactions.", "label": "Legitimate"},
    {"text": "Invitation: Department seminar on Post-Quantum Cryptography this Wednesday at 3 PM in Auditorium B.", "label": "Legitimate"},
    {"text": "Your Uber ride receipt from Friday evening. Total fare: $14.20 charged to card ending in 8912.", "label": "Legitimate"},
    {"text": "Course syllabus and grading policy for Cryptography and Network Security has been uploaded to Moodle.", "label": "Legitimate"},
    {"text": "Google Calendar: Reminder - Project presentation rehearsal scheduled for tomorrow at 10:00 AM.", "label": "Legitimate"},
    {"text": "Flight confirmation: Your booking with Delta Airlines for Seattle has been confirmed. Seat 14B.", "label": "Legitimate"},
    {"text": "Campus Health Center: Flu vaccination clinic open Monday through Thursday. Book an appointment online.", "label": "Legitimate"},
    {"text": "IEEE Xplore alert: New papers matching your research interest 'Network Intrusion Detection' have been published.", "label": "Legitimate"},
    {"text": "Your electric utility bill for October is $64.50. Scheduled automatic payment will occur on Nov 28.", "label": "Legitimate"},
    {"text": "Software update notice: Python 3.13.3 release notes and bug fix changelog are now available.", "label": "Legitimate"},
    {"text": "HR Announcement: Annual open enrollment period for health benefits begins next Monday.", "label": "Legitimate"},
    {"text": "Zoom meeting scheduled: Team sprint retrospective. Link and passcode provided in calendar invite.", "label": "Legitimate"},
    {"text": "Your Spotify Year in Review summary is now available to explore in the mobile app.", "label": "Legitimate"},
    {"text": "Courier tracking: Package delivered to front porch at 2:15 PM. Signed by resident.", "label": "Legitimate"},
    {"text": "University Registrar: Grade submission portal opens for instructors on December 15.", "label": "Legitimate"},
    {"text": "Gym membership receipt: Monthly membership fee of $30 processed successfully.", "label": "Legitimate"},
    {"text": "Research seminar: Keynote talk by Dr. Alice Smith on zero-knowledge proofs and lattice cryptography.", "label": "Legitimate"},
    {"text": "Automated build passed: Commit c89b12 built successfully in continuous integration pipeline.", "label": "Legitimate"},
    {"text": "Car service appointment confirmed for regular oil change and tire rotation on Saturday at 9 AM.", "label": "Legitimate"},
    {"text": "Your grocery delivery order has arrived. View full invoice in the store application.", "label": "Legitimate"},
    {"text": "Campus Wi-Fi certificate renewal reminder. Download updated profile from eduroam setup page.", "label": "Legitimate"},
    {"text": "Conference registration confirmation: Registration ID #9081 for CNS 2026 conference.", "label": "Legitimate"},
    {"text": "Mobile carrier: You have used 75% of your high-speed monthly data plan allowance.", "label": "Legitimate"},
    {"text": "Team collaboration: New comments posted on design proposal document in Google Drive.", "label": "Legitimate"},
    {"text": "Alumni association newsletter: Highlights of autumn homecoming weekend and upcoming reunions.", "label": "Legitimate"},
    {"text": "City transit pass: Monthly subway pass activated successfully for your smartcard.", "label": "Legitimate"},
    {"text": "Student council election results: Voter turnout and elected representatives announcement.", "label": "Legitimate"}
]
