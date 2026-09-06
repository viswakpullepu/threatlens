// ThreatLens - Realistic Threat Intelligence, Sample Emails & SOC Analysis

export const THREAT_LOCATIONS = [
  {
    id: 'TH-9021',
    ip: '185.220.101.5',
    city: 'Frankfurt',
    country: 'Germany',
    lat: 50.1109,
    lng: 8.6821,
    severity: 'critical',
    severityLabel: 'High Danger',
    type: 'Phishing (Stolen Passwords)',
    simpleTitle: 'Fake Microsoft 365 Login Scam',
    sender: 'security-update@micros0ft-auth-verify.com',
    subject: 'Action Required: Re-authenticate Microsoft 365 Account',
    threatScore: 94,
    asn: 'AS202425 (Tor Exit / Anonymous Hosting)',
    target: 'Finance Dept (US HQ)',
    targetCoords: { lat: 37.7749, lng: -122.4194 },
    status: 'Blocked by Gateway',
    timestamp: '2 mins ago',
    plainSummary: 'An attacker in Germany is sending fake Microsoft password expiry emails. If someone clicks the link, their Microsoft account password and MFA code will be stolen.',
    summary: 'High-risk automated credential harvesting campaign impersonating Microsoft 365 login portal with lookalike punycode domain.'
  },
  {
    id: 'TH-8419',
    ip: '103.145.13.88',
    city: 'Kuala Lumpur',
    country: 'Malaysia',
    lat: 3.1390,
    lng: 101.6869,
    severity: 'critical',
    severityLabel: 'High Danger',
    type: 'BEC (CEO Money Scam)',
    simpleTitle: 'Fake CEO Urgent Wire Transfer ($420k)',
    sender: 'ceo.office@acme-corp-direct.co',
    subject: 'URGENT: Confidential Acquisition Wire Instructions',
    threatScore: 98,
    asn: 'AS136557 (Megalodon Hosting Ltd)',
    target: 'Treasury Controller (London)',
    targetCoords: { lat: 51.5074, lng: -0.1278 },
    status: 'Quarantined & Alert Sent',
    timestamp: '7 mins ago',
    plainSummary: 'A scammer is pretending to be the company CEO asking an employee to secretly wire $420,000 before 4 PM. Responses are secretly forwarded to a personal Gmail account.',
    summary: 'Executive impersonation utilizing display-name spoofing and urgent payroll reroute request with off-shore escrow details.'
  },
  {
    id: 'TH-7732',
    ip: '91.240.118.172',
    city: 'St. Petersburg',
    country: 'Russia',
    lat: 59.9311,
    lng: 30.3609,
    severity: 'critical',
    severityLabel: 'High Danger',
    type: 'Malware (Ransomware File)',
    simpleTitle: 'Infected Excel Invoice with LockBit Virus',
    sender: 'accounts-payable@global-logistics-corp.biz',
    subject: 'Overdue Invoice #INV-2026-8891 (Final Notice)',
    threatScore: 96,
    asn: 'AS48282 (Selectel Obscured Route)',
    target: 'Accounts Payable (New York)',
    targetCoords: { lat: 40.7128, lng: -74.0060 },
    status: 'Infected File Blocked',
    timestamp: '14 mins ago',
    plainSummary: 'An email with an attached Excel file called "Invoice.xlsm". Opening the file runs a hidden virus script that attempts to lock and encrypt all company files for ransom.',
    summary: 'Weaponized XLSM Excel document containing obfuscated VBA macro executing shellcode to download LockBit 3.0 payload.'
  },
  {
    id: 'TH-6520',
    ip: '194.26.29.112',
    city: 'Amsterdam',
    country: 'Netherlands',
    lat: 52.3676,
    lng: 4.9041,
    severity: 'high',
    severityLabel: 'High Risk',
    type: 'Spoofing (QR Code Phish)',
    simpleTitle: 'Fake DocuSign with QR Code Trap',
    sender: 'notifications@docuslgn-secure-docs.net',
    subject: 'DocuSign: Executive Board Signatures Needed',
    threatScore: 82,
    asn: 'AS44592 (Serverius Holding B.V.)',
    target: 'Legal Counsel (Singapore)',
    targetCoords: { lat: 1.3521, lng: 103.8198 },
    status: 'Trap URL Neutralized',
    timestamp: '22 mins ago',
    plainSummary: 'The attacker uses the fake domain "docusLgn" (with an L instead of an I) and puts a QR code in the email. Scanning the QR code takes victims to a fake DocuSign login page.',
    summary: 'Evasive Quishing (QR code phishing) bypass attempt hiding zero-day reverse proxy behind SVG vector.'
  },
  {
    id: 'TH-5109',
    ip: '45.154.255.89',
    city: 'Panama City',
    country: 'Panama',
    lat: 8.9824,
    lng: -79.5199,
    severity: 'medium',
    severityLabel: 'Suspicious',
    type: 'Brand Impersonation',
    simpleTitle: 'Fake PayPal Security Alert',
    sender: 'billing@paypaI-notification-service.com',
    subject: 'Unusual Login Activity Detected from Unknown Device',
    threatScore: 68,
    asn: 'AS206981 (Offshore VPS Net)',
    target: 'Customer Service (Sydney)',
    targetCoords: { lat: -33.8688, lng: 151.2093 },
    status: 'Marked as Suspicious',
    timestamp: '35 mins ago',
    plainSummary: 'Uses a capital "I" instead of "l" in "paypaI". A trick designed to fool your eyes into thinking it came from real PayPal.',
    summary: 'Typosquatting domain leveraging capital I (paypaI) to deceive end users; SPF softfail and DMARC unaligned.'
  },
  {
    id: 'TH-4011',
    ip: '198.51.100.42',
    city: 'San Jose',
    country: 'United States',
    lat: 37.3382,
    lng: -121.8863,
    severity: 'safe',
    severityLabel: 'Safe & Verified',
    type: 'Legitimate Email',
    simpleTitle: 'Official Stripe Payment Receipt (Clean)',
    sender: 'receipts@stripe.com',
    subject: 'Your receipt from Cloud Services Inc (#2910-1849)',
    threatScore: 2,
    asn: 'AS16509 (Amazon AWS SES / Stripe)',
    target: 'Accounting Team (Berlin)',
    targetCoords: { lat: 52.5200, lng: 13.4050 },
    status: 'Delivered Safely',
    timestamp: '41 mins ago',
    plainSummary: 'A 100% genuine payment receipt from Stripe. All security seals (SPF, DKIM, DMARC) pass with flying colors. Completely safe to open.',
    summary: 'Verified RFC-compliant transaction receipt with strict DMARC alignment, valid cryptographic DKIM-RSA signature.'
  }
];

export const SAMPLE_EMAILS = [
  {
    id: 'sample-phish-m365',
    title: '1. Fake Microsoft 365 Password Alert',
    shortBadge: '🚨 Phishing Scam',
    userFriendlyCategory: 'Fake Login (Phishing)',
    threatScore: 94,
    severity: 'critical',
    severityLabel: 'Danger: Do Not Click',
    isThreat: true,
    simpleTakeaway: 'This email is FAKE. An attacker in Germany is impersonating Microsoft to steal your password.',
    whatHappened: [
      'The sender pretends to be "Microsoft Security", but the real domain is "micros0ft-auth-verify.com" (notice the number 0).',
      'The website link inside goes to a fake login portal created 3 days ago by attackers.',
      'The sender failed all 3 major email authenticity tests (SPF, DKIM, and DMARC).'
    ],
    whatToDo: 'Delete or quarantine this email. Never enter your password or MFA code on links from this sender.',
    sender: {
      displayName: 'Microsoft Security Team',
      email: 'security-update@micros0ft-auth-verify.com',
      envelopeFrom: 'bounce-daemon@micros0ft-auth-verify.com',
      replyTo: 'admin@micros0ft-auth-verify.com',
      originIp: '185.220.101.5',
      asn: 'AS202425 (Tor Exit / Anonymous VPS)',
      location: 'Frankfurt, Germany',
      reverseDns: 'node-185-220-101-5.bulletproof-vps.su',
      isSpoofed: true,
      spoofType: 'Fake Domain: Replaced "o" with zero "0" (micros0ft instead of microsoft)'
    },
    recipient: {
      email: 'j.miller@enterprise-corp.com',
      department: 'Finance & Operations',
      targetHost: 'mx1.enterprise-corp.com'
    },
    metadata: {
      subject: 'URGENT: Password Expiry Notification - 2 Hours Remaining',
      date: 'Today, 2:12 PM UTC',
      messageId: '<20260904.141205.991283@micros0ft-auth-verify.com>',
      userAgent: 'Automated Mail Client',
      contentType: 'text/html'
    },
    auth: {
      spf: { 
        status: 'FAIL', 
        exists: true, 
        friendlyName: 'SPF (Sender Identity Check)',
        explanation: 'Checks if the sender server is allowed to send email for this company.',
        message: 'FAILED — The sending computer in Germany is NOT authorized by Microsoft.' 
      },
      dkim: { 
        status: 'FAIL', 
        exists: true, 
        friendlyName: 'DKIM (Anti-Tamper Digital Seal)',
        explanation: 'A cryptographic digital stamp proving the email was not modified in transit.',
        message: 'FAILED — The digital seal is broken or forged.' 
      },
      dmarc: { 
        status: 'FAIL', 
        exists: true, 
        friendlyName: 'DMARC (Domain Protection Rule)',
        explanation: 'Enforces company rules on whether unverified emails should be blocked.',
        message: 'FAILED — Microsoft policy requires this unauthenticated message to be REJECTED.' 
      }
    },
    urls: [
      {
        url: 'https://login.micros0ft-auth-verify.com/token=8f9a21e0b',
        domain: 'micros0ft-auth-verify.com',
        risk: 'Dangerous Phishing Link',
        vtScore: '18/89 Security Vendors Flagged Malicious',
        ip: '185.220.101.5',
        domainAge: 'Registered only 3 days ago',
        isPunycode: true
      }
    ],
    attachments: [],
    hashes: {
      sha256: '9f83acde7821034459012bbde899120c8f1e8432170498aefb098172c91200fa',
      md5: '8f12a64c8d9e72b4510fa9c1782e44d1'
    },
    threatVerdict: {
      headline: 'Credential Harvesting Phishing Campaign Detected',
      confidence: 99.4,
      analysis: [
        'Domain `micros0ft-auth-verify.com` is an unauthorized typosquatted lookalike registered 72 hours ago.',
        'Fails SPF, DKIM, and DMARC alignment tests completely.',
        'Extracted target landing page mimics enterprise Single Sign-On to harvest credentials.',
        'Origin IP is an active Tor exit relay listed on global threat feeds.'
      ],
      recommendation: 'Block sender domain at edge gateway, revoke active session tokens for recipient, and push IOCs to firewall.'
    },
    timeline: [
      { time: 'Step 1', event: 'Inbound SMTP connection received from 185.220.101.5 (Frankfurt, Germany)', status: 'info' },
      { time: 'Step 2', event: 'Authentication verification failed: SPF FAIL, DKIM FAIL, DMARC FAIL', status: 'danger' },
      { time: 'Step 3', event: 'Heuristic engine flagged urgent lure pattern and unregistered sender domain', status: 'danger' },
      { time: 'Step 4', event: 'Message quarantined automatically by security gateway', status: 'success' }
    ],
    mitreAttack: [
      { id: 'T1566.002', name: 'Phishing: Fake Link', tactic: 'Initial Access' },
      { id: 'T1036.005', name: 'Masquerading: Impersonating Brand Name', tactic: 'Defense Evasion' }
    ]
  },
  {
    id: 'sample-bec-cfo',
    title: '2. Fake CEO Urgent Wire Request ($420k)',
    shortBadge: '🚨 CEO Money Scam',
    userFriendlyCategory: 'CEO Impersonation (BEC)',
    threatScore: 98,
    severity: 'critical',
    severityLabel: 'High Danger: Fraud Attempt',
    isThreat: true,
    simpleTakeaway: 'This email is a WIRE FRAUD SCAM. An attacker is impersonating your CEO Arthur Vance asking for money.',
    whatHappened: [
      'The sender name says "Arthur Vance (CEO)", but the actual email address is "@acme-corp-direct.co" (a fake cousin domain).',
      'The scammer created fake urgency asking for $420,000 for a "confidential acquisition".',
      'If you click reply, your message secretly goes to a scammer Gmail address (ceo.vance.exec@gmail.com).'
    ],
    whatToDo: 'DO NOT transfer money. Call the CEO directly via known internal phone number to verify.',
    sender: {
      displayName: 'Arthur Vance (Chief Executive Officer)',
      email: 'arthur.vance@acme-corp-direct.co',
      envelopeFrom: 'noreply@acme-corp-direct.co',
      replyTo: 'ceo.vance.exec@gmail.com',
      originIp: '103.145.13.88',
      asn: 'AS136557 (Megalodon Hosting Ltd)',
      location: 'Kuala Lumpur, Malaysia',
      reverseDns: 'mail.acme-corp-direct.co',
      isSpoofed: true,
      spoofType: 'Display Name Spoofing + Secret Reply-To divergence to personal Gmail'
    },
    recipient: {
      email: 'sarah.jenkins@acme-corp.com',
      department: 'Corporate Treasury',
      targetHost: 'mx2.acme-corp.com'
    },
    metadata: {
      subject: 'CONFIDENTIAL: Priority M&A Wire Transfer Authorization ($420,000)',
      date: 'Today, 1:48 PM UTC',
      messageId: '<ACME-EXEC-WIRE-20260904-88192@gmail.com>',
      userAgent: 'Webmail Client',
      contentType: 'text/plain'
    },
    auth: {
      spf: { 
        status: 'PASS', 
        exists: true, 
        friendlyName: 'SPF (Sender Identity Check)',
        explanation: 'Checks if sender server is allowed to send for domain.',
        message: 'PASSED for attacker domain (acme-corp-direct.co), but NOT your real company domain!' 
      },
      dkim: { 
        status: 'PASS', 
        exists: true, 
        friendlyName: 'DKIM (Anti-Tamper Digital Seal)',
        explanation: 'Digital seal on the email.',
        message: 'Valid on attacker server; completely unaligned with real corporate email.' 
      },
      dmarc: { 
        status: 'FAIL', 
        exists: true, 
        friendlyName: 'DMARC (Domain Protection Rule)',
        explanation: 'Enforces real company domain rules.',
        message: 'FAILED — Domain mismatch with official acme-corp.com identity.' 
      }
    },
    urls: [],
    attachments: [],
    hashes: {
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      md5: '4d8a1c9e2b3f7105a8d9e6c24157b102'
    },
    threatVerdict: {
      headline: 'Executive Impersonation (Wire Fraud Scam)',
      confidence: 98.7,
      analysis: [
        'Display name matches CEO Arthur Vance, but actual sender is registered on cousin domain `acme-corp-direct.co`.',
        'Hidden `Reply-To` header secretly routes responses to external unmonitored Gmail address.',
        'Intent heuristics identified urgency markers ("Strictly confidential", "Immediate settlement").',
        'Direct violation of Treasury dual-authorization protocol.'
      ],
      recommendation: 'Immediate outbound alert to Treasury, blacklist domain `acme-corp-direct.co`, execute BEC incident response.'
    },
    timeline: [
      { time: 'Step 1', event: 'Inbound message received via offshore relay 103.145.13.88', status: 'info' },
      { time: 'Step 2', event: 'Header inspection identified Reply-To mismatch (external Gmail route)', status: 'danger' },
      { time: 'Step 3', event: 'Heuristic engine flagged high VIP impersonation probability', status: 'danger' },
      { time: 'Step 4', event: 'Message quarantined; Out-of-band notification sent to CFO mobile', status: 'success' }
    ],
    mitreAttack: [
      { id: 'T1566.001', name: 'Spearphishing BEC', tactic: 'Initial Access' },
      { id: 'T1656', name: 'Impersonation of Executive', tactic: 'Social Engineering' }
    ]
  },
  {
    id: 'sample-malware-macro',
    title: '3. Infected Invoice with Virus Attachment',
    shortBadge: '🚨 Virus / Malware',
    userFriendlyCategory: 'Infected File (Malware)',
    threatScore: 96,
    severity: 'critical',
    severityLabel: 'Danger: Ransomware Inside',
    isThreat: true,
    simpleTakeaway: 'This email contains a DANGEROUS VIRUS inside the attached Excel file.',
    whatHappened: [
      'The email claims to be an overdue invoice notice with an attached file called "Invoice.xlsm".',
      'The Excel file contains a hidden malicious script (macro) that downloads LockBit ransomware.',
      'If opened and macros are enabled, it will attempt to encrypt your computer and demand a ransom.'
    ],
    whatToDo: 'DO NOT open the attachment. The file has been quarantined in our isolated sandbox.',
    sender: {
      displayName: 'Global Logistics Accounts',
      email: 'accounts-payable@global-logistics-corp.biz',
      envelopeFrom: 'bounces@mailer.global-logistics-corp.biz',
      replyTo: 'accounts-payable@global-logistics-corp.biz',
      originIp: '91.240.118.172',
      asn: 'AS48282 (Selectel Route)',
      location: 'St. Petersburg, Russia',
      reverseDns: 'smtp-out9.fastmail-relay.net',
      isSpoofed: false,
      spoofType: 'Compromised Mail Server delivering Ransomware'
    },
    recipient: {
      email: 'billing@enterprise-corp.com',
      department: 'Accounts Payable',
      targetHost: 'mx1.enterprise-corp.com'
    },
    metadata: {
      subject: 'Overdue Remittance Notice: Invoice #INV-2026-8891.xlsm',
      date: 'Today, 12:30 PM UTC',
      messageId: '<20260904123015.GLC.7812@global-logistics-corp.biz>',
      userAgent: 'Microsoft Outlook 16.0',
      contentType: 'multipart/mixed'
    },
    auth: {
      spf: { 
        status: 'PASS', 
        exists: true, 
        friendlyName: 'SPF (Sender Identity Check)',
        explanation: 'Checks if sending server is listed.',
        message: 'Origin server listed, but email content was tampered with.' 
      },
      dkim: { 
        status: 'FAIL', 
        exists: true, 
        friendlyName: 'DKIM (Anti-Tamper Digital Seal)',
        explanation: 'Integrity check on email contents.',
        message: 'FAILED — Message body was modified in transit by attackers.' 
      },
      dmarc: { 
        status: 'FAIL', 
        exists: true, 
        friendlyName: 'DMARC (Domain Protection Rule)',
        explanation: 'Domain security rule.',
        message: 'FAILED — DKIM tampering triggered DMARC failure.' 
      }
    },
    urls: [
      {
        url: 'http://cdn-update-check.su/payload/enc_loader.bin',
        domain: 'cdn-update-check.su',
        risk: 'LockBit Virus Download Server',
        vtScore: '54/89 Malicious (Known Virus Host)',
        ip: '91.240.118.172',
        domainAge: '5 days old',
        isPunycode: false
      }
    ],
    attachments: [
      {
        filename: 'Invoice_INV-2026-8891.xlsm',
        size: '142.8 KB',
        mimeType: 'Excel Macro Spreadsheet',
        sha256: 'a9876f1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        vtScore: '61/72 Antivirus Engines Flagged as Virus',
        sandboxVerdict: 'High Risk: Runs hidden PowerShell commands to install LockBit ransomware.',
        isMalicious: true
      }
    ],
    hashes: {
      sha256: 'a9876f1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      md5: '7d4f910a3c2e5b88192039485716a29f'
    },
    threatVerdict: {
      headline: 'Weaponized Macro Excel Ransomware Dropper',
      confidence: 99.8,
      analysis: [
        'Email contains weaponized macro attachment `Invoice_INV-2026-8891.xlsm` with known LockBit signatures.',
        'Static VBA inspection reveals obfuscated strings unpacking a hidden powershell download script.',
        'C2 callback domain `cdn-update-check.su` is listed on 54 threat intelligence feeds.',
        'DKIM signature verification failed indicating transit tampering.'
      ],
      recommendation: 'Quarantine email, detonate attachment in sandbox, block C2 at perimeter firewall.'
    },
    timeline: [
      { time: 'Step 1', event: 'Inbound message containing .xlsm attachment received from Russia', status: 'info' },
      { time: 'Step 2', event: 'Attachment parser detected embedded auto-execute VBA macro (Auto_Open)', status: 'danger' },
      { time: 'Step 3', event: 'Sandbox detonation confirmed C2 download attempt from .su domain', status: 'danger' },
      { time: 'Step 4', event: 'Attachment purged; recipient inbox protected; Incident alert dispatched', status: 'success' }
    ],
    mitreAttack: [
      { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access' },
      { id: 'T1486', name: 'Data Encrypted for Impact (Ransomware)', tactic: 'Impact' }
    ]
  },
  {
    id: 'sample-quish-docusign',
    title: '4. Fake DocuSign with QR Code Trap',
    shortBadge: '🚨 QR Code Phish',
    userFriendlyCategory: 'Fake DocuSign (QR Code)',
    threatScore: 82,
    severity: 'high',
    severityLabel: 'High Risk: QR Scam',
    isThreat: true,
    simpleTakeaway: 'This email uses a QR CODE TRAP to steal logins on your mobile phone.',
    whatHappened: [
      'The sender pretends to be "DocuSign", but spelled the domain "docuslgn" with a lowercase "L".',
      'Instead of a regular link, it includes an image of a QR code to trick mobile phone scanners.',
      'Scanning the QR code sends your phone to a fake DocuSign login page.'
    ],
    whatToDo: 'DO NOT scan the QR code with your phone. Never enter login details from unverified QR images.',
    sender: {
      displayName: 'DocuSign Electronic Signature',
      email: 'notifications@docuslgn-secure-docs.net',
      envelopeFrom: 'delivery@docuslgn-secure-docs.net',
      replyTo: 'no-reply@docuslgn-secure-docs.net',
      originIp: '194.26.29.112',
      asn: 'AS44592 (Serverius B.V.)',
      location: 'Amsterdam, Netherlands',
      reverseDns: 'cust-112.serverius.net',
      isSpoofed: true,
      spoofType: 'Lookalike Domain: Spelled "docuslgn" (letter L instead of I)'
    },
    recipient: {
      email: 'legal.counsel@enterprise-corp.com',
      department: 'Legal & Compliance',
      targetHost: 'mx3.enterprise-corp.com'
    },
    metadata: {
      subject: 'DocuSign: Please review and sign NDA Agreement #8192',
      date: 'Today, 11:15 AM UTC',
      messageId: '<DOCUSIGN-20260904-891290@docuslgn-secure-docs.net>',
      userAgent: 'CloudMTA Engine',
      contentType: 'multipart/related'
    },
    auth: {
      spf: { 
        status: 'NONE', 
        exists: false, 
        friendlyName: 'SPF (Sender Identity Check)',
        explanation: 'Checks if sender domain has published rules.',
        message: 'NONE — The fake domain has no published SPF security record.' 
      },
      dkim: { 
        status: 'NONE', 
        exists: false, 
        friendlyName: 'DKIM (Anti-Tamper Digital Seal)',
        explanation: 'Authenticity stamp.',
        message: 'NONE — No digital signature present.' 
      },
      dmarc: { 
        status: 'FAIL', 
        exists: false, 
        friendlyName: 'DMARC (Domain Protection Rule)',
        explanation: 'Domain protection level.',
        message: 'FAILED — Unprotected, unverified sender domain.' 
      }
    },
    urls: [
      {
        url: 'https://docuslgn-secure-docs.net/view/session_id=98a12bc',
        domain: 'docuslgn-secure-docs.net',
        risk: 'Fake DocuSign Credential Stealer',
        vtScore: '22/89 Malicious',
        ip: '194.26.29.112',
        domainAge: '2 days old',
        isPunycode: false
      }
    ],
    attachments: [
      {
        filename: 'Signature_Instructions_QR.png',
        size: '28.4 KB',
        mimeType: 'PNG Image with QR Code',
        sha256: '4f81029384756102938475610293847561029384756102938475610293847561',
        vtScore: 'Decoded QR leads to malicious site',
        sandboxVerdict: 'QR Code links to https://docuslgn-secure-docs.net/m/login',
        isMalicious: true
      }
    ],
    hashes: {
      sha256: '4f81029384756102938475610293847561029384756102938475610293847561',
      md5: '3c891a2e9b0147f8912d0a1b2c3d4e5f'
    },
    threatVerdict: {
      headline: 'Quishing / Brand Impersonation Attack Detected',
      confidence: 91.2,
      analysis: [
        'Sender domain `docuslgn-secure-docs.net` replaces character "i" with "l" to bypass brand filters.',
        'Email embeds a QR code designed to redirect victims to a credential harvesting proxy.',
        'Zero SPF/DKIM authentication records exist for domain.',
        'Originating IP is hosted on high-risk bulletproof VPS.'
      ],
      recommendation: 'Filter lookalike DocuSign variants, push domain to DNS sinkhole, alert recipient.'
    },
    timeline: [
      { time: 'Step 1', event: 'Inbound message containing embedded PNG image received from Netherlands', status: 'info' },
      { time: 'Step 2', event: 'Optical scanner decoded QR matrix to external reverse proxy', status: 'warning' },
      { time: 'Step 3', event: 'Domain lookup showed "docuslgn" was created 48 hours ago', status: 'danger' },
      { time: 'Step 4', event: 'Email blocked before delivery; SOC alert logged', status: 'success' }
    ],
    mitreAttack: [
      { id: 'T1566.002', name: 'Spearphishing Link (QR Code)', tactic: 'Initial Access' }
    ]
  },
  {
    id: 'sample-clean-stripe',
    title: '5. Official Stripe Invoice (Clean & Safe)',
    shortBadge: '✅ Verified Safe',
    userFriendlyCategory: 'Safe Email (Verified)',
    threatScore: 2,
    severity: 'safe',
    severityLabel: '100% Safe to Open',
    isThreat: false,
    simpleTakeaway: 'This email is 100% AUTHENTIC and SAFE. It is a genuine receipt from Stripe.',
    whatHappened: [
      'Sent directly by Stripe from their official authorized servers in the United States.',
      'Passes all 3 major security standards (SPF, DKIM, and DMARC) with valid digital signatures.',
      'All links go to official stripe.com websites and the PDF attachment is clean.'
    ],
    whatToDo: 'Safe to open, view receipt, and keep for accounting records.',
    sender: {
      displayName: 'Stripe Payments',
      email: 'receipts@stripe.com',
      envelopeFrom: 'bounces+991283@stripe.com',
      replyTo: 'support@stripe.com',
      originIp: '198.51.100.42',
      asn: 'AS16509 (Amazon AWS / Stripe)',
      location: 'San Jose, United States',
      reverseDns: 'outbound-mail-ses.stripe.com',
      isSpoofed: false,
      spoofType: 'None - Perfectly Authenticated'
    },
    recipient: {
      email: 'accounting@enterprise-corp.com',
      department: 'Finance & Accounting',
      targetHost: 'mx1.enterprise-corp.com'
    },
    metadata: {
      subject: 'Your Stripe Receipt for Invoice #INV-2910-1849 ($149.00)',
      date: 'Today, 10:05 AM UTC',
      messageId: '<01000189a12c8b9-e192-4912-8819-receipts@email.stripe.com>',
      userAgent: 'Stripe Mail Engine v2.4',
      contentType: 'multipart/alternative'
    },
    auth: {
      spf: { 
        status: 'PASS', 
        exists: true, 
        friendlyName: 'SPF (Sender Identity Check)',
        explanation: 'Checks if sending server is listed in official records.',
        message: 'PASSED — Verified Stripe server IP address.' 
      },
      dkim: { 
        status: 'PASS', 
        exists: true, 
        friendlyName: 'DKIM (Anti-Tamper Digital Seal)',
        explanation: 'Cryptographic digital signature on message.',
        message: 'PASSED — Valid 2048-bit digital seal from stripe.com.' 
      },
      dmarc: { 
        status: 'PASS', 
        exists: true, 
        friendlyName: 'DMARC (Domain Protection Rule)',
        explanation: 'Strict domain verification.',
        message: 'PASSED — 100% strict alignment verified.' 
      }
    },
    urls: [
      {
        url: 'https://dashboard.stripe.com/receipts/acct_192831/inv_99182',
        domain: 'dashboard.stripe.com',
        risk: 'Official Stripe Web Page',
        vtScore: '0/89 Clean (Official Reputable Domain)',
        ip: '198.51.100.42',
        domainAge: '14+ years old',
        isPunycode: false
      }
    ],
    attachments: [
      {
        filename: 'Receipt-INV-2910-1849.pdf',
        size: '48.2 KB',
        mimeType: 'Standard PDF Document',
        sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        vtScore: '0/72 Clean (No Viruses Found)',
        sandboxVerdict: 'Clean standard receipt PDF with zero executable code.',
        isMalicious: false
      }
    ],
    hashes: {
      sha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      md5: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d'
    },
    threatVerdict: {
      headline: 'Legitimate & Authenticated Transaction Email',
      confidence: 99.9,
      analysis: [
        'Sender domain `stripe.com` possesses verified global reputation.',
        'Full SPF, DKIM, and DMARC alignment verified with 2048-bit RSA keys.',
        'All links resolve strictly to official Stripe TLS certificates.',
        'Attachment is a clean, non-executable standard PDF receipt.'
      ],
      recommendation: 'Safe for inbox delivery. No security action required.'
    },
    timeline: [
      { time: 'Step 1', event: 'Inbound SMTP connection from Amazon SES (Stripe Verified Pool)', status: 'info' },
      { time: 'Step 2', event: 'DKIM signature verified; SPF IP verification passed (100% Alignment)', status: 'success' },
      { time: 'Step 3', event: 'PDF attachment parsed: Clean document with no executable scripts', status: 'success' },
      { time: 'Step 4', event: 'Email delivered safely to recipient inbox', status: 'success' }
    ],
    mitreAttack: []
  }
];

// Curated Threat Intelligence Database
export const THREAT_INTELLIGENCE_DB = {
  ips: [
    {
      indicator: '185.220.101.5',
      type: 'Malicious IP',
      friendlyType: 'Malicious Server (IP)',
      threatType: 'Phishing (Stolen Logins)',
      threatActor: 'Storm-0539 Group',
      reputationScore: 94,
      country: 'Germany',
      plainWhatItDoes: 'Sends high-volume fake Microsoft 365 login emails to harvest corporate credentials.',
      tags: ['Tor-Exit', 'Credential-Harvester', 'High-Risk']
    },
    {
      indicator: '103.145.13.88',
      type: 'Malicious IP',
      friendlyType: 'Malicious Server (IP)',
      threatType: 'CEO Wire Scam (BEC)',
      threatActor: 'SilverTerrier Group',
      reputationScore: 98,
      country: 'Malaysia',
      plainWhatItDoes: 'Relays fake CEO wire transfer emails attempting to divert treasury funds.',
      tags: ['CEO-Fraud', 'Wire-Theft', 'Scammer-Host']
    },
    {
      indicator: '91.240.118.172',
      type: 'Malicious IP',
      friendlyType: 'Malicious Server (IP)',
      threatType: 'Ransomware Server',
      threatActor: 'LockBit 3.0 Affiliate',
      reputationScore: 99,
      country: 'Russia',
      plainWhatItDoes: 'Hosts LockBit virus files that encrypt workstations and demand ransom payments.',
      tags: ['LockBit-3.0', 'Ransomware', 'Virus-Host']
    },
    {
      indicator: '194.26.29.112',
      type: 'Malicious IP',
      friendlyType: 'Malicious Server (IP)',
      threatType: 'QR Phishing Server',
      threatActor: 'EvilProxy Syndicate',
      reputationScore: 88,
      country: 'Netherlands',
      plainWhatItDoes: 'Hosts fake DocuSign login portals that victim mobile devices reach via QR codes.',
      tags: ['DocuSign-Spoof', 'QR-Phish', 'Fake-Login']
    }
  ],
  domains: [
    {
      indicator: 'micros0ft-auth-verify.com',
      type: 'Malicious Domain',
      friendlyType: 'Malicious Domain',
      threatType: 'Phishing',
      threatActor: 'Storm-0539',
      reputationScore: 96,
      plainWhatItDoes: 'Impersonates Microsoft with zero "0" instead of "o" to steal session tokens.',
      tags: ['Typosquatting', 'Punycode', 'M365-Lure']
    },
    {
      indicator: 'acme-corp-direct.co',
      type: 'Malicious Domain',
      friendlyType: 'Malicious Domain',
      threatType: 'CEO Money Fraud',
      threatActor: 'SilverTerrier',
      reputationScore: 98,
      plainWhatItDoes: 'Lookalike domain registered to send fake executive wire instructions.',
      tags: ['Cousin-Domain', 'CEO-Scam', 'Wire-Fraud']
    },
    {
      indicator: 'docuslgn-secure-docs.net',
      type: 'Malicious Domain',
      friendlyType: 'Malicious Domain',
      threatType: 'DocuSign Spoof',
      threatActor: 'EvilProxy',
      reputationScore: 89,
      plainWhatItDoes: 'Spells DocuSign with lowercase "L" to impersonate electronic signature workflows.',
      tags: ['DocuSign-Lookalike', 'Quishing-Gateway', 'Phish']
    }
  ],
  urls: [
    {
      indicator: 'https://login.micros0ft-auth-verify.com/token=8f9a21e0b',
      type: 'Malicious URL',
      friendlyType: 'Malicious URL',
      threatType: 'Phishing Page',
      threatActor: 'Storm-0539',
      reputationScore: 99,
      plainWhatItDoes: 'Reverse proxy portal designed to harvest session tokens and credentials.',
      tags: ['Credential-Theft', 'AiTM-Proxy', 'Trap-Link']
    },
    {
      indicator: 'http://cdn-update-check.su/payload/enc_loader.bin',
      type: 'Malicious URL',
      friendlyType: 'Malicious URL',
      threatType: 'Virus Downloader',
      threatActor: 'LockBit Group',
      reputationScore: 99,
      plainWhatItDoes: 'Direct binary link delivering staged LockBit ransomware payload.',
      tags: ['Ransomware-Payload', 'Raw-Binary', 'Dangerous']
    }
  ],
  hashes: [
    {
      indicator: 'a9876f1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
      type: 'Malicious File Hash',
      friendlyType: 'Malicious Hash (SHA-256)',
      threatType: 'Ransomware Excel Macro',
      threatActor: 'LockBit Affiliate',
      reputationScore: 99,
      plainWhatItDoes: 'SHA-256 fingerprint of the infected Excel invoice macro dropper.',
      tags: ['VBA.TrojanDownloader', 'LockBit-Dropper', 'Macro-File']
    },
    {
      indicator: '4f81029384756102938475610293847561029384756102938475610293847561',
      type: 'Malicious File Hash',
      friendlyType: 'Malicious Hash (SHA-256)',
      threatType: 'QR Phishing Image',
      threatActor: 'EvilProxy',
      reputationScore: 89,
      plainWhatItDoes: 'SHA-256 fingerprint of the malicious QR code phishing image.',
      tags: ['Quishing-Lure', 'Embedded-QR', 'Stego-Vector']
    }
  ]
};

export const THREAT_TYPES_INFO = [
  {
    id: 'phishing',
    name: 'Phishing (Credential Theft)',
    simpleExplain: 'Deceptive messages impersonating Microsoft, Google, or financial institutions to steal credentials.',
    badge: 'High Frequency',
    color: 'red',
    icon: 'mail-warning',
    count: '1,428',
    howToSpot: [
      'Lookalike domain spelling (e.g. micros0ft with zero).',
      'Urgent warning like "Account suspended in 2 hours".',
      'Directs victim to unauthenticated external login page.'
    ],
    simpleAdvice: 'Enforce hardware FIDO2 keys and automatically block unaligned DMARC domains.'
  },
  {
    id: 'malware',
    name: 'Malware & Ransomware Droppers',
    simpleExplain: 'Emails with weaponized attachments (.xlsm, .zip, .vbs) executing obfuscated scripts.',
    badge: 'High Severity',
    color: 'orange',
    icon: 'bug',
    count: '892',
    howToSpot: [
      'Unexpected invoice or remittance notice attachments.',
      'Prompts the recipient to "Enable Macros" or "Enable Content".',
      'Executes hidden PowerShell or cURL background processes.'
    ],
    simpleAdvice: 'Strip executable attachments at gateway and enforce micro-virtualized sandbox detonation.'
  },
  {
    id: 'spoofing',
    name: 'Domain & Brand Spoofing',
    simpleExplain: 'Techniques altering email headers, lookalike character sets, or QR codes to impersonate trusted brands.',
    badge: 'Deceptive Vector',
    color: 'amber',
    icon: 'shield-alert',
    count: '645',
    howToSpot: [
      'Subtle character substitution: "docuslgn" (letter L) instead of "docusign".',
      'Header From differs from envelope Return-Path.',
      'Embedded QR codes intended to bypass text-based gateway filters.'
    ],
    simpleAdvice: 'Enforce strict DMARC p=reject policy and deploy optical OCR filters for QR codes.'
  },
  {
    id: 'bec',
    name: 'Business Email Compromise (BEC)',
    simpleExplain: 'Targeted social engineering impersonating executives to execute unauthorized wire transfers.',
    badge: 'Financial Fraud',
    color: 'indigo',
    icon: 'dollar-sign',
    count: '312',
    howToSpot: [
      'Urgent wire requests: "Confidential acquisition, execute transfer immediately".',
      'Changes to vendor bank account or escrow routing numbers.',
      'Hidden Reply-To header pointing to external webmail address.'
    ],
    simpleAdvice: 'Enforce mandatory out-of-band voice verification for all wire authorization changes.'
  }
];
