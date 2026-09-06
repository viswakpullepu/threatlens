export type ThreatCategory = 
  | 'sqli' 
  | 'xss' 
  | 'prompt_injection' 
  | 'jailbreak' 
  | 'ssrf' 
  | 'path_traversal' 
  | 'command_injection' 
  | 'phishing_url' 
  | 'obfuscated_code' 
  | 'ddos_bot' 
  | 'xxe'
  | 'pii_leakage'
  | 'benign';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';

export interface ThreatAnalysisResult {
  id: string;
  timestamp: string;
  input: string;
  isThreat: boolean;
  confidence: number;
  primaryCategory: ThreatCategory;
  categoryLabel: string;
  severity: SeverityLevel;
  mitreAttackId: string;
  mitreTechnique: string;
  cweId: string;
  cweName: string;
  cvssScore: number;
  explanation: string;
  remediation: string;
  matchedTokens: string[];
  sanitizedOutput: string;
  vectorBreakdown: {
    category: ThreatCategory;
    score: number;
  }[];
}

export interface TrainingSample {
  id: string;
  category: ThreatCategory;
  payload: string;
  isThreat: boolean;
  difficulty: 'basic' | 'intermediate' | 'advanced' | 'zero-day';
  description: string;
  tags: string[];
}

export interface ModelMetrics {
  totalTrainedSamples: number;
  accuracy: number;
  loss: number;
  precision: number;
  recall: number;
  f1Score: number;
  epochsCompleted: number;
  lastTrainedAt: string;
  categoryAccuracy: Record<ThreatCategory, number>;
}

export interface LiveThreatLog {
  id: string;
  timestamp: string;
  source: string;
  targetUrl: string;
  payloadSummary: string;
  category: ThreatCategory | EmailSecurityCategory | string;
  severity: SeverityLevel;
  actionTaken: 'BLOCKED' | 'SANITIZED' | 'ALLOWED' | 'QUARANTINED';
  latencyMs: number;
}

export interface BrowserTab {
  id: string;
  title: string;
  url: string;
  favicon: string;
  type: 'ecommerce' | 'banking' | 'social' | 'saas_search' | 'api_tester' | 'custom';
}

// ==========================================
// Email Defense & Encrypted Agent Types
// ==========================================
export type EmailSecurityCategory = 
  | 'headers_auth'
  | 'phishing_bec'
  | 'malicious_links'
  | 'attachments_macros'
  | 'llm_prompt_injections'
  | 'evasion_quishing';

export interface EmailThreatVector {
  id: string;
  category: EmailSecurityCategory;
  code: string;
  name: string;
  severity: SeverityLevel;
  cvss: number;
  description: string;
  mitreId: string;
}

export interface EmailAttachment {
  filename: string;
  sizeBytes: number;
  mimeType: string;
  isThreat: boolean;
  threatType?: string;
  sha256?: string;
}

export interface IncomingEmailMessage {
  id: string;
  provider: 'gmail' | 'outlook' | 'proton' | 'imap';
  recipient: string;
  sender: string;
  senderDisplayName: string;
  replyTo?: string;
  subject: string;
  receivedAt: string;
  bodyHtml: string;
  bodyText: string;
  headers: {
    spf: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL';
    dkim: 'PASS' | 'FAIL' | 'INVALID';
    dmarc: 'PASS' | 'FAIL' | 'REJECT';
    returnPath: string;
    messageId: string;
    originIp: string;
    authResults: string;
  };
  attachments: EmailAttachment[];
  embeddedLinks: string[];
}

export interface EmailInspectionReport {
  emailId: string;
  scannedAt: string;
  isThreat: boolean;
  riskScore: number; // 0 to 100
  verdict: 'SAFE_INBOX' | 'SUSPICIOUS_CLEANED' | 'MALICIOUS_QUARANTINED';
  primaryCategory: EmailSecurityCategory;
  matchedVectors: EmailThreatVector[];
  totalChecksEvaluated: number;
  encryptionEnclave: {
    algorithm: 'AES-256-GCM / Ephemeral Key';
    enclaveId: string;
    decryptionLatencyMs: number;
    auditPassed: boolean;
  };
  sanitizedBodyHtml: string;
  summaryReason: string;
}

export interface LinkedMailAccount {
  id: string;
  provider: 'gmail' | 'outlook' | 'proton' | 'imap';
  email: string;
  status: 'CONNECTED' | 'SYNCHRONIZING' | 'DISCONNECTED';
  encryptionKeyFingerprint: string;
  webhookArmed: boolean;
  totalEmailsScanned: number;
  threatsIntercepted: number;
}
