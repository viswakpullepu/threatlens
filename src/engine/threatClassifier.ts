import { ThreatCategory, ThreatAnalysisResult, SeverityLevel } from '../types';
import { THREAT_CATEGORIES_METADATA } from './threatKnowledgeBase';

export interface ClassifierWeights {
  categorySensitivity: Record<ThreatCategory, number>;
  globalThreshold: number;
  learnedPatterns: { pattern: string; category: ThreatCategory; weight: number }[];
}

let activeWeights: ClassifierWeights = {
  categorySensitivity: {
    sqli: 1.0,
    xss: 1.0,
    prompt_injection: 1.0,
    jailbreak: 1.0,
    ssrf: 1.0,
    path_traversal: 1.0,
    command_injection: 1.0,
    phishing_url: 1.0,
    obfuscated_code: 1.0,
    ddos_bot: 1.0,
    xxe: 1.0,
    pii_leakage: 1.0,
    benign: 1.0
  },
  globalThreshold: 40,
  learnedPatterns: []
};

export function updateClassifierWeights(newWeights: Partial<ClassifierWeights>) {
  activeWeights = {
    ...activeWeights,
    ...newWeights,
    categorySensitivity: {
      ...activeWeights.categorySensitivity,
      ...(newWeights.categorySensitivity || {})
    }
  };
}

export function getActiveWeights(): ClassifierWeights {
  return activeWeights;
}

export function sanitizePayload(input: string, category: ThreatCategory): string {
  if (category === 'xss') {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/javascript:/gi, 'sanitized-js:');
  }
  if (category === 'sqli') {
    return input.replace(/'/g, "''").replace(/--/g, '').replace(/;/g, '');
  }
  if (category === 'command_injection') {
    return input.replace(/[;&|`$><]/g, '_');
  }
  if (category === 'path_traversal') {
    return input.replace(/\.\.[\/\\]/g, '').replace(/%2e%2e/gi, '');
  }
  if (category === 'prompt_injection' || category === 'jailbreak') {
    return '[Protected Prompt Stream] ' + input.replace(/(ignore|previous instructions|system prompt|dan mode)/gi, '[FILTERED]');
  }
  return input;
}

export function classifyThreat(rawInput: string): ThreatAnalysisResult {
  const input = rawInput || '';
  const matchedTokens: string[] = [];
  const vectorScores: Record<ThreatCategory, number> = {
    sqli: 0,
    xss: 0,
    prompt_injection: 0,
    jailbreak: 0,
    ssrf: 0,
    path_traversal: 0,
    command_injection: 0,
    phishing_url: 0,
    obfuscated_code: 0,
    ddos_bot: 0,
    xxe: 0,
    pii_leakage: 0,
    benign: 0
  };

  // 1. SQL Injection
  const sqliRules = [
    { regex: /('\s*(or|and)\s*['"\d]|['"]\s*=\s*['"])/i, score: 80, token: "Auth-bypass boolean (' OR '1'='1)" },
    { regex: /union(\s+all)?\s+select/i, score: 95, token: "UNION SELECT extraction" },
    { regex: /information_schema\.(tables|columns)/i, score: 90, token: "information_schema traversal" },
    { regex: /waitfor\s+delay/i, score: 85, token: "WAITFOR DELAY time-blind probe" },
    { regex: /sleep\(\s*\d+\s*\)|benchmark\(/i, score: 85, token: "SQL Sleep/Benchmark delay" },
    { regex: /xp_cmdshell|exec\s*\(/i, score: 95, token: "Stacked shell execution (xp_cmdshell)" },
    { regex: /(--|#|\/\*\*\/)/, score: 35, token: "SQL comment delimiter" },
    { regex: /drop\s+table|truncate\s+table|alter\s+table/i, score: 90, token: "Destructive DDL query" }
  ];
  for (const rule of sqliRules) {
    if (rule.regex.test(input)) {
      vectorScores.sqli += rule.score;
      matchedTokens.push(rule.token);
    }
  }

  // 2. XSS
  const xssRules = [
    { regex: /<script\b[^>]*>([\s\S]*?)<\/script>/i, score: 95, token: "<script> execution tag" },
    { regex: /<script/i, score: 80, token: "Unclosed <script tag" },
    { regex: /onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=/i, score: 90, token: "Inline DOM event handler" },
    { regex: /javascript:\s*[\s\S]+/i, score: 90, token: "javascript: protocol URI" },
    { regex: /<svg\b[^>]*onload/i, score: 95, token: "<svg onload= payload" },
    { regex: /<img\b[^>]*onerror/i, score: 95, token: "<img onerror= payload" },
    { regex: /document\.(cookie|location|domain)/i, score: 85, token: "Document cookie/location accessor" },
    { regex: /fetch\s*\(|axios\s*\(|XMLHttpRequest/i, score: 35, token: "Network exfiltration probe" }
  ];
  for (const rule of xssRules) {
    if (rule.regex.test(input)) {
      vectorScores.xss += rule.score;
      matchedTokens.push(rule.token);
    }
  }

  // 3. LLM Prompt Injection & Jailbreak
  const piRules = [
    { regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/i, score: 95, token: "Ignore previous instructions override" },
    { regex: /system\s+prompt|developer\s+mode|unfiltered\s+mode/i, score: 85, token: "System prompt leak attempt" },
    { regex: /you\s+are\s+now\s+(dan|unrestricted|godmode|jailbroken)/i, score: 95, token: "DAN / Persona Jailbreak" },
    { regex: /do\s+anything\s+now/i, score: 90, token: "Do Anything Now jailbreak trigger" },
    { regex: /output\s+(all\s+)?(confidential|secret|hidden|internal)\s+instructions/i, score: 90, token: "Instruction exfiltration probe" },
    { regex: /in\s+a\s+fictional\s+(story|novel|universe).*?(write|create)\s+(a\s+)?(malware|virus|exploit|keylogger)/i, score: 90, token: "Hypothetical fictional exploit generator" },
    { regex: /---?\s*(end\s+conversation|system\s+message)/i, score: 80, token: "System message masquerade delimiter" }
  ];
  for (const rule of piRules) {
    if (rule.regex.test(input)) {
      if (rule.token.includes('Jailbreak') || rule.token.includes('fictional')) {
        vectorScores.jailbreak += rule.score;
      } else {
        vectorScores.prompt_injection += rule.score;
      }
      matchedTokens.push(rule.token);
    }
  }

  // 4. SSRF & Path Traversal
  const ssrfRules = [
    { regex: /169\.254\.169\.254/i, score: 98, token: "AWS IMDS cloud metadata IP (169.254.169.254)" },
    { regex: /metadata\.google\.internal/i, score: 98, token: "GCP metadata endpoint" },
    { regex: /http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:\d+)?/i, score: 85, token: "Localhost loopback probe" },
    { regex: /gopher:\/\/|dict:\/\/|file:\/\//i, score: 90, token: "Alternative dangerous protocol URI" }
  ];
  for (const rule of ssrfRules) {
    if (rule.regex.test(input)) {
      vectorScores.ssrf += rule.score;
      matchedTokens.push(rule.token);
    }
  }

  const traversalRules = [
    { regex: /(\.\.[\/\\]){2,}/i, score: 90, token: "Repeated ../ directory traversal" },
    { regex: /%2e%2e[%2f%5c]|%252e%252e/i, score: 95, token: "URL-encoded ../ traversal" },
    { regex: /etc\/(passwd|shadow|hosts|group)/i, score: 95, token: "Unix sensitive system file (/etc/passwd)" },
    { regex: /windows\/system32|boot\.ini/i, score: 95, token: "Windows sensitive system path" }
  ];
  for (const rule of traversalRules) {
    if (rule.regex.test(input)) {
      vectorScores.path_traversal += rule.score;
      matchedTokens.push(rule.token);
    }
  }

  // 5. Command Injection
  const cmdRules = [
    { regex: /([;&|`]|^\$\()\s*(cat|ls|dir|whoami|id|uname|curl|wget|nc|bash|sh|powershell)/i, score: 95, token: "Chained shell command execution" },
    { regex: /\|\s*(curl|wget|bash|sh)/i, score: 95, token: "Pipe to shell download & execute" },
    { regex: /powershell(\s+-[a-z]+)*\s+(-enc|-encodedcommand)/i, score: 98, token: "Base64 encoded PowerShell execution" }
  ];
  for (const rule of cmdRules) {
    if (rule.regex.test(input)) {
      vectorScores.command_injection += rule.score;
      matchedTokens.push(rule.token);
    }
  }

  // 6. Phishing & Malicious URLs
  const phishRules = [
    { regex: /https?:\/\/.*(login|verify|secure|update|account|auth).*\.(online|top|xyz|tk|ga|ml|cf|gq|pw|cc)\b/i, score: 85, token: "Suspicious TLD + auth harvesting keywords" },
    { regex: /https?:\/\/.*(paypal|apple|microsoft|google|binance|metamask).*-(security|login|verify)/i, score: 92, token: "Brand spoofing typosquatting domain" },
    { regex: /redirect_to=https?:\/\/|url=https?:\/\//i, score: 75, token: "Unvalidated open redirect parameter" }
  ];
  for (const rule of phishRules) {
    if (rule.regex.test(input)) {
      vectorScores.phishing_url += rule.score;
      matchedTokens.push(rule.token);
    }
  }

  // 7. Obfuscated code, XXE, PII
  if (/eval\s*\(\s*string\.fromcharcode/i.test(input)) {
    vectorScores.obfuscated_code += 95;
    matchedTokens.push("eval(String.fromCharCode) payload deobfuscator");
  }
  if (/<!entity\s+.*system\s+['"]file:/i.test(input)) {
    vectorScores.xxe += 95;
    matchedTokens.push("XXE File System Entity Declaration");
  }
  if (/sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}/i.test(input)) {
    vectorScores.pii_leakage += 90;
    matchedTokens.push("API Secret Key Exfiltration Pattern");
  }

  // Check learned patterns from active weights
  for (const learned of activeWeights.learnedPatterns) {
    if (input.toLowerCase().includes(learned.pattern.toLowerCase())) {
      vectorScores[learned.category] += learned.weight;
      matchedTokens.push(`Learned Signature: ${learned.pattern}`);
    }
  }

  // Apply sensitivity modifiers
  const categories = Object.keys(vectorScores) as ThreatCategory[];
  for (const cat of categories) {
    if (cat !== 'benign') {
      vectorScores[cat] = vectorScores[cat] * (activeWeights.categorySensitivity[cat] || 1.0);
    }
  }

  let maxCategory: ThreatCategory = 'benign';
  let maxScore = 0;

  for (const cat of categories) {
    if (cat === 'benign') continue;
    if (vectorScores[cat] > maxScore) {
      maxScore = vectorScores[cat];
      maxCategory = cat;
    }
  }

  const confidence = Math.min(100, Math.round(maxScore));
  const isThreat = confidence >= activeWeights.globalThreshold;

  const meta = THREAT_CATEGORIES_METADATA[isThreat ? maxCategory : 'benign'];

  let severity: SeverityLevel = 'SAFE';
  if (isThreat) {
    if (confidence >= 85) severity = 'CRITICAL';
    else if (confidence >= 65) severity = 'HIGH';
    else if (confidence >= 40) severity = 'MEDIUM';
    else severity = 'LOW';
  }

  const vectorBreakdown = categories
    .filter(c => c !== 'benign')
    .map(c => ({
      category: c,
      score: Math.min(100, Math.round(vectorScores[c]))
    }))
    .sort((a, b) => b.score - a.score);

  return {
    id: 'res-' + Math.random().toString(36).substring(2, 9),
    timestamp: new Date().toISOString(),
    input,
    isThreat,
    confidence,
    primaryCategory: isThreat ? maxCategory : 'benign',
    categoryLabel: meta.name,
    severity,
    mitreAttackId: meta.mitreId,
    mitreTechnique: meta.mitreName,
    cweId: meta.cweId,
    cweName: meta.cweName,
    cvssScore: isThreat ? meta.baseCvss : 0.0,
    explanation: isThreat 
      ? `Detected ${meta.name} with ${confidence}% confidence. Matched markers: ${matchedTokens.slice(0, 3).join(', ')}.`
      : 'No malicious payload or adversarial vector detected. Content matches normal benign web traffic profile.',
    remediation: isThreat 
      ? `Implement strict input sanitization, parameterized queries, and output encoding for ${meta.cweId}.`
      : 'No remediation necessary.',
    matchedTokens: Array.from(new Set(matchedTokens)),
    sanitizedOutput: isThreat ? sanitizePayload(input, maxCategory) : input,
    vectorBreakdown
  };
}
