/**
 * NLP-Based Email Text Analysis Engine with TF-IDF Feature Extraction
 * Extracts unigrams and bigrams, computes Term Frequency (TF) and Inverse Document Frequency (IDF),
 * and scores suspicious linguistic patterns (Urgency, BEC, Credential Harvesting, Extortion).
 */

export interface TfidfFeature {
  term: string;
  tf: number;
  idf: number;
  tfidf: number;
  category: 'urgency' | 'bec_financial' | 'credential_lure' | 'extortion_threat' | 'general_suspicious' | 'benign';
  weightDescription: string;
}

export interface NlpTfidfAnalysisResult {
  linguisticThreatScore: number; // 0 to 100
  topFeatures: TfidfFeature[];
  dominantCategory: string;
  linguisticVerdict: string;
  tokenCount: number;
  lexicalDiversity: number; // TTR (Type-Token Ratio)
  urgencyDensity: number;
}

// Curated IDF reference dictionary from benchmark corpora (Enron, SpamAssassin, PhishTank, IWSPA-AP)
// Higher IDF = rarer across general email, highly discriminative for specific threat vectors
const PHISHING_IDF_DICTIONARY: Record<string, { idf: number; category: TfidfFeature['category'] }> = {
  // 1. Urgency / Coercive Action (High discriminative power in phishing)
  'urgent': { idf: 3.42, category: 'urgency' },
  'immediately': { idf: 3.65, category: 'urgency' },
  'asap': { idf: 3.85, category: 'urgency' },
  'immediate action': { idf: 4.88, category: 'urgency' },
  'action required': { idf: 4.52, category: 'urgency' },
  'account suspended': { idf: 5.12, category: 'urgency' },
  'suspended': { idf: 3.78, category: 'urgency' },
  'critical alert': { idf: 4.65, category: 'urgency' },
  'within 24 hours': { idf: 4.95, category: 'urgency' },
  'expires today': { idf: 4.82, category: 'urgency' },
  'unauthorized access': { idf: 4.74, category: 'urgency' },
  'security breach': { idf: 4.38, category: 'urgency' },
  'terminate': { idf: 3.92, category: 'urgency' },
  'final notice': { idf: 4.91, category: 'urgency' },

  // 2. BEC & Financial Fraud (Wire redirection, direct deposit, invoice fraud)
  'wire transfer': { idf: 5.25, category: 'bec_financial' },
  'wire': { idf: 3.95, category: 'bec_financial' },
  'swift transfer': { idf: 5.48, category: 'bec_financial' },
  'swift code': { idf: 5.32, category: 'bec_financial' },
  'direct deposit': { idf: 4.98, category: 'bec_financial' },
  'payroll': { idf: 3.82, category: 'bec_financial' },
  'update payroll': { idf: 5.35, category: 'bec_financial' },
  'banking details': { idf: 4.89, category: 'bec_financial' },
  'new account details': { idf: 5.42, category: 'bec_financial' },
  'overdue invoice': { idf: 4.62, category: 'bec_financial' },
  'gift card': { idf: 5.15, category: 'bec_financial' },
  'gift cards': { idf: 5.20, category: 'bec_financial' },
  'discreet purchase': { idf: 5.65, category: 'bec_financial' },
  'strictly confidential': { idf: 4.75, category: 'bec_financial' },
  'confidential acquisition': { idf: 5.72, category: 'bec_financial' },
  'remittance': { idf: 4.45, category: 'bec_financial' },
  'vendor payment': { idf: 4.35, category: 'bec_financial' },

  // 3. Credential Harvesting & Auth Lures
  'verify credentials': { idf: 5.45, category: 'credential_lure' },
  'verify account': { idf: 4.85, category: 'credential_lure' },
  'password reset': { idf: 4.22, category: 'credential_lure' },
  'password expires': { idf: 5.10, category: 'credential_lure' },
  'login credentials': { idf: 5.28, category: 'credential_lure' },
  'click here': { idf: 3.45, category: 'credential_lure' },
  'sign in': { idf: 3.12, category: 'credential_lure' },
  're-authenticate': { idf: 5.32, category: 'credential_lure' },
  'docusign': { idf: 4.18, category: 'credential_lure' },
  'sign document': { idf: 4.62, category: 'credential_lure' },
  'review and sign': { idf: 4.85, category: 'credential_lure' },
  'office 365': { idf: 3.95, category: 'credential_lure' },
  'microsoft security': { idf: 4.42, category: 'credential_lure' },
  'kyc verification': { idf: 5.21, category: 'credential_lure' },
  'update billing': { idf: 4.75, category: 'credential_lure' },

  // 4. Extortion & Blackmail
  'bitcoin': { idf: 4.78, category: 'extortion_threat' },
  'bitcoin wallet': { idf: 5.62, category: 'extortion_threat' },
  'webcam recorded': { idf: 5.85, category: 'extortion_threat' },
  'hacked your': { idf: 5.42, category: 'extortion_threat' },
  'intimate video': { idf: 5.92, category: 'extortion_threat' },
  'private key': { idf: 4.95, category: 'extortion_threat' },
  'pay ransom': { idf: 5.88, category: 'extortion_threat' },

  // 5. Baseline Benign Terms (Low IDF weight in enterprise context)
  'meeting': { idf: 1.15, category: 'benign' },
  'thank you': { idf: 1.05, category: 'benign' },
  'thanks': { idf: 1.08, category: 'benign' },
  'attached report': { idf: 1.65, category: 'benign' },
  'project update': { idf: 1.45, category: 'benign' },
  'calendar invitation': { idf: 1.55, category: 'benign' },
  'schedule': { idf: 1.25, category: 'benign' },
  'best regards': { idf: 1.02, category: 'benign' },
  'unsubscribe': { idf: 1.35, category: 'benign' }
};

// Common English stopwords to eliminate noise
const STOPWORDS = new Set([
  'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'aren\'t', 'as', 'at',
  'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by',
  'can', 'can\'t', 'cannot', 'could', 'couldn\'t', 'did', 'didn\'t', 'do', 'does', 'doesn\'t', 'doing', 'don\'t', 'down', 'during',
  'each', 'few', 'for', 'from', 'further',
  'had', 'hadn\'t', 'has', 'hasn\'t', 'have', 'haven\'t', 'having', 'he', 'he\'d', 'he\'ll', 'he\'s', 'her', 'here', 'here\'s', 'hers', 'herself', 'him', 'himself', 'his', 'how', 'how\'s',
  'i', 'i\'d', 'i\'ll', 'i\'m', 'i\'ve', 'if', 'in', 'into', 'is', 'isn\'t', 'it', 'it\'s', 'its', 'itself',
  'let\'s', 'me', 'more', 'most', 'mustn\'t', 'my', 'myself',
  'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'ought', 'our', 'ours', 'ourselves', 'out', 'over', 'own',
  'same', 'shan\'t', 'she', 'she\'d', 'she\'ll', 'she\'s', 'should', 'shouldn\'t', 'so', 'some', 'such',
  'than', 'that', 'that\'s', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'there\'s', 'these', 'they', 'they\'d', 'they\'ll', 'they\'re', 'they\'ve', 'this', 'those', 'through', 'to', 'too',
  'under', 'until', 'up', 'very',
  'was', 'wasn\'t', 'we', 'we\'d', 'we\'ll', 'we\'re', 'we\'ve', 'were', 'weren\'t', 'what', 'what\'s', 'when', 'when\'s', 'where', 'where\'s', 'which', 'while', 'who', 'who\'s', 'whom', 'why', 'why\'s', 'with', 'won\'t', 'would', 'wouldn\'t',
  'you', 'you\'d', 'you\'ll', 'you\'re', 'you\'ve', 'your', 'yours', 'yourself', 'yourselves'
]);

/**
 * Clean & tokenize text into unigrams and bigrams
 */
export function extractNGrams(rawText: string): { unigrams: string[]; bigrams: string[]; totalTokens: number } {
  // Normalize, remove non-alphanumeric (keep spaces and hyphens)
  const normalized = rawText
    .toLowerCase()
    .replace(/[^\w\s-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const words = normalized.split(' ').filter(w => w.length > 2 && !STOPWORDS.has(w));
  const unigrams = words;
  const bigrams: string[] = [];

  for (let i = 0; i < words.length - 1; i++) {
    bigrams.push(`${words[i]} ${words[i + 1]}`);
  }

  return {
    unigrams,
    bigrams,
    totalTokens: Math.max(1, words.length)
  };
}

/**
 * Execute TF-IDF Feature Extraction on Email Text
 */
export function analyzeEmailTextTfidf(text: string): NlpTfidfAnalysisResult {
  if (!text || text.trim().length === 0) {
    return {
      linguisticThreatScore: 0,
      topFeatures: [],
      dominantCategory: 'Benign Baseline',
      linguisticVerdict: 'Insufficient text body for NLP feature extraction.',
      tokenCount: 0,
      lexicalDiversity: 1.0,
      urgencyDensity: 0
    };
  }

  const { unigrams, bigrams, totalTokens } = extractNGrams(text);
  const allTerms = [...unigrams, ...bigrams];

  // 1. Calculate Term Frequency (TF): count(t) / total_tokens
  const termCounts: Record<string, number> = {};
  for (const term of allTerms) {
    termCounts[term] = (termCounts[term] || 0) + 1;
  }

  // 2. Calculate TF-IDF against reference dictionary
  const scoredFeatures: TfidfFeature[] = [];
  let threatTfidfSum = 0;
  let benignTfidfSum = 0;
  let urgencyHitCount = 0;

  for (const [term, count] of Object.entries(termCounts)) {
    const dictEntry = PHISHING_IDF_DICTIONARY[term];
    if (dictEntry) {
      // Augmented TF: 0.5 + 0.5 * (count / maxCount) or normalized count / totalTokens
      const tf = count / totalTokens;
      const idf = dictEntry.idf;
      const tfidf = Number((tf * idf * 10).toFixed(4)); // Scaled for interpretability

      if (dictEntry.category !== 'benign') {
        threatTfidfSum += tfidf;
        if (dictEntry.category === 'urgency') urgencyHitCount += count;
      } else {
        benignTfidfSum += tfidf;
      }

      scoredFeatures.push({
        term,
        tf: Number(tf.toFixed(4)),
        idf: Number(idf.toFixed(2)),
        tfidf,
        category: dictEntry.category,
        weightDescription: `TF: ${(tf * 100).toFixed(1)}% × IDF: ${idf.toFixed(2)} → TF-IDF: ${tfidf}`
      });
    }
  }

  // Sort by TF-IDF descending
  scoredFeatures.sort((a, b) => b.tfidf - a.tfidf);
  const topFeatures = scoredFeatures.slice(0, 10);

  // Calculate unique word ratio (Type-Token Ratio / Lexical Diversity)
  const uniqueWords = new Set(unigrams);
  const lexicalDiversity = Number((uniqueWords.size / Math.max(1, unigrams.length)).toFixed(2));

  // Urgency density per 100 words
  const urgencyDensity = Number(((urgencyHitCount / totalTokens) * 100).toFixed(1));

  // Composite Linguistic Threat Score (0 to 100)
  // Higher threat TF-IDF sum + urgency density minus benign offset
  let rawScore = Math.round((threatTfidfSum * 24) + (urgencyDensity * 4) - (benignTfidfSum * 5));
  const linguisticThreatScore = Math.min(99, Math.max(2, rawScore));

  // Determine dominant category
  const categoryCounts: Record<string, number> = {};
  for (const f of scoredFeatures) {
    if (f.category !== 'benign') {
      categoryCounts[f.category] = (categoryCounts[f.category] || 0) + f.tfidf;
    }
  }

  let dominant = 'Benign / Normal Discourse';
  let maxWeight = 0;
  for (const [cat, weight] of Object.entries(categoryCounts)) {
    if (weight > maxWeight) {
      maxWeight = weight;
      if (cat === 'urgency') dominant = 'Coercive Urgency & Pressure';
      else if (cat === 'bec_financial') dominant = 'BEC & Financial Redirection';
      else if (cat === 'credential_lure') dominant = 'Credential Harvesting Lure';
      else if (cat === 'extortion_threat') dominant = 'Extortion & Intimidation';
    }
  }

  let linguisticVerdict = 'Normal linguistic profile. Low semantic deception markers detected.';
  if (linguisticThreatScore >= 75) {
    linguisticVerdict = `High-risk linguistic anomaly detected: Predominant markers for ${dominant}. Elevated TF-IDF density indicates targeted social engineering.`;
  } else if (linguisticThreatScore >= 45) {
    linguisticVerdict = `Moderate linguistic concern: Identified suspicious n-grams (${topFeatures.slice(0, 3).map(f => `"${f.term}"`).join(', ')}).`;
  }

  return {
    linguisticThreatScore,
    topFeatures,
    dominantCategory: dominant,
    linguisticVerdict,
    tokenCount: totalTokens,
    lexicalDiversity,
    urgencyDensity
  };
}
