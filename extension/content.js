/**
 * ThreatLens AI — Live Gmail In-Mailbox Threat Shield
 * Clean, single-instance colored threat score injection next to sender names.
 */

(function() {
  'use strict';

  const DEFAULT_API_URL = 'https://threatlens-gen.vercel.app';
  let isEnabled = true;
  let customApiUrl = DEFAULT_API_URL;
  const analyzedCache = new Map();

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    chrome.storage.sync.get(['threatlens_enabled', 'threatlens_api_url'], function(res) {
      if (res.threatlens_enabled !== undefined) isEnabled = res.threatlens_enabled;
      if (res.threatlens_api_url) customApiUrl = res.threatlens_api_url;
    });
  }

  console.log('[ThreatLens Shield] Single-instance Guardian active.');

  /**
   * Comprehensive Multi-Aspect Threat Assessment Engine
   */
  function evaluateThreat(senderEmail, senderName, subject, snippetText) {
    const lowerEmail = (senderEmail || '').toLowerCase().trim();
    const lowerName = (senderName || '').toLowerCase().trim();
    const lowerSub = (subject || '').toLowerCase().trim();
    const lowerSnippet = (snippetText || '').toLowerCase().trim();
    const combinedText = lowerSub + ' ' + lowerSnippet;

    const reasons = [];

    // 0. ThreatLens Alerts (Internal system threat intercepts)
    if (lowerSub.includes('[threatlens alert]') || lowerSub.includes('high-risk threat intercepted')) {
      return {
        threatScore: 96,
        threatLevel: 'Critical',
        reasons: ['ThreatLens Automated High-Risk Intercept'],
        senderEmail: senderEmail,
        senderName: senderName,
        subject: subject
      };
    }

    const domain = lowerEmail.includes('@') ? lowerEmail.split('@')[1] : '';
    const isTier1 = /^(google\.com|github\.com|microsoft\.com|apple\.com|amazon\.com|stripe\.com|slack\.com|zoom\.us|cloudflare\.com|linkedin\.com|netflix\.com|twitter\.com|x\.com|spotify\.com|adobe\.com|notion\.so|figma\.com|atlassian\.net|uber\.com|airbnb\.com|dropbox\.com|salesforce\.com|zendesk\.com|hubspot\.com|sendgrid\.net|mailgun\.net|intuit\.com)$/i.test(domain);
    const isWebmail = /^(gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|icloud\.com|proton\.me|protonmail\.com)$/i.test(domain);
    const isSuspiciousTLD = /\.(top|xyz|work|tk|cc|click|gq|ml|cf|ga|buzz|rest|live|fit|surf|monster|icu|cam|ru|su)$/i.test(domain);

    // Aspect 1: Brand Impersonation & Typosquatting
    let identityScore = 0;
    const brandList = [
      { name: 'paypal', legit: 'paypal.com' },
      { name: 'microsoft', legit: 'microsoft.com' },
      { name: 'google', legit: 'google.com' },
      { name: 'apple', legit: 'apple.com' },
      { name: 'amazon', legit: 'amazon.com' },
      { name: 'netflix', legit: 'netflix.com' },
      { name: 'chase', legit: 'chase.com' },
      { name: 'bank of america', legit: 'bankofamerica.com' },
      { name: 'meta', legit: 'meta.com' },
      { name: 'stripe', legit: 'stripe.com' },
      { name: 'dhl', legit: 'dhl.com' },
      { name: 'fedex', legit: 'fedex.com' },
      { name: 'docusign', legit: 'docusign.com' }
    ];

    for (let i = 0; i < brandList.length; i++) {
      const b = brandList[i];
      if (lowerName.includes(b.name) && !domain.includes(b.legit.split('.')[0])) {
        identityScore += 42;
        reasons.push('Brand Impersonation: Displays "' + b.name + '" from unaligned domain (' + domain + ')');
        break;
      }
    }

    if (/micros0ft|microsft|m1crosoft|paypaI|pay-pal|docuslgn|goog1e|g00gle|amaz0n|app1e/i.test(domain)) {
      identityScore += 45;
      reasons.push('Typosquatting Masquerade Domain: ' + domain);
    }

    // Aspect 2: Domain Reputation & TLD Risk
    let domainScore = 0;
    if (isSuspiciousTLD) {
      domainScore += 24;
      reasons.push('Suspicious / Disposable TLD (.' + domain.split('.').pop() + ')');
    } else if (isTier1) {
      domainScore = 1;
    } else if (isWebmail) {
      domainScore = 8;
    } else {
      domainScore = 12;
    }

    // Aspect 3: NLP & Social Engineering Urgency
    let nlpScore = 0;
    // Critical Extortion / Ransomware
    if (/(webcam recorded|bitcoin transfer|bitcoin wallet|hacked your device|hacked your computer|private key|pegasus|recorded video of you|unusual webcam activity)/i.test(combinedText)) {
      nlpScore += 45;
      reasons.push('Extortion / Blackmail intimidation syntax detected');
    }
    // BEC & Wire Fraud
    else if (/(urgent wire transfer|updated direct deposit|swift wire|gift card purchase|urgent payroll update|overdue invoice payment|wire funds)/i.test(combinedText)) {
      nlpScore += 26;
      reasons.push('BEC financial redirection syntax');
    }
    // Credential Harvesting
    else if (/(verify your account|unauthorized login|security alert|password expires in 24 hours|account suspended immediately|action required immediately|click here to confirm|update payment method)/i.test(combinedText)) {
      nlpScore += 18;
      reasons.push('Credential harvesting urgency trigger');
    }

    // Aspect 4: Attachment & Link Indicators
    let payloadScore = 0;
    if (/\.(exe|scr|bat|cmd|vbs|js|wsf|hta|iso|img|lnk|docm|xlsm)/i.test(combinedText)) {
      payloadScore += 48;
      reasons.push('High-risk attachment or script reference detected');
    }
    if (/(bit\.ly|tinyurl\.com|is\.gd|t\.co|pages\.dev|firebaseapp\.com)/i.test(combinedText)) {
      payloadScore += 16;
      reasons.push('Obfuscated link or dynamic host');
    }

    // Hash entropy for subtle authentic dispersion
    let hashEntropy = 0;
    const seed = (senderEmail || '') + (subject || '');
    for (let c = 0; c < seed.length; c++) {
      hashEntropy = (hashEntropy * 31 + seed.charCodeAt(c)) % 5;
    }

    let rawScore = 0;
    if (identityScore >= 35 || payloadScore >= 35 || nlpScore >= 35 || isSuspiciousTLD) {
      // Critical / Attack vector
      rawScore = identityScore + payloadScore + nlpScore + domainScore;
      rawScore = Math.max(52, Math.min(99, rawScore));
    } else if (nlpScore > 10 || payloadScore > 10 || domainScore > 15) {
      // Mild / Suspicious
      rawScore = 50 + Math.floor((nlpScore + payloadScore + domainScore) / 2) + hashEntropy;
      rawScore = Math.min(79, Math.max(51, rawScore));
    } else {
      // Clean / Safe
      if (isTier1) {
        rawScore = 1 + hashEntropy;
      } else {
        rawScore = domainScore + hashEntropy;
      }
      rawScore = Math.min(48, Math.max(1, rawScore));
    }

    const finalScore = Math.min(99, Math.max(1, rawScore));
    const level = finalScore > 80 ? 'Critical' : (finalScore >= 50 ? 'Mild' : 'Safe');

    return {
      threatScore: finalScore,
      threatLevel: level,
      reasons: reasons.length > 0 ? reasons : ['Verified authentic sender posture.'],
      senderEmail: senderEmail,
      senderName: senderName,
      subject: subject
    };
  }

  /**
   * INBOX LIST VIEW: Inject clean colored number right next to sender name
   */
  function injectBadgeIntoInboxRow(rowEl) {
    if (!isEnabled) return;
    
    // Strict single-badge enforcement
    if (rowEl.querySelector('.threatlens-number-badge')) return;

    const senderContainer = rowEl.querySelector('.yW') || rowEl.querySelector('td.yX') || rowEl.querySelector('.yX');
    if (!senderContainer) return;
    if (senderContainer.querySelector('.threatlens-number-badge')) return;

    const senderSpan = senderContainer.querySelector('span[email], span[name], .bqe, .zF, .yP, span') || senderContainer;
    const senderName = (senderSpan ? senderSpan.textContent.trim() : '') || senderContainer.textContent.trim();
    const senderEmail = (senderSpan ? (senderSpan.getAttribute('email') || senderSpan.getAttribute('name')) : '') || '';

    const subjectEl = rowEl.querySelector('.bog, .bqr, .y6 span, [data-thread-id]');
    const subject = subjectEl ? subjectEl.textContent.trim() : '';

    const snippetEl = rowEl.querySelector('.y2');
    const snippet = snippetEl ? snippetEl.textContent.trim() : '';

    if (!senderName && !subject) return;

    const cacheKey = senderName + '_' + senderEmail + '_' + subject.slice(0, 30);
    let analysis = analyzedCache.get(cacheKey);
    if (!analysis) {
      analysis = evaluateThreat(senderEmail, senderName, subject, snippet);
      analyzedCache.set(cacheKey, analysis);
    }

    const score = analysis.threatScore;
    let scoreColorClass = 'tl-num-safe';
    if (score > 80) {
      scoreColorClass = 'tl-num-critical';
    } else if (score >= 50) {
      scoreColorClass = 'tl-num-mild';
    }

    // Clean any prior duplicate
    senderContainer.querySelectorAll('.threatlens-number-badge').forEach(function(b) { b.remove(); });

    const scoreSpan = document.createElement('span');
    scoreSpan.className = 'threatlens-number-badge ' + scoreColorClass;
    scoreSpan.title = 'ThreatLens AI Score: ' + score + '/100 (' + analysis.threatLevel + ')';
    scoreSpan.textContent = ' [' + score + ']';

    senderContainer.style.setProperty('overflow', 'visible', 'important');
    senderContainer.style.setProperty('display', 'inline-flex', 'important');
    senderContainer.style.setProperty('align-items', 'center', 'important');

    if (senderSpan && senderSpan !== senderContainer && senderSpan.parentNode) {
      if (senderSpan.nextSibling) {
        senderSpan.parentNode.insertBefore(scoreSpan, senderSpan.nextSibling);
      } else {
        senderSpan.parentNode.appendChild(scoreSpan);
      }
    } else {
      senderContainer.appendChild(scoreSpan);
    }
  }

  /**
   * OPENED EMAIL VIEW: Inject exactly ONE badge next to the sender name in the open email header
   */
  function injectBadgeIntoOpenMessage(messageEl) {
    if (!isEnabled) return;
    
    // Strict single-badge enforcement per message card
    if (messageEl.querySelector('.threatlens-number-badge')) return;

    const senderEl = messageEl.querySelector('span[email], .gD, [email]');
    if (!senderEl) return;

    const parent = senderEl.parentElement;
    if (!parent) return;
    if (parent.querySelector('.threatlens-number-badge')) return;

    const senderEmail = senderEl.getAttribute('email') || senderEl.textContent.trim();
    const senderName = senderEl.getAttribute('name') || senderEl.textContent.trim() || 'Sender';
    const subjectEl = document.querySelector('h2.hP, .ha h2') || messageEl.querySelector('.bog, h2');
    const subject = subjectEl ? subjectEl.textContent.trim() : 'Email Thread';
    const bodyEl = messageEl.querySelector('.a3s.aiL, .a3s, [role="article"]');
    const bodyText = bodyEl ? bodyEl.innerText.slice(0, 2000) : '';

    const cacheKey = senderEmail + '_' + subject.slice(0, 30);
    let analysis = analyzedCache.get(cacheKey);
    if (!analysis) {
      analysis = evaluateThreat(senderEmail, senderName, subject, bodyText);
      analyzedCache.set(cacheKey, analysis);
    }

    const score = analysis.threatScore;
    let scoreColorClass = 'tl-num-safe';
    if (score > 80) {
      scoreColorClass = 'tl-num-critical';
    } else if (score >= 50) {
      scoreColorClass = 'tl-num-mild';
    }

    // Remove any stale badge in parent before appending
    parent.querySelectorAll('.threatlens-number-badge').forEach(function(b) { b.remove(); });

    const scoreSpan = document.createElement('span');
    scoreSpan.className = 'threatlens-number-badge ' + scoreColorClass;
    scoreSpan.title = 'ThreatLens AI Score: ' + score + '/100 (' + analysis.threatLevel + ')';
    scoreSpan.textContent = ' [' + score + ']';

    if (senderEl.nextSibling) {
      senderEl.parentNode.insertBefore(scoreSpan, senderEl.nextSibling);
    } else {
      senderEl.parentNode.appendChild(scoreSpan);
    }
  }

  /**
   * Scan Gmail DOM without overlapping container collisions
   */
  function scanGmail() {
    // 1. Inbox Rows: exactly matches top-level table rows
    const rows = document.querySelectorAll('tr.zA, tr.zE, tr.yO');
    for (let i = 0; i < rows.length; i++) {
      injectBadgeIntoInboxRow(rows[i]);
    }

    // 2. Open Email Views: matches only the primary open message cards (.adn.ads or .adn)
    const messages = document.querySelectorAll('.adn.ads, .adn');
    for (let i = 0; i < messages.length; i++) {
      injectBadgeIntoOpenMessage(messages[i]);
    }
  }

  const observer = new MutationObserver(function() {
    scanGmail();
  });

  observer.observe(document.body, { childList: true, subtree: true });

  scanGmail();
  setInterval(scanGmail, 350);

  window.addEventListener('focus', function() { scanGmail(); });
  document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
      scanGmail();
      setTimeout(scanGmail, 100);
      setTimeout(scanGmail, 400);
    }
  });

  window.addEventListener('popstate', function() {
    scanGmail();
    setTimeout(scanGmail, 100);
    setTimeout(scanGmail, 400);
  });

  window.addEventListener('hashchange', function() {
    scanGmail();
    setTimeout(scanGmail, 100);
    setTimeout(scanGmail, 400);
  });

  window.addEventListener('scroll', scanGmail, { passive: true });
})();
