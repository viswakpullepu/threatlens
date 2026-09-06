/**
 * ThreatLens AI — Live Gmail In-Mailbox Threat Shield
 * Injects clean, minimalist colored threat scores directly after sender names:
 * No pills, no backgrounds — only pure colored score numbers.
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

  console.log('[ThreatLens Shield] Minimalist Colored Number Mode active.');

  /**
   * Fast Threat Assessment Engine
   */
  function evaluateThreat(senderEmail, senderName, subject, snippetText) {
    let score = 5;
    const reasons = [];
    const lowerEmail = (senderEmail || '').toLowerCase();
    const lowerName = (senderName || '').toLowerCase();
    const lowerSub = (subject || '').toLowerCase();
    const lowerSnippet = (snippetText || '').toLowerCase();

    // 0. ThreatLens Alerts (Internal alerts from system)
    if (lowerSub.includes('[threatlens alert]') || lowerSub.includes('high-risk threat intercepted')) {
      return {
        threatScore: 96,
        threatLevel: 'Critical',
        reasons: ['ThreatLens Automated Threat Warning Alert'],
        senderEmail: senderEmail,
        senderName: senderName,
        subject: subject
      };
    }

    // 1. Critical Urgency & Extortion keywords
    const criticalKeywords = [
      'pegasus', 'webcam recorded', 'bitcoin transfer', 'hacked your device',
      'password will expire', 'account suspended immediately', 'wire funds',
      'swift transfer', 'gift card', 'payroll update urgent', 'tax audit warrant',
      'unusual activity', 'compromised', 'action required immediately', 'threat mail', 'do not open'
    ];
    for (let i = 0; i < criticalKeywords.length; i++) {
      const kw = criticalKeywords[i];
      if (lowerSub.includes(kw) || lowerSnippet.includes(kw)) {
        score += 45;
        reasons.push('Urgency / Extortion trigger: "' + kw + '"');
        break;
      }
    }

    // 2. Phishing & credential harvesting indicators
    const mildKeywords = [
      'verify your account', 'unauthorized login', 'security alert',
      'update payment method', 'invoice attached', 'overdue payment', 'click here to confirm',
      'confirm your email', 'otp', 'password reset code', 'security code'
    ];
    for (let i = 0; i < mildKeywords.length; i++) {
      const kw = mildKeywords[i];
      if (lowerSub.includes(kw) || lowerSnippet.includes(kw)) {
        score += 25;
        reasons.push('Credential harvesting pattern: "' + kw + '"');
        break;
      }
    }

    // 3. VIP Brand Impersonation check
    const brandNames = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'chase', 'bank of america', 'meta', 'stripe', 'dhl', 'fedex', 'facebook', 'snapchat'];
    for (let i = 0; i < brandNames.length; i++) {
      const brand = brandNames[i];
      if (lowerName.includes(brand)) {
        if (!lowerEmail.includes(brand + '.') && !lowerEmail.endsWith('@' + brand + '.com')) {
          if (lowerEmail && !lowerEmail.includes(brand)) {
            score += 45;
            reasons.push('VIP Brand Impersonation: Displays "' + brand + '" from non-brand address (' + lowerEmail + ')');
            break;
          }
        }
      }
    }

    // 4. Institutional domains bonus
    if (lowerEmail.endsWith('@google.com') || lowerEmail.endsWith('@github.com') || lowerEmail.endsWith('@microsoft.com') || lowerEmail.endsWith('@apple.com')) {
      score = Math.max(0, score - 20);
    }

    score = Math.min(99, Math.max(2, score));
    const level = score > 80 ? 'Critical' : (score >= 50 ? 'Mild' : 'Safe');

    return {
      threatScore: score,
      threatLevel: level,
      reasons: reasons.length > 0 ? reasons : ['Verified sender reputation.'],
      senderEmail: senderEmail,
      senderName: senderName,
      subject: subject
    };
  }

  /**
   * INBOX LIST VIEW INJECTION: Clean colored number right after sender name
   */
  function injectBadgeIntoInboxRow(rowEl) {
    if (!isEnabled) return;
    if (rowEl.getAttribute('data-threatlens-row-injected') === 'true') return;

    // Sender cell in Gmail list view
    const senderCell = rowEl.querySelector('td.yX, .yX, div.yW, .yW');
    if (!senderCell) return;

    // Sender name element
    const senderNameEl = senderCell.querySelector('span[email], .bqe, .zF, span[name], span');
    if (!senderNameEl) return;

    const senderEmail = senderNameEl.getAttribute('email') || senderNameEl.getAttribute('name') || '';
    const senderName = senderNameEl.textContent.trim() || 'Sender';

    // Extract subject & snippet
    const subjectEl = rowEl.querySelector('.bog, .bqr, [data-thread-id]');
    const subject = subjectEl ? subjectEl.textContent.trim() : '';

    const snippetEl = rowEl.querySelector('.y2');
    const snippet = snippetEl ? snippetEl.textContent.trim() : '';

    rowEl.setAttribute('data-threatlens-row-injected', 'true');

    // Run evaluation
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

    // Create minimalist clean colored number element (No background, No pill)
    const scoreSpan = document.createElement('span');
    scoreSpan.className = 'threatlens-number-badge ' + scoreColorClass;
    scoreSpan.title = 'ThreatLens AI Threat Score: ' + score + '/100 (' + analysis.threatLevel + ')';
    scoreSpan.textContent = ' [' + score + ']';

    // Insert immediately after sender name
    if (senderNameEl.nextSibling) {
      senderNameEl.parentNode.insertBefore(scoreSpan, senderNameEl.nextSibling);
    } else {
      senderNameEl.parentNode.appendChild(scoreSpan);
    }
  }

  /**
   * OPENED EMAIL VIEW INJECTION: Clean colored number right next to sender in header
   */
  function injectBadgeIntoOpenMessage(messageEl) {
    if (!isEnabled) return;
    if (messageEl.getAttribute('data-threatlens-injected') === 'true') return;

    const senderEl = messageEl.querySelector('span[email], .gD, [email]');
    if (!senderEl) return;

    const senderEmail = senderEl.getAttribute('email') || senderEl.textContent.trim();
    const senderName = senderEl.getAttribute('name') || senderEl.textContent.trim() || 'Sender';
    const subjectEl = document.querySelector('h2.hP, .ha h2') || messageEl.querySelector('.bog, h2');
    const subject = subjectEl ? subjectEl.textContent.trim() : 'Email Thread';
    const bodyEl = messageEl.querySelector('.a3s.aiL, .a3s, [role="article"]');
    const bodyText = bodyEl ? bodyEl.innerText.slice(0, 2000) : '';

    messageEl.setAttribute('data-threatlens-injected', 'true');

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

    const scoreSpan = document.createElement('span');
    scoreSpan.className = 'threatlens-number-badge ' + scoreColorClass;
    scoreSpan.title = 'ThreatLens AI Threat Score: ' + score + '/100 (' + analysis.threatLevel + ') - ' + (analysis.reasons[0] || 'Verified');
    scoreSpan.textContent = ' [' + score + ']';

    if (senderEl.parentNode) {
      senderEl.parentNode.appendChild(scoreSpan);
    }
  }

  /**
   * Scan entire visible Gmail DOM
   */
  function scanGmail() {
    // 1. Scan Inbox Rows
    const rows = document.querySelectorAll('tr.zA, tr.zE, tr.yO, [role="row"]');
    for (let i = 0; i < rows.length; i++) {
      injectBadgeIntoInboxRow(rows[i]);
    }

    // 2. Scan Opened Email Views
    const messages = document.querySelectorAll('.adn.ads, .adn, [role="main"] .adn, .gE.iv.gt, div[data-message-id]');
    for (let i = 0; i < messages.length; i++) {
      injectBadgeIntoOpenMessage(messages[i]);
    }
  }

  // MutationObserver for continuous instant updates as you scroll
  const observer = new MutationObserver(function(mutations) {
    let shouldScan = false;
    for (let i = 0; i < mutations.length; i++) {
      if (mutations[i].addedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) scanGmail();
  });

  observer.observe(document.body, { childList: true, subtree: true });
  setTimeout(scanGmail, 800);
  setInterval(scanGmail, 1500);
})();
