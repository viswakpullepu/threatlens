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
   * Fast Threat Assessment Engine
   */
  function evaluateThreat(senderEmail, senderName, subject, snippetText) {
    let score = 5;
    const reasons = [];
    const lowerEmail = (senderEmail || '').toLowerCase();
    const lowerName = (senderName || '').toLowerCase();
    const lowerSub = (subject || '').toLowerCase();
    const lowerSnippet = (snippetText || '').toLowerCase();

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

    // 2. Phishing & credential verification patterns
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
            reasons.push('VIP Brand Impersonation: Displays "' + brand + '" from unverified domain (' + lowerEmail + ')');
            break;
          }
        }
      }
    }

    // 4. Institutional domains
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
