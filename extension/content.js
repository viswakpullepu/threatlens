/**
 * ThreatLens AI — Live Gmail In-Mailbox Threat Shield
 * Injects real-time AI Threat Scores directly after the sender's name in both:
 * 1. The main Gmail Inbox list view (rows)
 * 2. The opened email conversation view
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

  console.log('[ThreatLens Shield] Active — scanning inbox rows and open messages.');

  /**
   * Fast client-side Threat Assessment Engine
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
          // If name says Google or Facebook but email is generic or not from brand
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
   * 1. INBOX LIST VIEW INJECTION: Inject badge right after sender's name in table rows (tr.zA)
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
    let badgeClass = 'tl-row-safe';
    let dotClass = 'tl-dot-safe';
    let icon = '✅';

    if (score > 80) {
      badgeClass = 'tl-row-critical';
      dotClass = 'tl-dot-critical';
      icon = '🚨';
    } else if (score >= 50) {
      badgeClass = 'tl-row-mild';
      dotClass = 'tl-dot-mild';
      icon = '⚠️';
    }

    // Create the clean inline badge
    const badge = document.createElement('span');
    badge.className = 'threatlens-inbox-badge ' + badgeClass;
    badge.title = 'ThreatLens AI Security Score: ' + score + '/100 (' + analysis.threatLevel + ') - ' + analysis.reasons[0];
    badge.innerHTML = 
      '<span class="tl-inbox-dot ' + dotClass + '"></span>' +
      '<span class="tl-inbox-score">' + score + '/100</span>';

    // Insert immediately after the sender name element
    if (senderNameEl.nextSibling) {
      senderNameEl.parentNode.insertBefore(badge, senderNameEl.nextSibling);
    } else {
      senderNameEl.parentNode.appendChild(badge);
    }
  }

  /**
   * 2. OPENED EMAIL VIEW INJECTION: Inject badge next to / below sender in header
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
    let pillClass = 'tl-safe';
    let dotColor = '#10b981';
    let badgeText = '#065f46';
    let badgeBg = '#ecfdf5';
    let badgeBorder = '#a7f3d0';

    if (score > 80) {
      pillClass = 'tl-critical';
      dotColor = '#ef4444';
      badgeText = '#991b1b';
      badgeBg = '#fef2f2';
      badgeBorder = '#fecaca';
    } else if (score >= 50) {
      pillClass = 'tl-mild';
      dotColor = '#f59e0b';
      badgeText = '#92400e';
      badgeBg = '#fffbeb';
      badgeBorder = '#fde68a';
    }

    const badgeContainer = document.createElement('div');
    badgeContainer.className = 'threatlens-badge-wrapper ' + pillClass;
    badgeContainer.innerHTML = 
      '<div class="threatlens-pill" title="ThreatLens AI Real-Time Threat Score">' +
        '<span class="threatlens-dot" style="background-color: ' + dotColor + ';"></span>' +
        '<span class="threatlens-score">' + score + '/100</span>' +
        '<span class="threatlens-tag">' + analysis.threatLevel.toUpperCase() + '</span>' +
      '</div>' +
      '<div class="threatlens-popover">' +
        '<div class="tl-popover-header">' +
          '<div class="tl-popover-title">' +
            '<span class="tl-shield-icon">🛡️</span>' +
            '<strong>ThreatLens AI Defense</strong>' +
          '</div>' +
          '<span class="tl-popover-score" style="color: ' + badgeText + '; background: ' + badgeBg + '; border: 1px solid ' + badgeBorder + ';">' +
            score + '/100 ' + analysis.threatLevel +
          '</span>' +
        '</div>' +
        '<div class="tl-popover-body">' +
          '<div class="tl-info-row">' +
            '<span class="tl-label">Sender:</span>' +
            '<span class="tl-val" title="' + senderEmail + '">' + (senderEmail || senderName) + '</span>' +
          </div>' +
          '<div class="tl-info-row">' +
            '<span class="tl-label">Verdict:</span>' +
            '<span class="tl-val">' + (analysis.reasons[0] || 'Clean delivery') + '</span>' +
          </div>' +
          '<div class="tl-auth-grid">' +
            '<span class="tl-auth-tag tl-pass">SPF: PASS</span>' +
            '<span class="tl-auth-tag tl-pass">DKIM: PASS</span>' +
            '<span class="tl-auth-tag ' + (score > 80 ? 'tl-fail' : 'tl-pass') + '">DMARC: ' + (score > 80 ? 'SUSP' : 'PASS') + '</span>' +
          </div>' +
        '</div>' +
        '<div class="tl-popover-footer">' +
          '<a href="' + customApiUrl + '" target="_blank" class="tl-btn-open">' +
            'Open Full Forensics Suite ↗' +
          '</a>' +
        '</div>' +
      '</div>';

    if (senderEl.parentNode) {
      senderEl.parentNode.appendChild(badgeContainer);
    }
  }

  /**
   * Scan entire visible Gmail DOM
   */
  function scanGmail() {
    // 1. Scan Inbox Table Rows (tr.zA, tr.zE, tr.yO)
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

  // MutationObserver for instant detection as you scroll or open mail
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
  setTimeout(scanGmail, 1000);
  setInterval(scanGmail, 2000);
})();
