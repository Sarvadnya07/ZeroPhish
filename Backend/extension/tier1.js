/**
 * ZeroPhish Tier 1: Local Heuristic Engine (Manifest V3 safe)
 * Runs in the side panel (no Gmail UI injection).
 */

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function normalizeDomain(hostname) {
  return (hostname || '').toLowerCase().replace(/^www\./, '').trim();
}

function safeUrlParse(href) {
  try {
    return new URL(href);
  } catch {
    return null;
  }
}

const KEYWORD_RULES = [
  { re: /\burgent\b/i, points: 10 },
  { re: /\baction required\b/i, points: 12 },
  { re: /\bverify\b/i, points: 10 },
  { re: /\bsuspend(ed)?\b/i, points: 12 },
  { re: /\b(account|mailbox)\s+(locked|disabled|limited)\b/i, points: 14 },
  { re: /\bpassword\s+reset\b/i, points: 14 },
  { re: /\bsign\s*in\b/i, points: 8 },
  { re: /\blog(in)?\b/i, points: 8 },
  { re: /\bsecurity\s+alert\b/i, points: 12 },
  { re: /\bunauthorized\b/i, points: 10 },
  { re: /\bwire\b|\bbank transfer\b/i, points: 16 },
  { re: /\bgift\s*card\b/i, points: 18 },
  { re: /\bpay(ment)?\b|\binvoice\b/i, points: 10 },
];

const TRUSTED_BRANDS = [
  'google.com',
  'gmail.com',
  'microsoft.com',
  'paypal.com',
  'apple.com',
  'amazon.com',
];

const URL_SHORTENERS = new Set([
  'bit.ly',
  't.co',
  'tinyurl.com',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'cutt.ly',
  'rebrand.ly',
]);

const SUSPICIOUS_TLDS = new Set([
  'zip',
  'mov',
  'top',
  'xyz',
  'click',
  'country',
  'stream',
  'gq',
  'tk',
  'ml',
  'ga',
  'cf',
]);

function domainTld(domain) {
  const parts = domain.split('.');
  return parts.length >= 2 ? parts[parts.length - 1] : '';
}

function looksLikeIpHostname(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function containsNonAscii(str) {
  return /[^\u0000-\u007F]/.test(str);
}

function scoreTextKeywords(text, evidence) {
  let points = 0;
  for (const rule of KEYWORD_RULES) {
    if (rule.re.test(text)) {
      points += rule.points;
      evidence.push({ check: 'keyword', points: rule.points, detail: `Matched: ${rule.re.source}` });
    }
  }
  return points;
}

function scoreLinks({ bodyText, links }, evidence) {
  let points = 0;
  const bodyLower = (bodyText || '').toLowerCase();

  for (const link of links || []) {
    const href = typeof link === 'string' ? link : link?.href;
    const anchorText = typeof link === 'string' ? '' : (link?.text || '');
    if (!href) continue;

    const url = safeUrlParse(href);
    if (!url) continue;

    const domain = normalizeDomain(url.hostname);
    const tld = domainTld(domain);

    if (domain.includes('xn--')) {
      points += 18;
      evidence.push({ check: 'punycode', points: 18, detail: `Punycode domain: ${domain}` });
    }

    if (containsNonAscii(domain)) {
      points += 22;
      evidence.push({ check: 'homograph', points: 22, detail: `Non-ASCII domain: ${domain}` });
    }

    if (looksLikeIpHostname(domain)) {
      points += 20;
      evidence.push({ check: 'ip_url', points: 20, detail: `IP-based URL: ${domain}` });
    }

    if (URL_SHORTENERS.has(domain)) {
      points += 12;
      evidence.push({ check: 'shortener', points: 12, detail: `URL shortener: ${domain}` });
    }

    if (SUSPICIOUS_TLDS.has(tld)) {
      points += 10;
      evidence.push({ check: 'tld', points: 10, detail: `Suspicious TLD: .${tld}` });
    }

    const anchorLower = anchorText.toLowerCase();
    for (const brand of TRUSTED_BRANDS) {
      const brandInBody = bodyLower.includes(brand);
      const brandInAnchor = anchorLower.includes(brand) || anchorLower.includes(brand.split('.')[0]);
      if ((brandInBody || brandInAnchor) && !domain.includes(brand)) {
        points += 16;
        evidence.push({
          check: 'brand_mismatch',
          points: 16,
          detail: `Claims "${brand}" but links to "${domain}"`,
        });
        break;
      }
    }
  }

  return points;
}

export function analyzeTier1(emailData) {
  const evidence = [];
  const body = emailData?.body || '';
  const subject = emailData?.subject || '';
  const sender = emailData?.sender || '';

  let score = 0;
  score += scoreTextKeywords(`${subject}\n${body}`, evidence);
  score += scoreLinks({ bodyText: `${subject}\n${body}`, links: emailData?.links || [] }, evidence);

  if (!sender || sender === 'Unknown') {
    score += 4;
    evidence.push({ check: 'sender', points: 4, detail: 'Sender address unavailable.' });
  }

  return {
    t1_score: clampScore(score),
    t1_evidence: evidence,
    t1_status: score > 0 ? 'Suspicious' : 'Clean',
  };
}
