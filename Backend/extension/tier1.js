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

const SENDER_DOMAIN_ALLOWLIST = new Set(TRUSTED_BRANDS);

const BRAND_SPOOF_RULES = [
  { keywords: ['google', 'gmail'], domains: ['google.com', 'gmail.com'] },
  { keywords: ['microsoft', 'outlook', 'office', 'onedrive'], domains: ['microsoft.com', 'outlook.com', 'office.com', 'live.com'] },
  { keywords: ['paypal'], domains: ['paypal.com'] },
  { keywords: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
  { keywords: ['amazon', 'aws'], domains: ['amazon.com', 'amazonaws.com'] },
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

function extractEmailAddress(senderRaw) {
  const s = (senderRaw || '').toString().trim();
  if (!s) return '';

  const angle = s.match(/<([^>]+)>/);
  if (angle && angle[1]) return angle[1].trim();

  const plain = s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return plain ? plain[0].trim() : s;
}

function emailDomain(email) {
  const at = (email || '').lastIndexOf('@');
  if (at === -1) return '';
  return normalizeDomain(email.slice(at + 1));
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

function scoreSender({ senderEmail, senderName, sender }, evidence) {
  let points = 0;

  const email = extractEmailAddress(senderEmail || sender);
  const domain = emailDomain(email);
  const name = (senderName || '').toString();
  const nameLower = name.toLowerCase();

  if (!email || email === 'Unknown' || !domain) {
    points += 4;
    evidence.push({ check: 'sender', points: 4, detail: 'Sender address unavailable.' });
    return points;
  }

  if (domain.includes('xn--')) {
    points += 12;
    evidence.push({ check: 'sender_punycode', points: 12, detail: `Sender domain punycode: ${domain}` });
  }

  if (containsNonAscii(domain)) {
    points += 16;
    evidence.push({ check: 'sender_homograph', points: 16, detail: `Sender domain non-ASCII: ${domain}` });
  }

  const isAllowlisted = Array.from(SENDER_DOMAIN_ALLOWLIST).some(
    (d) => domain === d || domain.endsWith(`.${d}`),
  );
  if (isAllowlisted) {
    points -= 8;
    evidence.push({ check: 'sender_allowlist', points: -8, detail: `Sender domain allowlisted: ${domain}` });
  }

  for (const rule of BRAND_SPOOF_RULES) {
    const claimsBrand = rule.keywords.some((k) => nameLower.includes(k));
    if (!claimsBrand) continue;

    const matchesBrandDomain = rule.domains.some((d) => domain.endsWith(d));
    if (!matchesBrandDomain) {
      points += 18;
      evidence.push({
        check: 'sender_spoof',
        points: 18,
        detail: `Display name suggests ${rule.domains[0]} but sender domain is ${domain}`,
      });
    }

    break;
  }

  return points;
}

export function analyzeTier1(emailData) {
  const evidence = [];
  const body = emailData?.body || '';
  const subject = emailData?.subject || '';

  let score = 0;
  score += scoreTextKeywords(`${subject}\n${body}`, evidence);
  score += scoreSender(
    { senderEmail: emailData?.senderEmail, senderName: emailData?.senderName, sender: emailData?.sender },
    evidence,
  );
  score += scoreLinks({ bodyText: `${subject}\n${body}`, links: emailData?.links || [] }, evidence);

  return {
    t1_score: clampScore(score),
    t1_evidence: evidence,
    t1_status: score >= 20 ? 'Suspicious' : 'Clean',
  };
}
