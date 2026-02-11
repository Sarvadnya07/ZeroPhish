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

function baseDomain(hostname) {
  const host = normalizeDomain(hostname);
  if (!host) return '';

  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return host;

  // Minimal multi-part public suffix handling (not a full PSL).
  const last2 = parts.slice(-2).join('.');
  const last3 = parts.slice(-3).join('.');
  const multipart = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in']);
  if (multipart.has(last2)) return last3;

  return last2;
}

function safeUrlParse(href) {
  try {
    return new URL(href);
  } catch {
    return null;
  }
}

const KEYWORD_RULES = [
  { re: /\burgent\b/i, points: 10, kind: 'urgency' },
  { re: /\baction required\b/i, points: 12, kind: 'urgency' },
  { re: /\bverify\b/i, points: 10, kind: 'urgency' },
  { re: /\bsuspend(ed)?\b/i, points: 12, kind: 'urgency' },
  { re: /\b(account|mailbox)\s+(locked|disabled|limited)\b/i, points: 14, kind: 'urgency' },
  { re: /\bpassword\s+reset\b/i, points: 14, kind: 'credential' },
  { re: /\bsign\s*in\b/i, points: 8, kind: 'credential' },
  { re: /\blog(in)?\b/i, points: 8, kind: 'credential' },
  { re: /\bsecurity\s+alert\b/i, points: 12, kind: 'urgency' },
  { re: /\bunauthorized\b/i, points: 10, kind: 'urgency' },
  { re: /\bwire\b|\bbank transfer\b/i, points: 16, kind: 'financial' },
  { re: /\bgift\s*card\b/i, points: 18, kind: 'financial' },
  { re: /\bpay(ment)?\b|\binvoice\b/i, points: 10, kind: 'financial' },
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

// Known-good relationships (identity mapping).
// Example: gmail.com is part of Google; links to *.google.com or *.youtube.com should not be treated as mismatches.
const KNOWN_RELATIONSHIPS = new Map([
  ['gmail.com', new Set(['google.com', 'youtube.com'])],
  ['google.com', new Set(['gmail.com', 'youtube.com'])],
  ['youtube.com', new Set(['google.com', 'gmail.com'])],

  ['microsoft.com', new Set(['outlook.com', 'office.com', 'live.com', 'onedrive.com'])],
  ['outlook.com', new Set(['microsoft.com', 'office.com', 'live.com', 'onedrive.com'])],

  ['apple.com', new Set(['icloud.com'])],
  ['icloud.com', new Set(['apple.com'])],

  ['amazon.com', new Set(['amazonaws.com'])],
  ['amazonaws.com', new Set(['amazon.com'])],
]);

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

function areRelatedDomains(a, b) {
  const da = baseDomain(a);
  const db = baseDomain(b);
  if (!da || !db) return false;
  if (da === db) return true;

  const ra = KNOWN_RELATIONSHIPS.get(da);
  if (ra && ra.has(db)) return true;

  const rb = KNOWN_RELATIONSHIPS.get(db);
  if (rb && rb.has(da)) return true;

  return false;
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
      evidence.push({
        check: 'keyword',
        kind: rule.kind,
        points: rule.points,
        detail: `Matched: ${rule.re.source}`,
      });
    }
  }
  return points;
}

function classifyFromEvidence(score, evidence) {
  const checks = new Set((evidence || []).map((e) => e?.check).filter(Boolean));
  const kinds = new Set((evidence || []).map((e) => e?.kind).filter(Boolean));

  const strongIndicators =
    checks.has('brand_mismatch') ||
    checks.has('homograph') ||
    checks.has('punycode') ||
    checks.has('sender_spoof') ||
    checks.has('ip_url') ||
    checks.has('sender_homograph') ||
    checks.has('sender_punycode') ||
    kinds.has('credential');

  if (strongIndicators || score >= 50) return 'phishing';
  if (score >= 20) return 'spam';
  return 'safe';
}

function scoreLinks({ bodyText, links }, evidence) {
  let points = 0;
  const bodyLower = (bodyText || '').toLowerCase();
  const claimedBrands = new Set();

  for (const brand of TRUSTED_BRANDS) {
    if (bodyLower.includes(brand)) claimedBrands.add(brand);
  }

  for (const link of links || []) {
    const href = typeof link === 'string' ? link : link?.href;
    const anchorText = typeof link === 'string' ? '' : (link?.text || '');
    if (!href) continue;

    const url = safeUrlParse(href);
    if (!url) continue;

    const domain = normalizeDomain(url.hostname);
    const tld = domainTld(domain);
    const anchorLower = anchorText.toLowerCase();

    for (const brand of TRUSTED_BRANDS) {
      if (anchorLower.includes(brand) || anchorLower.includes(brand.split('.')[0])) claimedBrands.add(brand);
    }

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

    for (const brand of claimedBrands) {
      // Identity mapping: allow related domains (e.g., gmail.com -> google.com/youtube.com).
      if (areRelatedDomains(brand, domain)) continue;
      if (domain.includes(brand)) continue;

      points += 50;
      evidence.push({
        check: 'brand_mismatch',
        points: 50,
        detail: `Claims "${brand}" but links to "${domain}" (no known relationship)`,
      });
      break;
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
    points -= 20;
    evidence.push({ check: 'sender_allowlist', points: -20, detail: `Sender domain allowlisted: ${domain}` });
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
  const senderEmailRaw = emailData?.senderEmail || emailData?.sender || '';
  const senderDomain = emailDomain(extractEmailAddress(senderEmailRaw));
  const senderBase = baseDomain(senderDomain);

  let score = 0;
  score += scoreTextKeywords(`${subject}\n${body}`, evidence);
  score += scoreSender(
    { senderEmail: emailData?.senderEmail, senderName: emailData?.senderName, sender: emailData?.sender },
    evidence,
  );
  score += scoreLinks({ bodyText: `${subject}\n${body}`, links: emailData?.links || [] }, evidence);

  let finalScore = clampScore(score);

  // False positive mitigation: if score is high but every link is a verified/related subdomain of sender's parent org.
  const links = Array.isArray(emailData?.links) ? emailData.links : [];
  const linkBases = links
    .map((l) => (typeof l === 'string' ? l : l?.href))
    .map((href) => safeUrlParse(href))
    .filter(Boolean)
    .map((u) => baseDomain(u.hostname))
    .filter(Boolean);

  const allLinksRelatedToSender =
    linkBases.length > 0 &&
    !!senderBase &&
    linkBases.every((lb) => areRelatedDomains(senderBase, lb));

  if (finalScore > 25 && allLinksRelatedToSender) {
    const reducedTo = 9;
    evidence.push({
      check: 'fp_mitigation',
      points: reducedTo - finalScore,
      detail: "False-positive mitigation: all links are verified/related to the sender's parent organization.",
    });
    finalScore = reducedTo;
  }

  const category = classifyFromEvidence(finalScore, evidence);
  const summary =
    category === 'phishing'
      ? 'High risk: likely phishing. Do not click links; verify via official site/app.'
      : category === 'spam'
        ? 'Medium risk: suspicious/spam-like. Be cautious with links and requests.'
        : 'Low risk: looks safe based on local Tier 1 checks.';

  return {
    // Required output format (JSON-friendly)
    Final_Threat_Level: finalScore,
    Triggered_Heuristics: evidence,
    User_Friendly_Summary: summary,

    t1_score: finalScore,
    t1_evidence: evidence,
    t1_category: category, // safe | spam | phishing
    t1_status: finalScore >= 20 ? 'Suspicious' : 'Clean',
  };
}
