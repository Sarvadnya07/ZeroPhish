import { analyzeTier1 } from './tier1.js';

const BACKEND_BERT_URL = 'http://127.0.0.1:8000/tier1/bert';
const BACKEND_REPORT_URL = 'http://127.0.0.1:8000/tier1/report';

const scanButton = document.getElementById('scan-btn');
const threatScoreEl = document.getElementById('threat-score');
const statusTextEl = document.getElementById('status-text');
const mlStatusEl = document.getElementById('ml-status');
const evidenceListEl = document.getElementById('evidence-list');
const reasonsListEl = document.getElementById('reasons-list');
const toggleDetailsBtn = document.getElementById('toggle-details');
const detailsContainerEl = document.getElementById('details-container');
const threatCategoryEl = document.getElementById('threat-category');
const summaryTextEl = document.getElementById('summary-text');

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function setStatus(text) {
  statusTextEl.innerText = text;
}

function setCategory(category) {
  const c = (category || 'safe').toLowerCase();
  threatCategoryEl.innerText = c.toUpperCase();
  threatCategoryEl.classList.remove('pill-safe', 'pill-spam', 'pill-phishing');
  threatCategoryEl.classList.add(c === 'phishing' ? 'pill-phishing' : c === 'spam' ? 'pill-spam' : 'pill-safe');
}

function setSummary(text) {
  summaryTextEl.innerText = text || '';
}

function setMlStatus(text) {
  mlStatusEl.innerText = text;
}

function renderEvidence(items) {
  if (!Array.isArray(items) || items.length === 0) {
    evidenceListEl.innerHTML = '';
    return;
  }

  evidenceListEl.innerHTML = items
    .map((i) => {
      const points =
        typeof i?.points === 'number'
          ? `(${i.points > 0 ? '+' : ''}${i.points}) `
          : '';
      const detail = i?.detail ? i.detail : String(i);
      const check = i?.check ? `[${i.check}] ` : '';
      return `<li>${check}${points}${detail}</li>`;
    })
    .join('');
}

function friendlyReasonsFromEvidence(items, category) {
  const reasons = [];
  const seen = new Set();

  function add(msg) {
    const m = (msg || '').trim();
    if (!m) return;
    if (seen.has(m)) return;
    seen.add(m);
    reasons.push(m);
  }

  const evidence = Array.isArray(items) ? items : [];

  for (const e of evidence) {
    const check = e?.check;
    const kind = e?.kind;
    const detail = e?.detail || '';

    if (check === 'brand_mismatch') add('A link goes to a different website than it claims (common phishing trick).');
    if (check === 'shortener') add('A shortened link was used (can hide the real destination).');
    if (check === 'homograph' || check === 'punycode') add('A link domain looks suspicious (possible look‑alike domain).');
    if (check === 'ip_url') add('A link uses a raw IP address instead of a normal website name.');
    if (check === 'sender_spoof') add('The sender name looks like a known brand, but the email domain doesn’t match.');
    if (check === 'tld') add('A link uses an uncommon or risky domain ending (TLD).');
    if (check === 'fp_mitigation') add('Links look related to the sender organization (reduced false positives).');

    if (check === 'sender_allowlist' && typeof e?.points === 'number' && e.points < 0) {
      const m = detail.match(/allowlisted:\s*(.+)$/i);
      const d = m?.[1]?.trim();
      add(d ? `Sender domain is commonly trusted: ${d}.` : 'Sender domain is commonly trusted.');
    }

    if (check === 'keyword') {
      if (kind === 'credential') add('The message asks for sign-in/password/account access (high risk).');
      else if (kind === 'urgency') add('The message uses urgency/pressure language.');
      else if (kind === 'financial') add('The message mentions payment/invoice/transfer.');
    }

    if (check === 'ml') {
      add('Extra language check: message tone looks suspicious.');
    }
  }

  if (reasons.length === 0) {
    add(category === 'safe' ? 'No strong red flags detected.' : 'Suspicious signals detected.');
  }

  return reasons.slice(0, 4);
}

function renderReasons(items, category) {
  const reasons = friendlyReasonsFromEvidence(items, category);
  reasonsListEl.innerHTML = reasons.map((r) => `<li>${r}</li>`).join('');
}

function getReasonsFromUi() {
  return Array.from(reasonsListEl.querySelectorAll('li'))
    .map((li) => (li?.textContent || '').trim())
    .filter(Boolean);
}

function safeUuid() {
  try {
    return crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  } catch {
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
}

async function postLiveReport(payload) {
  try {
    await fetch(BACKEND_REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    console.warn('Live dashboard post failed', e);
  }
}

toggleDetailsBtn.addEventListener('click', () => {
  const open = detailsContainerEl.style.display !== 'none';
  detailsContainerEl.style.display = open ? 'none' : 'block';
  toggleDetailsBtn.innerText = open ? 'Show details' : 'Hide details';
});

async function extractEmailFromGmailActiveTab() {
  const tabs = await new Promise((resolve) =>
    chrome.tabs.query({ active: true, currentWindow: true }, resolve),
  );
  const [tab] = tabs || [];
  if (!tab?.id || !tab?.url?.includes('mail.google.com')) {
    throw new Error('Please open a Gmail message first.');
  }

  const response = await new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_EMAIL' }, (res) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(res);
    });
  });
  if (!response?.body) {
    throw new Error('Could not read the email. Refresh Gmail and try again.');
  }

  return response;
}

async function fetchBertThreat(emailText) {
  const res = await fetch(BACKEND_BERT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text: emailText }),
  });

  if (!res.ok) {
    const msg = await res.text().catch(() => '');
    throw new Error(`Backend error (${res.status}): ${msg}`);
  }

  return res.json();
}

scanButton.addEventListener('click', async () => {
  threatScoreEl.innerText = '0';
  renderEvidence([]);
  reasonsListEl.innerHTML = '';
  setMlStatus('');
  setCategory('safe');
  setSummary('');
  detailsContainerEl.style.display = 'none';
  toggleDetailsBtn.innerText = 'Show details';

  const scanId = safeUuid();

  try {
    setStatus('Reading Gmail content...');
    const email = await extractEmailFromGmailActiveTab();

    // Tier 1A: instant heuristics
    const heur = analyzeTier1(email);
    threatScoreEl.innerText = String(heur.t1_score);
    renderEvidence(heur.t1_evidence);
    renderReasons(heur.t1_evidence, heur.t1_category);
    setCategory(heur.t1_category);
    setSummary(heur.User_Friendly_Summary || '');
    setStatus(`Tier 1: ${(heur.t1_category || 'safe').toUpperCase()} (${heur.t1_status})`);

    void postLiveReport({
      version: 1,
      scan_id: scanId,
      created_at: new Date().toISOString(),
      source: 'chrome_sidepanel',
      email: {
        subject: email.subject || null,
        senderEmail: email.senderEmail || email.sender || null,
        senderName: email.senderName || null,
      },
      links: (email.links || []).map((l) => (typeof l === 'string' ? { href: l, text: null } : { href: l.href, text: l.text || null })),
      tier1: {
        score: heur.t1_score,
        category: heur.t1_category || 'safe',
        summary: heur.User_Friendly_Summary || '',
        evidence: heur.t1_evidence || [],
        reasons: getReasonsFromUi(),
        heuristics_score: heur.t1_score,
        ml_enabled: false,
      },
    });

    // Tier 1B: optional local HuggingFace/BERT backend
    setMlStatus('Extra language check: Checking...');

    try {
      const ml = await fetchBertThreat((email.body || '').substring(0, 2500));

      let combinedRaw = heur.t1_score * 0.65 + (ml.threat_level || 0) * 0.35;

      // Multiplier: if heuristics show urgency/action AND ML thinks it's risky, amplify the score.
      const hasUrgency = (heur.t1_evidence || []).some((e) => e?.kind === 'urgency');
      const mlRisky = (ml.category || '').toLowerCase() !== 'safe' || (ml.threat_level || 0) >= 20;
      if (hasUrgency && mlRisky) {
        combinedRaw *= 1.5;
      }

      const combined = clampScore(combinedRaw);

      const mergedEvidence = [...(heur.t1_evidence || [])];
      mergedEvidence.push({
        check: 'ml',
        points: Math.max(0, combined - heur.t1_score),
        detail: `Local ML: ${ml.category?.toUpperCase?.() || ml.label} (${Math.round((ml.confidence || 0) * 100)}%) - ${ml.reasoning}`,
      });
      if (hasUrgency && mlRisky) {
        mergedEvidence.push({
          check: 'ml_multiplier',
          points: 0,
          detail: 'Applied 1.5x multiplier due to urgency/action cues + ML risk.',
        });
      }

      threatScoreEl.innerText = String(combined);
      renderEvidence(mergedEvidence);
      const combinedCategory = combined >= 60 ? 'phishing' : combined >= 20 ? 'spam' : 'safe';
      renderReasons(mergedEvidence, combinedCategory);
      setMlStatus('Extra language check: On');
      setCategory(combinedCategory);
      setSummary(
        combinedCategory === 'phishing'
          ? 'High risk: likely phishing. Do not click links; verify via official site/app.'
          : combinedCategory === 'spam'
            ? 'Medium risk: suspicious/spam-like. Be cautious with links and requests.'
            : 'Low risk: looks safe based on local Tier 1 checks.',
      );
      setStatus(`Tier 1: ${combinedCategory.toUpperCase()} (complete)`);

      void postLiveReport({
        version: 1,
        scan_id: scanId,
        created_at: new Date().toISOString(),
        source: 'chrome_sidepanel',
        email: {
          subject: email.subject || null,
          senderEmail: email.senderEmail || email.sender || null,
          senderName: email.senderName || null,
        },
        links: (email.links || []).map((l) => (typeof l === 'string' ? { href: l, text: null } : { href: l.href, text: l.text || null })),
        tier1: {
          score: combined,
          category: combinedCategory,
          summary:
            combinedCategory === 'phishing'
              ? 'High risk: likely phishing. Do not click links; verify via official site/app.'
              : combinedCategory === 'spam'
                ? 'Medium risk: suspicious/spam-like. Be cautious with links and requests.'
                : 'Low risk: looks safe based on local Tier 1 checks.',
          evidence: mergedEvidence,
          reasons: getReasonsFromUi(),
          heuristics_score: heur.t1_score,
          ml_enabled: true,
          ml_threat_level: ml.threat_level ?? null,
          ml_category: ml.category ?? null,
          ml_confidence: ml.confidence ?? null,
          ml_label: ml.label ?? null,
          ml_model: ml.model ?? null,
          ml_reasoning: ml.reasoning ?? null,
        },
      });
    } catch (mlErr) {
      console.warn(mlErr);
      setMlStatus('Extra language check: Off');
      setStatus(`Tier 1: ${(heur.t1_category || 'safe').toUpperCase()} (ML offline)`);
    }
  } catch (err) {
    console.error(err);
    setMlStatus('Extra language check: Off');
    setStatus(err?.message || 'Scan failed.');
  }
});
