import { analyzeTier1 } from './tier1.js';

const BACKEND_BERT_URL = 'http://127.0.0.1:8000/tier1/bert';

const scanButton = document.getElementById('scan-btn');
const threatScoreEl = document.getElementById('threat-score');
const statusTextEl = document.getElementById('status-text');
const mlStatusEl = document.getElementById('ml-status');
const evidenceListEl = document.getElementById('evidence-list');

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function setStatus(text) {
  statusTextEl.innerText = text;
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
      const points = typeof i?.points === 'number' ? `(+${i.points}) ` : '';
      const detail = i?.detail ? i.detail : String(i);
      const check = i?.check ? `[${i.check}] ` : '';
      return `<li>${check}${points}${detail}</li>`;
    })
    .join('');
}

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
  setMlStatus('');

  try {
    setStatus('Reading Gmail content...');
    const email = await extractEmailFromGmailActiveTab();

    // Tier 1A: instant heuristics
    const heur = analyzeTier1(email);
    threatScoreEl.innerText = String(heur.t1_score);
    renderEvidence(heur.t1_evidence);
    setStatus(`Tier 1 heuristics: ${heur.t1_status}`);

    // Tier 1B: optional local HuggingFace/BERT backend
    setMlStatus('Local ML: pending (127.0.0.1:8000)');

    try {
      const ml = await fetchBertThreat((email.body || '').substring(0, 2500));

      const combined = clampScore(heur.t1_score * 0.65 + (ml.threat_level || 0) * 0.35);

      const mergedEvidence = [...(heur.t1_evidence || [])];
      mergedEvidence.push({
        check: 'ml',
        points: Math.max(0, combined - heur.t1_score),
        detail: `Local ML: ${ml.label} (${Math.round((ml.confidence || 0) * 100)}%) - ${ml.reasoning}`,
      });

      threatScoreEl.innerText = String(combined);
      renderEvidence(mergedEvidence);
      setMlStatus(`Local ML: online (${ml.model})`);
      setStatus('Tier 1 complete.');
    } catch (mlErr) {
      console.warn(mlErr);
      setMlStatus('Local ML: offline (heuristics only)');
      setStatus('Tier 1 heuristics complete (ML offline).');
    }
  } catch (err) {
    console.error(err);
    setMlStatus('Local ML: offline (heuristics only)');
    setStatus(err?.message || 'Scan failed.');
  }
});
