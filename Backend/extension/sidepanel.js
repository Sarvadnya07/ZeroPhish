import { analyzeTier1 } from './tier1.js';

// Gateway endpoints for 3-tier analysis
const GATEWAY_SCAN_URL = 'http://127.0.0.1:8001/gateway/scan';
const GATEWAY_STATUS_URL = 'http://127.0.0.1:8001/gateway/status';
const GATEWAY_RESULT_URL = 'http://127.0.0.1:8001/gateway/result';

// Dashboard endpoint
const BACKEND_REPORT_URL = 'http://127.0.0.1:8000/tier1/report';
const POLL_INTERVAL_MS = 500;
const MAX_POLLS = 20;
const MAX_POLL_ERRORS = 3;

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

const requiredUi = [
  scanButton,
  threatScoreEl,
  statusTextEl,
  mlStatusEl,
  evidenceListEl,
  reasonsListEl,
  toggleDetailsBtn,
  detailsContainerEl,
  threatCategoryEl,
  summaryTextEl,
];

const isUiReady = requiredUi.every(Boolean);
let activePollInterval = null;
let activeRunId = 0;

function toErrorMessage(err, fallback = 'Unknown error.') {
  if (typeof err === 'string' && err.trim()) return err.trim();
  const msg = err?.message;
  if (typeof msg === 'string' && msg.trim()) return msg.trim();
  return fallback;
}

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
}

function normalizeVerdict(verdict, fallback = 'SAFE') {
  const raw = typeof verdict === 'string' ? verdict.trim().toUpperCase() : '';
  if (raw === 'CRITICAL' || raw === 'SUSPICIOUS' || raw === 'SAFE') {
    return raw;
  }
  return fallback;
}

function categoryFromVerdict(verdict) {
  const normalized = normalizeVerdict(verdict);
  if (normalized === 'CRITICAL') return 'phishing';
  if (normalized === 'SUSPICIOUS') return 'spam';
  return 'safe';
}

function setStatus(text) {
  if (!statusTextEl) return;
  statusTextEl.innerText = text;
}

function setCategory(category) {
  if (!threatCategoryEl) return;
  const c = (category || 'safe').toLowerCase();
  threatCategoryEl.innerText = c.toUpperCase();
  threatCategoryEl.classList.remove('pill-safe', 'pill-spam', 'pill-phishing');
  threatCategoryEl.classList.add(c === 'phishing' ? 'pill-phishing' : c === 'spam' ? 'pill-spam' : 'pill-safe');
}

function setSummary(text) {
  if (!summaryTextEl) return;
  summaryTextEl.innerText = text || '';
}

function setMlStatus(text) {
  if (!mlStatusEl) return;
  mlStatusEl.innerText = text;
}

function renderEvidence(items) {
  if (!evidenceListEl) return;
  evidenceListEl.innerHTML = '';
  if (!Array.isArray(items) || items.length === 0) {
    return;
  }

  items.forEach((i) => {
    const li = document.createElement('li');
    const points = typeof i?.points === 'number'
      ? `(${i.points > 0 ? '+' : ''}${i.points}) `
      : '';
    const detail = i?.detail ? i.detail : String(i);
    const check = i?.check ? `[${i.check}] ` : '';
    li.textContent = `${check}${points}${detail}`;
    evidenceListEl.appendChild(li);
  });
}

function friendlyReasonsFromEvidence(items, category) {
  const reasons = [];
  const seen = new Set();

  function add(msg) {
    const m = (msg || '').trim();
    if (!m || seen.has(m)) return;
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
    if (check === 'homograph' || check === 'punycode') add('A link domain looks suspicious (possible look-alike domain).');
    if (check === 'ip_url') add('A link uses a raw IP address instead of a normal website name.');
    if (check === 'sender_spoof') add('The sender name looks like a known brand, but the email domain does not match.');
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
  if (!reasonsListEl) return;
  reasonsListEl.innerHTML = '';
  const reasons = friendlyReasonsFromEvidence(items, category);
  reasons.forEach((r) => {
    const li = document.createElement('li');
    li.textContent = r;
    reasonsListEl.appendChild(li);
  });
}

function renderOperationalReason(message) {
  if (!reasonsListEl) return;
  reasonsListEl.innerHTML = '';
  const li = document.createElement('li');
  li.textContent = message;
  reasonsListEl.appendChild(li);
}

function safeUuid() {
  try {
    return crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  } catch {
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
}

function scoreToVerdict(score) {
  const s = clampScore(score);
  if (s >= 70) return 'CRITICAL';
  if (s >= 30) return 'SUSPICIOUS';
  return 'SAFE';
}

function categoryToVerdict(category) {
  const c = String(category || '').toLowerCase();
  if (c === 'phishing') return 'CRITICAL';
  if (c === 'spam') return 'SUSPICIOUS';
  return 'SAFE';
}

function normalizeEvidenceForReport(items) {
  if (!Array.isArray(items)) return [];
  return items.map((item) => {
    if (item && typeof item === 'object') {
      return {
        check: item.check || 'extension',
        kind: item.kind || null,
        points: typeof item.points === 'number' ? item.points : null,
        detail: item.detail || String(item.check || 'signal'),
      };
    }
    return { check: 'extension', kind: null, points: null, detail: String(item) };
  });
}

function normalizeLinksForReport(email) {
  const links = Array.isArray(email?.links) ? email.links : [];
  return links
    .map((l) => (typeof l === 'string' ? { href: l, text: null } : { href: l?.href || '', text: l?.text || null }))
    .filter((l) => typeof l.href === 'string' && l.href.length > 0);
}

async function postLiveReport(payload) {
  try {
    await fetch(BACKEND_REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    // Dashboard sync is non-blocking for sidepanel UX.
  }
}

function clearActivePoll() {
  if (activePollInterval) {
    clearInterval(activePollInterval);
    activePollInterval = null;
  }
}

function setScanBusy(isBusy) {
  if (!scanButton) return;
  scanButton.disabled = isBusy;
  scanButton.innerText = isBusy ? 'SCANNING...' : 'INITIALIZE SCAN';
}

function resetUiForNewScan() {
  if (threatScoreEl) threatScoreEl.innerText = '...';
  renderEvidence([]);
  renderReasons([], 'safe');
  setMlStatus('');
  setCategory('safe');
  setSummary('');
  if (detailsContainerEl) detailsContainerEl.style.display = 'none';
  if (toggleDetailsBtn) toggleDetailsBtn.innerText = 'Show details';
}

if (toggleDetailsBtn && detailsContainerEl) {
  toggleDetailsBtn.addEventListener('click', () => {
    const open = detailsContainerEl.style.display !== 'none';
    detailsContainerEl.style.display = open ? 'none' : 'block';
    toggleDetailsBtn.innerText = open ? 'Show details' : 'Hide details';
  });
}

async function extractEmailFromGmailActiveTab() {
  async function sendExtractMessage(tabId) {
    return new Promise((resolve, reject) => {
      chrome.tabs.sendMessage(tabId, { action: 'EXTRACT_EMAIL' }, (res) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(res);
      });
    });
  }

  async function injectContentScript(tabId) {
    return new Promise((resolve, reject) => {
      chrome.scripting.executeScript(
        { target: { tabId }, files: ['content.js'] },
        () => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve();
        },
      );
    });
  }

  const tabs = await new Promise((resolve) =>
    chrome.tabs.query({ active: true, currentWindow: true }, resolve),
  );
  const [tab] = tabs || [];
  if (!tab?.id || !tab?.url?.includes('mail.google.com')) {
    throw new Error('Please open a Gmail message first.');
  }

  let response;
  try {
    response = await sendExtractMessage(tab.id);
  } catch (err) {
    const message = toErrorMessage(err);
    const missingReceiver = /Receiving end does not exist/i.test(message);
    if (!missingReceiver) {
      throw err;
    }
    await injectContentScript(tab.id);
    response = await sendExtractMessage(tab.id);
  }

  if (!response?.body) {
    throw new Error('Could not read the email. Refresh Gmail and try again.');
  }

  return response;
}

if (!isUiReady) {
  console.error('Sidepanel UI not ready: one or more required elements are missing.');
} else {
  scanButton.addEventListener('click', async () => {
    clearActivePoll();
    activeRunId += 1;
    const runId = activeRunId;
    const liveScanId = safeUuid();
    resetUiForNewScan();
    setScanBusy(true);

    try {
      setStatus('Reading Gmail content...');
      const email = await extractEmailFromGmailActiveTab();
      if (runId !== activeRunId) return;

      setStatus('Tier 1: Local analysis...');
      const heur = analyzeTier1(email);
      const tier1Score = clampScore(heur?.t1_score ?? 0);
      const tier1Evidence = Array.isArray(heur?.t1_evidence) ? heur.t1_evidence : [];
      const tier1Category = typeof heur?.t1_category === 'string' ? heur.t1_category : 'safe';
      const sender = email.senderEmail || email.sender || 'unknown@unknown.com';
      const subject = email.subject || 'No Subject';
      const links = normalizeLinksForReport(email);

      if (threatScoreEl) threatScoreEl.innerText = String(tier1Score);
      renderEvidence(tier1Evidence);
      renderReasons(tier1Evidence, tier1Category);
      setCategory(tier1Category);
      setSummary(typeof heur?.User_Friendly_Summary === 'string' ? heur.User_Friendly_Summary : 'Analyzing...');

      await postLiveReport({
        event_id: safeUuid(),
        scan_id: liveScanId,
        timestamp: new Date().toISOString(),
        sender,
        subject,
        links,
        final_score: tier1Score,
        verdict: categoryToVerdict(tier1Category) || scoreToVerdict(tier1Score),
        evidence: normalizeEvidenceForReport(tier1Evidence),
        reasons: friendlyReasonsFromEvidence(tier1Evidence, tier1Category),
        threat_analysis: {
          category: tier1Category,
          reasoning: typeof heur?.User_Friendly_Summary === 'string' ? heur.User_Friendly_Summary : 'Tier 1 complete',
          stage: 'tier1',
        },
        tier_details: {
          tier1: { score: tier1Score, status: tier1Category },
        },
      });

      setStatus('Tier 2: Analyzing metadata...');
      const gatewayPayload = {
        tier1_score: tier1Score,
        tier1_evidence: tier1Evidence.map((e) => e.detail || String(e)),
        sender,
        body: email.body || '',
        links: (Array.isArray(email?.links) ? email.links : [])
          .map((l) => (typeof l === 'string' ? l : l?.href))
          .filter(Boolean),
        subject,
        timestamp: new Date().toISOString()
      };

      let gatewayData;
      try {
        const gatewayResponse = await fetch(GATEWAY_SCAN_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(gatewayPayload)
        });
        if (runId !== activeRunId) return;

        if (!gatewayResponse.ok) {
          setStatus(`Tier 2/3 unavailable (gateway ${gatewayResponse.status}). Using Tier 1 result.`);
          setMlStatus('AI analysis unavailable.');
          await postLiveReport({
            event_id: safeUuid(),
            scan_id: liveScanId,
            timestamp: new Date().toISOString(),
            sender,
            subject,
            links,
            final_score: tier1Score,
            verdict: scoreToVerdict(tier1Score),
            evidence: normalizeEvidenceForReport(tier1Evidence),
            reasons: [
              ...friendlyReasonsFromEvidence(tier1Evidence, tier1Category),
              `Tier 2/3 unavailable (gateway ${gatewayResponse.status}).`,
            ],
            threat_analysis: { category: tier1Category, reasoning: 'Tier 2/3 unavailable', stage: 'tier1_fallback' },
            tier_details: { tier1: { score: tier1Score, status: tier1Category } },
          });
          return;
        }

        gatewayData = await gatewayResponse.json();
      } catch (gatewayErr) {
        if (runId !== activeRunId) return;
        setStatus('Tier 2/3 unavailable. Using Tier 1 result.');
        setMlStatus('AI analysis unavailable.');
        await postLiveReport({
          event_id: safeUuid(),
          scan_id: liveScanId,
          timestamp: new Date().toISOString(),
          sender,
          subject,
          links,
          final_score: tier1Score,
          verdict: scoreToVerdict(tier1Score),
          evidence: normalizeEvidenceForReport(tier1Evidence),
          reasons: [
            ...friendlyReasonsFromEvidence(tier1Evidence, tier1Category),
            'Tier 2/3 unavailable.',
          ],
          threat_analysis: { category: tier1Category, reasoning: 'Tier 2/3 unavailable', stage: 'tier1_fallback' },
          tier_details: { tier1: { score: tier1Score, status: tier1Category } },
        });
        return;
      }

      const gatewayScanId = gatewayData?.scan_id;
      if (!gatewayScanId) {
        setStatus('Gateway returned incomplete response. Using Tier 1 result.');
        setMlStatus('AI analysis unavailable.');
        await postLiveReport({
          event_id: safeUuid(),
          scan_id: liveScanId,
          timestamp: new Date().toISOString(),
          sender,
          subject,
          links,
          final_score: tier1Score,
          verdict: scoreToVerdict(tier1Score),
          evidence: normalizeEvidenceForReport(tier1Evidence),
          reasons: [
            ...friendlyReasonsFromEvidence(tier1Evidence, tier1Category),
            'Gateway returned incomplete response.',
          ],
          threat_analysis: { category: tier1Category, reasoning: 'Gateway incomplete response', stage: 'tier1_fallback' },
          tier_details: { tier1: { score: tier1Score, status: tier1Category } },
        });
        return;
      }

      const partialScore = clampScore(gatewayData.partial_score ?? tier1Score);
      if (threatScoreEl) threatScoreEl.innerText = String(partialScore);
      const tier2Verdict = normalizeVerdict(gatewayData?.verdict, 'SAFE');
      const tier2Category = categoryFromVerdict(tier2Verdict);

      const tier2EvidenceRaw = gatewayData?.tier2?.evidence;
      const tier2Evidence = Array.isArray(tier2EvidenceRaw)
        ? tier2EvidenceRaw
        : (tier2EvidenceRaw ? [String(tier2EvidenceRaw)] : []);
      const combinedEvidence = [...tier1Evidence];
      tier2Evidence.forEach((e) => {
        combinedEvidence.push({ detail: e, check: 'tier2' });
      });

      renderEvidence(combinedEvidence);
      renderReasons(combinedEvidence, tier2Category);
      setCategory(tier2Category);
      setSummary(`Tier 2 complete. Domain: ${gatewayData?.tier2?.domain_analysis?.status || 'analyzed'}`);
      setStatus('Tier 3: AI analyzing...');

      await postLiveReport({
        event_id: safeUuid(),
        scan_id: liveScanId,
        gateway_scan_id: gatewayScanId,
        timestamp: new Date().toISOString(),
        sender,
        subject,
        links,
        final_score: partialScore,
        verdict: tier2Verdict,
        evidence: normalizeEvidenceForReport(combinedEvidence),
        reasons: friendlyReasonsFromEvidence(combinedEvidence, tier2Category),
        threat_analysis: { category: tier2Category, reasoning: 'Tier 2 complete; Tier 3 running', stage: 'tier2' },
        tier_details: {
          tier1: { score: tier1Score, status: tier1Category },
          tier2: gatewayData?.tier2 || {},
        },
      });

      let pollCount = 0;
      let pollErrorCount = 0;
      let pollInFlight = false;

      activePollInterval = setInterval(async () => {
        if (pollInFlight || runId !== activeRunId) return;
        pollInFlight = true;
        pollCount++;

        try {
          const statusRes = await fetch(`${GATEWAY_STATUS_URL}/${gatewayScanId}`);
          if (runId !== activeRunId) return;

          if (!statusRes.ok) {
            clearActivePoll();
            setStatus('Status check failed.');
            setMlStatus('AI analysis unavailable.');
            return;
          }

          const status = await statusRes.json();
          pollErrorCount = 0;

          if (!status?.complete && pollCount >= MAX_POLLS) {
            clearActivePoll();
            setStatus('AI analysis timeout (using Tier 1+2 results).');
            setMlStatus('AI analysis unavailable.');
            return;
          }

          if (status?.complete) {
            clearActivePoll();

            const resultRes = await fetch(`${GATEWAY_RESULT_URL}/${gatewayScanId}`);
            if (runId !== activeRunId) return;

            if (!resultRes.ok) {
              setStatus(`Final AI result unavailable (${resultRes.status}). Using Tier 1+2.`);
              setMlStatus('AI analysis unavailable.');
              return;
            }

            const fullResult = await resultRes.json();
            const finalScore = clampScore(fullResult?.final_score ?? partialScore);
            if (threatScoreEl) threatScoreEl.innerText = String(finalScore);

            const finalVerdict = normalizeVerdict(fullResult?.verdict, tier2Verdict);
            const finalCategory = categoryFromVerdict(finalVerdict);

            const allEvidence = [...combinedEvidence];
            if (Array.isArray(fullResult?.tier3?.flagged_phrases)) {
              fullResult.tier3.flagged_phrases.forEach((phrase) => {
                allEvidence.push({ detail: `AI: ${phrase}`, check: 'tier3' });
              });
            }

            renderEvidence(allEvidence);
            renderReasons(allEvidence, finalCategory);
            setCategory(finalCategory);

            const verdictMessages = {
              'CRITICAL': 'HIGH RISK: Likely phishing. Do NOT click links. Verify via official channels.',
              'SUSPICIOUS': 'MEDIUM RISK: Suspicious patterns detected. Exercise caution.',
              'SAFE': 'LOW RISK: No significant threats detected.'
            };
            setSummary(verdictMessages[finalVerdict] || 'Analysis complete.');

            setStatus(`Complete. Verdict: ${finalVerdict} (Score: ${finalScore}/100)`);
            setMlStatus(`AI Analysis: ${fullResult?.tier3?.category || 'Complete'}`);

            const reportPayload = {
              event_id: safeUuid(),
              scan_id: liveScanId,
              gateway_scan_id: gatewayScanId,
              timestamp: new Date().toISOString(),
              sender,
              subject,
              links,
              final_score: finalScore,
              verdict: finalVerdict,
              evidence: normalizeEvidenceForReport(allEvidence),
              reasons: friendlyReasonsFromEvidence(allEvidence, finalCategory),
              threat_analysis: {
                ...(fullResult?.tier3 || {}),
                stage: 'tier3_complete',
              },
              tier_details: {
                tier1: { score: tier1Score, status: tier1Category },
                tier2: fullResult?.tier2 || {},
                tier3: fullResult?.tier3 || {}
              }
            };

            await postLiveReport(reportPayload);
          }
        } catch (pollErr) {
          pollErrorCount++;
          if (pollErrorCount >= MAX_POLL_ERRORS || pollCount >= MAX_POLLS) {
            clearActivePoll();
            setStatus('AI analysis interrupted (using Tier 1+2 results).');
            setMlStatus('AI analysis unavailable.');
          }
        } finally {
          pollInFlight = false;
        }
      }, POLL_INTERVAL_MS);
    } catch (err) {
      if (runId !== activeRunId) return;
      const message = toErrorMessage(err);
      const receivingEndMissing = /Receiving end does not exist/i.test(message);
      setMlStatus('');
      setStatus(`Scan failed: ${message}`);
      setSummary(
        receivingEndMissing
          ? 'Gmail page connection failed. Refresh the Gmail tab and run scan again.'
          : 'Scan did not complete.',
      );
      renderOperationalReason(
        receivingEndMissing
          ? 'Refresh Gmail (Ctrl+R) and open the email before scanning again.'
          : 'Scan could not complete. Check Gmail tab and backend availability, then retry.',
      );
      if (threatScoreEl) threatScoreEl.innerText = '0';
    } finally {
      if (runId === activeRunId) {
        setScanBusy(false);
      }
    }
  });
}
