import { analyzeTier1 } from './tier1.js';

// Configurable Gateway and Backend base URLs
const DEFAULT_GATEWAY_HOST = 'http://127.0.0.1:8001';
const DEFAULT_BACKEND_HOST = 'http://127.0.0.1:8000';

async function getEndpoints() {
  let gatewayHost = DEFAULT_GATEWAY_HOST;
  let backendHost = DEFAULT_BACKEND_HOST;

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.sync) {
    try {
      const items = await new Promise((resolve) => {
        chrome.storage.sync.get(['gatewayHost', 'backendHost'], resolve);
      });
      if (items?.gatewayHost) gatewayHost = items.gatewayHost.replace(/\/$/, '');
      if (items?.backendHost) backendHost = items.backendHost.replace(/\/$/, '');
    } catch (e) {
      console.warn('Could not load extension storage settings, falling back to defaults:', e);
    }
  }

  return {
    GATEWAY_SCAN_URL: `${gatewayHost}/gateway/scan`,
    GATEWAY_STATUS_URL: `${gatewayHost}/gateway/status`,
    GATEWAY_RESULT_URL: `${gatewayHost}/gateway/result`,
    VISION_ANALYZE_URL: `${gatewayHost}/vision/analyze`,
    BACKEND_REPORT_URL: `${backendHost}/tier1/report`,
  };
}

const POLL_INTERVAL_MS = 500;
const MAX_POLLS = 40; // Increased for Gemini logic
const MAX_POLL_ERRORS = 3;

// UI References
const scanButton = document.getElementById('scan-btn');
const visualCheckBtn = document.getElementById('visual-check-btn');
const threatScoreEl = document.getElementById('threat-score');
const gaugeProgress = document.getElementById('gauge-progress');
const scanIndicator = document.getElementById('scan-indicator');

// Status Pill
const statusPill = document.getElementById('status-pill');
const verdictText = document.getElementById('verdict-text');
const verdictRange = document.getElementById('verdict-range');
const verdictIcon = document.getElementById('verdict-icon');

// Summary Texts
const summaryLine1 = document.getElementById('summary-line-1');
const summaryLine2 = document.getElementById('summary-line-2');
const summaryLine3 = document.getElementById('summary-line-3');

// Pipeline elements
const t1Progress = document.getElementById('t1-progress');
const t1StatusText = document.getElementById('t1-status-text');
const t2Progress = document.getElementById('t2-progress');
const t2StatusText = document.getElementById('t2-status-text');
const t3Progress = document.getElementById('t3-progress');
const t3StatusText = document.getElementById('t3-status-text');

let activePollInterval = null;
let activeRunId = 0;

// Configuration for gauge
const GAUGE_MAX_OFFSET = 220; // Circumference of the gauge semicircle (r=70)

/**
 * Updates the SVG gauge needle/progress
 * @param {number} score 0-100
 */
function updateGauge(score) {
  const value = Math.max(0, Math.min(100, score));
  const offset = GAUGE_MAX_OFFSET - (value / 100) * GAUGE_MAX_OFFSET;
  if (gaugeProgress) {
    gaugeProgress.style.strokeDashoffset = offset;
  }
  if (threatScoreEl) {
    threatScoreEl.innerText = Math.round(value);
  }
}

/**
 * Updates the verdict pill and text
 */
function setVerdict(verdict, score) {
  const v = (verdict || 'SAFE').toUpperCase();
  if (!statusPill) return;

  statusPill.classList.remove('safe', 'suspicious', 'critical');
  
  if (v === 'CRITICAL' || score >= 70) {
    statusPill.classList.add('critical');
    verdictText.innerText = 'CRITICAL';
    verdictRange.innerText = '70-100';
    verdictIcon.innerText = '✕';
  } else if (v === 'SUSPICIOUS' || score >= 30) {
    statusPill.classList.add('suspicious');
    verdictText.innerText = 'SUSPICIOUS';
    verdictRange.innerText = '30-69';
    verdictIcon.innerText = '!';
  } else {
    statusPill.classList.add('safe');
    verdictText.innerText = 'SAFE';
    verdictRange.innerText = '0-29';
    verdictIcon.innerText = '✓';
  }
}

/**
 * Sets the multi-line analysis status text
 */
function setAnalysisSummary(l1, l2, l3) {
  if (summaryLine1) summaryLine1.innerText = l1 || '';
  if (summaryLine2) summaryLine2.innerText = l2 || '';
  if (summaryLine3) summaryLine3.innerText = l3 || '';
}

/**
 * Updates the T1/T2/T3 pipeline indicators
 */
function updatePipeline(tier, status, progress) {
  if (tier === 1) {
    if (t1Progress) t1Progress.style.width = `${progress}%`;
    if (t1StatusText) t1StatusText.innerText = status;
  } else if (tier === 2) {
    if (t2Progress) t2Progress.style.width = `${progress}%`;
    if (t2StatusText) t2StatusText.innerText = status;
  } else if (tier === 3) {
    if (t3Progress) t3Progress.style.width = `${progress}%`;
    if (t3StatusText) t3StatusText.innerText = status;
  }
}

function setScanningState(active) {
  if (scanIndicator) {
    if (active) scanIndicator.classList.remove('hidden');
    else scanIndicator.classList.add('hidden');
  }
  if (scanButton) {
    scanButton.disabled = active;
    scanButton.innerHTML = active 
      ? `SCANNING...` 
      : `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="btn-icon"><circle cx="12" cy="12" r="10"/><path d="m16 12-4-4-4 4"/></svg> INITIALIZE COMPLETE SCAN <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-right"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/></svg>`;
  }
}

function resetUI() {
  updateGauge(0);
  setVerdict('SAFE', 0);
  setAnalysisSummary('Waiting for session...', 'Scanner: Standby', 'Gemini AI: Ready to protect...');
  updatePipeline(1, 'Waiting...', 0);
  updatePipeline(2, 'Standby', 0);
  updatePipeline(3, 'Awaiting Input', 0);
  setScanningState(false);
}

// Reuse helper functions from original sidepanel.js
function safeUuid() {
  try {
    return crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  } catch {
    return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }
}

function toErrorMessage(err, fallback = 'Unknown error.') {
  if (typeof err === 'string' && err.trim()) return err.trim();
  const msg = err?.message;
  if (typeof msg === 'string' && msg.trim()) return msg.trim();
  return fallback;
}

function normalizeSenderEmail(email) {
  const raw = (email || '').toString().trim();
  const match = raw.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0] : 'unknown@unknown.com';
}

function formatGatewayError(status, data) {
  const detail = data?.detail;
  const errors = detail?.errors;
  if (Array.isArray(errors) && errors.length) {
    return `Gateway rejected scan (${status}): ${errors.join(', ')}`;
  }
  if (typeof detail === 'string' && detail.trim()) {
    return `Gateway rejected scan (${status}): ${detail}`;
  }
  return `Gateway rejected scan (${status})`;
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
    if (/Receiving end does not exist/i.test(message)) {
      await injectContentScript(tab.id);
      response = await sendExtractMessage(tab.id);
    } else {
      throw err;
    }
  }

  if (!response?.body) {
    throw new Error('Could not read the email. Refresh Gmail and try again.');
  }

  return response;
}

async function postLiveReport(payload) {
  try {
    const endpoints = await getEndpoints();
    await fetch(endpoints.BACKEND_REPORT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    // Non-blocking
  }
}

function clearPoll() {
  if (activePollInterval) {
    clearInterval(activePollInterval);
    activePollInterval = null;
  }
}

// MAIN SCAN LOGIC
scanButton.addEventListener('click', async () => {
  clearPoll();
  activeRunId += 1;
  const runId = activeRunId;
  const liveScanId = safeUuid();
  
  resetUI();
  setScanningState(true);

  try {
    const endpoints = await getEndpoints();
    setAnalysisSummary('Initializing connection...', 'Reading Gmail context...', 'Syncing with Gateway...');
    const email = await extractEmailFromGmailActiveTab();
    if (runId !== activeRunId) return;

    // TIER 1: Local Heuristics
    updatePipeline(1, 'Analyzing...', 40);
    const heur = analyzeTier1(email);
    const t1Score = Math.max(0, Math.min(100, Math.round(heur?.t1_score || 0)));
    
    updateGauge(t1Score);
    setVerdict(heur?.t1_category, t1Score);
    updatePipeline(1, 'Complete', 100);
    setAnalysisSummary('Tier 1: Local Heuristics Complete.', 'Analysis T2 & T3 Pending...', heur?.User_Friendly_Summary || 'Analyzing patterns...');

    const sender = normalizeSenderEmail(email.senderEmail || email.sender);
    const subject = email.subject || 'No Subject';
    const links = Array.isArray(email?.links) ? email.links.map(l => typeof l === 'string' ? l : l.href) : [];

    // TIER 2: Processing via Gateway
    updatePipeline(2, 'Connecting...', 20);
    const gatewayPayload = {
      tier1_score: t1Score,
      tier1_evidence: (heur?.t1_evidence || []).map(e => e.detail || String(e)),
      sender,
      body: email.body || '',
      links,
      subject,
      timestamp: new Date().toISOString()
    };

    const gResponse = await fetch(endpoints.GATEWAY_SCAN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(gatewayPayload)
    });

    if (!gResponse.ok) {
      const errorData = await gResponse.json().catch(() => null);
      throw new Error(formatGatewayError(gResponse.status, errorData));
    }
    const gData = await gResponse.json();
    if (runId !== activeRunId) return;

    const gScanId = gData.scan_id;
    const partialScore = Math.round(gData.partial_score || t1Score);
    
    updateGauge(partialScore);
    setVerdict(gData.verdict, partialScore);
    updatePipeline(2, 'Analyzing ML...', 60);
    setAnalysisSummary('Tier 2: ML & Metadata Active.', 'Polling Gemini AI (Tier 3)...', `Domain Status: ${gData.tier2?.domain_analysis?.status || 'Flagged'}`);

    // TIER 3: AI Polling
    updatePipeline(3, 'Awaiting Data', 20);
    let pollCount = 0;
    
    activePollInterval = setInterval(async () => {
      pollCount++;
      if (runId !== activeRunId) { clearPoll(); return; }

      try {
        const sRes = await fetch(`${endpoints.GATEWAY_STATUS_URL}/${gScanId}`);
        const status = await sRes.json();

        if (status.complete) {
          clearPoll();
          const rRes = await fetch(`${endpoints.GATEWAY_RESULT_URL}/${gScanId}`);
          const result = await rRes.json();
          
          const finalScore = Math.round(result.final_score || partialScore);
          updateGauge(finalScore);
          setVerdict(result.verdict, finalScore);
          
          updatePipeline(2, 'Complete', 100);
          updatePipeline(3, 'Complete', 100);
          
          setScanningState(false);
          setAnalysisSummary(
            `Final Result: ${result.verdict}`,
            `Overall Threat Score: ${finalScore}/100`,
            result.tier3?.reasoning || '3-Tier Analysis finalized successfully.'
          );

        } else if (pollCount >= MAX_POLLS) {
          clearPoll();
          setScanningState(false);
          setAnalysisSummary('Tier 3: AI Analysis Timeout', 'Falling back to T1 + T2 results.', 'Heavy traffic or slow AI response.');
          updatePipeline(3, 'Timeout', 50);
        } else {
          // Dynamic polling progress visually synchronized
          const prog = Math.min(95, (pollCount / MAX_POLLS) * 80 + 20);
          updatePipeline(3, `Thinking... (${Math.round(prog)}%)`, prog);
          
          if (status.layers_completed >= 2) {
             updatePipeline(2, 'Complete', 100);
          } else {
             updatePipeline(2, 'Analyzing...', 80);
          }
        }
      } catch (e) {
        // Retry polling
      }
    }, POLL_INTERVAL_MS);

  } catch (err) {
    if (runId !== activeRunId) return;
    setScanningState(false);
    setAnalysisSummary('Scan Failed', 'System encountered an error.', toErrorMessage(err));
    updatePipeline(1, 'Error', 0);
    updatePipeline(2, 'Error', 0);
    updatePipeline(3, 'Error', 0);
  }
});

// VISION CHECK LOGIC
visualCheckBtn.addEventListener('click', async () => {
  try {
    setAnalysisSummary('Visual Check Active...', 'Capturing rendering snapshot...', '');
    visualCheckBtn.innerHTML = 'ANALYZING...';
    visualCheckBtn.disabled = true;

    const tabs = await new Promise((resolve) => chrome.tabs.query({ active: true, currentWindow: true }, resolve));
    const [tab] = tabs || [];
    if (!tab?.id) throw new Error('No active tab found.');

    // Capture screenshot
    const screenshotUrl = await new Promise((resolve, reject) => {
      chrome.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 20 }, (dataUrl) => {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(dataUrl);
      });
    });

    const payload = {
      image_data_b64: screenshotUrl,
      url: tab.url,
      title: tab.title
    };

    const endpoints = await getEndpoints();
    const res = await fetch(endpoints.VISION_ANALYZE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) throw new Error('Vision analysis failed. Check backend.');
    const data = await res.json();

    if (data.is_phishing) {
      setVerdict('CRITICAL', data.threat_score);
      updateGauge(data.threat_score);
      setAnalysisSummary('🚨 SPOOFED PORTAL DETECTED!', `Brand spoofed: ${data.matched_brand}`, data.reasoning);
      updatePipeline(3, 'Intercepted', 100);
    } else {
      setVerdict('SAFE', data.threat_score);
      updateGauge(data.threat_score);
      setAnalysisSummary('Visual checks passed.', 'Domain matches visual structure.', data.reasoning);
      updatePipeline(3, 'Verified', 100);
    }
  } catch (e) {
    setAnalysisSummary('Visual Check Failed', toErrorMessage(e), '');
  } finally {
    visualCheckBtn.innerHTML = 'QUICK VISUAL CHECK';
    visualCheckBtn.disabled = false;
  }
});

// Initialize with a clean slate
resetUI();
