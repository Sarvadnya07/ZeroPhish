/**
 * ZeroPhish Sentinel Side Panel Controller
 * Orchestrates Tier 1 (Client), Tier 2 (ML & OSINT), and Tier 3 (Gemini AI)
 * analysis pipeline with Clerk authentication and visual security checks.
 */

import { analyzeTier1 } from './tier1.js';

// Configuration defaults
const DEFAULT_GATEWAY_BASE = 'http://127.0.0.1:8001';
const DEFAULT_WEB_URL = 'http://localhost:3000';

let GATEWAY_BASE = DEFAULT_GATEWAY_BASE;
let WEB_URL = DEFAULT_WEB_URL;
let currentAuthToken = null;
let currentAuthUser = null;

function getEndpoints() {
  return {
    health: `${GATEWAY_BASE}/gateway/health`,
    scan: `${GATEWAY_BASE}/gateway/scan`,
    status: (id) => `${GATEWAY_BASE}/gateway/status/${id}`,
    result: (id) => `${GATEWAY_BASE}/gateway/result/${id}`,
    vision: `${GATEWAY_BASE}/vision/analyze`,
    report: `${GATEWAY_BASE}/tier1/report`,
    me: `${GATEWAY_BASE}/auth/me`,
  };
}

// Load custom base URLs (non-sensitive, cloud-synced) from storage.
if (typeof chrome !== 'undefined' && chrome.storage?.sync) {
  chrome.storage.sync.get(['gatewayBase', 'backendBase', 'webUrl'], (cfg) => {
    if (cfg?.gatewayBase) {
      GATEWAY_BASE = cfg.gatewayBase.replace(/\/+$/, '');
    } else if (cfg?.backendBase) {
      GATEWAY_BASE = cfg.backendBase.replace(/\/+$/, '');
    }
    if (cfg?.webUrl) WEB_URL = cfg.webUrl.replace(/\/+$/, '');
  });
}

// The session bearer token is a credential: it is read from chrome.storage.local,
// which stays on-device. chrome.storage.sync would replicate it to the user's
// cloud-synced profile in plaintext.
if (typeof chrome !== 'undefined' && chrome.storage?.local) {
  chrome.storage.local.get(['clerkSessionToken'], (cfg) => {
    if (cfg?.clerkSessionToken) {
      currentAuthToken = cfg.clerkSessionToken;
      fetchUserProfile(currentAuthToken);
    }
  });
}

// Polling configuration
const POLL_INTERVAL_MS = 400;
const MAX_POLLS = 45; // ~18 seconds max for AI analysis

// DOM References
const scanButton = document.getElementById('scan-btn');
const visualCheckBtn = document.getElementById('visual-check-btn');
const threatScoreEl = document.getElementById('threat-score');
const gaugeProgress = document.getElementById('gauge-progress');
const scanIndicator = document.getElementById('scan-indicator');

// Auth DOM References
const userProfileBadge = document.getElementById('user-profile-badge');
const userNameDisplay = document.getElementById('user-name-display');
const authLoginCta = document.getElementById('auth-login-cta');
const signinBtn = document.getElementById('signin-btn');
const signoutBtn = document.getElementById('signout-btn');

// Status Pill Elements
const statusPill = document.getElementById('status-pill');
const verdictText = document.getElementById('verdict-text');
const verdictRange = document.getElementById('verdict-range');
const verdictIcon = document.getElementById('verdict-icon');

// Summary Lines
const summaryLine1 = document.getElementById('summary-line-1');
const summaryLine2 = document.getElementById('summary-line-2');
const summaryLine3 = document.getElementById('summary-line-3');

// Pipeline Stage Elements
const t1Progress = document.getElementById('t1-progress');
const t1StatusText = document.getElementById('t1-status-text');
const t2Progress = document.getElementById('t2-progress');
const t2StatusText = document.getElementById('t2-status-text');
const t3Progress = document.getElementById('t3-progress');
const t3StatusText = document.getElementById('t3-status-text');

// Evidence Section
const reasonsContainer = document.getElementById('reasons-container');
const reasonsList = document.getElementById('reasons-list');

let activePollInterval = null;
let activeRunId = 0;

const GAUGE_MAX_OFFSET = 220; // Circumference of semicircle (r=70)

/**
 * Updates the authentication UI state
 */
function updateAuthUI(user) {
  if (user) {
    currentAuthUser = user;
    if (userProfileBadge) userProfileBadge.classList.remove('hidden');
    if (userNameDisplay) userNameDisplay.innerText = user.full_name || user.email || 'Protected';
    if (authLoginCta) authLoginCta.classList.add('hidden');
  } else {
    currentAuthUser = null;
    currentAuthToken = null;
    if (userProfileBadge) userProfileBadge.classList.add('hidden');
    if (authLoginCta) authLoginCta.classList.remove('hidden');
  }
}

async function fetchUserProfile(token) {
  try {
    const res = await fetch(getEndpoints().me, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const user = await res.json();
      updateAuthUI(user);
    } else {
      updateAuthUI(null);
    }
  } catch {
    updateAuthUI(null);
  }
}

if (signinBtn) {
  signinBtn.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url: `${WEB_URL}/login` });
    }
  });
}

if (signoutBtn) {
  signoutBtn.addEventListener('click', () => {
    currentAuthToken = null;
    if (typeof chrome !== 'undefined' && chrome.storage?.local) {
      chrome.storage.local.remove('clerkSessionToken');
    }
    updateAuthUI(null);
    setAnalysisSummary('Signed Out', 'Sign in via ZeroPhish Combat Centre to access personalized defense feeds.', '');
  });
}

/**
 * Updates the SVG circular threat gauge
 */
function updateGauge(score) {
  const value = Math.max(0, Math.min(100, score || 0));
  const offset = GAUGE_MAX_OFFSET - (value / 100) * GAUGE_MAX_OFFSET;
  if (gaugeProgress) {
    gaugeProgress.style.strokeDashoffset = offset;
  }
  if (threatScoreEl) {
    threatScoreEl.innerText = Math.round(value);
  }
}

/**
 * Canonical verdict vocabulary.
 *
 * The server emits SAFE | SUSPICIOUS | CRITICAL | UNKNOWN. The local Tier 1
 * heuristic emits its own advisory vocabulary (safe | spam | phishing) which is
 * NOT server-authoritative. Both are mapped explicitly here.
 *
 * Trust-boundary rule: an unrecognised, missing, or not-yet-evaluated verdict
 * must NEVER fall through to a benign SAFE render.
 */
const VERDICT_ALIASES = {
  SAFE: 'SAFE',
  SPAM: 'SUSPICIOUS',       // local advisory category
  PHISHING: 'CRITICAL',     // local advisory category
  SUSPICIOUS: 'SUSPICIOUS',
  CRITICAL: 'CRITICAL',
  UNKNOWN: 'UNKNOWN',
  ERROR: 'ERROR',
  OFFLINE: 'OFFLINE',
  PENDING: 'PENDING',       // not yet evaluated
};

/**
 * Updates the verdict badge styling and label
 */
function setVerdict(verdict, score) {
  const raw = String(verdict ?? '').trim().toUpperCase();
  const v = VERDICT_ALIASES[raw] || 'UNKNOWN';
  if (!statusPill) return;

  statusPill.classList.remove('safe', 'suspicious', 'critical', 'offline', 'pending');

  if (v === 'CRITICAL' || score >= 70) {
    statusPill.classList.add('critical');
    if (verdictText) verdictText.innerText = 'CRITICAL';
    if (verdictRange) verdictRange.innerText = '70-100';
    if (verdictIcon) verdictIcon.innerText = '✕';
  } else if (v === 'SUSPICIOUS' || score >= 30) {
    statusPill.classList.add('suspicious');
    if (verdictText) verdictText.innerText = 'SUSPICIOUS';
    if (verdictRange) verdictRange.innerText = '30-69';
    if (verdictIcon) verdictIcon.innerText = '!';
  } else if (v === 'OFFLINE' || v === 'ERROR') {
    statusPill.classList.add('critical');
    if (verdictText) verdictText.innerText = v;
    if (verdictRange) verdictRange.innerText = 'ERROR';
    if (verdictIcon) verdictIcon.innerText = '⚠';
  } else if (v === 'UNKNOWN') {
    statusPill.classList.add('suspicious');
    if (verdictText) verdictText.innerText = 'UNKNOWN';
    if (verdictRange) verdictRange.innerText = 'UNRESOLVED';
    if (verdictIcon) verdictIcon.innerText = '?';
  } else if (v === 'PENDING') {
    statusPill.classList.add('pending');
    if (verdictText) verdictText.innerText = 'NOT SCANNED';
    if (verdictRange) verdictRange.innerText = 'PENDING';
    if (verdictIcon) verdictIcon.innerText = '·';
  } else if (v === 'SAFE') {
    statusPill.classList.add('safe');
    if (verdictText) verdictText.innerText = 'SAFE';
    if (verdictRange) verdictRange.innerText = '0-29';
    if (verdictIcon) verdictIcon.innerText = '✓';
  } else {
    // Defensive: an unmapped verdict is never rendered as benign.
    statusPill.classList.add('suspicious');
    if (verdictText) verdictText.innerText = 'UNKNOWN';
    if (verdictRange) verdictRange.innerText = 'UNRESOLVED';
    if (verdictIcon) verdictIcon.innerText = '?';
  }
}



/**
 * Updates the 3 multi-line analysis text fields
 */
function setAnalysisSummary(l1, l2, l3) {
  if (summaryLine1) summaryLine1.innerText = l1 || '';
  if (summaryLine2) summaryLine2.innerText = l2 || '';
  if (summaryLine3) summaryLine3.innerText = l3 || '';
}

/**
 * Updates T1/T2/T3 pipeline status badges and progress bars
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

/**
 * Toggles scanning visual state and button disabling
 */
function setScanningState(active) {
  if (scanIndicator) {
    if (active) scanIndicator.classList.remove('hidden');
    else scanIndicator.classList.add('hidden');
  }
  if (scanButton) {
    scanButton.disabled = active;
    scanButton.innerHTML = active
      ? `<span class="btn-spinner"></span> SCANNING...`
      : `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="btn-icon"><circle cx="12" cy="12" r="10"/><path d="m16 12-4-4-4 4"/></svg> INITIALIZE COMPLETE SCAN <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="btn-icon-right"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/></svg>`;
  }
}

/**
 * Displays list of detected forensic evidence items
 */
function renderEvidence(evidenceList) {
  if (!reasonsList || !reasonsContainer) return;
  reasonsList.innerHTML = '';
  if (!evidenceList || !evidenceList.length) {
    reasonsContainer.classList.add('hidden');
    return;
  }
  evidenceList.forEach((item) => {
    const li = document.createElement('li');
    li.innerText = typeof item === 'string' ? item : item.detail || JSON.stringify(item);
    reasonsList.appendChild(li);
  });
  reasonsContainer.classList.remove('hidden');
}

/**
 * Resets the UI to ready/standby state
 */
function resetUI() {
  updateGauge(0);
  setVerdict('PENDING', 0);
  setAnalysisSummary(
    'Ready for Scan.',
    'No analysis has been run for this page.',
    'Tier 1 (Local) & Tier 2 (ML) Standby.'
  );
  updatePipeline(1, 'READY', 0);
  updatePipeline(2, 'READY', 0);
  updatePipeline(3, 'READY', 0);
  if (reasonsContainer) reasonsContainer.classList.add('hidden');
  setScanningState(false);
}

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

/**
 * Checks if the backend gateway is reachable
 */
async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);
    const res = await fetch(getEndpoints().health, {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Extracts email content from active tab or falls back to active web page URL context
 */
async function extractActiveTabContext() {
  if (typeof chrome === 'undefined' || !chrome.tabs) {
    throw new Error('Chrome extension APIs unavailable in current context.');
  }

  const tabs = await new Promise((resolve) =>
    chrome.tabs.query({ active: true, currentWindow: true }, resolve)
  );
  const [tab] = tabs || [];
  if (!tab?.id) {
    throw new Error('No active browser tab found.');
  }

  // Check if Gmail is active
  let isGmail = false;
  if (tab.url) {
    try {
      const parsedTabUrl = new URL(tab.url);
      isGmail = parsedTabUrl.hostname === 'mail.google.com';
    } catch {
      isGmail = false;
    }
  }

  if (isGmail) {
    try {
      const response = await new Promise((resolve, reject) => {
        chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_EMAIL' }, (res) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(res);
          }
        });
      });
      if (response && response.body) {
        return response;
      }
    } catch (e) {
      // Content script injection fallback
      try {
        await new Promise((resolve, reject) => {
          chrome.scripting.executeScript(
            { target: { tabId: tab.id }, files: ['content.js'] },
            () => {
              if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
              else resolve();
            }
          );
        });
        const retryRes = await new Promise((resolve, reject) => {
          chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_EMAIL' }, (res) => {
            if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
            else resolve(res);
          });
        });
        if (retryRes && retryRes.body) {
          return retryRes;
        }
      } catch {
        // Fall through to tab metadata
      }
    }
  }

  // Fallback for general web pages or non-email tabs
  return {
    sender: 'web-session@' + (new URL(tab.url || 'http://localhost').hostname || 'unknown.local'),
    senderEmail: 'web-session@' + (new URL(tab.url || 'http://localhost').hostname || 'unknown.local'),
    senderName: tab.title || 'Web Page Session',
    subject: tab.title || 'Web Security Scan',
    body: `Page Title: ${tab.title || ''}\nURL: ${tab.url || ''}`,
    links: tab.url ? [tab.url] : [],
  };
}

function clearPoll() {
  if (activePollInterval) {
    clearInterval(activePollInterval);
    activePollInterval = null;
  }
}

// -----------------------------------------------------------------------------
// INITIALIZE COMPLETE SCAN EVENT HANDLER
// -----------------------------------------------------------------------------
if (scanButton) {
  scanButton.addEventListener('click', async () => {
    clearPoll();
    activeRunId += 1;
    const runId = activeRunId;

    resetUI();
    setScanningState(true);

    try {
      setAnalysisSummary('Verifying Gateway...', 'Checking ZeroPhish API connection...', '');
      updatePipeline(1, 'Connecting...', 10);

      // Preflight Health Verification
      const isHealthy = await checkBackendHealth();
      if (!isHealthy) {
        setScanningState(false);
        setVerdict('OFFLINE', 0);
        updatePipeline(1, 'Offline', 0);
        updatePipeline(2, 'Offline', 0);
        updatePipeline(3, 'Offline', 0);
        setAnalysisSummary(
          'ZeroPhish Gateway Offline',
          'Could not reach API Gateway at ' + GATEWAY_BASE,
          'Ensure the backend is running via "python gateway.py"'
        );
        return;
      }

      setAnalysisSummary('Extracting Context...', 'Reading page/email context...', 'Running Tier 1 heuristics...');
      updatePipeline(1, 'Analyzing...', 40);

      const emailData = await extractActiveTabContext();
      if (runId !== activeRunId) return;

      // ── TIER 1: Local Heuristic Analysis ──────────────────────────────────
      const heur = analyzeTier1(emailData);
      const t1Score = Math.max(0, Math.min(100, Math.round(heur?.t1_score || 0)));

      updateGauge(t1Score);
      // Local Tier 1 is advisory. It is mapped through the canonical verdict
      // vocabulary so its category (safe|spam|phishing) never falls through to
      // a benign render. The server verdict replaces this once Tier 2 returns.
      setVerdict(heur?.t1_category, t1Score);
      updatePipeline(1, 'Complete', 100);
      setAnalysisSummary(
        'Tier 1: Local Analysis Complete.',
        'Submitting to Gateway for Tier 2 ML & OSINT...',
        heur?.User_Friendly_Summary || 'Heuristic checks evaluated.'
      );

      const sender = emailData.senderEmail || emailData.sender || 'unknown@unknown.com';
      const subject = emailData.subject || 'No Subject';
      const links = Array.isArray(emailData?.links)
        ? emailData.links.map((l) => (typeof l === 'string' ? l : l.href))
        : [];

      // ── TIER 2: Gateway ML & Threat Analysis ─────────────────────────────
      updatePipeline(2, 'Analyzing ML...', 30);

      const gatewayPayload = {
        tier1_score: t1Score,
        tier1_evidence: (heur?.t1_evidence || []).map((e) => e.detail || String(e)),
        sender,
        body: emailData.body || '',
        links,
        subject,
        timestamp: new Date().toISOString(),
      };

      const headers = { 'Content-Type': 'application/json' };
      if (currentAuthToken) {
        headers['Authorization'] = `Bearer ${currentAuthToken}`;
      }

      const gResponse = await fetch(getEndpoints().scan, {
        method: 'POST',
        headers,
        body: JSON.stringify(gatewayPayload),
      });

      if (!gResponse.ok) {
        throw new Error(`Gateway returned HTTP ${gResponse.status}`);
      }

      const gData = await gResponse.json();
      if (runId !== activeRunId) return;

      const gScanId = gData.scan_id;
      const partialScore = Math.round(gData.partial_score ?? t1Score);

      updateGauge(partialScore);
      setVerdict(gData.verdict, partialScore);
      updatePipeline(2, 'Complete', 100);

      // ── TIER 3: Semantic AI Polling ──────────────────────────────────────
      updatePipeline(3, 'Analyzing...', 25);
      setAnalysisSummary(
        'Tier 2: ML & Metadata Complete.',
        'Analyzing semantic patterns with Gemini AI...',
        `Domain analysis: ${gData.tier2?.domain_analysis?.status || 'OK'}`
      );

      let pollCount = 0;
      activePollInterval = setInterval(async () => {
        pollCount++;
        if (runId !== activeRunId) {
          clearPoll();
          return;
        }

        try {
          const sRes = await fetch(getEndpoints().status(gScanId));
          if (!sRes.ok) {
            // If polling status is not found, fallback to partial result
            if (pollCount >= 5) {
              clearPoll();
              finishScanWithResult(gData);
            }
            return;
          }

          const status = await sRes.json();

          if (status.complete) {
            clearPoll();
            const rRes = await fetch(getEndpoints().result(gScanId));
            const result = rRes.ok ? await rRes.json() : gData;
            finishScanWithResult(result);
          } else if (pollCount >= MAX_POLLS) {
            clearPoll();
            finishScanWithResult({
              ...gData,
              tier3_status: 'timeout',
              tier3: { reasoning: 'AI semantic analysis timed out. Falling back to Tier 1 + Tier 2.' },
            });
          } else {
            const prog = Math.min(95, Math.round(25 + (pollCount / MAX_POLLS) * 70));
            updatePipeline(3, `Thinking... (${prog}%)`, prog);
          }
        } catch {
          if (pollCount >= MAX_POLLS) {
            clearPoll();
            finishScanWithResult(gData);
          }
        }
      }, POLL_INTERVAL_MS);
    } catch (err) {
      if (runId !== activeRunId) return;
      setScanningState(false);
      setVerdict('ERROR', 0);
      setAnalysisSummary('Scan Failed', 'System encountered an error.', toErrorMessage(err));
      updatePipeline(1, 'Error', 0);
      updatePipeline(2, 'Error', 0);
      updatePipeline(3, 'Error', 0);
    }
  });
}

function finishScanWithResult(result) {
  const isComplete = result.complete === true;
  const hasFinal = typeof result.final_score === 'number';
  // A partial score is NOT an overall score: never present one as the other.
  const finalScore = Math.round(hasFinal ? result.final_score : (result.partial_score ?? 0));

  updateGauge(finalScore);
  setVerdict(result.verdict, finalScore);

  updatePipeline(1, 'Complete', 100);
  updatePipeline(2, 'Complete', 100);

  // Tier 3 state: an incomplete or unrecognised state must never be collapsed
  // into a benign label ("Standby") that reads as "finished and fine".
  if (result.tier3_status === 'complete' && result.tier3) {
    updatePipeline(3, 'Complete', 100);
  } else if (result.tier3_status === 'failed') {
    updatePipeline(3, 'Failed', 100);
  } else if (result.tier3_status === 'timeout') {
    updatePipeline(3, 'Timeout', 100);
  } else if (result.tier3_status === 'skipped') {
    updatePipeline(3, 'Skipped', 100);
  } else {
    updatePipeline(3, 'Incomplete', 100);
  }

  // Server-authoritative signal that visual verification is still required.
  const visionStatus = String(result.vision?.status || '').toUpperCase();
  const requiresVisual =
    result.requires_visual_check === true ||
    result.vision?.requires_followup === true ||
    visionStatus === 'VISUAL_REQUIRED';

  setScanningState(false);

  const scoreLabel = hasFinal ? 'Overall Threat Score' : 'Partial Threat Score (Tier 3 incomplete)';
  let detailLine;
  if (requiresVisual) {
    detailLine = 'Visual verification required: screenshot analysis did not complete.';
  } else if (result.tier3?.reasoning) {
    detailLine = result.tier3.reasoning;
  } else if (isComplete) {
    detailLine = 'Analysis complete.';
  } else {
    detailLine = 'Tier 3 AI analysis did not complete; this result is partial.';
  }

  setAnalysisSummary(
    `Verdict: ${result.verdict || 'UNKNOWN'}`,
    `${scoreLabel}: ${finalScore}/100`,
    detailLine
  );

  renderEvidence(result.combined_evidence || result.tier1?.evidence || []);
}

// -----------------------------------------------------------------------------
// QUICK VISUAL CHECK EVENT HANDLER
// -----------------------------------------------------------------------------
if (visualCheckBtn) {
  visualCheckBtn.addEventListener('click', async () => {
    try {
      setAnalysisSummary('Visual Security Check', 'Capturing current viewport screenshot...', '');
      visualCheckBtn.innerHTML = 'ANALYZING...';
      visualCheckBtn.disabled = true;

      const tabs = await new Promise((resolve) =>
        chrome.tabs.query({ active: true, currentWindow: true }, resolve)
      );
      const [tab] = tabs || [];
      if (!tab?.id) throw new Error('No active browser tab found.');

      // Capture screenshot
      const screenshotUrl = await new Promise((resolve, reject) => {
        chrome.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 30 }, (dataUrl) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(dataUrl);
          }
        });
      });

      const payload = {
        image_data_b64: screenshotUrl,
        url: tab.url || '',
        title: tab.title || '',
      };

      const headers = { 'Content-Type': 'application/json' };
      if (currentAuthToken) {
        headers['Authorization'] = `Bearer ${currentAuthToken}`;
      }

      const res = await fetch(getEndpoints().vision, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error(`Vision backend returned HTTP ${res.status}`);
      const data = await res.json();

      const visionStatus = String(data?.status || '').toUpperCase();
      const visualScore = typeof data?.visual_score === 'number' ? data.visual_score : null;

      // A Vision result that did not complete successfully carries no visual
      // verdict. It must NEVER be rendered as a pass.
      const visionCompleted =
        (visionStatus === 'SUCCESS' || visionStatus === 'HEURISTIC_FALLBACK') && visualScore !== null;

      if (!visionCompleted) {
        updatePipeline(3, visionStatus === 'TIMEOUT' ? 'Timeout' : 'Failed', 100);
        updateGauge(0);
        setVerdict('UNKNOWN', 0);
        const reason =
          (Array.isArray(data?.findings) && data.findings.join(' ')) ||
          data?.error_category ||
          'No visual verdict was produced.';
        setAnalysisSummary(
          'Visual Check Inconclusive.',
          `Vision analysis did not complete (status: ${visionStatus || 'UNKNOWN'}).`,
          reason
        );
      } else {
        const score = Math.round(visualScore);
        updateGauge(score);

        if (data.is_phishing) {
          setVerdict('CRITICAL', score);
          setAnalysisSummary(
            '🚨 SPOOFED PORTAL DETECTED!',
            `Brand spoofed: ${data.matched_brand || 'Unknown Target'}`,
            data.reasoning || 'Visual portal layout matches high-risk phishing signatures.'
          );
          updatePipeline(3, 'Intercepted', 100);
        } else {
          setVerdict('SAFE', score);
          setAnalysisSummary(
            'Visual Checks Passed.',
            'Page visual layout matches authentic domain structure.',
            data.reasoning || 'No deceptive logo or brand spoofing patterns detected.'
          );
          updatePipeline(3, 'Verified', 100);
        }
      }
    } catch (e) {
      setAnalysisSummary('Visual Check Failed', toErrorMessage(e), '');
    } finally {
      visualCheckBtn.innerHTML = 'QUICK VISUAL CHECK';
      visualCheckBtn.disabled = false;
    }
  });
}

// Initial UI Setup
resetUI();
