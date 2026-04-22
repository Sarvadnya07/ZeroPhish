import { h, render } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import htm from 'htm';
import { analyzeTier1 } from './tier1.js';

const html = htm.bind(h);

// Gateway endpoints for 3-tier analysis
const GATEWAY_SCAN_URL = 'http://127.0.0.1:8001/gateway/scan';
const GATEWAY_STATUS_URL = 'http://127.0.0.1:8001/gateway/status';
const GATEWAY_RESULT_URL = 'http://127.0.0.1:8001/gateway/result';
const VISION_ANALYZE_URL = 'http://127.0.0.1:8001/vision/analyze';

const POLL_INTERVAL_MS = 500;
const MAX_POLLS = 40;

function App() {
  const [scanning, setScanning] = useState(false);
  const [score, setScore] = useState(0);
  const [verdict, setVerdict] = useState('SAFE');
  const [summary, setSummary] = useState({
    l1: 'Analysis T2 & T3 Pending.',
    l2: 'Scanner: Local & Tier 2 Active.',
    l3: 'Gemini AI (Tier 3) Standby. Ready to protect...'
  });
  const [pipeline, setPipeline] = useState({
    t1: { status: 'Waiting...', progress: 0 },
    t2: { status: 'Standby', progress: 0 },
    t3: { status: 'Awaiting Input', progress: 0 }
  });

  const updateGauge = (value) => {
    setScore(Math.round(value));
  };

  const updatePipeline = (tier, status, progress) => {
    setPipeline(prev => ({
      ...prev,
      [`t${tier}`]: { status, progress }
    }));
  };

  const resetUI = () => {
    setScore(0);
    setVerdict('SAFE');
    setSummary({
      l1: 'Waiting for session...',
      l2: 'Scanner: Standby',
      l3: 'Gemini AI: Ready to protect...'
    });
    setPipeline({
      t1: { status: 'Waiting...', progress: 0 },
      t2: { status: 'Standby', progress: 0 },
      t3: { status: 'Awaiting Input', progress: 0 }
    });
    setScanning(false);
  };

  const runScan = async () => {
    resetUI();
    setScanning(true);

    try {
      setSummary({ l1: 'Initializing...', l2: 'Reading Gmail context...', l3: 'Syncing...' });
      
      const email = await extractEmailFromGmailActiveTab();
      
      // T1
      updatePipeline(1, 'Analyzing...', 40);
      const heur = analyzeTier1(email);
      const t1Score = Math.max(0, Math.min(100, Math.round(heur?.t1_score || 0)));
      
      updateGauge(t1Score);
      setVerdict(heur?.t1_category || 'SAFE');
      updatePipeline(1, 'Complete', 100);
      setSummary({ 
        l1: 'Tier 1: Local Heuristics Complete.', 
        l2: 'Analysis T2 & T3 Pending...', 
        l3: heur?.User_Friendly_Summary || 'Analyzing patterns...' 
      });

      // T2
      updatePipeline(2, 'Connecting...', 20);
      const gatewayPayload = {
        tier1_score: t1Score,
        tier1_evidence: (heur?.t1_evidence || []).map(e => e.detail || String(e)),
        sender: email.senderEmail || email.sender || 'unknown@unknown.com',
        body: email.body || '',
        links: Array.isArray(email?.links) ? email.links.map(l => typeof l === 'string' ? l : l.href) : [],
        subject: email.subject || 'No Subject',
        timestamp: new Date().toISOString()
      };

      const gResponse = await fetch(GATEWAY_SCAN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(gatewayPayload)
      });

      if (!gResponse.ok) throw new Error('Gateway Connection Failed');
      const gData = await gResponse.json();
      
      const gScanId = gData.scan_id;
      const partialScore = Math.round(gData.partial_score || t1Score);
      
      updateGauge(partialScore);
      setVerdict(gData.verdict);
      updatePipeline(2, 'Analyzing ML...', 60);
      setSummary(prev => ({
        ...prev,
        l1: 'Tier 2: ML & Metadata Active.',
        l2: 'Polling Gemini AI (Tier 3)...',
        l3: `Domain Status: ${gData.tier2?.domain_analysis?.status || 'Flagged'}`
      }));

      // T3 Polling
      updatePipeline(3, 'Awaiting Data', 20);
      let pollCount = 0;
      const poll = setInterval(async () => {
        pollCount++;
        try {
          const sRes = await fetch(`${GATEWAY_STATUS_URL}/${gScanId}`);
          const status = await sRes.json();

          if (status.complete) {
            clearInterval(poll);
            const rRes = await fetch(`${GATEWAY_RESULT_URL}/${gScanId}`);
            const result = await rRes.json();
            
            const finalScore = Math.round(result.final_score || partialScore);
            updateGauge(finalScore);
            setVerdict(result.verdict);
            updatePipeline(2, 'Complete', 100);
            updatePipeline(3, 'Complete', 100);
            setScanning(false);
            setSummary({
              l1: `Final Result: ${result.verdict}`,
              l2: `Overall Threat Score: ${finalScore}/100`,
              l3: result.tier3?.reasoning || '3-Tier Analysis finalized successfully.'
            });
          } else if (pollCount >= MAX_POLLS) {
            clearInterval(poll);
            setScanning(false);
            setSummary({
              l1: 'Tier 3: AI Analysis Timeout',
              l2: 'Falling back to T1 + T2 results.',
              l3: 'Heavy traffic or slow AI response.'
            });
            updatePipeline(3, 'Timeout', 50);
          } else {
            const prog = Math.min(95, (pollCount / MAX_POLLS) * 80 + 20);
            updatePipeline(3, `Thinking... (${Math.round(prog)}%)`, prog);
          }
        } catch { /* retry */ }
      }, POLL_INTERVAL_MS);

    } catch (err) {
      setScanning(false);
      setSummary({ l1: 'Scan Failed', l2: 'System error occurred.', l3: err.message });
      updatePipeline(1, 'Error', 0);
      updatePipeline(2, 'Error', 0);
      updatePipeline(3, 'Error', 0);
    }
  };

  const runVisualCheck = async () => {
    try {
      setSummary({ l1: 'Visual Check Active...', l2: 'Capturing snapshot...', l3: '' });
      setScanning(true);

      const tabs = await new Promise(resolve => chrome.tabs.query({ active: true, currentWindow: true }, resolve));
      const [tab] = tabs || [];
      if (!tab?.id) throw new Error('No active tab.');

      const screenshotUrl = await new Promise((resolve, reject) => {
        chrome.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 20 }, data => {
          if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
          else resolve(data);
        });
      });

      const res = await fetch(VISION_ANALYZE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ image_data_b64: screenshotUrl, url: tab.url, title: tab.title })
      });

      if (!res.ok) throw new Error('Vision analysis failed.');
      const data = await res.json();

      setVerdict(data.is_phishing ? 'CRITICAL' : 'SAFE');
      updateGauge(data.threat_score);
      setSummary({
        l1: data.is_phishing ? '🚨 SPOOFED PORTAL DETECTED!' : 'Visual checks passed.',
        l2: data.matched_brand ? `Brand: ${data.matched_brand}` : 'No brand spoofing detected.',
        l3: data.reasoning
      });
      updatePipeline(3, 'Verified', 100);
    } catch (e) {
      setSummary({ l1: 'Visual Check Failed', l2: e.message, l3: '' });
    } finally {
      setScanning(false);
    }
  };

  const getVerdictClass = () => {
    if (verdict === 'CRITICAL' || score >= 70) return 'critical';
    if (verdict === 'SUSPICIOUS' || score >= 30) return 'suspicious';
    return 'safe';
  };

  const GAUGE_MAX_OFFSET = 220;
  const strokeDashoffset = GAUGE_MAX_OFFSET - (score / 100) * GAUGE_MAX_OFFSET;

  return html`
    <div class="app-container">
      <header class="header">
        <div class="brand">
          <span class="logo-text">ZeroPhish</span>
        </div>
        ${scanning && html`
          <div class="scan-indicator">
            <span class="pulse-dot red"></span>
            <span class="indicator-text">SCAN IN PROGRESS</span>
          </div>
        `}
      </header>

      <main class="dashboard">
        <section class="gauge-section">
          <div class="gauge-wrapper">
            <svg viewBox="0 0 200 120" class="gauge-svg">
              <defs>
                <linearGradient id="cyanGlow" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stop-color="#0ea5e9" />
                  <stop offset="100%" stop-color="#00f0ff" />
                </linearGradient>
              </defs>
              <path d="M 10 100 A 90 90 0 0 1 190 100" fill="none" class="gauge-track secondary" stroke-width="1.5" stroke-linecap="round" />
              <path d="M 30 100 A 70 70 0 0 1 170 100" fill="none" class="gauge-track" stroke-width="6" stroke-linecap="round" />
              <path d="M 50 100 A 50 50 0 0 1 150 100" fill="none" class="gauge-track secondary" stroke-width="1.5" stroke-linecap="round" />
              <path id="gauge-progress" d="M 30 100 A 70 70 0 0 1 170 100" fill="none" class="gauge-fill" stroke-width="6" stroke-linecap="round" 
                style=${{ strokeDashoffset }} />
            </svg>
            <div class="gauge-content">
              <div class="score-value">${score}</div>
              <div class="score-label">THREAT LEVEL</div>
            </div>
          </div>

          <div class="status-pill ${getVerdictClass()}">
            <span class="pill-title">STATUS</span>
            <div class="pill-body">
              <span class="pill-text">Status: <strong>${verdict}</strong> (${getVerdictClass() === 'critical' ? '70-100' : getVerdictClass() === 'suspicious' ? '30-69' : '0-29'})</span>
              <span class="status-icon">${getVerdictClass() === 'critical' ? '✕' : getVerdictClass() === 'suspicious' ? '!' : '✓'}</span>
            </div>
          </div>

          <div class="analysis-summary">
            <p>${summary.l1}</p>
            <p>${summary.l2}</p>
            <p>${summary.l3}</p>
          </div>
        </section>

        <section class="pipeline-container">
          <h2 class="section-header">ANALYSIS PIPELINE</h2>
          <div class="pipeline-grid">
            <div class="pipeline-item">
              <div class="icon-box green">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
              </div>
              <div class="tier-label">T1</div>
              <div class="tier-desc">LOCAL</div>
              <div class="progress-bar-bg"><div class="progress-bar-fill green" style=${{ width: `${pipeline.t1.progress}%` }}></div></div>
              <div class="status-subtext">${pipeline.t1.status}</div>
            </div>

            <div class="pipeline-item">
              <div class="icon-box blue">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
              </div>
              <div class="tier-label">T2</div>
              <div class="tier-desc">ML & METADATA</div>
              <div class="progress-bar-bg"><div class="progress-bar-fill blue" style=${{ width: `${pipeline.t2.progress}%` }}></div></div>
              <div class="status-subtext">${pipeline.t2.status}</div>
            </div>

            <div class="pipeline-item">
              <div class="icon-box cyan">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5a3 3 0 1 0-5.997.125 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .52 5.886 4.002 4.002 0 0 0 5.137 5.49 4 4 0 0 0 5.732-2.324 4 4 0 0 0 2.131-7.143 4 4 0 0 0-2.001-6.843A3 3 0 0 0 12 5Z"/></svg>
              </div>
              <div class="tier-label">T3</div>
              <div class="tier-desc">SEMANTIC AI</div>
              <div class="progress-bar-bg"><div class="progress-bar-fill cyan" style=${{ width: `${pipeline.t3.progress}%` }}></div></div>
              <div class="status-subtext">${pipeline.t3.status}</div>
            </div>
          </div>
        </section>

        <section class="action-section">
          <button onClick=${runScan} disabled=${scanning} class="btn btn-primary">
            ${scanning ? 'SCANNING...' : html`
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="btn-icon"><circle cx="12" cy="12" r="10"/><path d="m16 12-4-4-4 4"/></svg>
              INITIALIZE COMPLETE SCAN
            `}
          </button>
          
          <button onClick=${runVisualCheck} disabled=${scanning} class="btn btn-secondary">
            QUICK VISUAL CHECK
          </button>
        </section>
      </main>

      <footer class="footer">
        <div class="system-stats">
          <span>Rate Limit: 20 scans/min</span>
          <span class="separator">|</span>
          <span>System Health: Nominal</span>
        </div>
        <div class="system-stats secondary">
          <span>ML Model v2.1</span>
          <span class="separator">|</span>
          <span>Redis Cache Active</span>
        </div>
      </footer>
    </div>
  `;
}

// Helper functions (extracted from original script)
async function extractEmailFromGmailActiveTab() {
  const tabs = await new Promise(resolve => chrome.tabs.query({ active: true, currentWindow: true }, resolve));
  const [tab] = tabs || [];
  if (!tab?.id || !tab?.url?.includes('mail.google.com')) throw new Error('Please open a Gmail message.');

  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_EMAIL' }, res => {
      if (chrome.runtime.lastError) {
        chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] }, () => {
          chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_EMAIL' }, res2 => {
            if (chrome.runtime.lastError) reject(new Error('Extension context lost. Refresh Gmail.'));
            else resolve(res2);
          });
        });
      } else resolve(res);
    });
  });
}

render(html`<${App} />`, document.getElementById('app'));
