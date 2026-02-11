// ZeroPhish Extension - Gateway Integration
// Updated to work with unified API Gateway

import { analyzeTier1 } from './tier1.js';

// Gateway URL
const GATEWAY_URL = 'http://127.0.0.1:8000/gateway';

// UI Elements
const scanButton = document.getElementById('scan-btn');
const threatScoreEl = document.getElementById('threat-score');
const statusTextEl = document.getElementById('status-text');
const evidenceListEl = document.getElementById('evidence-list');

function clampScore(score) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function setStatus(text) {
  statusTextEl.innerText = text;
}

function renderEvidence(items) {
  if (!Array.isArray(items) || items.length === 0) {
    evidenceListEl.innerHTML = '';
    return;
  }

  evidenceListEl.innerHTML = items
    .map((i) => {
      const detail = typeof i === 'string' ? i : (i?.detail || String(i));
      return `<li>${detail}</li>`;
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

  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_EMAIL' }, (response) => {
      if (chrome.runtime.lastError || !response) {
        reject(new Error('Failed to extract email. Please refresh Gmail.'));
      } else {
        resolve(response);
      }
    });
  });
}

// Poll for Tier 3 completion
async function pollForTier3(scanId, partialScore) {
  const maxPolls = 10;
  let pollCount = 0;

  const pollInterval = setInterval(async () => {
    pollCount++;

    try {
      const response = await fetch(`${GATEWAY_URL}/status/${scanId}`);
      if (!response.ok) {
        clearInterval(pollInterval);
        return;
      }

      const status = await response.json();

      if (status.complete) {
        clearInterval(pollInterval);

        // Update with final results
        threatScoreEl.innerText = clampScore(status.final_score);

        // Get full result
        const fullResponse = await fetch(`${GATEWAY_URL}/result/${scanId}`);
        const fullResult = await fullResponse.json();

        const finalEvidence = [
          `🎯 Final Score: ${status.final_score.toFixed(1)}`,
          `📊 Verdict: ${status.verdict}`,
          ...fullResult.combined_evidence,
          status.tier3 ? `🤖 AI: ${status.tier3.category}` : '',
        ].filter(e => e);

        renderEvidence(finalEvidence);

        // Update status based on verdict
        if (status.verdict === "CRITICAL") {
          setStatus("🚨 CRITICAL THREAT DETECTED!");
        } else if (status.verdict === "SUSPICIOUS") {
          setStatus("⚠️ Suspicious Email - Exercise Caution");
        } else {
          setStatus("✅ Email appears safe");
        }
      } else if (pollCount >= maxPolls) {
        clearInterval(pollInterval);
        setStatus(`⚠️ ${status.verdict} (AI timeout)`);
      }
    } catch (error) {
      console.error("Polling error:", error);
      clearInterval(pollInterval);
    }
  }, 500); // Poll every 500ms
}

// Main scan handler
scanButton.addEventListener('click', async () => {
  try {
    setStatus('🔍 Extracting email...');
    threatScoreEl.innerText = '0';
    renderEvidence([]);

    // Extract email from Gmail
    const emailData = await extractEmailFromGmailActiveTab();

    // Run Tier 1 analysis
    setStatus('⚡ Running Tier 1 analysis...');
    const tier1Result = analyzeTier1(emailData);

    const tier1Score = tier1Result.t1_score || 0;
    const tier1Evidence = tier1Result.t1_evidence || [];

    // Show Tier 1 results
    threatScoreEl.innerText = clampScore(tier1Score);
    renderEvidence([...tier1Evidence, '⏳ Sending to Gateway...']);

    // Send to Gateway
    setStatus('🔄 Sending to Gateway (Tier 2 + Tier 3)...');

    const response = await fetch(`${GATEWAY_URL}/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tier1_score: tier1Score,
        tier1_evidence: tier1Evidence,
        sender: emailData.sender,
        body: emailData.body,
        links: emailData.links
      })
    });

    if (!response.ok) {
      throw new Error(`Gateway error: ${response.status}`);
    }

    const result = await response.json();
    const scanId = result.scan_id;

    // Update UI with partial results (T1 + T2)
    threatScoreEl.innerText = clampScore(result.partial_score);

    const partialEvidence = [
      `📊 Partial: ${result.partial_score.toFixed(1)} (T1+T2)`,
      `⚖️ Formula: T1×0.2 + T2×0.3 + T3×0.5`,
      ...result.combined_evidence,
      `🔬 Category: ${result.tier2.threat_details.category}`,
      `⏳ Tier 3: Processing...`
    ];

    renderEvidence(partialEvidence);
    setStatus(`⚡ ${result.verdict} (Partial) - Waiting for AI...`);

    // Poll for Tier 3 completion
    pollForTier3(scanId, result.partial_score);

  } catch (error) {
    console.error('Scan error:', error);
    setStatus(`❌ Error: ${error.message}`);
    renderEvidence([
      '⚠️ Gateway unavailable',
      '💡 Start gateway: .\\start_gateway.ps1'
    ]);
  }
});
