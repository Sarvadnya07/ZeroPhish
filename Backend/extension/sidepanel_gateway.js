import { analyzeTier1 } from './tier1.js';

// Gateway endpoints for 3-tier analysis
const GATEWAY_SCAN_URL = 'http://127.0.0.1:8000/gateway/scan';
const GATEWAY_STATUS_URL = 'http://127.0.0.1:8000/gateway/status';
const GATEWAY_RESULT_URL = 'http://127.0.0.1:8000/gateway/result';

// Legacy Tier 1 endpoints (fallback)
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

function verdictToCategory(verdict) {
    const v = (verdict || '').toString().trim().toUpperCase();
    if (v === 'CRITICAL') return 'phishing';
    if (v === 'SUSPICIOUS') return 'spam';
    return 'safe';
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
    evidenceListEl.innerHTML = ''; // Clear first
    if (!Array.isArray(items) || items.length === 0) {
        return;
    }

    items.forEach(i => {
        const li = document.createElement('li');
        const points = typeof i?.points === 'number'
            ? `(${i.points > 0 ? '+' : ''}${i.points}) `
            : '';
        const detail = i?.detail ? i.detail : String(i);
        const check = i?.check ? `[${i.check}] ` : '';
        li.textContent = `${check}${points}${detail}`;  // SAFE - no XSS
        evidenceListEl.appendChild(li);
    });
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
        if (check === 'sender_spoof') add('The sender name looks like a known brand, but the email domain does not match.');
        if (check === 'tld') add('A link uses an uncommon or risky domain ending (TLD).');
        if (check === 'fp_mitigation') add('Links look related to the sender organization (reduced false positives).');

        if (check === 'sender_allowlist' && typeof e?.points === 'number' && e.points < 0) {
            const m = detail.match(/allowlisted:\\s*(.+)$/i);
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
    reasonsListEl.innerHTML = ''; // Clear first
    const reasons = friendlyReasonsFromEvidence(items, category);
    reasons.forEach(r => {
        const li = document.createElement('li');
        li.textContent = r;  // SAFE - no XSS
        reasonsListEl.appendChild(li);
    });
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

// NEW: Gateway integration for 3-tier analysis
scanButton.addEventListener('click', async () => {
    threatScoreEl.innerText = '...';
    renderEvidence([]);
    reasonsListEl.innerHTML = '';
    setMlStatus('');
    setCategory('safe');
    setSummary('');
    detailsContainerEl.style.display = 'none';
    toggleDetailsBtn.innerText = 'Show details';

    const scanId = safeUuid();

    try {
        setStatus('🔍 Reading Gmail content...');
        const email = await extractEmailFromGmailActiveTab();

        // Step 1: Run local Tier 1 heuristics (instant feedback)
        setStatus('⚡ Tier 1: Local analysis...');
        const heur = analyzeTier1(email);
        threatScoreEl.innerText = String(heur.t1_score);
        renderEvidence(heur.t1_evidence);
        renderReasons(heur.t1_evidence, heur.t1_category);
        setCategory(heur.t1_category);
        setSummary(heur.User_Friendly_Summary || 'Analyzing...');

        // Step 2: Send to gateway for Tier 2 + Tier 3
        setStatus('🌐 Tier 2: Analyzing metadata...');

        const gatewayPayload = {
            tier1_score: heur.t1_score,
            tier1_evidence: heur.t1_evidence.map(e => e.detail || String(e)),
            sender: email.senderEmail || email.sender || 'unknown@unknown.com',
            body: email.body || '',
            links: (email.links || []).map(l => typeof l === 'string' ? l : l.href),
            subject: email.subject || 'No Subject',
            timestamp: new Date().toISOString()
        };

        const gatewayResponse = await fetch(GATEWAY_SCAN_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(gatewayPayload)
        });

        if (!gatewayResponse.ok) {
            throw new Error(`Gateway error: ${gatewayResponse.status}`);
        }

        const gatewayData = await gatewayResponse.json();
        const gatewayScanId = gatewayData.scan_id;

        // Step 3: Show partial score (T1 + T2)
        const partialScore = Math.round(gatewayData.partial_score || heur.t1_score);
        threatScoreEl.innerText = String(partialScore);

        // Merge Tier 1 + Tier 2 evidence
        const tier2Evidence = gatewayData.tier2?.evidence || [];
        const combinedEvidence = [...heur.t1_evidence];
        tier2Evidence.forEach(e => {
            combinedEvidence.push({ detail: e, check: 'tier2' });
        });

        renderEvidence(combinedEvidence);
        const gatewayCategory = verdictToCategory(gatewayData.verdict);
        renderReasons(combinedEvidence, gatewayCategory);
        setCategory(gatewayCategory);
        setSummary(`Tier 2 complete. Domain: ${gatewayData.tier2?.domain_analysis?.status || 'analyzed'}`);
        setStatus('🤖 Tier 3: AI analyzing...');

        // Step 4: Poll for Tier 3 completion
        let pollCount = 0;
        const maxPolls = 20; // 10 seconds max (500ms * 20)

        const pollInterval = setInterval(async () => {
            pollCount++;

            try {
                const statusRes = await fetch(`${GATEWAY_STATUS_URL}/${gatewayScanId}`);
                if (!statusRes.ok) {
                    clearInterval(pollInterval);
                    setStatus('⚠️ Status check failed');
                    return;
                }

                const status = await statusRes.json();

                if (status.complete || pollCount >= maxPolls) {
                    clearInterval(pollInterval);

                    // Get full result
                    const resultRes = await fetch(`${GATEWAY_RESULT_URL}/${gatewayScanId}`);
                    const fullResult = await resultRes.json();

                    // Update with final score
                    const finalScore = Math.round(fullResult.final_score || partialScore);
                    threatScoreEl.innerText = String(finalScore);

                    // Merge all evidence
                    const allEvidence = [...combinedEvidence];
                    if (fullResult.tier3 && fullResult.tier3.flagged_phrases) {
                        fullResult.tier3.flagged_phrases.forEach(phrase => {
                            allEvidence.push({ detail: `AI: ${phrase}`, check: 'tier3' });
                        });
                    }

                    renderEvidence(allEvidence);
                    const fullCategory = verdictToCategory(fullResult.verdict);
                    renderReasons(allEvidence, fullCategory);
                    setCategory(fullCategory);

                    // Update summary based on final verdict
                    const verdictMessages = {
                        'CRITICAL': '🚨 HIGH RISK: Likely phishing. Do NOT click links. Verify via official channels.',
                        'SUSPICIOUS': '⚠️ MEDIUM RISK: Suspicious patterns detected. Exercise caution.',
                        'SAFE': '✅ LOW RISK: No significant threats detected.'
                    };
                    setSummary(verdictMessages[fullResult.verdict] || 'Analysis complete.');

                    setStatus(`✅ Complete! Verdict: ${fullResult.verdict} (Score: ${finalScore}/100)`);
                    setMlStatus(`AI Analysis: ${fullResult.tier3?.category || 'Complete'}`);
                }
            } catch (pollErr) {
                console.error('Poll error:', pollErr);
                if (pollCount >= maxPolls) {
                    clearInterval(pollInterval);
                    setStatus('⚠️ AI analysis timeout (using Tier 1+2 results)');
                }
            }
        }, 500); // Poll every 500ms

    } catch (err) {
        console.error(err);
        setMlStatus('');
        setStatus(`❌ ${err?.message || 'Scan failed.'}`);
        threatScoreEl.innerText = '0';
    }
});
