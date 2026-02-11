// Initialize Web Worker
const aiWorker = new Worker('worker.js', { type: 'module' });

// UI Elements
const progressBar = document.getElementById('ai-progress-bar');
const loadingContainer = document.getElementById('ai-loading-container');
const statusText = document.getElementById('status-text');
const threatScore = document.getElementById('threat-score');
const evidenceList = document.getElementById('evidence-list');

// Backend API URL
const BACKEND_URL = 'http://127.0.0.1:8000';

// 1. Safety Net: Initialize AI Worker
aiWorker.postMessage({ action: 'init' });

aiWorker.onmessage = (e) => {
    const { status, progress, output, message } = e.data;

    if (status === 'loading') {
        loadingContainer.style.display = 'block';
        progressBar.style.width = `${progress}%`;
        statusText.innerText = `Downloading Intelligence: ${Math.round(progress)}%`;
    } else if (status === 'ready') {
        loadingContainer.style.display = 'none';
        statusText.innerText = "🛡️ Tier 1 Guard Active";
    } else if (status === 'error') {
        console.error("AI Worker Error:", message);
        loadingContainer.style.display = 'none';
        statusText.innerText = "⚠️ AI Offline (Heuristics Only)";
    }
};

// 2. Main Scan Function
document.getElementById('scan-btn').addEventListener('click', async () => {
    statusText.innerText = "🔍 Accessing Gmail Content...";
    threatScore.innerText = "0";
    evidenceList.innerHTML = "";

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // Ensure we are actually on Gmail
    if (!tab.url.includes("mail.google.com")) {
        statusText.innerText = "❌ Please open a Gmail message.";
        return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "EXTRACT_EMAIL" }, async (response) => {
        if (chrome.runtime.lastError || !response) {
            statusText.innerText = "❌ Error: Refresh Gmail and try again.";
            return;
        }

        // --- TIER 1: INSTANT HEURISTICS (<10ms) ---
        let t1Score = 0;
        let evidence = [];
        
        // Regex Check
        if (/urgent|verify|suspend|action required/i.test(response.body)) {
            t1Score += 20;
            evidence.push("🚩 Heuristic: High-pressure keywords.");
        }

        // Homograph/Link Mismatch Check
        response.links.forEach(link => {
            if (/[^\u0000-\u007F]/.test(link)) { 
                t1Score += 40; 
                evidence.push("🚨 Homograph URL detected."); 
            }
        });

        // --- TIER 1: BERT AI (WEB WORKER) ---
        statusText.innerText = "🧠 Running Local BERT Analysis...";
        aiWorker.postMessage({ action: 'classify', text: response.body.substring(0, 512) });

        aiWorker.onmessage = (e) => {
            if (e.data.status === 'result') {
                const ai = e.data.output[0];
                if (ai.label === 'NEGATIVE' && ai.score > 0.8) {
                    t1Score += 30;
                    evidence.push(`🤖 Local AI: Fear/Urgency intent detected.`);
                }

                // Final UI Update
                threatScore.innerText = Math.min(t1Score, 100);
                updateEvidenceUI(evidence);
                statusText.innerText = "Tier 1 Complete. Syncing with Backend...";
                
                // Send to backend for Tier 2 & 3 analysis
                sendToBackend(response, t1Score, evidence);
            }
        };
    });
});

// Update evidence UI
function updateEvidenceUI(items) {
    evidenceList.innerHTML = items.map(i => `<li>${i}</li>`).join('');
}

// Send data to backend for deeper analysis
async function sendToBackend(emailData, tier1Score, tier1Evidence) {
    try {
        statusText.innerText = "🔄 Sending to Backend for Deep Analysis...";
        
        const response = await fetch(`${BACKEND_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                sender: emailData.sender,
                body: emailData.body,
                links: emailData.links
            })
        });

        if (!response.ok) {
            throw new Error(`Backend error: ${response.status}`);
        }

        const result = await response.json();
        
        // Update UI with backend results
        threatScore.innerText = Math.round(result.final_score);
        
        // Combine Tier 1 and backend evidence
        const allEvidence = [
            ...tier1Evidence,
            ...result.evidence,
            `📊 Verdict: ${result.verdict}`,
            `🔍 Category: ${result.threat_analysis.category}`,
            result.cached ? "⚡ Cached Result" : "🆕 Fresh Analysis"
        ];
        
        updateEvidenceUI(allEvidence);
        
        // Update status based on verdict
        if (result.verdict === "CRITICAL") {
            statusText.innerText = "🚨 CRITICAL THREAT DETECTED!";
        } else if (result.verdict === "SUSPICIOUS") {
            statusText.innerText = "⚠️ Suspicious Email - Exercise Caution";
        } else {
            statusText.innerText = "✅ Email appears safe";
        }
        
    } catch (error) {
        console.error("Backend communication error:", error);
        statusText.innerText = "⚠️ Backend offline - Using Tier 1 results only";
        
        // Show tier 1 results with warning
        const fallbackEvidence = [
            ...tier1Evidence,
            "⚠️ Backend unavailable - Limited analysis",
            "💡 Start backend: python tier_2/main.py"
        ];
        updateEvidenceUI(fallbackEvidence);
    }
}