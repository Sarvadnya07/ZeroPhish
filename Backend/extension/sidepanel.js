// Initialize Web Worker
const aiWorker = new Worker('worker.js', { type: 'module' });

// UI Elements
const progressBar = document.getElementById('ai-progress-bar');
const loadingContainer = document.getElementById('ai-loading-container');
const statusText = document.getElementById('status-text');

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
    const statusText = document.getElementById('status-text');
    statusText.innerText = "🔍 Accessing Gmail Content...";

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
            if (/[^\u0000-\u007F]/.test(link)) { t1Score += 40; evidence.push("🚨 Homograph URL detected."); }
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
                document.getElementById('threat-score').innerText = Math.min(t1Score, 100);
                updateEvidenceUI(evidence);
                statusText.innerText = "Tier 1 Complete. Syncing with Backend...";
                
                // CALL PERSON B
                sendToBackend(response, t1Score);
            }
        };
    });
});

function updateEvidenceUI(items) {
    const list = document.getElementById('evidence-list');
    list.innerHTML = items.map(i => `<li>${i}</li>`).join('');
}

function renderEvidence(items) {
    const list = document.getElementById('evidence-list');
    list.innerHTML = items.map(i => `<li>${i}</li>`).join('');
}