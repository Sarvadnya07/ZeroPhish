chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

chrome.runtime.onInstalled.addListener(() => {
  console.log("ZeroPhish Tier 1 Guard Active");
});

// Vision & Behavior Analysis
//
// A credential field on its own is NOT a threat signal: essentially every
// legitimate login page has one. A tab is therefore tracked as suspicious only
// when an explicit high-risk verdict has been reported for it, so the
// credential-typing interstitial can never assert a threat that no analysis
// produced.
//
// NOTE: no component currently emits THREAT_VERDICT, so the interstitial is
// inert until a verdict feed is wired up. That is intentional: asserting
// "suspicious or critical threat page" without a verdict is an unsupported
// claim, and this module must not make one.
let suspiciousTabs = new Set();
const THREAT_VERDICTS = new Set(["SUSPICIOUS", "CRITICAL"]);

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "CAPTURE_SCREENSHOT" && sender.tab) {
        chrome.tabs.captureVisibleTab(sender.tab.windowId, { format: "png" }, (dataUrl) => {
            // Forward the screenshot to Tier 3 or ML model for CNN based analysis
            console.log("Screenshot requested for tab:", sender.tab.id);
            sendResponse({ image: dataUrl });
        });
        return true;
    }

    if (!sender.tab) return;
    const tabId = sender.tab.id;

    if (request.action === "THREAT_VERDICT") {
        const verdict = String(request.verdict || "").toUpperCase();
        if (THREAT_VERDICTS.has(verdict)) {
            suspiciousTabs.add(tabId);
        } else {
            suspiciousTabs.delete(tabId);
        }
        return;
    }

    if (request.action === "PASSWORD_FIELD_DETECTED") {
        console.log(`[Behavioral] Tab ${tabId} has credential fields.`);
        return;
    }

    if (request.action === "PASSWORD_TYPED") {
        console.log(`[Behavioral] Password typed in tab ${tabId}`);
        // Warn only when this tab carries an actual high-risk verdict.
        if (suspiciousTabs.has(tabId)) {
            chrome.tabs.sendMessage(tabId, { action: "CREDENTIAL_LEAK_WARNING" });
        }
    }
});

// A verdict applies only to the page it was computed for.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === "loading") suspiciousTabs.delete(tabId);
});

chrome.tabs.onRemoved.addListener((tabId) => {
    suspiciousTabs.delete(tabId);
});