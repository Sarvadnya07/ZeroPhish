chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

chrome.runtime.onInstalled.addListener(() => {
  console.log("ZeroPhish Tier 1 Guard Active");
});

// Vision & Behavior Analysis
let suspiciousTabs = new Set();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "CAPTURE_SCREENSHOT" && sender.tab) {
        chrome.tabs.captureVisibleTab(sender.tab.windowId, { format: "png" }, (dataUrl) => {
            // Forward the screenshot to Tier 3 or ML model for CNN based analysis
            console.log("Screenshot requested for tab:", sender.tab.id);
            sendResponse({ image: dataUrl });
        });
        return true; 
    }
    
    if (request.action === "PASSWORD_FIELD_DETECTED" && sender.tab) {
        console.log(`[Behavioral] Tab ${sender.tab.id} has credential fields.`);
        // Assuming we look up the tab's threat score from a global map/store
        // Here we stub marking it suspicious if we know it is.
        suspiciousTabs.add(sender.tab.id);
    }

    if (request.action === "PASSWORD_TYPED" && sender.tab) {
        console.log(`[Behavioral] Password typed in tab ${sender.tab.id}`);
        // If tab is suspicious, warn them immediately
        if (suspiciousTabs.has(sender.tab.id)) {
            chrome.tabs.sendMessage(sender.tab.id, { action: "CREDENTIAL_LEAK_WARNING" });
        }
    }
});