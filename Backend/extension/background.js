chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });

chrome.runtime.onInstalled.addListener(() => {
  console.log("ZeroPhish Tier 1 Guard Active");
});