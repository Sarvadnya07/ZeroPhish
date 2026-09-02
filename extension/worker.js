// NOTE: MV3 extensions cannot execute remote code (no CDN imports).
// This worker is kept as a stub. Tier 1 ML is provided by the local backend
// (see Backend/main.py, POST /tier1/bert).

self.onmessage = async (e) => {
  // Validate origin if available to prevent untrusted postMessage invocation
  if (e.origin && self.location && e.origin !== self.location.origin) {
    return;
  }
  const { action } = e.data || {};
  if (action === 'init') {
    self.postMessage({ status: 'error', message: 'Edge-AI worker disabled. Use local backend /tier1/bert.' });
  }
  if (action === 'classify') {
    self.postMessage({ status: 'error', message: 'Edge-AI worker disabled. Use local backend /tier1/bert.' });
  }
};
