## 2024-05-23 - Redundant Polling with SSE
**Learning:** Even when implementing modern patterns like Server-Sent Events (SSE), legacy or backup polling mechanisms can silently consume resources if not properly gated.
**Action:** Always ensure fallback mechanisms (like polling) are mutually exclusive with the primary real-time connection. Check `readyState` or connection status before polling.
