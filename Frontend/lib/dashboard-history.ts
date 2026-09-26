/**
 * Normalize the dashboard history API response at the UI boundary.
 * Unexpected payloads should produce a safe empty state instead of a render crash.
 */
export function normalizeScanHistory(value: unknown): any[] {
  return Array.isArray(value) ? value : [];
}
