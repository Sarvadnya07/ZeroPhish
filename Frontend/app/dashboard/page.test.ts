import { describe, expect, it } from "vitest";
import { normalizeScanHistory } from "../../lib/dashboard-history";

describe("DashboardPage scan history", () => {
  it("preserves an empty API response as an empty history", () => {
    expect(normalizeScanHistory([])).toEqual([]);
  });

  it.each([null, undefined, {}, "invalid", 42])(
    "normalizes malformed API data (%s) to an empty history",
    (value) => {
      expect(normalizeScanHistory(value)).toEqual([]);
    },
  );

  it("keeps valid scan history entries unchanged", () => {
    const history = [{ verdict: "SAFE", sender_domain: "example.com" }];

    expect(normalizeScanHistory(history)).toBe(history);
  });
});
