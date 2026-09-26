import { describe, expect, it } from "vitest";
import { normalizeScanHistory } from "./page";

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

  it("preserves valid scan history entries", () => {
    const history = [{ verdict: "SAFE", sender_domain: "example.com" }];

    expect(normalizeScanHistory(history)).toBe(history);
  });
});
