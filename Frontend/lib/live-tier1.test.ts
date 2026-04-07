import { describe, it, expect } from "vitest"
import { evidenceToItems, type Tier1HeuristicItem } from "./live-tier1"

describe("evidenceToItems", () => {
  it("should handle empty or null evidence safely", () => {
    expect(evidenceToItems([])).toEqual([])
    expect(evidenceToItems(undefined as any)).toEqual([])
    expect(evidenceToItems(null as any)).toEqual([])
  })

  it("should handle evidence items with missing fields, defaulting appropriately", () => {
    const evidence: any[] = [{}]
    const result = evidenceToItems(evidence)
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      category: "Signal",
      label: "signal",
      severity: "low",
    })
  })

  describe("severity mapping", () => {
    it("should map high severity conditions correctly", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "brand_mismatch" },
        { check: "sender_spoof" },
        { check: "any", kind: "credential" },
        { check: "homograph" },
        { check: "punycode" },
        { check: "ip_url" },
      ]

      const result = evidenceToItems(evidence)
      result.forEach(item => {
        expect(item.severity).toBe("high")
      })
    })

    it("should map medium severity conditions correctly", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "shortener" },
        { check: "tld" },
        { check: "any", kind: "financial" },
        { check: "any", kind: "urgency" },
      ]

      const result = evidenceToItems(evidence)
      result.forEach(item => {
        expect(item.severity).toBe("medium")
      })
    })

    it("should map low severity conditions correctly", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "unknown_check" },
        { check: "sender_allowlist" },
      ]

      const result = evidenceToItems(evidence)
      result.forEach(item => {
        expect(item.severity).toBe("low")
      })
    })
  })

  describe("category mapping", () => {
    it("should map categories based on kind", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "any", kind: "credential" },
        { check: "any", kind: "financial" },
        { check: "any", kind: "urgency" },
      ]

      const result = evidenceToItems(evidence)
      expect(result[0].category).toBe("Credential")
      expect(result[1].category).toBe("Financial")
      expect(result[2].category).toBe("Urgency")
    })

    it("should map categories based on check when kind is absent or unrecognized", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "sender_allowlist" },
        { check: "brand_mismatch" },
        { check: "sender_spoof" },
        { check: "unknown_check" },
      ]

      const result = evidenceToItems(evidence)
      expect(result[0].category).toBe("Sender")
      expect(result[1].category).toBe("Link")
      expect(result[2].category).toBe("Impersonation")
      expect(result[3].category).toBe("Signal")
    })

    it("should prioritize kind over check for categories", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "brand_mismatch", kind: "credential" },
        { check: "sender_spoof", kind: "financial" },
      ]

      const result = evidenceToItems(evidence)
      expect(result[0].category).toBe("Credential")
      expect(result[1].category).toBe("Financial")
    })
  })

  describe("label extraction", () => {
    it("should use detail as label if present", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "some_check", detail: "Detailed description here" },
      ]

      const result = evidenceToItems(evidence)
      expect(result[0].label).toBe("Detailed description here")
    })

    it("should fallback to check as label if detail is absent", () => {
      const evidence: Tier1HeuristicItem[] = [
        { check: "some_check" },
      ]

      const result = evidenceToItems(evidence)
      expect(result[0].label).toBe("some_check")
    })
  })

  describe("item limits", () => {
    it("should return at most 12 items", () => {
      const evidence: Tier1HeuristicItem[] = Array.from({ length: 15 }, (_, i) => ({
        check: `check_${i}`,
      }))

      const result = evidenceToItems(evidence)
      expect(result).toHaveLength(12)
      expect(result[0].label).toBe("check_0")
      expect(result[11].label).toBe("check_11")
    })
  })
})
