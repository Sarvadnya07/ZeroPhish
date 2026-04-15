import { describe, it, expect } from "vitest"
import { evidenceToItems, tier1ReportToScanResult, type Tier1HeuristicItem, type Tier1Report } from "./live-tier1"

describe("evidenceToItems", () => {
  it("should handle empty or null evidence safely", () => {
    expect(evidenceToItems([])).toEqual([])
    expect(evidenceToItems(undefined as any)).toEqual([])
    expect(evidenceToItems(null as any)).toEqual([])
  })

  it("should handle null or undefined elements within the evidence array", () => {
    const evidence: any[] = [null, undefined]
    const result = evidenceToItems(evidence)
    expect(result).toHaveLength(2)
    expect(result[0]).toEqual({ category: "Signal", label: "signal", severity: "low" })
    expect(result[1]).toEqual({ category: "Signal", label: "signal", severity: "low" })
  })

  it("should handle evidence items with empty string fields", () => {
    const evidence: any[] = [{ check: "", detail: "", kind: "" }]
    const result = evidenceToItems(evidence)
    expect(result).toHaveLength(1)
    expect(result[0]).toEqual({
      category: "Signal",
      label: "signal",
      severity: "low",
    })
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

describe("tier1ReportToScanResult", () => {
  it("should handle minimal or undefined report structures", () => {
    const report = {} as any
    const result = tier1ReportToScanResult(report)

    expect(result.threatScore).toBe(0)
    expect(result.threatLevel).toBe("safe")
    expect(result.phase).toBe("scanning")
    expect(result.urls).toEqual([])
    expect(result.evidence).toEqual([])
  })

  it("should clamp and round the score correctly", () => {
    let report = { tier1: { score: 105.6 } } as any
    let result = tier1ReportToScanResult(report)
    expect(result.threatScore).toBe(100)

    report = { tier1: { score: -10 } } as any
    result = tier1ReportToScanResult(report)
    expect(result.threatScore).toBe(0)

    report = { tier1: { score: 45.4 } } as any
    result = tier1ReportToScanResult(report)
    expect(result.threatScore).toBe(45)
  })

  it("should assign correct threat level based on score", () => {
    let result = tier1ReportToScanResult({ tier1: { score: 75 } } as any)
    expect(result.threatLevel).toBe("threat")

    result = tier1ReportToScanResult({ tier1: { score: 50 } } as any)
    expect(result.threatLevel).toBe("warning")

    result = tier1ReportToScanResult({ tier1: { score: 10 } } as any)
    expect(result.threatLevel).toBe("safe")
  })

  it("should evaluate regexStatus correctly", () => {
    let result = tier1ReportToScanResult({ tier1: { evidence: [{ kind: "credential" }] } } as any)
    expect(result.tier1.regexCheck.status).toBe("fail")

    result = tier1ReportToScanResult({ tier1: { evidence: [{ kind: "urgency" }] } } as any)
    expect(result.tier1.regexCheck.status).toBe("warning")

    result = tier1ReportToScanResult({ tier1: { evidence: [{ kind: "financial" }] } } as any)
    expect(result.tier1.regexCheck.status).toBe("warning")

    result = tier1ReportToScanResult({ tier1: { evidence: [{ kind: "other" }] } } as any)
    expect(result.tier1.regexCheck.status).toBe("pass")
  })

  it("should evaluate linkStatus correctly", () => {
    const failingChecks = ["brand_mismatch", "homograph", "punycode", "ip_url"]
    for (const check of failingChecks) {
      const result = tier1ReportToScanResult({ tier1: { evidence: [{ check }] } } as any)
      expect(result.tier1.linkMismatch.status).toBe("fail")
    }

    const warningChecks = ["shortener", "tld"]
    for (const check of warningChecks) {
      const result = tier1ReportToScanResult({ tier1: { evidence: [{ check }] } } as any)
      expect(result.tier1.linkMismatch.status).toBe("warning")
    }

    const result = tier1ReportToScanResult({ tier1: { evidence: [{ check: "other" }] } } as any)
    expect(result.tier1.linkMismatch.status).toBe("pass")
  })

  it("should evaluate whitelistStatus correctly", () => {
    const failingChecks = ["sender_spoof", "sender_homograph", "sender_punycode"]
    for (const check of failingChecks) {
      const result = tier1ReportToScanResult({ tier1: { evidence: [{ check }] } } as any)
      expect(result.tier1.whitelistHit.status).toBe("fail")
    }

    let result = tier1ReportToScanResult({ tier1: { evidence: [{ check: "sender_allowlist" }] } } as any)
    expect(result.tier1.whitelistHit.status).toBe("pass")

    result = tier1ReportToScanResult({ tier1: { evidence: [{ check: "sender" }] } } as any)
    expect(result.tier1.whitelistHit.status).toBe("warning")

    result = tier1ReportToScanResult({ tier1: { evidence: [{ check: "other" }] } } as any)
    expect(result.tier1.whitelistHit.status).toBe("pending")
  })

  it("should correctly handle layersCompleted and phase", () => {
    let result = tier1ReportToScanResult({ layers_completed: 1 } as any)
    expect(result.phase).toBe("scanning")
    expect(result.tier3.active).toBe(false)

    result = tier1ReportToScanResult({ layers_completed: 3 } as any)
    expect(result.phase).toBe("complete")
    expect(result.tier3.active).toBe(true)
  })

  it("should process urls from links correctly", () => {
    const report = {
      links: [
        { href: "http://example.com", text: " Example " },
        { href: "http://malicious.com" },
        { href: "" },
        null
      ],
      tier1: { score: 75 } // this maps to 'phishing' => suspicious true
    } as any

    const result = tier1ReportToScanResult(report)
    expect(result.urls).toHaveLength(2)

    expect(result.urls[0]).toEqual({
      displayText: "Example",
      actualUrl: "http://example.com",
      suspicious: true,
    })

    expect(result.urls[1]).toEqual({
      displayText: "http://malicious.com",
      actualUrl: "http://malicious.com",
      suspicious: true,
    })
  })

  it("should populate flaggedExcerpts from reasons", () => {
    const report = {
      tier1: {
        reasons: ["reason1", "reason2"]
      }
    } as any

    const result = tier1ReportToScanResult(report)
    expect(result.flaggedExcerpts).toEqual([
      "**Reason**: reason1",
      "**Reason**: reason2",
    ])
  })

  it("should populate tier3 markers if ml_reasoning is present", () => {
    const report = {
      tier1: {
        ml_reasoning: "AI detected a threat"
      }
    } as any

    const result = tier1ReportToScanResult(report)
    expect(result.tier3.markers).toEqual(["AI detected a threat"])
  })
})
