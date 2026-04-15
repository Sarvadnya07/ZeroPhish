import { describe, it, expect } from "vitest"
import { evidenceToItems, tier1ReportToScanResult, type Tier1HeuristicItem, type Tier1Report } from "./live-tier1"

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

describe("tier1ReportToScanResult", () => {
  const baseReport: Tier1Report = {
    version: 1,
    scan_id: "test-scan-id",
    created_at: new Date().toISOString(),
    source: "test",
    email: {},
    links: [],
    tier1: {
      score: 0,
      category: "safe",
      summary: "",
      evidence: [],
      reasons: [],
    },
  }

  it("should handle a basic safe report correctly", () => {
    const result = tier1ReportToScanResult(baseReport)

    expect(result.threatScore).toBe(0)
    expect(result.threatLevel).toBe("safe")
    expect(result.phase).toBe("scanning") // default layers_completed is < 3
    expect(result.evidence).toEqual([])
    expect(result.urls).toEqual([])
    expect(result.flaggedExcerpts).toEqual([])
  })

  it("should correctly clamp and round the score", () => {
    const testCases = [
      { inputScore: -10, expectedScore: 0, expectedLevel: "safe" },
      { inputScore: 110, expectedScore: 100, expectedLevel: "threat" }, // > 70 is phishing -> threat
      { inputScore: 35.5, expectedScore: 36, expectedLevel: "warning" }, // >= 30 is spam -> warning
      { inputScore: 70, expectedScore: 70, expectedLevel: "threat" },
    ]

    for (const { inputScore, expectedScore, expectedLevel } of testCases) {
      const report = { ...baseReport, tier1: { ...baseReport.tier1, score: inputScore } }
      const result = tier1ReportToScanResult(report)
      expect(result.threatScore).toBe(expectedScore)
      expect(result.threatLevel).toBe(expectedLevel)
    }
  })

  it("should handle null or undefined fields gracefully", () => {
    // Pass incomplete report, similar to what might happen if the report is malformed
    const incompleteReport = {
      ...baseReport,
      tier1: undefined as any,
    }

    const result = tier1ReportToScanResult(incompleteReport)
    expect(result.threatScore).toBe(0)
    expect(result.threatLevel).toBe("safe")
    expect(result.evidence).toEqual([])
    expect(result.urls).toEqual([])
  })

  describe("tier statuses based on evidence", () => {
    it("should map regexStatus correctly", () => {
      // Credential -> fail
      let report = {
        ...baseReport,
        tier1: { ...baseReport.tier1, evidence: [{ check: "any", kind: "credential" }] },
      }
      expect(tier1ReportToScanResult(report).tier1.regexCheck.status).toBe("fail")

      // Urgency or financial -> warning
      report.tier1.evidence = [{ check: "any", kind: "urgency" }]
      expect(tier1ReportToScanResult(report).tier1.regexCheck.status).toBe("warning")

      report.tier1.evidence = [{ check: "any", kind: "financial" }]
      expect(tier1ReportToScanResult(report).tier1.regexCheck.status).toBe("warning")

      // None of the above -> pass
      report.tier1.evidence = [{ check: "any", kind: "other" }]
      expect(tier1ReportToScanResult(report).tier1.regexCheck.status).toBe("pass")
    })

    it("should map linkStatus correctly", () => {
      // Brand mismatch, homograph, punycode, ip_url -> fail
      const failChecks = ["brand_mismatch", "homograph", "punycode", "ip_url"]
      for (const check of failChecks) {
        const report = {
          ...baseReport,
          tier1: { ...baseReport.tier1, evidence: [{ check }] },
        }
        expect(tier1ReportToScanResult(report).tier1.linkMismatch.status).toBe("fail")
      }

      // Shortener, tld -> warning
      const warningChecks = ["shortener", "tld"]
      for (const check of warningChecks) {
        const report = {
          ...baseReport,
          tier1: { ...baseReport.tier1, evidence: [{ check }] },
        }
        expect(tier1ReportToScanResult(report).tier1.linkMismatch.status).toBe("warning")
      }

      // None of the above -> pass
      const report = {
        ...baseReport,
        tier1: { ...baseReport.tier1, evidence: [{ check: "other" }] },
      }
      expect(tier1ReportToScanResult(report).tier1.linkMismatch.status).toBe("pass")
    })

    it("should map whitelistStatus correctly", () => {
      // Sender spoof, sender homograph, sender punycode -> fail
      const failChecks = ["sender_spoof", "sender_homograph", "sender_punycode"]
      for (const check of failChecks) {
        const report = {
          ...baseReport,
          tier1: { ...baseReport.tier1, evidence: [{ check }] },
        }
        expect(tier1ReportToScanResult(report).tier1.whitelistHit.status).toBe("fail")
      }

      // Sender allowlist -> pass
      let report = {
        ...baseReport,
        tier1: { ...baseReport.tier1, evidence: [{ check: "sender_allowlist" }] },
      }
      expect(tier1ReportToScanResult(report).tier1.whitelistHit.status).toBe("pass")

      // Sender -> warning
      report.tier1.evidence = [{ check: "sender" }]
      expect(tier1ReportToScanResult(report).tier1.whitelistHit.status).toBe("warning")

      // None -> pending
      report.tier1.evidence = [{ check: "other" }]
      expect(tier1ReportToScanResult(report).tier1.whitelistHit.status).toBe("pending")
    })
  })

  describe("phase and layersCompleted", () => {
    it("should set phase to scanning if layers_completed < 3", () => {
      const report = { ...baseReport, layers_completed: 2 }
      const result = tier1ReportToScanResult(report)
      expect(result.phase).toBe("scanning")
      expect(result.layersCompleted).toBe(2)
      expect(result.tier3.active).toBe(false)
    })

    it("should set phase to complete if layers_completed >= 3", () => {
      const report = { ...baseReport, layers_completed: 3 }
      const result = tier1ReportToScanResult(report)
      expect(result.phase).toBe("complete")
      expect(result.layersCompleted).toBe(3)
      expect(result.tier3.active).toBe(true)
    })
  })

  describe("urls extraction", () => {
    it("should extract urls from links and mark them based on category", () => {
      // Score 0 -> safe
      let report = {
        ...baseReport,
        links: [{ href: "https://example.com", text: "Example" }, { href: "https://test.com" }],
        tier1: { ...baseReport.tier1, score: 0 },
      }
      let result = tier1ReportToScanResult(report)
      expect(result.urls).toHaveLength(2)
      expect(result.urls[0]).toEqual({
        displayText: "Example",
        actualUrl: "https://example.com",
        suspicious: false,
      })
      expect(result.urls[1]).toEqual({
        displayText: "https://test.com",
        actualUrl: "https://test.com",
        suspicious: false,
      })

      // Score 75 -> phishing -> suspicious
      report.tier1.score = 75
      result = tier1ReportToScanResult(report)
      expect(result.urls[0].suspicious).toBe(true)
      expect(result.urls[1].suspicious).toBe(true)
    })
  })

  describe("extracting text fields", () => {
    it("should populate flaggedExcerpts from reasons", () => {
      const report = {
        ...baseReport,
        tier1: { ...baseReport.tier1, reasons: ["Suspicious sender", "Bad link"] },
      }
      const result = tier1ReportToScanResult(report)
      expect(result.flaggedExcerpts).toEqual([
        "**Reason**: Suspicious sender",
        "**Reason**: Bad link",
      ])
    })

    it("should populate tier3 markers from ml_reasoning", () => {
      const report = {
        ...baseReport,
        tier1: { ...baseReport.tier1, ml_reasoning: "ML found anomalies" },
      }
      const result = tier1ReportToScanResult(report)
      expect(result.tier3.markers).toEqual(["ML found anomalies"])
    })
  })
})
