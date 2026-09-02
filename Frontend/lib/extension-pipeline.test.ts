import { describe, it, expect } from "vitest";
import { analyzeTier1 } from "../../extension/tier1.js";

describe("Tier 1 Extension Heuristic Engine", () => {
  it("evaluates clean email to SAFE verdict with low threat score", () => {
    const cleanEmail = {
      sender: "notifications@google.com",
      senderEmail: "notifications@google.com",
      senderName: "Google Accounts",
      subject: "Security Alert",
      body: "Your security settings were updated. Visit https://myaccount.google.com/security to review.",
      links: ["https://myaccount.google.com/security"],
    };

    const result = analyzeTier1(cleanEmail);
    expect(result).toBeDefined();
    expect(result.t1_score).toBeLessThan(30);
    expect(result.t1_category).toBe("safe");
    expect(result.t1_status).toBe("Clean");
  });

  it("evaluates suspicious credential harvesting to phishing / suspicious category", () => {
    const phishingEmail = {
      sender: "security@paypa1-update.com",
      senderEmail: "security@paypa1-update.com",
      senderName: "PayPal Support",
      subject: "URGENT: Your Account Has Been Suspended! Action Required!",
      body: "Your account is locked. Please verify your password reset immediately: http://192.168.1.1/login",
      links: ["http://192.168.1.1/login"],
    };

    const result = analyzeTier1(phishingEmail);
    expect(result).toBeDefined();
    expect(result.t1_score).toBeGreaterThanOrEqual(40);
    expect(["phishing", "spam"]).toContain(result.t1_category);
    expect(result.t1_status).toBe("Suspicious");
    expect(result.t1_evidence.length).toBeGreaterThan(0);
  });

  it("handles empty or malformed email context safely without crashing", () => {
    const emptyEmail = {};
    const result = analyzeTier1(emptyEmail);
    expect(result).toBeDefined();
    expect(result.t1_score).toBeLessThanOrEqual(10);
    expect(result.t1_category).toBe("safe");
  });
});

describe("Pipeline State & Response Normalization", () => {
  interface ScanResult {
    scanId: string;
    status: string;
    verdict: string;
    finalScore: number;
    t1Status: string;
    t2Status: string;
    t3Status: string;
  }

  function normalizeGatewayResponse(gatewayData: any): ScanResult {
    const finalScore = Math.round(gatewayData.final_score ?? gatewayData.partial_score ?? 0);
    let t3Status = "Standby";
    if (gatewayData.tier3_status === "complete" && gatewayData.tier3) {
      t3Status = "Complete";
    } else if (gatewayData.tier3_status === "skipped") {
      t3Status = "Skipped";
    } else if (gatewayData.tier3_status === "timeout") {
      t3Status = "Timeout";
    }

    return {
      scanId: gatewayData.scan_id || "unknown",
      status: gatewayData.complete ? "COMPLETE" : "PROCESSING",
      verdict: (gatewayData.verdict || "SAFE").toUpperCase(),
      finalScore,
      t1Status: "Complete",
      t2Status: "Complete",
      t3Status,
    };
  }

  it("normalizes complete 3-tier scan response accurately", () => {
    const mockGatewayResponse = {
      scan_id: "test-scan-123",
      timestamp: "2026-08-24T22:00:00Z",
      partial_score: 25.0,
      final_score: 85.0,
      verdict: "CRITICAL",
      tier1: { score: 20, evidence: ["urgent"], status: "Suspicious" },
      tier2: { score: 30, evidence: [], status: "OK" },
      tier3: { score: 95, category: "phishing", reasoning: "Credential harvesting detected" },
      tier3_status: "complete",
      complete: true,
      layers_completed: 3,
    };

    const normalized = normalizeGatewayResponse(mockGatewayResponse);
    expect(normalized.scanId).toBe("test-scan-123");
    expect(normalized.status).toBe("COMPLETE");
    expect(normalized.verdict).toBe("CRITICAL");
    expect(normalized.finalScore).toBe(85);
    expect(normalized.t1Status).toBe("Complete");
    expect(normalized.t2Status).toBe("Complete");
    expect(normalized.t3Status).toBe("Complete");
  });

  it("normalizes skipped / fallback Tier 3 gracefully", () => {
    const mockSkippedResponse = {
      scan_id: "test-scan-456",
      partial_score: 15.0,
      verdict: "SAFE",
      tier3_status: "skipped",
      complete: true,
    };

    const normalized = normalizeGatewayResponse(mockSkippedResponse);
    expect(normalized.verdict).toBe("SAFE");
    expect(normalized.finalScore).toBe(15);
    expect(normalized.t3Status).toBe("Skipped");
  });
});
