import type { EvidenceItem, ScanResult, ThreatLevel, TierStatus, UrlEntry } from "./sentinel-data"

export type Tier1Category = "safe" | "spam" | "phishing"

export interface Tier1HeuristicItem {
  check: string
  points?: number
  detail?: string
  kind?: string
}

/**
 * Modern canonical API Gateway scan response interface.
 * Authoritative schema emitted by Backend/gateway.py and received via SSE / polling.
 */
export interface GatewayScanResponse {
  scan_id: string
  timestamp?: string
  sender?: string
  subject?: string
  final_score?: number | null
  partial_score?: number | null
  verdict?: "SAFE" | "SUSPICIOUS" | "CRITICAL" | string
  layers_completed?: number
  complete?: boolean
  evidence?: string[]
  threat_analysis?: {
    category?: string
    reasoning?: string
  }
  tier_details?: {
    tier1?: { score: number; status?: string }
    tier2?: { score: number; status?: string }
    tier3?: { score: number; status?: string }
  }
  links?: { href: string; text?: string | null }[]
}

/**
 * @deprecated Legacy Tier 1 report schema. Retained for backwards compatibility.
 */
export interface Tier1Report {
  version: number
  event_id?: string | null
  scan_id: string
  created_at: string
  source: string
  email: {
    subject?: string | null
    senderEmail?: string | null
    senderName?: string | null
  }
  links: { href: string; text?: string | null }[]
  tier1: {
    score: number
    category: Tier1Category
    summary: string
    evidence: Tier1HeuristicItem[]
    reasons: string[]
    heuristics_score?: number | null
    ml_enabled?: boolean
    ml_threat_level?: number | null
    ml_category?: Tier1Category | null
    ml_confidence?: number | null
    ml_label?: string | null
    ml_model?: string | null
    ml_reasoning?: string | null
  }
  layers_completed?: number
}

function threatLevelFromCategory(category: Tier1Category): ThreatLevel {
  if (category === "phishing") return "threat"
  if (category === "spam") return "warning"
  return "safe"
}

function categoryFromScore(score: number): Tier1Category {
  if (score >= 70) return "phishing"
  if (score >= 30) return "spam"
  return "safe"
}

function tierStatus(label: string, status: TierStatus["status"]): TierStatus {
  return { label, status }
}

export function evidenceToItems(evidence: Tier1HeuristicItem[]): EvidenceItem[] {
  const items: EvidenceItem[] = []

  for (const e of evidence || []) {
    const check = e?.check || "signal"
    const detail = e?.detail || ""
    const kind = e?.kind || ""

    const severity: EvidenceItem["severity"] =
      check === "brand_mismatch" || check === "sender_spoof" || kind === "credential"
        ? "high"
        : check === "homograph" || check === "punycode" || check === "ip_url"
          ? "high"
          : check === "shortener" || check === "tld" || kind === "financial" || kind === "urgency"
            ? "medium"
            : "low"

    const category =
      kind === "credential"
        ? "Credential"
        : kind === "financial"
          ? "Financial"
          : kind === "urgency"
            ? "Urgency"
            : check === "sender_allowlist"
              ? "Sender"
              : check === "brand_mismatch"
                ? "Link"
                : check === "sender_spoof"
                  ? "Impersonation"
                  : "Signal"

    items.push({
      category,
      label: detail || check,
      severity,
    })
  }

  return items.slice(0, 12)
}

function urlsFromLinks(links: { href: string; text?: string | null }[], category: Tier1Category): UrlEntry[] {
  const suspicious = category !== "safe"
  return (links || [])
    .filter((l) => typeof l?.href === "string" && l.href.length > 0)
    .slice(0, 12)
    .map((l) => ({
      displayText: (l.text && l.text.trim().length > 0 ? l.text.trim() : l.href).slice(0, 64),
      actualUrl: l.href,
      suspicious,
    }))
}

/**
 * Canonical adapter: converts modern GatewayScanResponse (or legacy Tier1Report)
 * into the frontend ScanResult view model.
 *
 * GatewayScanResponse is authoritative.
 */
export function gatewayScanResponseToScanResult(report: GatewayScanResponse | Tier1Report): ScanResult {
  const gw = report as Partial<GatewayScanResponse>
  const t1 = report as Partial<Tier1Report>

  // 1. Compute authoritative threat score (0-100)
  const rawScore =
    gw.final_score !== undefined && gw.final_score !== null
      ? gw.final_score
      : gw.partial_score !== undefined && gw.partial_score !== null
        ? gw.partial_score
        : t1.tier1?.score ?? 0

  const score = Math.max(0, Math.min(100, Math.round(rawScore)))

  // 2. Compute threat level
  let threatLevel: ThreatLevel
  if (gw.verdict === "CRITICAL") {
    threatLevel = "threat"
  } else if (gw.verdict === "SUSPICIOUS") {
    threatLevel = "warning"
  } else if (gw.verdict === "SAFE") {
    threatLevel = "safe"
  } else {
    threatLevel = threatLevelFromCategory(categoryFromScore(score))
  }

  // 3. Process layers and phase
  const layersCompleted = gw.layers_completed ?? (gw.complete ? 3 : t1.layers_completed ?? 1)
  const phase: ScanResult["phase"] = layersCompleted < 3 ? "scanning" : "complete"

  // 4. Tier details mapping
  const t1Score = gw.tier_details?.tier1?.score ?? t1.tier1?.score ?? 0
  const t2Score = gw.tier_details?.tier2?.score ?? 0
  const t3Score = gw.tier_details?.tier3?.score ?? 0

  // 5. Evidence mapping
  let evidenceItems: EvidenceItem[] = []
  if (Array.isArray(gw.evidence) && gw.evidence.length > 0) {
    // Modern Gateway string evidence
    evidenceItems = gw.evidence.slice(0, 12).map((item: string) => {
      const text = String(item)
      const lower = text.toLowerCase()
      const isHigh = lower.includes("phish") || lower.includes("spoof") || lower.includes("punycode") || lower.includes("critical")
      const isMed = lower.includes("suspicious") || lower.includes("shortener") || lower.includes("urgency") || lower.includes("financial")
      const category = lower.startsWith("ai:")
        ? "AI Semantic"
        : lower.includes("domain")
          ? "Domain Intel"
          : lower.includes("link")
            ? "Link Analysis"
            : lower.includes("sender")
              ? "Impersonation"
              : "Threat Signal"
      return {
        category,
        label: text,
        severity: isHigh ? "high" : isMed ? "medium" : "low",
      }
    })
  } else if (Array.isArray(t1.tier1?.evidence)) {
    // Legacy Tier 1 structured evidence
    evidenceItems = evidenceToItems(t1.tier1?.evidence ?? [])
  }

  // Heuristic status indicators
  const legacyEvidence = t1.tier1?.evidence ?? []
  const checks = new Set(legacyEvidence.map((e) => e?.check).filter(Boolean))
  const kinds = new Set(legacyEvidence.map((e) => e?.kind).filter(Boolean))

  const regexStatus: TierStatus["status"] =
    kinds.has("credential") || t1Score >= 70
      ? "fail"
      : kinds.has("urgency") || kinds.has("financial") || t1Score >= 30
        ? "warning"
        : "pass"

  const linkStatus: TierStatus["status"] =
    checks.has("brand_mismatch") || checks.has("homograph") || checks.has("punycode") || checks.has("ip_url") || t1Score >= 70
      ? "fail"
      : checks.has("shortener") || checks.has("tld")
        ? "warning"
        : "pass"

  const whitelistStatus: TierStatus["status"] =
    checks.has("sender_spoof") || checks.has("sender_homograph") || checks.has("sender_punycode")
      ? "fail"
      : checks.has("sender_allowlist")
        ? "pass"
        : checks.has("sender")
          ? "warning"
          : "pending"

  return {
    threatScore: score,
    threatLevel,
    phase,
    layersCompleted,

    tier1: {
      regexCheck: tierStatus("Regex Pattern Check", regexStatus),
      linkMismatch: tierStatus("Link-Text Mismatch", linkStatus),
      whitelistHit: tierStatus("Sender Whitelist", whitelistStatus),
    },

    tier2: {
      spf: tierStatus("SPF", t2Score >= 50 ? "warning" : "pass"),
      dkim: tierStatus("DKIM", t2Score >= 50 ? "warning" : "pass"),
      dmarc: tierStatus("DMARC", t2Score >= 70 ? "fail" : "pass"),
      domainAge: gw.tier_details?.tier2 ? (t2Score >= 70 ? "Suspicious / New" : "Established") : "Tier 2 disabled",
      hostingProvider: gw.tier_details?.tier2 ? "Active (Verified)" : "Tier 2 disabled",
    },

    tier3: {
      active: layersCompleted >= 3 || t3Score > 0,
      markers: gw.threat_analysis?.reasoning
        ? [gw.threat_analysis.reasoning]
        : t1.tier1?.ml_reasoning
          ? [t1.tier1.ml_reasoning]
          : [],
      intentProfile: gw.threat_analysis?.category
        ? [{ label: gw.threat_analysis.category, value: Math.round(score) }]
        : [],
    },

    urls: urlsFromLinks(gw.links ?? t1.links ?? [], categoryFromScore(score)),
    evidence: evidenceItems,
    flaggedExcerpts:
      Array.isArray(gw.evidence) && gw.evidence.length > 0
        ? gw.evidence.map((e: string) => `**Evidence**: ${e}`)
        : t1.tier1?.reasons?.map((r) => `**Reason**: ${r}`) ?? [],
  }
}

/**
 * @deprecated Legacy adapter function. Use `gatewayScanResponseToScanResult` instead.
 * Retained for backwards compatibility with older components and tests.
 */
export function tier1ReportToScanResult(report: Tier1Report): ScanResult {
  return gatewayScanResponseToScanResult(report)
}

