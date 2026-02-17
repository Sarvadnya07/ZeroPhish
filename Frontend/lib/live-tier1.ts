import type { EvidenceItem, ScanResult, ThreatLevel, TierStatus, UrlEntry } from "./sentinel-data"

export type Tier1Category = "safe" | "spam" | "phishing"

export interface Tier1HeuristicItem {
  check: string
  points?: number
  detail?: string
  kind?: string
}

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

function evidenceToItems(evidence: Tier1HeuristicItem[]): EvidenceItem[] {
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

export function tier1ReportToScanResult(report: Tier1Report): ScanResult {
  const score = Math.max(0, Math.min(100, Math.round(report?.tier1?.score ?? 0)))
  // Use score-derived category to keep gauge value and severity label consistent.
  const category = categoryFromScore(score)
  const threatLevel = threatLevelFromCategory(category)

  const evidence = report?.tier1?.evidence ?? []
  const checks = new Set(evidence.map((e) => e?.check).filter(Boolean))
  const kinds = new Set(evidence.map((e) => e?.kind).filter(Boolean))

  const regexStatus: TierStatus["status"] =
    kinds.has("credential") ? "fail" : kinds.has("urgency") || kinds.has("financial") ? "warning" : "pass"

  const linkStatus: TierStatus["status"] =
    checks.has("brand_mismatch") || checks.has("homograph") || checks.has("punycode") || checks.has("ip_url")
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
    phase: "complete",

    tier1: {
      regexCheck: tierStatus("Regex Pattern Check", regexStatus),
      linkMismatch: tierStatus("Link-Text Mismatch", linkStatus),
      whitelistHit: tierStatus("Sender Whitelist", whitelistStatus),
    },

    tier2: {
      spf: tierStatus("SPF", "pending"),
      dkim: tierStatus("DKIM", "pending"),
      dmarc: tierStatus("DMARC", "pending"),
      domainAge: "Tier 2 disabled",
      hostingProvider: "Tier 2 disabled",
    },

    tier3: {
      active: false,
      markers: [],
      intentProfile: [],
    },

    urls: urlsFromLinks(report?.links ?? [], category),
    evidence: evidenceToItems(evidence),
    flaggedExcerpts: report?.tier1?.reasons?.map((r) => `**Reason**: ${r}`) ?? [],
  }
}

