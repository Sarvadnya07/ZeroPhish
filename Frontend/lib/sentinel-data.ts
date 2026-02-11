export type ScanPhase = "idle" | "scanning" | "complete"
export type ThreatLevel = "safe" | "warning" | "threat"

export interface TierStatus {
  label: string
  status: "pending" | "running" | "pass" | "fail" | "warning"
}

export interface UrlEntry {
  displayText: string
  actualUrl: string
  suspicious: boolean
}

export interface EvidenceItem {
  category: string
  label: string
  severity: "low" | "medium" | "high"
}

export interface ScanResult {
  threatScore: number
  threatLevel: ThreatLevel
  phase: ScanPhase

  tier1: {
    regexCheck: TierStatus
    linkMismatch: TierStatus
    whitelistHit: TierStatus
  }

  tier2: {
    spf: TierStatus
    dkim: TierStatus
    dmarc: TierStatus
    domainAge: string
    hostingProvider: string
  }

  tier3: {
    active: boolean
    markers: string[]
    intentProfile: { label: string; value: number }[]
  }

  urls: UrlEntry[]
  evidence: EvidenceItem[]
  flaggedExcerpts: string[]
}

export const SAFE_STATE: ScanResult = {
  threatScore: 8,
  threatLevel: "safe",
  phase: "complete",

  tier1: {
    regexCheck: { label: "Regex Pattern Check", status: "pass" },
    linkMismatch: { label: "Link-Text Mismatch", status: "pass" },
    whitelistHit: { label: "Sender Whitelist", status: "pass" },
  },

  tier2: {
    spf: { label: "SPF", status: "pass" },
    dkim: { label: "DKIM", status: "pass" },
    dmarc: { label: "DMARC", status: "pass" },
    domainAge: "Created: 8 years ago",
    hostingProvider: "Google Cloud Platform",
  },

  tier3: {
    active: false,
    markers: [],
    intentProfile: [
      { label: "Financial", value: 5 },
      { label: "Social Eng.", value: 3 },
      { label: "Credential", value: 0 },
      { label: "Malware", value: 0 },
    ],
  },

  urls: [
    {
      displayText: "accounts.google.com",
      actualUrl: "https://accounts.google.com/settings",
      suspicious: false,
    },
  ],

  evidence: [],
  flaggedExcerpts: [],
}

export const THREAT_STATE: ScanResult = {
  threatScore: 92,
  threatLevel: "threat",
  phase: "complete",

  tier1: {
    regexCheck: { label: "Regex Pattern Check", status: "fail" },
    linkMismatch: { label: "Link-Text Mismatch", status: "fail" },
    whitelistHit: { label: "Sender Whitelist", status: "fail" },
  },

  tier2: {
    spf: { label: "SPF", status: "fail" },
    dkim: { label: "DKIM", status: "warning" },
    dmarc: { label: "DMARC", status: "fail" },
    domainAge: "Created: 4 days ago",
    hostingProvider: "Unknown VPS (Bulletproof Hosting)",
  },

  tier3: {
    active: true,
    markers: ["Urgency", "Financial Request", "Authority Impersonation", "Scarcity"],
    intentProfile: [
      { label: "Financial", value: 90 },
      { label: "Social Eng.", value: 75 },
      { label: "Credential", value: 60 },
      { label: "Malware", value: 15 },
    ],
  },

  urls: [
    {
      displayText: "accounts.google.com/verify",
      actualUrl: "https://g00gle-secure.tk/phish/harvest",
      suspicious: true,
    },
    {
      displayText: "Click here to confirm",
      actualUrl: "https://bit.ly/3xF9k2m",
      suspicious: true,
    },
    {
      displayText: "Unsubscribe",
      actualUrl: "https://g00gle-secure.tk/track/open",
      suspicious: true,
    },
  ],

  evidence: [
    { category: "Urgency", label: "\"Your account will be suspended in 24 hours\"", severity: "high" },
    { category: "Authority", label: "Impersonates Google Security Team", severity: "high" },
    { category: "Financial", label: "Requests credit card re-verification", severity: "high" },
    { category: "Scarcity", label: "\"Limited time to respond\"", severity: "medium" },
  ],

  flaggedExcerpts: [
    "Dear valued customer, we have detected **unusual activity** on your account. Your account will be **suspended within 24 hours** unless you verify your identity immediately.",
    "Please click the link below to **confirm your payment details** and avoid service interruption.",
    "This is an **automated message** from Google Security. Do not reply to this email.",
  ],
}

export const SCANNING_STATE: ScanResult = {
  threatScore: 0,
  threatLevel: "safe",
  phase: "scanning",

  tier1: {
    regexCheck: { label: "Regex Pattern Check", status: "running" },
    linkMismatch: { label: "Link-Text Mismatch", status: "pending" },
    whitelistHit: { label: "Sender Whitelist", status: "pending" },
  },

  tier2: {
    spf: { label: "SPF", status: "pending" },
    dkim: { label: "DKIM", status: "pending" },
    dmarc: { label: "DMARC", status: "pending" },
    domainAge: "Checking...",
    hostingProvider: "Checking...",
  },

  tier3: {
    active: false,
    markers: [],
    intentProfile: [],
  },

  urls: [],
  evidence: [],
  flaggedExcerpts: [],
}

export const LOG_MESSAGES = [
  "Initializing Sentinel AI v3.2.1...",
  "Scanning email headers...",
  "Checking sender reputation...",
  "Running regex pattern analysis...",
  "Detecting link-text mismatches...",
  "Querying WHOIS database...",
  "Verifying SPF records...",
  "Validating DKIM signatures...",
  "Checking DMARC policy...",
  "Running Gemini Semantic Analysis...",
  "Analyzing psychological markers...",
  "Building threat profile...",
  "Forensic analysis complete.",
]
