"use client"

import { motion, AnimatePresence } from "framer-motion"
import type { ScanResult } from "@/lib/sentinel-data"

export function TechLogs({ data, open }: { data: ScanResult; open: boolean }) {
  const logData = {
    zerophish_version: "3.2.1",
    scan_timestamp: new Date().toISOString(),
    threat_score: data.threatScore,
    threat_level: data.threatLevel,
    tier1: {
      regex_match: data.tier1.regexCheck.status,
      link_mismatch: data.tier1.linkMismatch.status,
      whitelist: data.tier1.whitelistHit.status,
    },
    tier2: {
      spf: data.tier2.spf.status,
      dkim: data.tier2.dkim.status,
      dmarc: data.tier2.dmarc.status,
      domain_age: data.tier2.domainAge,
      hosting: data.tier2.hostingProvider,
    },
    tier3: {
      ai_active: data.tier3.active,
      markers: data.tier3.markers,
      intent_profile: data.tier3.intentProfile,
    },
    urls_scanned: data.urls.length,
    evidence_flags: data.evidence.length,
  }

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          transition={{ duration: 0.3 }}
          className="overflow-hidden"
        >
          <div className="rounded-lg border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,3%)] p-4">
            <pre className="font-mono text-[10px] leading-relaxed text-[#00F0FF]/70 overflow-x-auto whitespace-pre-wrap">
              {JSON.stringify(logData, null, 2)}
            </pre>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
