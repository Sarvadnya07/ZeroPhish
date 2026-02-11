"use client"

import { useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import {
  Link2,
  ExternalLink,
  AlertCircle,
  FileWarning,
  ChevronDown,
  ChevronUp,
  Quote,
} from "lucide-react"
import type { ScanResult } from "@/lib/sentinel-data"

function SeverityDot({ severity }: { severity: "low" | "medium" | "high" }) {
  const color =
    severity === "high"
      ? "bg-[#FF003C] shadow-[0_0_6px_rgba(255,0,60,0.5)]"
      : severity === "medium"
        ? "bg-[#FF9900] shadow-[0_0_6px_rgba(255,153,0,0.5)]"
        : "bg-[#00F0FF] shadow-[0_0_6px_rgba(0,240,255,0.5)]"
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />
}

export function ForensicsPanel({ data }: { data: ScanResult }) {
  const [urlsOpen, setUrlsOpen] = useState(true)
  const [evidenceOpen, setEvidenceOpen] = useState(true)
  const [excerptOpen, setExcerptOpen] = useState(false)

  if (
    data.urls.length === 0 &&
    data.evidence.length === 0 &&
    data.flaggedExcerpts.length === 0
  ) {
    return null
  }

  return (
    <div className="flex flex-col gap-4">
      <h2 className="font-mono text-[10px] font-bold uppercase tracking-widest text-[hsl(0,0%,40%)] px-1">
        Deep Forensics
      </h2>

      {/* URL Inspector */}
      {data.urls.length > 0 && (
        <div className="rounded-lg border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,7%)]/80 backdrop-blur-md overflow-hidden">
          <button
            type="button"
            onClick={() => setUrlsOpen(!urlsOpen)}
            className="flex w-full items-center justify-between p-4"
          >
            <div className="flex items-center gap-2">
              <Link2 className="h-4 w-4 text-[hsl(0,0%,50%)]" />
              <span className="text-sm font-semibold text-[hsl(0,0%,90%)]">
                URL Inspector
              </span>
              <span className="rounded-full bg-[#FF003C]/10 px-2 py-0.5 font-mono text-[10px] text-[#FF003C]">
                {data.urls.filter((u) => u.suspicious).length} suspicious
              </span>
            </div>
            {urlsOpen ? (
              <ChevronUp className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            ) : (
              <ChevronDown className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            )}
          </button>

          <AnimatePresence>
            {urlsOpen && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="flex flex-col gap-2 px-4 pb-4">
                  {data.urls.map((url, i) => (
                    <div
                      key={i}
                      className={`rounded-md border p-3 ${
                        url.suspicious
                          ? "border-[#FF003C]/20 bg-[#FF003C]/5"
                          : "border-[hsl(0,0%,100%)]/[0.04] bg-[hsl(0,0%,5%)]"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex flex-col gap-1.5 min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[10px] uppercase text-[hsl(0,0%,40%)]">
                              Display
                            </span>
                            <span className="font-mono text-xs text-[hsl(0,0%,70%)] truncate">
                              {url.displayText}
                            </span>
                          </div>
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-[10px] uppercase text-[hsl(0,0%,40%)]">
                              Target
                            </span>
                            <span
                              className={`font-mono text-xs truncate ${
                                url.suspicious ? "text-[#FF003C]" : "text-[#00F0FF]"
                              }`}
                            >
                              {url.actualUrl}
                            </span>
                          </div>
                        </div>
                        {url.suspicious && (
                          <AlertCircle className="h-4 w-4 shrink-0 text-[#FF003C]" />
                        )}
                        {!url.suspicious && (
                          <ExternalLink className="h-3.5 w-3.5 shrink-0 text-[hsl(0,0%,35%)]" />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Evidence Drawer */}
      {data.evidence.length > 0 && (
        <div className="rounded-lg border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,7%)]/80 backdrop-blur-md overflow-hidden">
          <button
            type="button"
            onClick={() => setEvidenceOpen(!evidenceOpen)}
            className="flex w-full items-center justify-between p-4"
          >
            <div className="flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-[#FF9900]" />
              <span className="text-sm font-semibold text-[hsl(0,0%,90%)]">
                Evidence Flags
              </span>
            </div>
            {evidenceOpen ? (
              <ChevronUp className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            ) : (
              <ChevronDown className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            )}
          </button>

          <AnimatePresence>
            {evidenceOpen && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="flex flex-col gap-2 px-4 pb-4">
                  {data.evidence.map((item, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.08 }}
                      className="flex items-start gap-3 rounded-md border border-[hsl(0,0%,100%)]/[0.04] bg-[hsl(0,0%,5%)] p-3"
                    >
                      <SeverityDot severity={item.severity} />
                      <div className="flex flex-col gap-0.5 min-w-0">
                        <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-[hsl(0,0%,45%)]">
                          {item.category}
                        </span>
                        <span className="text-xs text-[hsl(0,0%,75%)]">{item.label}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Flagged Excerpts */}
      {data.flaggedExcerpts.length > 0 && (
        <div className="rounded-lg border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,7%)]/80 backdrop-blur-md overflow-hidden">
          <button
            type="button"
            onClick={() => setExcerptOpen(!excerptOpen)}
            className="flex w-full items-center justify-between p-4"
          >
            <div className="flex items-center gap-2">
              <Quote className="h-4 w-4 text-[hsl(0,0%,50%)]" />
              <span className="text-sm font-semibold text-[hsl(0,0%,90%)]">
                Flagged Excerpts
              </span>
            </div>
            {excerptOpen ? (
              <ChevronUp className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            ) : (
              <ChevronDown className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            )}
          </button>

          <AnimatePresence>
            {excerptOpen && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="flex flex-col gap-2 px-4 pb-4">
                  {data.flaggedExcerpts.map((excerpt, i) => (
                    <div
                      key={i}
                      className="rounded-md border-l-2 border-l-[#FF003C]/50 bg-[hsl(0,0%,5%)] px-3 py-2.5"
                    >
                      <p className="font-mono text-xs leading-relaxed text-[hsl(0,0%,65%)]">
                        {excerpt.split("**").map((part, j) =>
                          j % 2 === 1 ? (
                            <span key={j} className="text-[#FF003C] font-semibold underline decoration-[#FF003C]/40 underline-offset-2">
                              {part}
                            </span>
                          ) : (
                            <span key={j}>{part}</span>
                          )
                        )}
                      </p>
                    </div>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </div>
  )
}
