"use client"

import React from "react"

import { motion } from "framer-motion"
import {
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  Loader2,
  Clock,
  Fingerprint,
  Server,
  Brain,
  Sparkles,
} from "lucide-react"
import type { ScanResult, TierStatus } from "@/lib/sentinel-data"

function StatusIcon({ status }: { status: TierStatus["status"] }) {
  switch (status) {
    case "pass":
      return <ShieldCheck className="h-3.5 w-3.5 text-[#00F0FF]" />
    case "fail":
      return <ShieldX className="h-3.5 w-3.5 text-[#FF003C]" />
    case "warning":
      return <AlertTriangle className="h-3.5 w-3.5 text-[#FF9900]" />
    case "running":
      return <Loader2 className="h-3.5 w-3.5 text-[#00F0FF] animate-spin" />
    case "pending":
      return <Clock className="h-3.5 w-3.5 text-[hsl(0,0%,35%)]" />
  }
}

function statusColor(status: TierStatus["status"]) {
  switch (status) {
    case "pass":
      return "text-[#00F0FF]"
    case "fail":
      return "text-[#FF003C]"
    case "warning":
      return "text-[#FF9900]"
    default:
      return "text-[hsl(0,0%,45%)]"
  }
}

function TierCheck({ item }: { item: TierStatus }) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="font-mono text-xs text-[hsl(0,0%,70%)]">{item.label}</span>
      <div className="flex items-center gap-1.5">
        <StatusIcon status={item.status} />
        <span className={`font-mono text-xs uppercase ${statusColor(item.status)}`}>
          {item.status}
        </span>
      </div>
    </div>
  )
}

function TierCard({
  number,
  title,
  icon: Icon,
  children,
  delay,
  glowing,
}: {
  number: number
  title: string
  icon: React.ElementType
  children: React.ReactNode
  delay: number
  glowing?: boolean
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay, duration: 0.4 }}
      className="relative"
    >
      {/* Vertical connector line */}
      {number < 3 && (
        <div className="absolute left-5 top-full h-4 w-px bg-[hsl(187,100%,47%)]/20" />
      )}

      <div className="rounded-lg border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,7%)]/80 backdrop-blur-md p-4">
        <div className="flex items-center gap-3 mb-3">
          <div
            className={`flex h-10 w-10 items-center justify-center rounded-lg border ${
              glowing
                ? "border-[#00F0FF]/30 bg-[#00F0FF]/10 shadow-[0_0_12px_rgba(0,240,255,0.2)]"
                : "border-[hsl(0,0%,100%)]/[0.08] bg-[hsl(0,0%,10%)]"
            }`}
          >
            <Icon
              className={`h-5 w-5 ${glowing ? "text-[#00F0FF] animate-glow-pulse" : "text-[hsl(0,0%,50%)]"}`}
            />
          </div>
          <div>
            <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-[hsl(0,0%,40%)]">
              Tier {number}
            </span>
            <h3 className="text-sm font-semibold text-[hsl(0,0%,90%)]">{title}</h3>
          </div>
        </div>
        {children}
      </div>
    </motion.div>
  )
}

export function AnalysisPipeline({ data }: { data: ScanResult }) {
  return (
    <div className="flex flex-col gap-4">
      <h2 className="font-mono text-[10px] font-bold uppercase tracking-widest text-[hsl(0,0%,40%)] px-1">
        Analysis Pipeline
      </h2>

      {/* Tier 1 */}
      <TierCard number={1} title="Local Guard" icon={Fingerprint} delay={0.1}>
        <div className="flex flex-col gap-0.5">
          <TierCheck item={data.tier1.regexCheck} />
          <TierCheck item={data.tier1.linkMismatch} />
          <TierCheck item={data.tier1.whitelistHit} />
        </div>
      </TierCard>

      {/* Tier 2 */}
      <TierCard number={2} title="Technical DNA" icon={Server} delay={0.25}>
        <div className="flex flex-col gap-0.5">
          <TierCheck item={data.tier2.spf} />
          <TierCheck item={data.tier2.dkim} />
          <TierCheck item={data.tier2.dmarc} />
        </div>
        <div className="mt-3 flex flex-col gap-1.5 border-t border-[hsl(0,0%,100%)]/[0.06] pt-3">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-[hsl(0,0%,50%)]">Domain Age</span>
            <span
              className={`font-mono text-xs ${
                data.tier2.domainAge.includes("days")
                  ? "text-[#FF003C]"
                  : data.tier2.domainAge === "Checking..."
                    ? "text-[hsl(0,0%,45%)]"
                    : "text-[#00F0FF]"
              }`}
            >
              {data.tier2.domainAge}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-[hsl(0,0%,50%)]">Hosting</span>
            <span
              className={`font-mono text-xs text-right max-w-[180px] truncate ${
                data.tier2.hostingProvider.includes("Unknown")
                  ? "text-[#FF003C]"
                  : data.tier2.hostingProvider === "Checking..."
                    ? "text-[hsl(0,0%,45%)]"
                    : "text-[hsl(0,0%,70%)]"
              }`}
            >
              {data.tier2.hostingProvider}
            </span>
          </div>
        </div>
      </TierCard>

      {/* Tier 3 */}
      <TierCard
        number={3}
        title="AI Core"
        icon={Brain}
        delay={0.4}
        glowing={data.tier3.active}
      >
        {data.tier3.markers.length > 0 ? (
          <div className="flex flex-col gap-3">
            <div className="flex items-center gap-1.5">
              <Sparkles className="h-3 w-3 text-[#FF9900]" />
              <span className="font-mono text-[10px] font-bold uppercase tracking-widest text-[#FF9900]">
                Psychological Markers
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {data.tier3.markers.map((marker) => (
                <motion.span
                  key={marker}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className="rounded-full border border-[#FF003C]/20 bg-[#FF003C]/10 px-2.5 py-1 font-mono text-[10px] text-[#FF003C]"
                >
                  {marker}
                </motion.span>
              ))}
            </div>

            {/* Intent profile bars */}
            <div className="flex flex-col gap-2 mt-1">
              {data.tier3.intentProfile.map((item) => (
                <div key={item.label} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] text-[hsl(0,0%,55%)]">
                      {item.label}
                    </span>
                    <span className="font-mono text-[10px] text-[hsl(0,0%,70%)]">
                      {item.value}%
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-[hsl(0,0%,12%)]">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${item.value}%` }}
                      transition={{ duration: 0.8, delay: 0.5 }}
                      className="h-full rounded-full"
                      style={{
                        backgroundColor:
                          item.value > 70
                            ? "#FF003C"
                            : item.value > 40
                              ? "#FF9900"
                              : "#00F0FF",
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 py-2">
            {data.phase === "scanning" ? (
              <>
                <Loader2 className="h-3.5 w-3.5 text-[#00F0FF] animate-spin" />
                <span className="font-mono text-xs text-[hsl(0,0%,50%)]">
                  Awaiting upstream data...
                </span>
              </>
            ) : (
              <span className="font-mono text-xs text-[#00F0FF]">
                No psychological markers detected.
              </span>
            )}
          </div>
        )}
      </TierCard>
    </div>
  )
}
