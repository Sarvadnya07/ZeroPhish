"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { Shield, Radio } from "lucide-react"
import { StatusTicker } from "./status-ticker"
import { ThreatGauge } from "./threat-gauge"
import { AnalysisPipeline } from "./analysis-pipeline"
import { ForensicsPanel } from "./forensics-panel"
import { TacticalActions } from "./tactical-actions"
import { TechLogs } from "./tech-logs"
import { LIVE_IDLE_STATE } from "@/lib/sentinel-data"
import type { ScanResult } from "@/lib/sentinel-data"
import { tier1ReportToScanResult, type Tier1Report } from "@/lib/live-tier1"

export function SentinelPanel() {
  const [scanData, setScanData] = useState<ScanResult>(LIVE_IDLE_STATE)
  const [logsOpen, setLogsOpen] = useState(false)
  const [liveStatus, setLiveStatus] = useState<"online" | "offline" | "connecting">("connecting")

  useEffect(() => {
    setScanData(LIVE_IDLE_STATE)
    setLogsOpen(false)

    const baseUrl = process.env.NEXT_PUBLIC_ZEROPHISH_BACKEND_URL || "http://127.0.0.1:8000"
    let closed = false
    let es: EventSource | null = null
    let latestPollTimer: ReturnType<typeof setInterval> | null = null
    let lastSeenEventKey = ""

    function eventKey(report: Tier1Report): string {
      return String(report?.event_id || `${report?.scan_id || "unknown"}|${report?.created_at || "unknown"}`)
    }

    function applyLiveReport(data: Tier1Report) {
      setScanData(tier1ReportToScanResult(data))
      lastSeenEventKey = eventKey(data)
    }

    async function bootstrapLatest() {
      try {
        const res = await fetch(`${baseUrl}/tier1/latest`, { cache: "no-store" })
        if (!res.ok) return
        const data = (await res.json()) as Tier1Report | null
        if (data && !closed) {
          applyLiveReport(data)
        }
      } catch {
        // ignore
      }
    }

    async function pollLatest() {
      try {
        const res = await fetch(`${baseUrl}/tier1/latest`, { cache: "no-store" })
        if (!res.ok) return
        const data = (await res.json()) as Tier1Report | null
        if (!data || closed) return
        const key = eventKey(data)
        if (key !== lastSeenEventKey) {
          applyLiveReport(data)
          setLiveStatus("online")
        }
      } catch {
        // ignore
      }
    }

    function connect() {
      setLiveStatus("connecting")
      es = new EventSource(`${baseUrl}/tier1/stream`)

      es.onmessage = (ev) => {
        try {
          const data = JSON.parse(ev.data) as Tier1Report
          applyLiveReport(data)
          setLiveStatus("online")
        } catch {
          // ignore
        }
      }

      es.addEventListener("ping", () => {
        setLiveStatus("online")
      })

      es.onerror = () => {
        if (closed) return
        setLiveStatus("offline")
        try {
          es?.close()
        } catch {
          // ignore
        }
        es = null
        setTimeout(() => {
          if (!closed) connect()
        }, 1200)
      }
    }

    bootstrapLatest()
    connect()
    latestPollTimer = setInterval(pollLatest, 2000)

    return () => {
      closed = true
      if (latestPollTimer) clearInterval(latestPollTimer)
      try {
        es?.close()
      } catch {
        // ignore
      }
    }
  }, [])

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col bg-[#050505] px-4 lg:px-8" suppressHydrationWarning>
      {/* Header */}
      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-[hsl(0,0%,100%)]/[0.06] bg-[#050505]/95 backdrop-blur-md py-4 -mx-4 px-4 lg:-mx-8 lg:px-8">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#00F0FF]/20 bg-[#00F0FF]/10">
            <Shield className="h-5 w-5 text-[#00F0FF]" />
          </div>
          <div>
            <h1 className="text-base font-bold text-[hsl(0,0%,95%)] tracking-tight">
              ZeroPhish
            </h1>
            <p className="font-mono text-xs text-[hsl(0,0%,45%)]">
              Phishing Forensics v3.2
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            <span className="font-mono text-xs text-[hsl(0,0%,40%)] uppercase tracking-widest hidden sm:inline">
              Live Stream
            </span>
            <div className="flex rounded-md border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,5%)] overflow-hidden">
              <div className="px-4 py-2 font-mono text-xs bg-[#00F0FF]/15 text-[#00F0FF]">
                LIVE
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00F0FF] opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#00F0FF]" />
            </span>
            <span className="font-mono text-xs text-[#00F0FF]">
              {liveStatus.toUpperCase()}
            </span>
          </div>
        </div>
      </header>

      {/* Scrollable body with 2-column grid */}
      <div className="flex-1 overflow-y-auto sentinel-scrollbar py-6">
        <div className="flex flex-col gap-6">
          {/* Status Ticker - Full Width */}
          <StatusTicker phase={scanData.phase} />

          {/* 2-Column Grid Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left Column */}
            <div className="flex flex-col gap-6">
              {/* Threat Gauge Hero */}
              <motion.div
                layout
                className="rounded-xl border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,7%)]/80 backdrop-blur-md"
              >
                <ThreatGauge
                  score={scanData.threatScore}
                  level={scanData.threatLevel}
                  phase={scanData.phase}
                />
              </motion.div>

              {/* Deep Forensics */}
              <ForensicsPanel data={scanData} />
            </div>

            {/* Right Column */}
            <div className="flex flex-col gap-6">
              {/* Analysis Pipeline */}
              <AnalysisPipeline data={scanData} />
            </div>
          </div>

          {/* Full Width Bottom Section */}
          <div className="flex flex-col gap-6">
            {/* Tech Logs */}
            <TechLogs data={scanData} open={logsOpen} />

            {/* Action Buttons */}
            <TacticalActions
              data={scanData}
              onToggleLogs={() => setLogsOpen((prev) => !prev)}
              logsOpen={logsOpen}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
