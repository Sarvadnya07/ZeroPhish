"use client"

import { useState, useEffect, useCallback } from "react"
import { motion } from "framer-motion"
import { Shield, Radio } from "lucide-react"
import { StatusTicker } from "./status-ticker"
import { ThreatGauge } from "./threat-gauge"
import { AnalysisPipeline } from "./analysis-pipeline"
import { ForensicsPanel } from "./forensics-panel"
import { TacticalActions } from "./tactical-actions"
import { TechLogs } from "./tech-logs"
import {
  SAFE_STATE,
  THREAT_STATE,
  SCANNING_STATE,
} from "@/lib/sentinel-data"
import type { ScanResult } from "@/lib/sentinel-data"

type Demo = "safe" | "threat"

export function SentinelPanel() {
  const [demo, setDemo] = useState<Demo>("threat")
  const [scanData, setScanData] = useState<ScanResult>(SCANNING_STATE)
  const [logsOpen, setLogsOpen] = useState(false)

  const runScan = useCallback((target: Demo) => {
    setScanData(SCANNING_STATE)
    setLogsOpen(false)

    const result = target === "safe" ? SAFE_STATE : THREAT_STATE

    // Simulate scanning phase
    const timer = setTimeout(() => {
      setScanData(result)
    }, 3500)

    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    const cleanup = runScan(demo)
    return cleanup
  }, [demo, runScan])

  return (
    <div className="mx-auto flex min-h-screen w-full max-w-7xl flex-col bg-[#050505] px-4 lg:px-8">
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
          {/* Demo Switcher */}
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-[hsl(0,0%,40%)]" />
            <span className="font-mono text-xs text-[hsl(0,0%,40%)] uppercase tracking-widest hidden sm:inline">
              Simulate
            </span>
            <div className="flex rounded-md border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,5%)] overflow-hidden">
              <button
                type="button"
                onClick={() => setDemo("safe")}
                className={`px-4 py-2 font-mono text-xs transition-colors ${demo === "safe"
                    ? "bg-[#00F0FF]/15 text-[#00F0FF]"
                    : "text-[hsl(0,0%,45%)] hover:text-[hsl(0,0%,65%)]"
                  }`}
              >
                SAFE
              </button>
              <button
                type="button"
                onClick={() => setDemo("threat")}
                className={`px-4 py-2 font-mono text-xs transition-colors ${demo === "threat"
                    ? "bg-[#FF003C]/15 text-[#FF003C]"
                    : "text-[hsl(0,0%,45%)] hover:text-[hsl(0,0%,65%)]"
                  }`}
              >
                THREAT
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00F0FF] opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-[#00F0FF]" />
            </span>
            <span className="font-mono text-xs text-[#00F0FF]">
              ACTIVE
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
