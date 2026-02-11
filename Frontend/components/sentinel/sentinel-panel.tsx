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
    <div className="mx-auto flex min-h-screen w-full max-w-[400px] flex-col bg-[#050505]">
      {/* Header */}
      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-[hsl(0,0%,100%)]/[0.06] bg-[#050505]/95 backdrop-blur-md px-4 py-3">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#00F0FF]/20 bg-[#00F0FF]/10">
            <Shield className="h-4 w-4 text-[#00F0FF]" />
          </div>
          <div>
            <h1 className="text-sm font-bold text-[hsl(0,0%,95%)] tracking-tight">
              Sentinel AI
            </h1>
            <p className="font-mono text-[10px] text-[hsl(0,0%,45%)]">
              Phishing Forensics v3.2
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#00F0FF] opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-[#00F0FF]" />
          </span>
          <span className="font-mono text-[10px] text-[#00F0FF]">
            ACTIVE
          </span>
        </div>
      </header>

      {/* Demo Switcher */}
      <div className="flex items-center gap-2 px-4 pt-4 pb-2">
        <Radio className="h-3.5 w-3.5 text-[hsl(0,0%,40%)]" />
        <span className="font-mono text-[10px] text-[hsl(0,0%,40%)] uppercase tracking-widest">
          Simulate
        </span>
        <div className="ml-auto flex rounded-md border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,5%)] overflow-hidden">
          <button
            type="button"
            onClick={() => setDemo("safe")}
            className={`px-3 py-1.5 font-mono text-[10px] transition-colors ${
              demo === "safe"
                ? "bg-[#00F0FF]/15 text-[#00F0FF]"
                : "text-[hsl(0,0%,45%)] hover:text-[hsl(0,0%,65%)]"
            }`}
          >
            SAFE
          </button>
          <button
            type="button"
            onClick={() => setDemo("threat")}
            className={`px-3 py-1.5 font-mono text-[10px] transition-colors ${
              demo === "threat"
                ? "bg-[#FF003C]/15 text-[#FF003C]"
                : "text-[hsl(0,0%,45%)] hover:text-[hsl(0,0%,65%)]"
            }`}
          >
            THREAT
          </button>
        </div>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto sentinel-scrollbar px-4 pb-6">
        <div className="flex flex-col gap-6">
          {/* Status Ticker */}
          <StatusTicker phase={scanData.phase} />

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

          {/* Analysis Pipeline */}
          <AnalysisPipeline data={scanData} />

          {/* Deep Forensics */}
          <ForensicsPanel data={scanData} />

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
  )
}
