"use client"

import { useEffect, useState } from "react"
import { motion, AnimatePresence } from "framer-motion"
import { Terminal } from "lucide-react"
import { LOG_MESSAGES } from "@/lib/sentinel-data"
import type { ScanPhase } from "@/lib/sentinel-data"

export function StatusTicker({ phase }: { phase: ScanPhase }) {
  const [logIndex, setLogIndex] = useState(0)

  useEffect(() => {
    if (phase !== "scanning") return
    const interval = setInterval(() => {
      setLogIndex((prev) => (prev + 1) % LOG_MESSAGES.length)
    }, 1800)
    return () => clearInterval(interval)
  }, [phase])

  const message =
    phase === "idle"
      ? "ZeroPhish standing by..."
      : phase === "scanning"
        ? LOG_MESSAGES[logIndex]
        : "Analysis complete."

  return (
    <div className="flex items-center gap-2 rounded-md border border-[hsl(187,100%,47%)]/10 bg-[hsl(0,0%,5%)] px-3 py-2">
      <Terminal className="h-3.5 w-3.5 shrink-0 text-[#00F0FF]" />
      <div className="relative overflow-hidden flex-1 h-4">
        <AnimatePresence mode="wait">
          <motion.span
            key={message}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.25 }}
            className="absolute inset-0 font-mono text-xs text-[#00F0FF]/80 whitespace-nowrap"
          >
            {message}
          </motion.span>
        </AnimatePresence>
      </div>
      {phase === "scanning" && (
        <span className="h-2 w-2 shrink-0 rounded-full bg-[#00F0FF] animate-glow-pulse" />
      )}
    </div>
  )
}
