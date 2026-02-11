"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { Flame, CheckCircle2, FileCode2 } from "lucide-react"
import type { ScanResult } from "@/lib/sentinel-data"

export function TacticalActions({
  data,
  onToggleLogs,
  logsOpen,
}: {
  data: ScanResult
  onToggleLogs: () => void
  logsOpen: boolean
}) {
  const [confirming, setConfirming] = useState(false)
  const [reported, setReported] = useState(false)
  const isSafe = data.threatLevel === "safe" && data.phase === "complete"
  const isComplete = data.phase === "complete"

  function handleQuarantine() {
    if (!confirming) {
      setConfirming(true)
      return
    }
    setReported(true)
    setConfirming(false)
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
      {/* Quarantine & Report */}
      {isComplete && !reported && (
        <motion.button
          type="button"
          onClick={handleQuarantine}
          whileTap={{ scale: 0.97 }}
          animate={confirming ? { x: [0, -3, 3, -2, 2, 0] } : {}}
          transition={confirming ? { duration: 0.4 } : {}}
          className={`flex items-center justify-center gap-2 rounded-lg py-3 font-semibold text-sm transition-colors ${confirming
              ? "border-2 border-[#FF003C] bg-[#FF003C]/20 text-[#FF003C]"
              : "bg-[#FF003C] text-[hsl(0,0%,100%)]  hover:bg-[#FF003C]/90"
            }`}
        >
          <Flame className="h-4 w-4" />
          {confirming ? "Confirm Quarantine & Report" : "Quarantine & Report"}
        </motion.button>
      )}

      {reported && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="flex items-center justify-center gap-2 rounded-lg border border-[#00F0FF]/20 bg-[#00F0FF]/10 py-3 text-sm font-semibold text-[#00F0FF] md:col-span-2"
        >
          <CheckCircle2 className="h-4 w-4" />
          Email Quarantined & Reported
        </motion.div>
      )}

      {/* Safe Passage */}
      {isComplete && isSafe && !reported && (
        <motion.button
          type="button"
          whileTap={{ scale: 0.97 }}
          className="flex items-center justify-center gap-2 rounded-lg border border-[#00F0FF]/20 bg-[#00F0FF]/10 py-3 text-sm font-semibold text-[#00F0FF] hover:bg-[#00F0FF]/20 transition-colors"
        >
          <CheckCircle2 className="h-4 w-4" />
          Safe Passage
        </motion.button>
      )}

      {/* Explain Logic toggle */}
      {isComplete && (
        <button
          type="button"
          onClick={onToggleLogs}
          className={`flex items-center justify-center gap-2 rounded-lg border border-[hsl(0,0%,100%)]/[0.06] bg-[hsl(0,0%,7%)] py-2.5 text-xs font-mono text-[hsl(0,0%,55%)] hover:text-[hsl(0,0%,75%)] hover:border-[hsl(0,0%,100%)]/[0.1] transition-colors ${isSafe && !reported ? "" : "md:col-span-2"
            }`}
        >
          <FileCode2 className="h-3.5 w-3.5" />
          {logsOpen ? "Hide Technical Logs" : "Explain Logic"}
        </button>
      )}
    </div>
  )
}
