"use client"

import { motion } from "framer-motion"
import { Shield, ShieldAlert, ShieldCheck } from "lucide-react"
import type { ScanPhase, ThreatLevel } from "@/lib/sentinel-data"

function getColor(level: ThreatLevel) {
  switch (level) {
    case "safe":
      return "#00F0FF"
    case "warning":
      return "#FF9900"
    case "threat":
      return "#FF003C"
  }
}

function getLabel(level: ThreatLevel) {
  switch (level) {
    case "safe":
      return "SECURE"
    case "warning":
      return "SUSPICIOUS"
    case "threat":
      return "THREAT DETECTED"
  }
}

interface ThreatGaugeProps {
  score: number
  level: ThreatLevel
  phase: ScanPhase
}

export function ThreatGauge({ score, level, phase }: ThreatGaugeProps) {
  const color = getColor(level)
  const isScanning = phase === "scanning"
  const circumference = 2 * Math.PI * 58
  const offset = circumference - (score / 100) * circumference

  const ShieldIcon =
    level === "threat" ? ShieldAlert : level === "safe" ? ShieldCheck : Shield

  return (
    <div className="flex flex-col items-center gap-4 py-6">
      <div className="relative flex items-center justify-center">
        {/* Pulsing ring behind the gauge */}
        {phase === "complete" && level === "threat" && (
          <div
            className="absolute inset-0 rounded-full animate-pulse-ring"
            style={{
              border: `2px solid ${color}`,
              opacity: 0.3,
            }}
          />
        )}

        <svg
          width="160"
          height="160"
          viewBox="0 0 128 128"
          className="drop-shadow-lg"
          style={{
            filter: `drop-shadow(0 0 12px ${color}40)`,
          }}
        >
          {/* Background track */}
          <circle
            cx="64"
            cy="64"
            r="58"
            fill="none"
            stroke="hsl(0 0% 12%)"
            strokeWidth="6"
          />

          {/* Animated progress arc */}
          <motion.circle
            cx="64"
            cy="64"
            r="58"
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{
              strokeDashoffset: isScanning ? circumference * 0.6 : offset,
            }}
            transition={{
              duration: isScanning ? 1.5 : 1.2,
              ease: "easeInOut",
              repeat: isScanning ? Number.POSITIVE_INFINITY : 0,
              repeatType: "reverse",
            }}
            transform="rotate(-90 64 64)"
            style={{
              filter: `drop-shadow(0 0 6px ${color})`,
            }}
          />
        </svg>

        {/* Center content */}
        <div className="absolute flex flex-col items-center justify-center">
          <motion.div
            animate={
              isScanning
                ? { rotate: 360, scale: [1, 1.1, 1] }
                : { rotate: 0 }
            }
            transition={
              isScanning
                ? { rotate: { duration: 3, repeat: Number.POSITIVE_INFINITY, ease: "linear" }, scale: { duration: 1.5, repeat: Number.POSITIVE_INFINITY } }
                : { duration: 0.4 }
            }
          >
            <ShieldIcon
              className="h-8 w-8"
              style={{ color }}
            />
          </motion.div>

          {!isScanning && (
            <motion.span
              className="mt-1 font-mono text-3xl font-bold"
              style={{ color }}
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.4, type: "spring", stiffness: 200 }}
            >
              {score}
            </motion.span>
          )}

          {isScanning && (
            <span className="mt-1 font-mono text-xs text-[hsl(0,0%,55%)]">
              SCANNING
            </span>
          )}
        </div>
      </div>

      {/* Threat label */}
      {!isScanning && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="flex items-center gap-2"
        >
          <span
            className="h-2.5 w-2.5 rounded-full"
            style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}` }}
          />
          <span
            className="font-mono text-xs font-semibold tracking-widest"
            style={{ color }}
          >
            {getLabel(level)}
          </span>
        </motion.div>
      )}
    </div>
  )
}
