"use client";
// Live Sentinel page — combines the existing sentinel panel with a user risk card
import React, { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { ShieldCheck, ShieldAlert, Zap, TrendingUp, Clock } from "lucide-react";

// Re-export the existing SentinelPanel inline (imports from the existing component path)
// Using dynamic import to avoid SSR issues with SSE
import dynamic from "next/dynamic";

const SentinelContent = dynamic(
  () => import("@/components/sentinel/sentinel-panel").then(m => ({ default: m.SentinelPanel ?? m.default })),
  { ssr: false, loading: () => <PanelSkeleton /> }
);

function PanelSkeleton() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

function StatCard({
  label, value, sub, icon: Icon, color,
}: { label: string; value: string | number; sub?: string; icon: any; color: string }) {
  return (
    <div className={`bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5 flex items-start gap-4`}>
      <div className={`w-10 h-10 rounded-xl ${color} flex items-center justify-center flex-shrink-0`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
      <div>
        <div className="text-2xl font-bold text-white">{value}</div>
        <div className="text-xs text-zinc-400 font-medium mt-0.5">{label}</div>
        {sub && <div className="text-[10px] text-zinc-600 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const { token, user } = useAuth();
  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [loadingStats, setLoadingStats] = useState(false);

  useEffect(() => {
    if (!token) return;
    setLoadingStats(true);
    Promise.allSettled([
      api.analytics.riskScore(token),
      api.analytics.history(token),
    ]).then(([rs, sh]) => {
      if (rs.status === "fulfilled") setRiskScore(rs.value.risk_score);
      if (sh.status === "fulfilled") setScanHistory(sh.value);
    }).finally(() => setLoadingStats(false));
  }, [token]);

  const criticalCount = scanHistory.filter(s => s.verdict === "CRITICAL").length;
  const lastScan = scanHistory[0];

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white">Live Sentinel</h1>
        <p className="text-sm text-zinc-400 mt-0.5">Real-time email threat detection dashboard</p>
      </div>

      {/* Personal stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Personal Risk Score"
          value={riskScore !== null ? `${riskScore.toFixed(1)}` : "—"}
          sub="Rolling avg of your scans"
          icon={TrendingUp}
          color={riskScore !== null && riskScore >= 50 ? "bg-red-500/20" : "bg-cyan-500/20"}
        />
        <StatCard
          label="Total Scans"
          value={scanHistory.length}
          sub={`${user?.scan_count ?? 0} lifetime`}
          icon={Zap}
          color="bg-violet-500/20"
        />
        <StatCard
          label="Critical Detections"
          value={criticalCount}
          sub="In your history"
          icon={ShieldAlert}
          color="bg-orange-500/20"
        />
        <StatCard
          label="Last Scan"
          value={lastScan ? lastScan.verdict : "—"}
          sub={lastScan ? new Date(lastScan.timestamp).toLocaleTimeString() : "No scans yet"}
          icon={Clock}
          color="bg-emerald-500/20"
        />
      </div>

      {/* Main sentinel panel */}
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
        <div className="border-b border-zinc-800 px-5 py-3 flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-sm font-medium text-zinc-300">Live Feed</span>
        </div>
        <div className="p-4">
          <SentinelContent />
        </div>
      </div>

      {/* Recent scan history */}
      {scanHistory.length > 0 && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
          <div className="border-b border-zinc-800 px-5 py-3">
            <h2 className="text-sm font-semibold text-zinc-300">Recent Scan History</h2>
          </div>
          <div className="divide-y divide-zinc-800/50">
            {scanHistory.slice(0, 10).map((s: any, i) => (
              <div key={i} className="px-5 py-3 flex items-center gap-3 text-sm">
                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${
                  s.verdict === "CRITICAL" ? "bg-red-500/20 text-red-400" :
                  s.verdict === "SUSPICIOUS" ? "bg-orange-500/20 text-orange-400" :
                  "bg-emerald-500/20 text-emerald-400"
                }`}>{s.verdict}</span>
                <span className="text-zinc-400 font-mono text-xs">{s.sender_domain}</span>
                <span className="ml-auto text-zinc-500 text-xs">{s.final_score?.toFixed(1)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
