"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { BarChart3, Activity, Shield, AlertTriangle, TrendingUp, Cpu, Loader2 } from "lucide-react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
  ScatterChart, Scatter, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis,
} from "recharts";

const DAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];

function SummaryCard({ label, value, change, icon: Icon, color }: any) {
  return (
    <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-zinc-400">{label}</span>
        <div className={`w-8 h-8 rounded-lg ${color} flex items-center justify-center`}>
          <Icon className="w-4 h-4 text-white" />
        </div>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      {change !== undefined && (
        <div className={`text-xs mt-1 ${change >= 0 ? "text-emerald-400" : "text-red-400"}`}>
          {change >= 0 ? "↑" : "↓"} {Math.abs(change)}% vs yesterday
        </div>
      )}
    </div>
  );
}

export default function AnalyticsPage() {
  const { token } = useAuth();
  const [dashboard, setDashboard] = useState<any>(null);
  const [heatmap, setHeatmap] = useState<any[]>([]);
  const [feed, setFeed] = useState<any[]>([]);
  const [metrics, setMetrics] = useState<any>(null);
  const [fpList, setFpList] = useState<any[]>([]);
  const [tab, setTab] = useState<"overview"|"heatmap"|"feed"|"model"|"fp">("overview");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    const [d, h, f, m, fp] = await Promise.allSettled([
      api.analytics.dashboard(token),
      api.analytics.heatmap(token),
      api.analytics.feed(token),
      api.analytics.modelMetrics(token),
      api.analytics.fpList(token),
    ]);
    if (d.status === "fulfilled") setDashboard(d.value);
    if (h.status === "fulfilled") setHeatmap(h.value);
    if (f.status === "fulfilled") setFeed(f.value);
    if (m.status === "fulfilled") setMetrics(m.value);
    if (fp.status === "fulfilled") setFpList(fp.value);
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  // Build 24-col heatmap data per day
  const heatmapGrid = DAYS.map((day, d) => ({
    day,
    hours: Array.from({ length: 24 }, (_, h) => {
      const cell = heatmap.find(c => c.day === d && c.hour === h);
      return cell ?? { count: 0, avg_score: 0 };
    }),
  }));

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <BarChart3 className="w-5 h-5 text-cyan-400" /> Analytics
        </h1>
        <p className="text-sm text-zinc-400 mt-0.5">Threat heatmaps, feed, model performance, and false-positive review</p>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2">
        {(["overview","heatmap","feed","model","fp"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-xl text-sm font-medium border transition-all ${tab === t ? "bg-cyan-500/15 border-cyan-500/30 text-cyan-400" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}
          >
            { t === "fp" ? "False Positives" : t[0].toUpperCase() + t.slice(1) }
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 text-cyan-400 animate-spin" /></div>
      ) : tab === "overview" && dashboard ? (
        <div className="space-y-5">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <SummaryCard label="Scans Today" value={dashboard.total_scans_today} icon={Activity} color="bg-cyan-500/20" />
            <SummaryCard label="Critical Today" value={dashboard.critical_today} icon={AlertTriangle} color="bg-red-500/20" />
            <SummaryCard label="Open Incidents" value={dashboard.open_incidents} icon={Shield} color="bg-orange-500/20" />
            <SummaryCard label="Model Accuracy" value={`${(dashboard.model_accuracy * 100).toFixed(1)}%`} icon={Cpu} color="bg-violet-500/20" />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-zinc-300 mb-4">Top Threat Domains (week)</h3>
              {dashboard.top_malicious_domains?.length ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={dashboard.top_malicious_domains.slice(0,7)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                    <XAxis dataKey="domain" tick={{ fill: "#71717a", fontSize: 10 }} />
                    <YAxis tick={{ fill: "#71717a", fontSize: 10 }} />
                    <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8 }} />
                    <Bar dataKey="count" fill="#06b6d4" radius={[4,4,0,0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-48 text-zinc-600 text-sm">No data yet — run some scans</div>
              )}
            </div>
            <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5">
              <h3 className="text-sm font-semibold text-zinc-300 mb-4">Today's Verdict Distribution</h3>
              <div className="flex items-end justify-around h-48">
                {[
                  { label:"SAFE", count: dashboard.safe_today, color:"bg-emerald-500" },
                  { label:"SUSPICIOUS", count: dashboard.suspicious_today, color:"bg-yellow-500" },
                  { label:"CRITICAL", count: dashboard.critical_today, color:"bg-red-500" },
                ].map(({ label, count, color }) => {
                  const total = Math.max(dashboard.total_scans_today, 1);
                  return (
                    <div key={label} className="flex flex-col items-center gap-2">
                      <span className="text-sm font-bold text-white">{count}</span>
                      <div className={`w-16 ${color} rounded-t-lg`} style={{ height: `${Math.max(8, (count / total) * 140)}px` }} />
                      <span className="text-[10px] text-zinc-500">{label}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      ) : tab === "heatmap" ? (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5">
          <h3 className="text-sm font-semibold text-zinc-300 mb-4">Threat Activity Heatmap (7 days × 24 hours)</h3>
          <div className="overflow-x-auto">
            <div className="min-w-[600px]">
              <div className="flex mb-1">
                <div className="w-12" />
                {Array.from({length:24},(_,h)=>(
                  <div key={h} className="flex-1 text-center text-[9px] text-zinc-600">{h}</div>
                ))}
              </div>
              {heatmapGrid.map(({ day, hours }) => (
                <div key={day} className="flex items-center mb-1">
                  <div className="w-12 text-[10px] text-zinc-500">{day}</div>
                  {hours.map((h, i) => {
                    const intensity = Math.min(1, h.avg_score / 100);
                    return (
                      <div
                        key={i}
                        className="flex-1 h-5 rounded-sm mx-px"
                        style={{ background: h.count === 0 ? "#1f1f23" : `rgba(239,68,68,${0.1 + intensity * 0.9})` }}
                        title={`${day} ${i}:00 — ${h.count} scans, avg ${h.avg_score}`}
                      />
                    );
                  })}
                </div>
              ))}
              <div className="flex items-center gap-3 mt-3 justify-end">
                <span className="text-[9px] text-zinc-600">Low</span>
                {[0.1,0.3,0.5,0.7,0.9].map(o => (
                  <div key={o} className="w-4 h-4 rounded-sm" style={{ background: `rgba(239,68,68,${o})` }} />
                ))}
                <span className="text-[9px] text-zinc-600">High</span>
              </div>
            </div>
          </div>
        </div>
      ) : tab === "feed" ? (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
          <div className="border-b border-zinc-800 px-5 py-3">
            <h3 className="text-sm font-semibold text-zinc-300">Live Threat Feed</h3>
          </div>
          {feed.length === 0 ? (
            <div className="text-center py-12 text-zinc-500 text-sm">No critical/suspicious scans yet.</div>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800">
                  {["Time","Domain","Subject","Score","Verdict","Category"].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-zinc-500 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {feed.map((e: any) => (
                  <tr key={e.id} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="px-4 py-2.5 text-zinc-500 font-mono">{new Date(e.timestamp).toLocaleTimeString()}</td>
                    <td className="px-4 py-2.5 text-zinc-300 font-mono">{e.sender_domain}</td>
                    <td className="px-4 py-2.5 text-zinc-400 max-w-[200px] truncate">{e.subject_snippet}</td>
                    <td className="px-4 py-2.5 font-bold text-zinc-200">{e.final_score?.toFixed(1)}</td>
                    <td className="px-4 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded-full text-[9px] font-bold ${e.verdict==="CRITICAL"?"bg-red-500/20 text-red-400":"bg-orange-500/20 text-orange-400"}`}>
                        {e.verdict}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-zinc-500">{e.category}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      ) : tab === "model" && metrics ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-zinc-300 mb-4">Model Performance</h3>
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={[
                { metric: "Accuracy",  value: metrics.accuracy * 100 },
                { metric: "Precision", value: metrics.precision * 100 },
                { metric: "Recall",    value: metrics.recall * 100 },
                { metric: "F1 Score",  value: metrics.f1 * 100 },
                { metric: "Clean FPR", value: (1 - metrics.false_positive_rate) * 100 },
              ]}>
                <PolarGrid stroke="#27272a" />
                <PolarAngleAxis dataKey="metric" tick={{ fill: "#71717a", fontSize: 10 }} />
                <Radar name="Model" dataKey="value" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.15} />
                <Tooltip contentStyle={{ background:"#18181b", border:"1px solid #27272a", borderRadius:8 }}
                  formatter={(v: any) => `${Number(v).toFixed(1)}%`} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-5 space-y-4">
            <h3 className="text-sm font-semibold text-zinc-300">Raw Metrics</h3>
            {[
              ["Model ID",        metrics.model_id],
              ["Accuracy",        `${(metrics.accuracy*100).toFixed(2)}%`],
              ["Precision",       `${(metrics.precision*100).toFixed(2)}%`],
              ["Recall",          `${(metrics.recall*100).toFixed(2)}%`],
              ["F1",              metrics.f1.toFixed(4)],
              ["False Positive Rate", `${(metrics.false_positive_rate*100).toFixed(2)}%`],
              ["False Negative Rate", `${(metrics.false_negative_rate*100).toFixed(2)}%`],
              ["Total Inferences",metrics.total_inferences],
              ["Avg Latency",     `${metrics.avg_latency_ms.toFixed(0)}ms`],
              ["Last Evaluated",  new Date(metrics.last_evaluated).toLocaleString()],
            ].map(([k,v]) => (
              <div key={k as string} className="flex justify-between text-xs">
                <span className="text-zinc-500">{k}</span>
                <span className="text-zinc-200 font-medium font-mono">{v}</span>
              </div>
            ))}
          </div>
        </div>
      ) : tab === "fp" ? (
        <div className="space-y-3">
          <p className="text-sm text-zinc-400">Pending analyst review of flagged false positives.</p>
          {fpList.length === 0 ? (
            <div className="text-center py-12 text-zinc-500 text-sm">No pending false-positive reports.</div>
          ) : (
            fpList.map((fp: any) => (
              <div key={fp.id} className="bg-zinc-900/60 border border-zinc-800 rounded-xl px-5 py-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="text-sm font-medium text-zinc-200">Scan: {fp.scan_id}</div>
                    <div className="text-xs text-zinc-400 mt-0.5">"{fp.reason}"</div>
                    <div className="text-xs text-zinc-600 mt-1">Original: {fp.original_verdict} ({fp.original_score})</div>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => {
                      api.analytics.fpList(token!);
                    }} className="px-3 py-1.5 text-xs rounded-lg bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/30">
                      Mark Reviewed
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      ) : null}
    </div>
  );
}
