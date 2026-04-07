"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Webhook, Plus, Trash2, CheckCircle, XCircle, Loader2, X } from "lucide-react";

const EVENT_TYPES = [
  "scan.complete","scan.critical","scan.suspicious",
  "incident.created","incident.updated","circuit.opened",
  "user.registered","false_positive.flagged",
];

export default function WebhooksPage() {
  const { token } = useAuth();
  const [subs, setSubs] = useState<any[]>([]);
  const [deliveries, setDeliveries] = useState<any[]>([]);
  const [tab, setTab] = useState<"subscriptions"|"deliveries">("subscriptions");
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ url: "", events: [] as string[], description: "" });
  const [loading, setLoading] = useState(true);
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    const [s, d] = await Promise.allSettled([
      api.webhooks.list(token),
      api.webhooks.deliveries(token).catch(() => []),
    ]);
    if (s.status === "fulfilled") setSubs(s.value);
    if (d.status === "fulfilled") setDeliveries(d.value as any[]);
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setCreating(true);
    try {
      const sub = await api.webhooks.create(form, token);
      setSubs(prev => [sub, ...prev]);
      setShowCreate(false);
      setForm({ url: "", events: [], description: "" });
    } finally { setCreating(false); }
  };

  const handleDelete = async (id: string) => {
    if (!token) return;
    await api.webhooks.delete(id, token).catch(() => {});
    setSubs(prev => prev.filter(s => s.id !== id));
  };

  const toggleEvent = (ev: string) => {
    setForm(f => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter(e => e !== ev) : [...f.events, ev],
    }));
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Webhook className="w-5 h-5 text-violet-400" /> Webhooks
          </h1>
          <p className="text-sm text-zinc-400 mt-0.5">Subscribe to ZeroPhish events for real-time alerts</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded-xl text-sm font-medium hover:bg-cyan-500/30 transition-all"
        >
          <Plus className="w-4 h-4" /> New Subscription
        </button>
      </div>

      <div className="flex gap-2">
        {(["subscriptions","deliveries"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-xl text-sm font-medium border transition-all ${tab===t?"bg-cyan-500/15 border-cyan-500/30 text-cyan-400":"border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}
          >
            {t[0].toUpperCase()+t.slice(1)}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 text-cyan-400 animate-spin" /></div>
      ) : tab === "subscriptions" ? (
        subs.length === 0 ? (
          <div className="text-center py-16 text-zinc-500 text-sm">No webhook subscriptions. Create one to start receiving events.</div>
        ) : (
          <div className="space-y-3">
            {subs.map((s: any) => (
              <div key={s.id} className="bg-zinc-900/60 border border-zinc-800 rounded-xl px-5 py-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      {s.enabled ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" /> : <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
                      <span className="text-sm font-medium text-zinc-200 font-mono truncate">{s.url}</span>
                    </div>
                    {s.description && <p className="text-xs text-zinc-500 mb-2">{s.description}</p>}
                    <div className="flex flex-wrap gap-1.5">
                      {s.events.map((ev: string) => (
                        <span key={ev} className="px-1.5 py-0.5 bg-violet-500/10 border border-violet-500/20 text-violet-400 text-[9px] rounded-full">{ev}</span>
                      ))}
                    </div>
                    <div className="mt-2 text-[10px] text-zinc-600 font-mono">Secret: {s.secret.slice(0,16)}…</div>
                  </div>
                  <button onClick={() => handleDelete(s.id)} className="text-zinc-600 hover:text-red-400 transition-colors flex-shrink-0">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        deliveries.length === 0 ? (
          <div className="text-center py-16 text-zinc-500 text-sm">No deliveries yet.</div>
        ) : (
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800">
                  {["Time","Event","Status","HTTP","Duration"].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-zinc-500 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {deliveries.map((d: any) => (
                  <tr key={d.id} className="hover:bg-zinc-800/30">
                    <td className="px-4 py-2.5 text-zinc-500 font-mono">{new Date(d.attempted_at).toLocaleTimeString()}</td>
                    <td className="px-4 py-2.5"><span className="px-1.5 py-0.5 bg-violet-500/10 text-violet-400 rounded text-[9px]">{d.event_type}</span></td>
                    <td className="px-4 py-2.5">
                      <span className={`font-medium ${d.status==="success"?"text-emerald-400":d.status==="failed"?"text-red-400":"text-yellow-400"}`}>{d.status}</span>
                    </td>
                    <td className="px-4 py-2.5 text-zinc-400">{d.http_status ?? "—"}</td>
                    <td className="px-4 py-2.5 text-zinc-500">{d.duration_ms?.toFixed(0)}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {showCreate && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-lg shadow-2xl">
            <div className="flex items-center justify-between p-5 border-b border-zinc-800">
              <h2 className="text-base font-semibold text-white">New Webhook Subscription</h2>
              <button onClick={() => setShowCreate(false)} className="text-zinc-500 hover:text-zinc-200"><X className="w-5 h-5" /></button>
            </div>
            <form onSubmit={handleCreate} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1.5">Endpoint URL *</label>
                <input
                  required type="url" value={form.url}
                  onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  placeholder="https://your-server.com/webhooks/zerophish"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1.5">Description</label>
                <input
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  placeholder="Slack alerting webhook"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-2">Events to subscribe *</label>
                <div className="grid grid-cols-2 gap-2">
                  {EVENT_TYPES.map(ev => (
                    <label key={ev} className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer text-xs transition-all ${form.events.includes(ev)?"bg-violet-500/15 border-violet-500/30 text-violet-400":"border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}>
                      <input type="checkbox" checked={form.events.includes(ev)} onChange={() => toggleEvent(ev)} className="hidden" />
                      <div className={`w-3.5 h-3.5 rounded flex-shrink-0 border ${form.events.includes(ev)?"bg-violet-500 border-violet-500":"border-zinc-600"} flex items-center justify-center`}>
                        {form.events.includes(ev) && <span className="text-white text-[8px]">✓</span>}
                      </div>
                      {ev}
                    </label>
                  ))}
                </div>
              </div>
              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setShowCreate(false)} className="flex-1 py-2.5 rounded-xl border border-zinc-700 text-zinc-400 text-sm">Cancel</button>
                <button type="submit" disabled={creating || form.events.length === 0} className="flex-1 py-2.5 rounded-xl text-sm font-medium bg-gradient-to-r from-cyan-500 to-violet-600 text-white disabled:opacity-50">
                  {creating ? "Creating…" : "Create Subscription"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
