"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import {
  AlertTriangle, Plus, Filter, MessageSquare, ChevronDown,
  CheckCircle, Clock, Loader2, X, Flag,
} from "lucide-react";
import { SEVERITY_COLOR, STATUS_COLOR } from "@/components/incidents/constants";
import { IncidentModal } from "@/components/incidents/incident-modal";

export default function IncidentsPage() {
  const { token, role } = useAuth();
  const [incidents, setIncidents] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<any>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [filterStatus, setFilterStatus] = useState("open");

  // Create form state
  const [form, setForm] = useState({ title: "", description: "", severity: "medium", sender: "", subject: "" });
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    const [inc, st] = await Promise.allSettled([
      api.incidents.list(token, filterStatus !== "all" ? `status=${filterStatus}` : ""),
      api.incidents.stats(token).catch(() => null),
    ]);
    if (inc.status === "fulfilled") setIncidents(inc.value);
    if (st.status === "fulfilled" && st.value) setStats(st.value);
    setLoading(false);
  }, [token, filterStatus]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) return;
    setCreating(true);
    try {
      const inc = await api.incidents.create(form, token);
      setIncidents(prev => [inc, ...prev]);
      setShowCreate(false);
      setForm({ title: "", description: "", severity: "medium", sender: "", subject: "" });
    } finally { setCreating(false); }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400" /> Incidents
          </h1>
          <p className="text-sm text-zinc-400 mt-0.5">Report, triage, and track phishing incidents</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded-xl text-sm font-medium hover:bg-cyan-500/30 transition-all"
        >
          <Plus className="w-4 h-4" /> Report Incident
        </button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-3 lg:grid-cols-6 gap-3">
          {["open","triaging","in_progress","resolved","false_positives","total"].map(k => (
            <div key={k} className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-3 text-center">
              <div className="text-xl font-bold text-white">{stats[k] ?? 0}</div>
              <div className="text-[10px] text-zinc-500 capitalize mt-0.5">{k.replace("_"," ")}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter */}
      <div className="flex gap-2">
        {["all","open","triaging","in_progress","resolved","false_positive"].map(s => (
          <button
            key={s}
            onClick={() => setFilterStatus(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              filterStatus === s
                ? "bg-cyan-500/20 border-cyan-500/30 text-cyan-400"
                : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
            }`}
          >
            {s.replace("_", " ")}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="flex justify-center py-16">
          <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
        </div>
      ) : incidents.length === 0 ? (
        <div className="text-center py-16 text-zinc-500 text-sm">No incidents found.</div>
      ) : (
        <div className="space-y-2">
          {incidents.map((inc: any) => (
            <button
              key={inc.id}
              onClick={() => setSelected(inc)}
              className="w-full text-left bg-zinc-900/60 border border-zinc-800 hover:border-zinc-600 rounded-xl px-5 py-4 transition-all group"
            >
              <div className="flex items-start gap-3">
                <span className={`mt-0.5 px-2 py-0.5 rounded-full text-xs font-bold border flex-shrink-0 ${SEVERITY_COLOR[inc.severity]}`}>
                  {inc.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-zinc-200 group-hover:text-white truncate">{inc.title}</div>
                  <div className="text-xs text-zinc-500 mt-0.5 truncate">{inc.description}</div>
                </div>
                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                  <span className={`text-xs font-medium ${STATUS_COLOR[inc.status]}`}>{inc.status.replace("_"," ")}</span>
                  <span className="text-[10px] text-zinc-600">{new Date(inc.created_at).toLocaleDateString()}</span>
                  {inc.comments?.length > 0 && (
                    <div className="flex items-center gap-1 text-[10px] text-zinc-600">
                      <MessageSquare className="w-3 h-3" />{inc.comments.length}
                    </div>
                  )}
                </div>
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-lg shadow-2xl">
            <div className="flex items-center justify-between p-5 border-b border-zinc-800">
              <h2 className="text-base font-semibold text-white">Report New Incident</h2>
              <button onClick={() => setShowCreate(false)} className="text-zinc-500 hover:text-zinc-200">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleCreate} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1.5">Title *</label>
                <input
                  required value={form.title}
                  onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  placeholder="Suspicious PayPal impersonation email"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-1.5">Description *</label>
                <textarea
                  required rows={3} value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 resize-none"
                  placeholder="Describe the phishing attempt…"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1.5">Severity</label>
                  <select
                    value={form.severity}
                    onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  >
                    {["critical","high","medium","low","info"].map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-400 mb-1.5">Sender</label>
                  <input
                    value={form.sender}
                    onChange={e => setForm(f => ({ ...f, sender: e.target.value }))}
                    className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                    placeholder="attacker@domain.com"
                  />
                </div>
              </div>
              <div className="flex gap-3 pt-2">
                <button type="button" onClick={() => setShowCreate(false)} className="flex-1 py-2 rounded-xl text-sm text-zinc-400 border border-zinc-700 hover:border-zinc-500">Cancel</button>
                <button type="submit" disabled={creating} className="flex-1 py-2 rounded-xl text-sm font-medium bg-gradient-to-r from-cyan-500 to-violet-600 text-white disabled:opacity-50">
                  {creating ? "Creating…" : "Create Incident"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Detail modal */}
      {selected && (
        <IncidentModal
          incident={selected}
          token={token!}
          role={role}
          api={api}
          onClose={() => setSelected(null)}
          onUpdated={updated => {
            setIncidents(prev => prev.map(i => i.id === updated.id ? updated : i));
            setSelected(updated);
          }}
        />
      )}
    </div>
  );
}
