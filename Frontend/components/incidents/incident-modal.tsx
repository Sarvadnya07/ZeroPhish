import React, { useState } from "react";
import { MessageSquare, X, Loader2 } from "lucide-react";
import { SEVERITY_COLOR, STATUS_COLOR } from "./constants";

export function IncidentModal({
  incident,
  token,
  role,
  onClose,
  onUpdated,
  api,
}: {
  incident: any;
  token: string;
  role: string | null;
  onClose: () => void;
  onUpdated: (i: any) => void;
  api: any;
}) {
  const [comment, setComment] = useState("");
  const [status, setStatus] = useState(incident.status);
  const [saving, setSaving] = useState(false);

  const updateStatus = async (newStatus: string) => {
    setSaving(true);
    try {
      const updated = await api.incidents.update(incident.id, { status: newStatus }, token);
      setStatus(newStatus);
      onUpdated(updated);
    } finally { setSaving(false); }
  };

  const addComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!comment.trim()) return;
    setSaving(true);
    try {
      const updated = await api.incidents.comment(incident.id, comment, token);
      setComment("");
      onUpdated(updated);
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl">
        <div className="flex items-start justify-between p-5 border-b border-zinc-800">
          <div>
            <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-bold border mb-2 ${SEVERITY_COLOR[incident.severity]}`}>
              {incident.severity.toUpperCase()}
            </div>
            <h2 className="text-base font-semibold text-white">{incident.title}</h2>
          </div>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200 mt-1">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          <p className="text-sm text-zinc-300 leading-relaxed">{incident.description}</p>

          {incident.sender && (
            <div className="text-xs font-mono text-zinc-500 bg-zinc-800/50 rounded px-3 py-2">
              From: {incident.sender}
              {incident.subject && <> · Subject: {incident.subject}</>}
            </div>
          )}

          {incident.evidence?.length > 0 && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1.5">Evidence</p>
              {incident.evidence.map((e: string, i: number) => (
                <div key={i} className="text-xs text-zinc-300 bg-zinc-800/40 rounded px-2 py-1 mb-1">{e}</div>
              ))}
            </div>
          )}

          {(role === "admin" || role === "analyst") && (
            <div>
              <p className="text-xs font-medium text-zinc-400 mb-1.5">Update Status</p>
              <div className="flex flex-wrap gap-2">
                {["triaging","in_progress","resolved","closed","false_positive"].map(s => (
                  <button
                    key={s}
                    disabled={saving || status === s}
                    onClick={() => updateStatus(s)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
                      status === s
                        ? "bg-cyan-500/20 border-cyan-500/30 text-cyan-400"
                        : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
                    }`}
                  >
                    {s.replace("_", " ")}
                  </button>
                ))}
              </div>
            </div>
          )}

          <div>
            <p className="text-xs font-medium text-zinc-400 mb-2">
              Comments ({incident.comments?.length ?? 0})
            </p>
            <div className="space-y-2 mb-3">
              {incident.comments?.map((c: any) => (
                <div key={c.id} className="bg-zinc-800/40 rounded-xl px-3 py-2">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-medium text-zinc-300">{c.author_name}</span>
                    <span className="text-[10px] text-zinc-600">{new Date(c.created_at).toLocaleString()}</span>
                  </div>
                  <p className="text-xs text-zinc-400">{c.body}</p>
                </div>
              ))}
            </div>
            <form onSubmit={addComment} className="flex gap-2">
              <input
                value={comment}
                onChange={e => setComment(e.target.value)}
                placeholder="Add a comment…"
                className="flex-1 bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white placeholder-zinc-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={saving || !comment.trim()}
                className="bg-cyan-500/20 border border-cyan-500/30 text-cyan-400 px-4 py-2 rounded-lg text-sm hover:bg-cyan-500/30 disabled:opacity-40 transition-all"
              >
                {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <MessageSquare className="w-4 h-4" />}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
