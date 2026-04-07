export const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/20",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/20",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/20",
  info:     "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
};

export const STATUS_COLOR: Record<string, string> = {
  open:        "text-red-400",
  triaging:    "text-orange-400",
  in_progress: "text-yellow-400",
  resolved:    "text-emerald-400",
  closed:      "text-zinc-400",
  false_positive: "text-violet-400",
};
