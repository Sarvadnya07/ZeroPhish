import React from "react";
import { CheckCircle, ChevronRight } from "lucide-react";

export const DIFF_COLOR: Record<string, string> = {
  beginner:     "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  intermediate: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  advanced:     "text-red-400 bg-red-500/10 border-red-500/20",
};

export function ProgressBar({ value, color = "bg-cyan-500" }: { value: number; color?: string }) {
  return (
    <div className="h-1.5 bg-zinc-800 rounded-full overflow-hidden">
      <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${Math.min(100, value)}%` }} />
    </div>
  );
}

export function LessonCard({
  lesson,
  completed,
  score,
  onStart,
}: { lesson: any; completed: boolean; score?: number; onStart: () => void }) {
  return (
    <div className="bg-zinc-900/60 border border-zinc-800 hover:border-zinc-600 rounded-2xl p-5 transition-all group cursor-pointer" onClick={onStart}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${DIFF_COLOR[lesson.difficulty]}`}>
              {lesson.difficulty}
            </span>
            {completed && <CheckCircle className="w-4 h-4 text-emerald-400" />}
          </div>
          <h3 className="text-sm font-semibold text-zinc-200 group-hover:text-white">{lesson.title}</h3>
          <p className="text-xs text-zinc-500 mt-0.5 leading-relaxed">{lesson.description}</p>
        </div>
        <div className="text-right flex-shrink-0">
          <div className="text-sm font-bold text-cyan-400">+{lesson.xp_reward} XP</div>
          <div className="text-[10px] text-zinc-600">{lesson.estimated_minutes} min</div>
        </div>
      </div>
      {score !== undefined && (
        <div>
          <ProgressBar value={score} color={score >= 70 ? "bg-emerald-500" : "bg-orange-500"} />
          <div className="text-[10px] text-zinc-500 mt-1">Last score: {score}%</div>
        </div>
      )}
      <div className="flex items-center justify-end mt-3">
        <span className="text-xs text-cyan-500 group-hover:text-cyan-400 font-medium flex items-center gap-1">
          {completed ? "Review" : "Start"} <ChevronRight className="w-3.5 h-3.5" />
        </span>
      </div>
    </div>
  );
}
