"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { BookOpen, Trophy, Loader2 } from "lucide-react";
import { LessonCard, ProgressBar } from "@/components/awareness/lesson-card";
import { QuizModal } from "@/components/awareness/quiz-modal";

export default function AwarenessPage() {
  const { token } = useAuth();
  const [lessons, setLessons] = useState<any[]>([]);
  const [progress, setProgress] = useState<any>(null);
  const [leaderboard, setLeaderboard] = useState<any[]>([]);
  const [activeLesson, setActiveLesson] = useState<any>(null);
  const [tab, setTab] = useState<"lessons" | "leaderboard">("lessons");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    const [l, p, lb] = await Promise.allSettled([
      api.awareness.lessons(token),
      api.awareness.progress(token),
      api.awareness.leaderboard(token),
    ]);
    if (l.status === "fulfilled") setLessons(l.value);
    if (p.status === "fulfilled") setProgress(p.value);
    if (lb.status === "fulfilled") setLeaderboard(lb.value);
    setLoading(false);
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const level = progress?.level ?? 1;
  const xp = progress?.xp ?? 0;
  const nextLevelXp = level * 500;

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <BookOpen className="w-5 h-5 text-violet-400" /> Security Awareness Training
        </h1>
        <p className="text-sm text-zinc-400 mt-0.5">Interactive lessons, quizzes, and progress tracking</p>
      </div>

      {/* XP Card */}
      {progress && (
        <div className="bg-gradient-to-br from-violet-900/40 to-cyan-900/30 border border-violet-500/20 rounded-2xl p-5">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-xs text-violet-400 font-medium">LEVEL {level}</div>
              <div className="text-2xl font-bold text-white mt-0.5">{xp} XP</div>
            </div>
            <div className="text-right">
              <div className="text-lg font-bold text-cyan-400">{progress.detection_score ?? 0}%</div>
              <div className="text-xs text-zinc-400">Detection Rate</div>
            </div>
          </div>
          <ProgressBar value={(xp / nextLevelXp) * 100} color="bg-gradient-to-r from-violet-500 to-cyan-500" />
          <div className="flex justify-between text-[10px] text-zinc-500 mt-1">
            <span>{xp} XP</span><span>{nextLevelXp} XP to Level {level + 1}</span>
          </div>
          {progress.badges?.length > 0 && (
            <div className="flex gap-2 mt-3">
              {progress.badges.map((b: string) => (
                <span key={b} className="px-2 py-0.5 bg-violet-500/20 border border-violet-500/30 text-violet-400 text-[10px] rounded-full">🏆 {b.replace("_"," ")}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab */}
      <div className="flex gap-2">
        {(["lessons","leaderboard"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-xl text-sm font-medium border transition-all ${tab === t ? "bg-cyan-500/15 border-cyan-500/30 text-cyan-400" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}
          >
            {t === "lessons" ? "Lessons" : "Leaderboard"}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 text-cyan-400 animate-spin" /></div>
      ) : tab === "lessons" ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {lessons.map((l: any) => (
            <LessonCard
              key={l.id}
              lesson={l}
              completed={progress?.lessons_completed?.includes(l.id)}
              score={progress?.quiz_scores?.[l.id]}
              onStart={() => setActiveLesson(l)}
            />
          ))}
        </div>
      ) : (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
          <div className="border-b border-zinc-800 px-5 py-3 flex items-center gap-2">
            <Trophy className="w-4 h-4 text-yellow-400" />
            <span className="text-sm font-medium text-zinc-300">Security Awareness Leaderboard</span>
          </div>
          <div className="divide-y divide-zinc-800/50">
            {leaderboard.map((e: any) => (
              <div key={e.user_id} className="flex items-center gap-4 px-5 py-3">
                <div className={`w-8 text-center font-bold text-sm ${e.rank <= 3 ? "text-yellow-400" : "text-zinc-500"}`}>#{e.rank}</div>
                <div className="flex-1">
                  <div className="text-sm font-medium text-zinc-200">{e.display_name}</div>
                  <div className="text-xs text-zinc-500">{e.lessons_completed} lessons · {e.detection_score}% detection</div>
                </div>
                <div className="text-right">
                  <div className="text-sm font-bold text-cyan-400">{e.xp} XP</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeLesson && (
        <QuizModal
          lesson={activeLesson}
          token={token!}
          api={api}
          onClose={() => { setActiveLesson(null); load(); }}
          onComplete={() => {}}
        />
      )}
    </div>
  );
}
