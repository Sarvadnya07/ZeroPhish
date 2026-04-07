import React, { useState } from "react";
import { Award, Star, Loader2 } from "lucide-react";
import { ProgressBar } from "./lesson-card";

export function QuizModal({
  lesson,
  token,
  onClose,
  onComplete,
  api,
}: { lesson: any; token: string; onClose: () => void; onComplete: (result: any) => void; api: any }) {
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const [result, setResult] = useState<any>(null);
  const [submitting, setSubmitting] = useState(false);
  const [qIdx, setQIdx] = useState(0);

  const q = lesson.quiz[qIdx];

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      const res = await api.awareness.submitQuiz(lesson.id, answers, token);
      setResult(res);
      onComplete(res);
    } finally { setSubmitting(false); }
  };

  if (result) {
    return (
      <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-md p-8 text-center shadow-2xl">
          <div className={`w-16 h-16 rounded-full mx-auto flex items-center justify-center mb-4 ${result.passed ? "bg-emerald-500/20" : "bg-red-500/20"}`}>
            {result.passed ? <Award className="w-8 h-8 text-emerald-400" /> : <Star className="w-8 h-8 text-red-400" />}
          </div>
          <h2 className="text-xl font-bold text-white mb-1">{result.passed ? "Passed! 🎉" : "Keep Practicing"}</h2>
          <p className="text-3xl font-bold text-cyan-400 my-3">{result.score_pct}%</p>
          <p className="text-sm text-zinc-400 mb-1">{result.correct}/{result.total} correct</p>
          {result.xp_earned > 0 && (
            <p className="text-sm text-emerald-400 font-medium">+{result.xp_earned} XP earned!</p>
          )}
          <div className="mt-6 space-y-2 text-left">
            {result.feedback?.map((f: any) => (
              <div key={f.question_id} className={`flex items-start gap-2 px-3 py-2 rounded-lg text-xs ${f.correct ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}`}>
                <span className="flex-shrink-0">{f.correct ? "✓" : "✗"}</span>
                <span>{f.explanation}</span>
              </div>
            ))}
          </div>
          <button onClick={onClose} className="mt-6 w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-violet-600 text-white text-sm font-medium">
            Done
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-2xl w-full max-w-lg shadow-2xl">
        <div className="p-5 border-b border-zinc-800">
          <div className="flex items-center justify-between mb-1">
            <h2 className="text-sm font-semibold text-white">{lesson.title}</h2>
            <span className="text-xs text-zinc-500">{qIdx + 1}/{lesson.quiz.length}</span>
          </div>
          <ProgressBar value={((qIdx) / lesson.quiz.length) * 100} />
        </div>
        <div className="p-6">
          <p className="text-sm font-medium text-zinc-200 mb-5">{q.question}</p>
          <div className="space-y-2.5">
            {q.options.map((opt: string, i: number) => (
              <button
                key={i}
                onClick={() => setAnswers(a => ({ ...a, [q.id]: i }))}
                className={`w-full text-left px-4 py-3 rounded-xl text-sm border transition-all ${
                  answers[q.id] === i
                    ? "bg-cyan-500/15 border-cyan-500/40 text-cyan-300"
                    : "bg-zinc-800/40 border-zinc-700 text-zinc-300 hover:border-zinc-500"
                }`}
              >
                <span className="text-zinc-500 mr-2">{String.fromCharCode(65 + i)}.</span> {opt}
              </button>
            ))}
          </div>
        </div>
        <div className="p-5 border-t border-zinc-800 flex gap-3">
          <button onClick={onClose} className="flex-1 py-2.5 rounded-xl border border-zinc-700 text-zinc-400 text-sm hover:border-zinc-500">Cancel</button>
          {qIdx < lesson.quiz.length - 1 ? (
            <button
              disabled={answers[q.id] === undefined}
              onClick={() => setQIdx(i => i + 1)}
              className="flex-1 py-2.5 rounded-xl text-sm font-medium bg-zinc-800 text-zinc-200 disabled:opacity-40 hover:bg-zinc-700"
            >
              Next →
            </button>
          ) : (
            <button
              disabled={Object.keys(answers).length < lesson.quiz.length || submitting}
              onClick={handleSubmit}
              className="flex-1 py-2.5 rounded-xl text-sm font-medium bg-gradient-to-r from-cyan-500 to-violet-600 text-white disabled:opacity-40"
            >
              {submitting ? <Loader2 className="w-4 h-4 animate-spin mx-auto" /> : "Submit"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
