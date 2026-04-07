"use client";
import React, { useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { FileUp, Search, ShieldAlert, CheckCircle, FileScan, UploadCloud, FileIcon, Loader2, AlertTriangle } from "lucide-react";

export default function ScannerPage() {
  const { token } = useAuth();
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setResult(null);
      setError(null);
    }
  };

  const handleScan = async () => {
    if (!file || !token) return;
    setScanning(true);
    setError(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch("http://localhost:8001/email/scan-eml", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${token}`
        },
        body: formData,
      });

      if (!res.ok) {
        throw new Error("Failed to scan file");
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <FileScan className="w-5 h-5 text-cyan-400" /> EML Scanner
        </h1>
        <p className="text-sm text-zinc-400 mt-0.5">Deep inspection of raw .eml files: SPF/DKIM/DMARC headers, attachments, and URLs.</p>
      </div>

      <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl p-6">
        <div className="flex flex-col items-center justify-center p-10 border-2 border-dashed border-zinc-700 rounded-xl bg-zinc-800/30">
          <UploadCloud className="w-10 h-10 text-cyan-500 mb-4" />
          <p className="text-sm text-zinc-300 font-medium mb-1">Upload a raw .eml file</p>
          <p className="text-xs text-zinc-500 mb-6">Max size 10MB</p>
          
          <input
            type="file"
            id="eml-upload"
            accept=".eml"
            className="hidden"
            onChange={handleFileChange}
          />
          <label
            htmlFor="eml-upload"
            className="bg-zinc-800 border border-zinc-700 hover:border-cyan-500 text-zinc-300 px-4 py-2 rounded-xl text-sm cursor-pointer transition-all"
          >
            {file ? file.name : "Select File"}
          </label>
        </div>

        <div className="mt-6 flex justify-end">
          <button
            disabled={!file || scanning}
            onClick={handleScan}
            className="bg-gradient-to-r from-cyan-500 to-violet-600 text-white px-6 py-2 rounded-xl text-sm font-medium hover:from-cyan-400 hover:to-violet-500 disabled:opacity-50 transition-all flex items-center gap-2"
          >
            {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            {scanning ? "Scanning..." : "Run Deep Scan"}
          </button>
        </div>
        
        {error && (
            <div className="mt-4 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                Error: {error}
            </div>
        )}
      </div>

      {result && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
          <div className="border-b border-zinc-800 px-6 py-4">
            <h2 className="text-base font-semibold text-white">Scan Results</h2>
          </div>
          
          <div className="p-6 space-y-6">
            <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                    <p className="text-xs text-zinc-500">Sender</p>
                    <p className="text-sm text-zinc-200 font-mono">{result.sender}</p>
                </div>
                <div className="space-y-1">
                    <p className="text-xs text-zinc-500">Subject</p>
                    <p className="text-sm text-zinc-200">{result.subject}</p>
                </div>
            </div>

            <div className="border-t border-zinc-800 pt-6">
                <h3 className="text-sm font-semibold text-zinc-300 mb-4">Authentication (SPF / DKIM / DMARC)</h3>
                <div className="flex gap-4">
                    {["spf", "dkim", "dmarc"].map(proto => (
                        <div key={proto} className="bg-zinc-800/50 border border-zinc-700 rounded-lg p-3 flex-1 flex items-center justify-between">
                            <span className="text-xs font-semibold text-zinc-400 uppercase">{proto}</span>
                            <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                                result.auth_results[proto] === "pass" ? "bg-emerald-500/20 text-emerald-400" :
                                result.auth_results[proto] === "fail" || result.auth_results[proto] === "softfail" ? "bg-red-500/20 text-red-400" :
                                "bg-zinc-700 text-zinc-400"
                            }`}>
                                {result.auth_results[proto]}
                            </span>
                        </div>
                    ))}
                </div>
                {result.auth_results.score_penalty > 0 && (
                    <p className="mt-2 text-xs text-red-400 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" />
                        Authentication failure adds +{result.auth_results.score_penalty} to threat score.
                    </p>
                )}
            </div>

            {result.attachments?.length > 0 && (
                <div className="border-t border-zinc-800 pt-6">
                    <h3 className="text-sm font-semibold text-zinc-300 mb-4">Attachments ({result.attachments.length})</h3>
                    <div className="space-y-2">
                        {result.attachments.map((att: any, i: number) => (
                            <div key={i} className="bg-zinc-800/30 border border-zinc-700 rounded-lg p-3 flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    <FileIcon className="w-5 h-5 text-zinc-500" />
                                    <div>
                                        <p className="text-sm text-zinc-200">{att.filename}</p>
                                        <p className="text-xs text-zinc-500">{(att.size_bytes / 1024).toFixed(1)} KB · {att.content_type}</p>
                                    </div>
                                </div>
                                <div className="flex flex-col items-end">
                                    <span className={`text-xs font-bold px-2 py-0.5 rounded uppercase ${
                                        att.risk_level === "dangerous" ? "bg-red-500/20 text-red-400" :
                                        att.risk_level === "suspicious" ? "bg-orange-500/20 text-orange-400" :
                                        "bg-emerald-500/20 text-emerald-400"
                                    }`}>
                                        {att.risk_level}
                                    </span>
                                    {att.risk_reason && <span className="text-[10px] text-zinc-500 mt-1">{att.risk_reason}</span>}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
