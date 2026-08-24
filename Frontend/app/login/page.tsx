"use client";
import React, { Suspense, useState } from "react";
import { SignIn, SignUp } from "@clerk/nextjs";
import { Shield } from "lucide-react";

function AuthComponent() {
  const [isSignUp, setIsSignUp] = useState(false);

  return (
    <div className="min-h-screen bg-[#050505] flex items-center justify-center p-4">
      {/* Background glow */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-violet-500/10 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-md flex flex-col items-center">
        {/* Logo Header */}
        <div className="flex flex-col items-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center mb-3 shadow-lg shadow-cyan-500/20">
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">ZeroPhish</h1>
          <p className="text-xs text-zinc-400 mt-1">Combat Centre · Identity & Access</p>
        </div>

        {/* Mode Toggle */}
        <div className="flex rounded-lg bg-zinc-900/80 border border-zinc-800 p-1 mb-6 w-full max-w-sm">
          <button
            type="button"
            onClick={() => setIsSignUp(false)}
            className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-all ${
              !isSignUp ? "bg-cyan-500/20 text-cyan-400 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => setIsSignUp(true)}
            className={`flex-1 py-1.5 text-xs font-semibold rounded-md transition-all ${
              isSignUp ? "bg-cyan-500/20 text-cyan-400 shadow-sm" : "text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Create Account
          </button>
        </div>

        {/* Clerk Auth Card */}
        <div className="w-full flex justify-center">
          {isSignUp ? (
            <SignUp
              routing="hash"
              appearance={{
                elements: {
                  card: "bg-zinc-900/90 border border-zinc-800 shadow-2xl backdrop-blur rounded-2xl",
                  headerTitle: "text-white text-lg font-bold",
                  headerSubtitle: "text-zinc-400 text-xs",
                  socialButtonsBlockButton: "border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-white",
                  formButtonPrimary: "bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-white font-medium text-sm",
                  formFieldInput: "bg-zinc-800 border-zinc-700 text-white focus:border-cyan-500",
                  footerActionLink: "text-cyan-400 hover:text-cyan-300",
                },
              }}
              fallbackRedirectUrl="/dashboard"
            />
          ) : (
            <SignIn
              routing="hash"
              appearance={{
                elements: {
                  card: "bg-zinc-900/90 border border-zinc-800 shadow-2xl backdrop-blur rounded-2xl",
                  headerTitle: "text-white text-lg font-bold",
                  headerSubtitle: "text-zinc-400 text-xs",
                  socialButtonsBlockButton: "border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-white",
                  formButtonPrimary: "bg-gradient-to-r from-cyan-500 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-white font-medium text-sm",
                  formFieldInput: "bg-zinc-800 border-zinc-700 text-white focus:border-cyan-500",
                  footerActionLink: "text-cyan-400 hover:text-cyan-300",
                },
              }}
              fallbackRedirectUrl="/dashboard"
            />
          )}
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-[#050505] flex items-center justify-center p-4">
          <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <AuthComponent />
    </Suspense>
  );
}
