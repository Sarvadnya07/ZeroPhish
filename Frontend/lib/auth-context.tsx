"use client";
import React, { createContext, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";

interface AuthState {
  token: string | null; // Kept in state for client interoperability; null when using cookie sessions
  user: any | null;
  role: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (email: string, password: string, name: string) => Promise<void>;
}

const AuthCtx = createContext<AuthState>({} as AuthState);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  // `token` is kept in state for Chrome extension / API client compatibility.
  // Browser dashboard clients rely on the httpOnly session cookie automatically.
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser]   = useState<any>(null);
  const [role, setRole]   = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Probe /auth/me — if the session cookie is valid the server returns the profile.
    api.auth.me("")
      .then(u => {
        setUser(u);
        setRole(u.role);
        setToken("cookie");
      })
      .catch(() => {
        // No cookie / expired session — user stays logged out
        setUser(null);
        setRole(null);
        setToken(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const res = await api.auth.login(email, password);
    setToken(res.access_token);
    setRole(res.role);
    const me = await api.auth.me(res.access_token);
    setUser(me);
  };

  const logout = () => {
    api.auth.logout(token ?? "").catch(() => {});
    setToken(null);
    setUser(null);
    setRole(null);
  };

  const register = async (email: string, password: string, name: string) => {
    await api.auth.register(email, password, name);
  };

  return (
    <AuthCtx.Provider value={{ token, user, role, loading, login, logout, register }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
