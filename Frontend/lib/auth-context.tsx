"use client";
import React, { createContext, useContext, useEffect, useState } from "react";
import { api } from "@/lib/api";

interface AuthState {
  token: string | null;
  user: any | null;
  role: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  register: (email: string, password: string, name: string) => Promise<void>;
}

const AuthCtx = createContext<AuthState>({} as AuthState);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser]   = useState<any>(null);
  const [role, setRole]   = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const saved = typeof window !== "undefined" ? localStorage.getItem("zp_token") : null;
    if (saved) {
      setToken(saved);
      api.auth.me(saved)
        .then(u => { setUser(u); setRole(u.role); })
        .catch(() => { localStorage.removeItem("zp_token"); setToken(null); })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = async (email: string, password: string) => {
    const res = await api.auth.login(email, password);
    setToken(res.access_token);
    setRole(res.role);
    localStorage.setItem("zp_token", res.access_token);
    const me = await api.auth.me(res.access_token);
    setUser(me);
  };

  const logout = () => {
    if (token) api.auth.logout(token).catch(() => {});
    setToken(null); setUser(null); setRole(null);
    localStorage.removeItem("zp_token");
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
