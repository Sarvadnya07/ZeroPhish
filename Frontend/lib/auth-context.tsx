"use client";
import React, { createContext, useContext, useEffect, useState } from "react";
import { useAuth as useClerkAuth, useUser as useClerkUser } from "@clerk/nextjs";
import { api } from "@/lib/api";

interface AuthState {
  token: string | null;
  user: any | null;
  role: string | null;
  loading: boolean;
  logout: () => Promise<void>;
  getToken: () => Promise<string | null>;
}

const AuthCtx = createContext<AuthState>({} as AuthState);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const clerkAuth = useClerkAuth();
  const { user: clerkUser, isLoaded: userLoaded } = useClerkUser();
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<any>(null);
  const [role, setRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!clerkAuth.isLoaded || !userLoaded) {
      return;
    }

    if (!clerkAuth.isSignedIn) {
      setUser(null);
      setRole(null);
      setToken(null);
      setLoading(false);
      return;
    }

    let isMounted = true;
    clerkAuth.getToken().then((rawToken) => {
      if (!isMounted) return;
      if (!rawToken) {
        setUser(null);
        setRole(null);
        setToken(null);
        setLoading(false);
        return;
      }

      setToken(rawToken);
      api.auth
        .me(rawToken)
        .then((u) => {
          if (isMounted) {
            setUser(u);
            setRole(u.role);
          }
        })
        .catch(() => {
          if (isMounted) {
            // Fallback to clerk profile
            setUser({
              id: clerkAuth.userId,
              clerk_user_id: clerkAuth.userId,
              email: clerkUser?.primaryEmailAddress?.emailAddress || "",
              full_name: clerkUser?.fullName || clerkUser?.firstName || "User",
              role: "user",
            });
            setRole("user");
          }
        })
        .finally(() => {
          if (isMounted) setLoading(false);
        });
    });

    return () => {
      isMounted = false;
    };
  }, [clerkAuth.isLoaded, clerkAuth.isSignedIn, clerkAuth.userId, userLoaded, clerkUser]);

  const logout = async () => {
    await clerkAuth.signOut();
    setToken(null);
    setUser(null);
    setRole(null);
  };

  const getToken = async () => {
    if (!clerkAuth.isSignedIn) return null;
    const t = await clerkAuth.getToken();
    if (t) setToken(t);
    return t;
  };

  return (
    <AuthCtx.Provider value={{ token, user, role, loading, logout, getToken }}>
      {children}
    </AuthCtx.Provider>
  );
}

export const useAuth = () => useContext(AuthCtx);
