"use client";
import React from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { UserButton } from "@clerk/nextjs";
import {
  Shield, LayoutDashboard, AlertTriangle, BookOpen, BarChart3,
  Webhook, Settings, LogOut, ChevronRight, User, Zap, ScanSearch,
} from "lucide-react";

const NAV = [
  { href: "/dashboard",            label: "Live Sentinel",    icon: Zap,             roles: ["admin","analyst","user","readonly"] },
  { href: "/dashboard/incidents",  label: "Incidents",        icon: AlertTriangle,   roles: ["admin","analyst","user"] },
  { href: "/dashboard/scanner",    label: "EML Scanner",      icon: ScanSearch,      roles: ["admin","analyst","user","readonly"] },
  { href: "/dashboard/awareness",  label: "Security Training",icon: BookOpen,        roles: ["admin","analyst","user","readonly"] },
  { href: "/dashboard/analytics",  label: "Analytics",        icon: BarChart3,       roles: ["admin","analyst"] },
  { href: "/dashboard/webhooks",   label: "Webhooks",         icon: Webhook,         roles: ["admin","analyst","user"] },
  { href: "/dashboard/admin",      label: "Admin",            icon: Settings,        roles: ["admin"] },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, role, logout, loading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-[#050505]">
        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!user) {
    if (typeof window !== "undefined") router.replace("/login");
    return null;
  }

  const visibleNav = NAV.filter(n => !role || n.roles.includes(role));

  return (
    <div className="flex h-screen bg-[#050505] text-white overflow-hidden">
      {/* Sidebar */}
      <aside className="w-60 flex-shrink-0 bg-zinc-900/60 border-r border-zinc-800 flex flex-col">
        {/* Logo */}
        <div className="p-5 border-b border-zinc-800">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="text-sm font-bold text-white tracking-tight">ZeroPhish</div>
              <div className="text-[10px] text-zinc-500">Combat Centre</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
          {visibleNav.map(({ href, label, icon: Icon }) => {
            const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all group ${
                  active
                    ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/20"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60"
                }`}
              >
                <Icon className={`w-4 h-4 flex-shrink-0 ${active ? "text-cyan-400" : "text-zinc-500 group-hover:text-zinc-300"}`} />
                {label}
                {active && <ChevronRight className="w-3.5 h-3.5 ml-auto text-cyan-500" />}
              </Link>
            );
          })}
        </nav>

        {/* User footer */}
        <div className="p-3 border-t border-zinc-800">
          <div className="flex items-center gap-3 px-3 py-2 rounded-xl bg-zinc-800/40">
            <UserButton
              appearance={{
                elements: {
                  userButtonAvatarBox: "w-8 h-8",
                },
              }}
            />
            <div className="flex-1 min-w-0">
              <div className="text-xs font-medium text-zinc-200 truncate">{user?.full_name || "User"}</div>
              <div className="text-[10px] text-zinc-500 capitalize">{role}</div>
            </div>
            <button
              onClick={logout}
              className="text-zinc-500 hover:text-red-400 transition-colors"
              title="Sign out"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  );
}
