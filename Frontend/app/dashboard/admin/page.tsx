"use client";
import React, { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { api } from "@/lib/api";
import { Settings, Shield, Trash2, Edit2, CheckCircle, XCircle, Loader2 } from "lucide-react";

export default function AdminPage() {
  const { token, role } = useAuth();
  const [users, setUsers] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!token || role !== "admin") return;
    setLoading(true);
    const res = await api.admin.users(token).catch(() => []);
    setUsers(res);
    setLoading(false);
  }, [token, role]);

  useEffect(() => { load(); }, [load]);

  const updateRole = async (id: string, newRole: string) => {
    if (!token) return;
    await api.admin.updateUser(id, { role: newRole }, token);
    setUsers(prev => prev.map(u => u.id === id ? { ...u, role: newRole } : u));
  };

  const updateStatus = async (id: string, newStatus: string) => {
    if (!token) return;
    await api.admin.updateUser(id, { status: newStatus }, token);
    setUsers(prev => prev.map(u => u.id === id ? { ...u, status: newStatus } : u));
  };

  const deleteUser = async (id: string) => {
    if (!token || !confirm("Are you sure you want to delete this user?")) return;
    await api.admin.deleteUser(id, token);
    setUsers(prev => prev.filter(u => u.id !== id));
  };

  if (role !== "admin") {
    return <div className="p-6 text-red-500">Access Denied: Admin role required.</div>;
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-zinc-400" /> Administration
        </h1>
        <p className="text-sm text-zinc-400 mt-0.5">Manage users, roles, and platform settings</p>
      </div>

      <div className="bg-zinc-900/60 border border-zinc-800 rounded-2xl overflow-hidden">
        <div className="border-b border-zinc-800 px-5 py-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-zinc-300">User Management</h2>
        </div>
        
        {loading ? (
          <div className="flex justify-center py-16"><Loader2 className="w-6 h-6 text-cyan-400 animate-spin" /></div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-800/20">
                  <th className="px-5 py-3 text-left font-medium text-zinc-500">Name / Email</th>
                  <th className="px-5 py-3 text-left font-medium text-zinc-500">Role</th>
                  <th className="px-5 py-3 text-center font-medium text-zinc-500">Status</th>
                  <th className="px-5 py-3 text-right font-medium text-zinc-500">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {users.map(u => (
                  <tr key={u.id} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="px-5 py-3">
                      <div className="font-medium text-zinc-200">{u.full_name}</div>
                      <div className="text-[10px] text-zinc-500">{u.email}</div>
                    </td>
                    <td className="px-5 py-3">
                      <select
                        value={u.role}
                        onChange={(e) => updateRole(u.id, e.target.value)}
                        className="bg-zinc-800 border border-zinc-700 text-zinc-300 rounded-lg px-2 py-1 text-xs focus:outline-none focus:border-cyan-500"
                      >
                        <option value="user">User</option>
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                        <option value="readonly">Readonly</option>
                      </select>
                    </td>
                    <td className="px-5 py-3 text-center">
                      <button
                        onClick={() => updateStatus(u.id, u.status === "active" ? "suspended" : "active")}
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold border transition-colors ${
                          u.status === "active" 
                            ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-red-500/10 hover:border-red-500/20 hover:text-red-400" 
                            : "bg-red-500/10 border-red-500/20 text-red-400 hover:bg-emerald-500/10 hover:border-emerald-500/20 hover:text-emerald-400"
                        }`}
                        title={u.status === "active" ? "Click to suspend" : "Click to activate"}
                      >
                        {u.status === "active" ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}
                        {u.status.toUpperCase()}
                      </button>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button 
                        onClick={() => deleteUser(u.id)}
                        className="text-zinc-500 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
