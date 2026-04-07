// Centralised API client for all ZeroPhish backend endpoints
const BASE = process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://localhost:8001";

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ── Auth ──────────────────────────────────────────────────────────────────────
export const api = {
  auth: {
    login:    (email: string, password: string) =>
      request<{ access_token: string; role: string; user_id: string }>("/auth/login", {
        method: "POST", body: JSON.stringify({ email, password }),
      }),
    register: (email: string, password: string, full_name: string) =>
      request("/auth/register", {
        method: "POST", body: JSON.stringify({ email, password, full_name }),
      }),
    me:       (token: string) => request<any>("/auth/me", {}, token),
    logout:   (token: string) => request("/auth/logout", { method: "POST" }, token),
  },

  // ── Gateway scan ──────────────────────────────────────────────────────────
  scan: {
    submit:  (payload: any, token?: string) =>
      request<any>("/gateway/scan", { method: "POST", body: JSON.stringify(payload) }, token),
    status:  (id: string, token?: string) =>
      request<any>(`/gateway/status/${id}`, {}, token),
    result:  (id: string, token?: string) =>
      request<any>(`/gateway/result/${id}`, {}, token),
    health:  () => request<any>("/gateway/health"),
  },

  // ── Incidents ─────────────────────────────────────────────────────────────
  incidents: {
    list:   (token: string, params?: string) =>
      request<any[]>(`/incidents${params ? "?" + params : ""}`, {}, token),
    get:    (id: string, token: string) => request<any>(`/incidents/${id}`, {}, token),
    create: (data: any, token: string) =>
      request<any>("/incidents", { method: "POST", body: JSON.stringify(data) }, token),
    update: (id: string, data: any, token: string) =>
      request<any>(`/incidents/${id}`, { method: "PATCH", body: JSON.stringify(data) }, token),
    comment:(id: string, body: string, token: string) =>
      request<any>(`/incidents/${id}/comments`, { method: "POST", body: JSON.stringify({ body }) }, token),
    stats:  (token: string) => request<any>("/incidents/stats", {}, token),
  },

  // ── Analytics ─────────────────────────────────────────────────────────────
  analytics: {
    dashboard:    (token: string) => request<any>("/admin/dashboard", {}, token),
    heatmap:      (token: string) => request<any[]>("/analytics/heatmap", {}, token),
    feed:         (token: string) => request<any[]>("/analytics/threat-feed", {}, token),
    modelMetrics: (token: string) => request<any>("/analytics/model-metrics", {}, token),
    fpList:       (token: string) => request<any[]>("/analytics/false-positives?reviewed=false", {}, token),
    fpReport:     (data: any, token: string) =>
      request<any>("/analytics/false-positives", { method: "POST", body: JSON.stringify(data) }, token),
    policies:     (token: string) => request<any[]>("/admin/policies", {}, token),
    history:      (token: string) => request<any[]>("/user/history", {}, token),
    riskScore:    (token: string) => request<any>("/user/risk-score", {}, token),
  },

  // ── Awareness ─────────────────────────────────────────────────────────────
  awareness: {
    lessons:     (token: string) => request<any[]>("/awareness/lessons", {}, token),
    lesson:      (id: string, token: string) => request<any>(`/awareness/lessons/${id}`, {}, token),
    submitQuiz:  (id: string, answers: any, token: string) =>
      request<any>(`/awareness/lessons/${id}/quiz`, { method: "POST", body: JSON.stringify(answers) }, token),
    progress:    (token: string) => request<any>("/awareness/progress", {}, token),
    leaderboard: (token: string) => request<any[]>("/awareness/leaderboard", {}, token),
    campaigns:   (token: string) => request<any[]>("/awareness/campaigns", {}, token),
  },

  // ── Webhooks ──────────────────────────────────────────────────────────────
  webhooks: {
    list:   (token: string) => request<any[]>("/webhooks", {}, token),
    create: (data: any, token: string) =>
      request<any>("/webhooks", { method: "POST", body: JSON.stringify(data) }, token),
    delete: (id: string, token: string) =>
      request<void>(`/webhooks/${id}`, { method: "DELETE" }, token),
    deliveries: (token: string) => request<any[]>("/webhooks/deliveries", {}, token),
  },

  // ── Admin ──────────────────────────────────────────────────────────────────
  admin: {
    users:       (token: string) => request<any[]>("/admin/users", {}, token),
    updateUser:  (id: string, data: any, token: string) =>
      request<any>(`/admin/users/${id}`, { method: "PATCH", body: JSON.stringify(data) }, token),
    deleteUser:  (id: string, token: string) =>
      request<void>(`/admin/users/${id}`, { method: "DELETE" }, token),
  },
};
