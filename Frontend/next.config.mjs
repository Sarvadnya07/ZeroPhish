/** @type {import('next').NextConfig} */

function getClerkFrontendOrigin() {
  const pk = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
  if (!pk) return "";
  try {
    const parts = pk.split("_");
    if (parts.length >= 3) {
      const b64 = parts.slice(2).join("_");
      const decoded = Buffer.from(b64, "base64").toString("utf-8").replace(/\$$/, "");
      if (decoded) {
        return `https://${decoded}`;
      }
    }
  } catch {
    // Fallback if parsing fails
  }
  return "";
}

const clerkOrigin = getClerkFrontendOrigin();
const clerkOrigins = Array.from(
  new Set(
    [
      clerkOrigin,
      "https://*.clerk.accounts.dev",
      "https://*.clerk.com",
      "https://clerk.accounts.dev",
      "https://clerk.com",
      "https://challenges.cloudflare.com",
    ].filter(Boolean)
  )
);

const gatewayUrl = process.env.NEXT_PUBLIC_GATEWAY_URL || "http://localhost:8001";
const gatewayOrigins = Array.from(
  new Set(
    [
      "http://localhost:8001",
      "http://127.0.0.1:8001",
      "http://localhost:8000",
      "http://127.0.0.1:8000",
      gatewayUrl,
    ].filter(Boolean)
  )
);

const cspHeader = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline' 'unsafe-eval' ${clerkOrigins.join(" ")}`,
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  `img-src 'self' data: blob: https://img.clerk.com ${clerkOrigins.join(" ")}`,
  "font-src 'self' data: https://fonts.gstatic.com",
  `connect-src 'self' ${gatewayOrigins.join(" ")} ${clerkOrigins.join(" ")} https://clerk-telemetry.com`,
  `frame-src 'self' https://challenges.cloudflare.com ${clerkOrigins.join(" ")}`,
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "base-uri 'self'",
].join("; ");

const nextConfig = {
  typescript: {
    ignoreBuildErrors: false,
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
          {
            key: "Content-Security-Policy",
            value: cspHeader,
          },
        ],
      },
    ];
  },
};

export default nextConfig;
