/**
 * Gateway authorisation rules (lld/identity.md §8.1). Pure: route matching against the spec's
 * public route table, credential precedence, CSRF, rate-limit classes, token buckets, client IP.
 */

export interface RouteRef {
  readonly id: string;
  readonly method: string;
  readonly path: string;
  readonly auth: readonly string[];
  readonly errors: readonly string[];
}

interface Compiled {
  readonly route: RouteRef;
  readonly re: RegExp;
  readonly literal: number;
}

/** Matches request paths against route templates (`/v1/x/{id}`); literal segments win over parameters. */
export function routeMatcher(routes: readonly RouteRef[]) {
  const compiled: Compiled[] = routes.map((r) => ({
    route: r,
    re: new RegExp(
      `^${r.path
        .split("/")
        .map((seg) => (/^\{[^}]+\}$/.test(seg) ? "[^/]+" : seg.replace(/[.*+?^$()|[\]\\{}]/g, "\\$&")))
        .join("/")}$`,
    ),
    literal: r.path.split("/").filter((s) => s && !s.startsWith("{")).length,
  }));
  compiled.sort((a, b) => b.literal - a.literal);
  return (method: string, path: string): RouteRef | null => {
    const p = path.split("?")[0] ?? "";
    for (const c of compiled) if (c.route.method === method && c.re.test(p)) return c.route;
    return null;
  };
}

export const isUnsafe = (method: string) => !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());

/** Routes a publishable key may call. */
export const publishableAllowed = (r: RouteRef | null) => r?.auth.includes("publishable_key") ?? false;

/** Routes reachable without a credential (anonymous at the gateway; client-secret routes check the secret themselves). */
export const anonymousAllowed = (r: RouteRef | null) =>
  (r?.auth.includes("anonymous") || r?.auth.includes("client_secret")) ?? false;

/**
 * "Money routes": live, unsafe calls need `live_enabled` (L-ID-02). Defined from the contract: the
 * routes that declare `account_not_live`.
 */
export const requiresLiveEnabled = (r: RouteRef | null) => r?.errors.includes("account_not_live") ?? false;

export type RateClass = "live" | "test" | "anonymous";

export interface Bucket {
  readonly rate: number;
  readonly burst: number;
}

/** lld/identity.md §8.1 step 5 (per key/user: live 100 rps burst 200, test 25/50; anonymous 10/20 per IP). */
export const RATE_LIMITS: Readonly<Record<RateClass, Bucket>> = {
  live: { rate: 100, burst: 200 },
  test: { rate: 25, burst: 50 },
  anonymous: { rate: 10, burst: 20 },
};

/** Per-pod fallback when Valkey is down: half the limits. */
export const degraded = (b: Bucket): Bucket => ({ rate: b.rate / 2, burst: Math.max(1, Math.floor(b.burst / 2)) });

export interface BucketState {
  tokens: number;
  at: number;
}

/** Token bucket step: returns the new state and, when refused, the seconds until one token is back. */
export function takeToken(
  state: BucketState | undefined,
  b: Bucket,
  now: number,
): { allowed: boolean; state: BucketState; retryAfter: number } {
  const s = state ?? { tokens: b.burst, at: now };
  const tokens = Math.min(b.burst, s.tokens + ((now - s.at) / 1000) * b.rate);
  if (tokens >= 1) return { allowed: true, state: { tokens: tokens - 1, at: now }, retryAfter: 0 };
  return { allowed: false, state: { tokens, at: now }, retryAfter: Math.max(1, Math.ceil((1 - tokens) / b.rate)) };
}

/**
 * Client IP (L-ID-07): `CF-Connecting-IP` on the server stage (Cloudflare-only origin); locally the
 * first `X-Forwarded-For` hop set by Traefik. Never trust either outside its stage.
 */
export function clientIp(
  env: string,
  h: { cfConnectingIp?: string | undefined; xForwardedFor?: string | undefined },
): string | null {
  const v = env === "server" ? h.cfConnectingIp : h.xForwardedFor?.split(",")[0];
  const ip = v?.trim();
  return ip && /^[0-9a-fA-F:.]{2,45}$/.test(ip) ? ip : null;
}

/** `NearPay-Mode` header → livemode for session principals (default test). */
export const sessionMode = (header: string | undefined) => header?.trim().toLowerCase() === "live";

/** The console is served on `ops.<domain>`; its sessions are ops principals (L-ID-04). */
export const isConsoleHost = (host: string | undefined) =>
  (host ?? "").toLowerCase().split(":")[0]?.startsWith("ops.") ?? false;
