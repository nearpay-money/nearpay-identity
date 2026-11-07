/**
 * Dashboard and console sessions (lld/identity.md §4, §12). Pure.
 *
 * Cookie `__Host-np_session` (console: `__Host-np_ops`) = 32 random bytes base64url; the hash is
 * stored. `SameSite=Strict; Secure; HttpOnly; Path=/`; 12 h sliding, 7 days absolute. A step-up
 * (fresh passkey assertion) counts for 10 minutes.
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "__Host-np_session";
export const OPS_COOKIE = "__Host-np_ops";
export const SLIDING_MS = 12 * 3_600_000;
export const ABSOLUTE_MS = 7 * 24 * 3_600_000;
export const STEP_UP_MS = 10 * 60_000;
/** Console sessions (spec `OPS_SESSION_TTL_SECONDS`): 30 min idle, 12 h absolute. */
export const OPS_IDLE_MS = 30 * 60_000;
export const OPS_ABSOLUTE_MS = 12 * 3_600_000;

export type SessionKind = "dashboard" | "ops";

/** Idle limit and absolute lifetime of a session kind. */
export const LIFETIME: Readonly<Record<SessionKind, { idleMs: number; absoluteMs: number }>> = {
  dashboard: { idleMs: SLIDING_MS, absoluteMs: ABSOLUTE_MS },
  ops: { idleMs: OPS_IDLE_MS, absoluteMs: OPS_ABSOLUTE_MS },
};
/** last_seen_at is written at most once a minute (authz is hot). */
export const TOUCH_EVERY_MS = 60_000;

export const newSecret = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest();

/** Constant-time check of a presented secret against its stored SHA-256. */
export function matchesHash(presented: string | undefined, hash: Buffer): boolean {
  if (!presented) return false;
  const h = sha256(presented);
  return h.length === hash.length && timingSafeEqual(h, hash);
}

export interface SessionTimes {
  readonly expires_at: Date;
  readonly last_seen_at: Date;
  readonly revoked_at: Date | null;
}

export type SessionState = "valid" | "revoked" | "expired" | "idle";

/**
 * State of a session at `now`. `expires_at` is the absolute end (creation + the kind's lifetime);
 * the idle limit depends on the kind (dashboard 12 h sliding, console 30 min).
 */
export function sessionState(s: SessionTimes, now: number, kind: SessionKind = "dashboard"): SessionState {
  if (s.revoked_at) return "revoked";
  if (s.expires_at.getTime() <= now) return "expired";
  if (now - s.last_seen_at.getTime() > LIFETIME[kind].idleMs) return "idle";
  return "valid";
}

/** When an idle session ends: the idle limit after the last activity, never after the absolute end. */
export function idleExpiresAt(s: Pick<SessionTimes, "expires_at" | "last_seen_at">, kind: SessionKind): Date {
  return new Date(Math.min(s.last_seen_at.getTime() + LIFETIME[kind].idleMs, s.expires_at.getTime()));
}

/** Unix seconds until which the step-up is fresh, or undefined. */
export function stepUpUntil(stepUpAt: Date | null, now: number): number | undefined {
  if (!stepUpAt) return undefined;
  const until = stepUpAt.getTime() + STEP_UP_MS;
  return until > now ? Math.floor(until / 1000) : undefined;
}

export function setCookie(name: string, value: string, maxAgeSeconds: number): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}`;
}

export function clearCookie(name: string): string {
  return `${name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0`;
}

/** Value of one cookie in a `Cookie` header. */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) {
      const v = part.slice(i + 1).trim();
      return /^[A-Za-z0-9_-]{16,128}$/.test(v) ? v : undefined;
    }
  }
  return undefined;
}
