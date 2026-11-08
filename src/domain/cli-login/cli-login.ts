/**
 * CLI login (lld/identity.md §6.2): device authorization in the RFC 8628 shape. Pure.
 *
 * The CLI creates a login and gets a high-entropy device code (`npdc_` + 43 base62 ≈ 256 bits, stored
 * as SHA-256 only) and a short user code (`XXXX-XXXX` from the RFC 8628 §6.1 consonant alphabet, 20⁸ ≈
 * 2.6·10¹⁰ values, unique among pending logins). A dashboard user approves or denies it; the first poll
 * that sees `approved` receives the minted key once and moves the login to `redeemed`.
 *
 * | From      | Command / event                               | Guard                         | To        |
 * |-----------|-----------------------------------------------|-------------------------------|-----------|
 * | —         | create                                        | per-IP limit (10 / 10 min)    | pending   |
 * | pending   | approve (session owner/admin/developer, step-up) | before `expires_at`        | approved  |
 * | pending   | deny (session owner/admin/developer)          | before `expires_at`           | denied    |
 * | pending   | expire (job, or read after `expires_at`)      | at/after `expires_at`         | expired   |
 * | approved  | poll                                          | within the redeem window      | redeemed  |
 * | approved  | expire (job): never collected                 | redeem window over            | expired (key revoked) |
 *
 * `denied`, `expired` and `redeemed` are terminal. Reads never trust the stored status alone: a
 * `pending` row past its expiry, or an `approved` row past its redeem window, reads as `expired`
 * before the job has run (the job only makes it durable).
 */
import { createHash, randomBytes } from "node:crypto";
import { randomBase62 } from "../api-key/key.js";

export type CliLoginStatus = "pending" | "approved" | "denied" | "expired" | "redeemed";

/** RFC 8628 §6.1: 20 consonants (no vowels → no words; no 0/O/1/I confusion). */
export const USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";
export const USER_CODE_RE = /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/;
export const DEVICE_CODE_PREFIX = "npdc_";
export const DEVICE_CODE_BODY_LENGTH = 43;
export const DEVICE_CODE_RE = /^npdc_[0-9A-Za-z]{43}$/;

/** How long an approved key waits for its poll before the login expires and the key is revoked. */
export const REDEEM_WINDOW_MS = 15 * 60_000;
/** A poll within this many ms of the previous one is accepted as on time (network/timer jitter). */
export const POLL_JITTER_MS = 1_000;
/** `getCliLogin` keeps answering for a login that expired less than this long ago. */
export const VISIBLE_AFTER_EXPIRY_MS = 24 * 3_600_000;
/** createCliLogin per client IP: 10 per 10 min (token bucket: burst 10, one back every 60 s). */
export const CREATE_LIMIT = { rate: 10 / 600, burst: 10 } as const;

/** Uniform user code by rejection sampling (256 = 12·20 + 16: bytes ≥ 240 are dropped). */
export function generateUserCode(random: (size: number) => Buffer = randomBytes): string {
  let out = "";
  while (out.length < 8) {
    for (const b of random(16)) {
      if (b >= 240) continue;
      out += USER_CODE_ALPHABET[b % 20];
      if (out.length === 8) break;
    }
  }
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

export function generateDeviceCode(random?: (size: number) => Buffer): string {
  return `${DEVICE_CODE_PREFIX}${randomBase62(DEVICE_CODE_BODY_LENGTH, random)}`;
}

export const deviceCodeHash = (code: string): Buffer => createHash("sha256").update(code, "utf8").digest();

export interface CliLoginState {
  readonly status: CliLoginStatus;
  readonly expires_at: Date;
  /** When it was approved (approved / redeemed rows). */
  readonly decided_at: Date | null;
}

/** The status a reader sees at `now` (expiry applied even before the job ran). */
export function effectiveStatus(l: CliLoginState, now: number): CliLoginStatus {
  if (l.status === "pending" && now >= l.expires_at.getTime()) return "expired";
  if (l.status === "approved" && l.decided_at && now >= l.decided_at.getTime() + REDEEM_WINDOW_MS) return "expired";
  return l.status;
}

/** When a login stopped being actionable (its expiry; for a never-collected approval, the window end). */
export function expiredAt(l: CliLoginState): number {
  if (l.status !== "pending" && l.decided_at && l.status !== "denied")
    return Math.max(l.expires_at.getTime(), l.decided_at.getTime() + REDEEM_WINDOW_MS);
  return l.expires_at.getTime();
}

export type Decision = "approve" | "deny";

export type DecideCheck =
  | { readonly ok: true; readonly to: "approved" | "denied" }
  | { readonly ok: false; readonly state: CliLoginStatus };

/** approve / deny: only a pending, unexpired login (otherwise `409 state_conflict` with its state). */
export function decide(l: CliLoginState, d: Decision, now: number): DecideCheck {
  const s = effectiveStatus(l, now);
  if (s !== "pending") return { ok: false, state: s };
  return { ok: true, to: d === "approve" ? "approved" : "denied" };
}

/** What a poll does at `now`: hand out the key (approved → redeemed) or just report the status. */
export function pollOutcome(l: CliLoginState, now: number): { status: CliLoginStatus; redeem: boolean } {
  const s = effectiveStatus(l, now);
  return s === "approved" ? { status: "approved", redeem: true } : { status: s, redeem: false };
}

/**
 * RFC 8628 `slow_down`: a poll sooner than `interval` after the previous accepted one is refused with
 * the seconds to wait (`Retry-After`). Refused polls do not move the clock, so a client that backs off
 * as told always gets through.
 */
export function pollPace(
  lastPolledAt: Date | null,
  now: number,
  intervalSeconds: number,
): { ok: true } | { ok: false; retryAfter: number } {
  if (!lastPolledAt) return { ok: true };
  const due = lastPolledAt.getTime() + intervalSeconds * 1000;
  if (now >= due - POLL_JITTER_MS) return { ok: true };
  return { ok: false, retryAfter: Math.max(1, Math.ceil((due - now) / 1000)) };
}

/**
 * Who may see a login on `getCliLogin`: anyone signed in while it is pending (it belongs to no account
 * yet; the user code is the capability), afterwards only the account that decided it; nobody once it
 * expired more than 24 h ago.
 */
export function visibleTo(l: CliLoginState & { account_id: string | null }, accountUuid: string, now: number): boolean {
  const s = effectiveStatus(l, now);
  if (s === "pending") return true;
  if (s === "expired" && now >= expiredAt(l) + VISIBLE_AFTER_EXPIRY_MS) return false;
  return l.account_id === null ? s === "expired" : l.account_id === accountUuid;
}

/** Name of the minted key: `CLI · <device name>` (the device name is ≤ 64 characters by contract). */
export const cliKeyName = (deviceName: string) => `CLI · ${deviceName}`;

/** Normalises the free-text metadata stored with a login (no control characters, bounded). */
export function cleanText(v: string | undefined | null, max: number): string | null {
  if (v === undefined || v === null) return null;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping control characters is the point
  const t = v.replace(/[\u0000-\u001f\u007f]/g, "").trim();
  return t ? t.slice(0, max) : null;
}

/** `CF-IPCountry` (two letters; Cloudflare also sends `XX` / `T1`), else null. */
export const cleanCountry = (v: string | undefined) => {
  const t = v?.trim().toUpperCase();
  return t && /^[A-Z0-9]{2}$/.test(t) ? t : null;
};
