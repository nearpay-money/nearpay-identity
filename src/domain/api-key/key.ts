/**
 * API key format (lld/identity.md §4): `sk_live_` / `sk_test_` / `pk_…` / `rk_…` + 48 base62
 * characters (≈ 285 bits), shown once, stored as SHA-256. Pure.
 */
import { createHash, randomBytes } from "node:crypto";

export type KeyType = "secret" | "publishable" | "restricted";

const PREFIX: Record<KeyType, string> = { secret: "sk", publishable: "pk", restricted: "rk" };
const TYPE_OF: Record<string, KeyType> = { sk: "secret", pk: "publishable", rk: "restricted" };
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
export const KEY_BODY_LENGTH = 48;
export const KEY_RE = /^(sk|pk|rk)_(live|test)_([0-9A-Za-z]{48})$/;

/** Scopes publishable keys hold (lld/identity.md §6). */
export const PUBLISHABLE_SCOPES = ["checkout:public", "elements:public"] as const;

export function displayPrefix(type: KeyType, livemode: boolean): string {
  return `${PREFIX[type]}_${livemode ? "live" : "test"}_`;
}

/** Uniform base62 characters by rejection sampling (no modulo bias). */
export function randomBase62(n: number, random: (size: number) => Buffer = randomBytes): string {
  let out = "";
  while (out.length < n) {
    for (const b of random(n * 2)) {
      if (b < 248) out += BASE62[b % 62];
      if (out.length === n) break;
    }
  }
  return out;
}

export function generateKey(type: KeyType, livemode: boolean, random?: (size: number) => Buffer): string {
  return `${displayPrefix(type, livemode)}${randomBase62(KEY_BODY_LENGTH, random)}`;
}

/** Type and mode of a well-formed key, or null. */
export function parseKey(secret: string): { type: KeyType; livemode: boolean } | null {
  const m = KEY_RE.exec(secret);
  if (!m) return null;
  return { type: TYPE_OF[m[1] as string] as KeyType, livemode: m[2] === "live" };
}

export function keyHash(secret: string): Buffer {
  return createHash("sha256").update(secret, "utf8").digest();
}

export const last4 = (secret: string) => secret.slice(-4);

/** Whether `ip` is inside one of the CIDR ranges (empty list = any address). */
export function ipAllowed(ip: string | null, cidrs: readonly string[]): boolean {
  if (cidrs.length === 0) return true;
  if (!ip) return false;
  const addr = parseIp(ip);
  if (!addr) return false;
  return cidrs.some((c) => {
    const [base, bitsText] = c.split("/");
    const net = parseIp(base ?? "");
    if (!net || net.v !== addr.v) return false;
    const bits = bitsText === undefined ? (net.v === 4 ? 32 : 128) : Number(bitsText);
    const width = net.v === 4 ? 32 : 128;
    if (!Number.isInteger(bits) || bits < 0 || bits > width) return false;
    const shift = BigInt(width - bits);
    return addr.n >> shift === net.n >> shift;
  });
}

function parseIp(s: string): { v: 4 | 6; n: bigint } | null {
  const ip = s.trim().replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, "$1");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts.some((p) => p > 255)) return null;
    return { v: 4, n: parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n) };
  }
  if (!ip.includes(":") || !/^[0-9a-f:]+$/i.test(ip)) return null;
  const [head, tail, extra] = ip.split("::");
  if (extra !== undefined) return null;
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : null;
  const groups = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { v: 6, n: groups.reduce((acc, g) => (acc << 16n) | BigInt(Number.parseInt(g, 16)), 0n) };
}

// ---- restricted keys (Stage 2, lld/identity.md §6) ---------------------------------------------

/** `<resource>.read|write` scopes of the spec catalogue (`KEY_SCOPES`), passed in to keep this module pure. */
export type ScopeCatalogue = readonly string[];

export type ScopeCheck =
  | { readonly ok: true; readonly scopes: string[] }
  | {
      readonly ok: false;
      readonly error: "scope_unknown" | "invalid_request";
      readonly scope?: string;
      readonly reason: string;
    };

/**
 * Validates the scopes of a key being created or updated: restricted keys need ≥ 1 scope from the
 * catalogue (stored de-duplicated and sorted); secret and publishable keys take none.
 */
export function checkScopes(
  type: KeyType,
  scopes: readonly string[] | undefined,
  catalogue: ScopeCatalogue,
): ScopeCheck {
  if (type !== "restricted") {
    if (scopes !== undefined && scopes.length > 0)
      return { ok: false, error: "invalid_request", reason: "only restricted keys take scopes" };
    return { ok: true, scopes: [] };
  }
  if (!scopes || scopes.length === 0)
    return { ok: false, error: "invalid_request", reason: "restricted keys need at least one scope" };
  const unknown = scopes.find((s) => !catalogue.includes(s));
  if (unknown !== undefined) return { ok: false, error: "scope_unknown", scope: unknown, reason: "unknown scope" };
  return { ok: true, scopes: [...new Set(scopes)].sort() };
}

/**
 * Scopes a restricted key holds at the gateway: its own, plus `<resource>.read` for every
 * `<resource>.write` (write implies read). Only catalogue scopes survive (a stale stored scope that
 * left the catalogue grants nothing).
 */
export function expandScopes(scopes: readonly string[], catalogue: ScopeCatalogue): string[] {
  const out = new Set<string>();
  for (const s of scopes) {
    if (!catalogue.includes(s)) continue;
    out.add(s);
    if (s.endsWith(".write")) {
      const read = `${s.slice(0, -".write".length)}.read`;
      if (catalogue.includes(read)) out.add(read);
    }
  }
  return [...out].sort();
}

/**
 * Whether a restricted key with `held` (expanded) scopes may call a route with `auth` entries — the
 * same rule `@nearpay-internal/service` applies (`restricted_key:<scope>`), checked early at the gateway.
 */
export function restrictedAllows(auth: readonly string[], held: readonly string[]): boolean {
  return auth.some((a) => a.startsWith("restricted_key:") && held.includes(a.slice("restricted_key:".length)));
}
