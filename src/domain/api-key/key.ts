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
