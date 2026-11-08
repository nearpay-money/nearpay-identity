/**
 * Authz caches and the rate limiter (lld/identity.md §8.1): per-process LRU (keys 30 s, sessions and
 * accounts 10 s) in front of Valkey (keys 60 s) in front of Postgres; token buckets in Valkey with a
 * per-pod fallback at half the limits when Valkey is down (§14). A revoked key is purged from Valkey
 * and the local LRU at once and from other replicas' LRUs by `ctl.identity.cache.purge` (or ≤ 30 s).
 */
import { Redis } from "ioredis";
import { LRUCache } from "lru-cache";
import { type Bucket, type BucketState, degraded, takeToken } from "../domain/authz/authz.js";

export interface CachedKey {
  id: string;
  account_id: string;
  livemode: boolean;
  type: "secret" | "publishable" | "restricted";
  scopes: string[];
  ip_allowlist: string[];
  expires_at: number | null;
  revoked_at: number | null;
}

export interface AuthzCache {
  getKey(hashHex: string, load: () => Promise<CachedKey | null>): Promise<CachedKey | null>;
  /** Valkey + local LRU + broadcast to the other replicas. */
  purgeKey(hashHex: string): Promise<void>;
  /** Local session-cache eviction + broadcast (step-up, logout). */
  purgeSession(tokenHashHex: string): void;
  /** Applies a purge broadcast (`key:<hash>` / `session:<hash>`) to the local LRUs. */
  applyPurge(message: string): void;
  /** Where purges are broadcast (core NATS `ctl.identity.cache.purge`); unset = local only. */
  setBroadcast(fn: ((message: string) => void) | null): void;
  local<T extends object>(name: string, ttlMs: number): LRUCache<string, T>;
  take(key: string, bucket: Bucket, now: number): Promise<{ allowed: boolean; retryAfter: number }>;
  valkeyUp(): boolean;
  close(): Promise<void>;
}

/** Token bucket in one round trip; state is a hash {t: tokens, at: ms}. */
const BUCKET_LUA = `
local rate = tonumber(ARGV[1]); local burst = tonumber(ARGV[2]); local now = tonumber(ARGV[3])
local s = redis.call('HMGET', KEYS[1], 't', 'at')
local tokens = tonumber(s[1]) or burst; local at = tonumber(s[2]) or now
tokens = math.min(burst, tokens + ((now - at) / 1000) * rate)
local allowed = 0; local retry = 0
if tokens >= 1 then tokens = tokens - 1; allowed = 1 else retry = math.ceil((1 - tokens) / rate) end
redis.call('HSET', KEYS[1], 't', tokens, 'at', now)
redis.call('PEXPIRE', KEYS[1], math.ceil(burst / rate * 1000) + 1000)
return {allowed, retry}`;

export function createAuthzCache(o: { valkeyUrl: string | null; keyTtlMs?: number }): AuthzCache {
  const keys = new LRUCache<string, { v: CachedKey | null }>({ max: 50_000, ttl: o.keyTtlMs ?? 30_000 });
  const buckets = new LRUCache<string, BucketState>({ max: 100_000, ttl: 60_000 });
  const locals = new Map<string, LRUCache<string, object>>();
  const redis = o.valkeyUrl
    ? new Redis(o.valkeyUrl, {
        lazyConnect: false,
        enableOfflineQueue: false,
        maxRetriesPerRequest: 0,
        connectTimeout: 1_000,
        commandTimeout: 250,
      })
    : null;
  redis?.on("error", () => {}); // state is read from redis.status; errors fall back per call
  const up = () => redis?.status === "ready";
  let broadcast: ((message: string) => void) | null = null;

  return {
    async getKey(hashHex, load) {
      const hit = keys.get(hashHex);
      if (hit) return hit.v;
      if (up()) {
        try {
          const raw = await (redis as Redis).get(`ak:${hashHex}`);
          if (raw) {
            const v = JSON.parse(raw) as CachedKey;
            keys.set(hashHex, { v });
            return v;
          }
        } catch {}
      }
      const v = await load();
      // negative results are not cached: a new key works at once
      if (v) {
        keys.set(hashHex, { v });
        if (up()) await (redis as Redis).set(`ak:${hashHex}`, JSON.stringify(v), "PX", 60_000).catch(() => {});
      }
      return v;
    },
    async purgeKey(hashHex) {
      keys.delete(hashHex);
      if (up()) await (redis as Redis).del(`ak:${hashHex}`).catch(() => {});
      broadcast?.(`key:${hashHex}`);
    },
    purgeSession(tokenHashHex) {
      locals.get("sessions")?.delete(tokenHashHex);
      broadcast?.(`session:${tokenHashHex}`);
    },
    applyPurge(message) {
      const [kind, hash] = message.split(":");
      if (!hash || !/^[0-9a-f]{64}$/.test(hash)) return;
      if (kind === "key") keys.delete(hash);
      if (kind === "session") locals.get("sessions")?.delete(hash);
    },
    setBroadcast(fn) {
      broadcast = fn;
    },
    local<T extends object>(name: string, ttlMs: number) {
      let c = locals.get(name);
      if (!c) {
        c = new LRUCache<string, object>({ max: 50_000, ttl: ttlMs });
        locals.set(name, c);
      }
      return c as unknown as LRUCache<string, T>;
    },
    async take(key, bucket, now) {
      if (up()) {
        try {
          const [allowed, retry] = (await (redis as Redis).eval(
            BUCKET_LUA,
            1,
            `rl:${key}`,
            bucket.rate,
            bucket.burst,
            now,
          )) as [number, number];
          return { allowed: allowed === 1, retryAfter: retry };
        } catch {}
      }
      const d = degraded(bucket);
      const r = takeToken(buckets.get(key), d, now);
      // keep the state until the bucket would be full again (slow buckets, e.g. 10 per 10 min, outlive 60 s)
      buckets.set(key, r.state, { ttl: Math.max(60_000, Math.ceil((d.burst / d.rate) * 1000) + 1000) });
      return { allowed: r.allowed, retryAfter: r.retryAfter };
    },
    valkeyUp: up,
    async close() {
      redis?.disconnect();
    },
  };
}
