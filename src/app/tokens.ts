/**
 * Internal JWTs (foundations §9, lld/identity.md §8.1, §9): identity signs request tokens (60 s),
 * service tokens (5 min) and its own outbound service token with the current key; JWKS publishes
 * current + next. Kid = `local-` + 12 hex of SHA-256 of the raw public key (step 1.1 wiring).
 */
import { createHash, createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { type ClaimsInput, loadSigningKey, publicJwk, type SigningKey, signInternalJwt } from "@nearpay-internal/auth";
import { SERVICE_CLIENT_SCOPES, SERVICES, type ServiceName, TOKEN_TTL_SECONDS } from "@nearpay-money/spec";

export interface Signer {
  readonly current: SigningKey;
  readonly next: SigningKey;
  sign(claims: ClaimsInput, ttlSeconds?: number): Promise<string>;
  jwks(): Promise<{ keys: Awaited<ReturnType<typeof publicJwk>>[] }>;
  /** identity's own service token (it is the issuer: no round trip). */
  serviceToken(): Promise<string>;
}

export function kidOf(pem: string): string {
  const jwk = createPublicKey(createPrivateKey(pem)).export({ format: "jwk" }) as { x: string };
  return `local-${createHash("sha256").update(Buffer.from(jwk.x, "base64url")).digest("hex").slice(0, 12)}`;
}

/** Loads `current.pem` and `next.pem`; a missing or invalid key file fails startup (§14). */
export function loadSigner(dir: string): Signer {
  const read = (f: string) => readFileSync(join(dir, f), "utf8");
  const pems = { current: read("current.pem"), next: read("next.pem") };
  return signerFrom(loadSigningKey(kidOf(pems.current), pems.current), loadSigningKey(kidOf(pems.next), pems.next));
}

export function signerFrom(current: SigningKey, next: SigningKey): Signer {
  let cached: { token: string; until: number } | null = null;
  const signer: Signer = {
    current,
    next,
    sign: (claims, ttl = TOKEN_TTL_SECONDS.request) => signInternalJwt(claims, current, ttl),
    jwks: async () => ({ keys: await Promise.all([publicJwk(current), publicJwk(next)]) }),
    async serviceToken() {
      const now = Math.floor(Date.now() / 1000);
      if (cached && now < cached.until) return cached.token;
      const token = await signInternalJwt(
        { sub: "identity", ptype: "service", scp: [...SERVICE_CLIENT_SCOPES.identity] },
        current,
        TOKEN_TTL_SECONDS.service,
      );
      cached = { token, until: now + TOKEN_TTL_SECONDS.service - TOKEN_TTL_SECONDS.serviceRefreshBefore };
      return token;
    },
  };
  return signer;
}

/** client_id → SHA-256 of its secret (NP_SERVICE_CLIENTS_FILE); unknown clients are dropped. */
export function loadServiceClients(file: string): Map<ServiceName, Buffer> {
  const doc = JSON.parse(readFileSync(file, "utf8")) as { clients?: { client_id: string; secret_sha256: string }[] };
  const out = new Map<ServiceName, Buffer>();
  for (const c of doc.clients ?? []) {
    if (!(SERVICES as readonly string[]).includes(c.client_id) || !/^[0-9a-f]{64}$/.test(c.secret_sha256)) continue;
    out.set(c.client_id as ServiceName, Buffer.from(c.secret_sha256, "hex"));
  }
  return out;
}

/** Verifies HTTP Basic client credentials; returns the client or null. */
export function authenticateClient(
  clients: ReadonlyMap<ServiceName, Buffer>,
  authorization: string | undefined,
): ServiceName | null {
  const m = /^Basic ([A-Za-z0-9+/=]+)$/.exec(authorization?.trim() ?? "");
  if (!m) return null;
  const decoded = Buffer.from(m[1] as string, "base64").toString("utf8");
  const i = decoded.indexOf(":");
  if (i <= 0) return null;
  const id = decoded.slice(0, i) as ServiceName;
  const expected = clients.get(id);
  const presented = createHash("sha256")
    .update(decoded.slice(i + 1))
    .digest();
  // compare even for unknown clients (no timing oracle on client ids)
  const ok = timingSafeEqual(presented, expected ?? Buffer.alloc(32));
  return ok && expected ? id : null;
}
