/**
 * Console sign-in through Cloudflare Access (lld/identity.md §6.1 "Console auth mode: Cloudflare
 * Access"; `NP_OPS_AUTH_MODE=cloudflare_access`, default `passkey`).
 *
 * Cloudflare Access (Google login, owner allow-list) sits in front of the console host and forwards every
 * request with `Cf-Access-Jwt-Assertion`. Identity trusts that header only after verifying the JWT: RS256,
 * `aud` = `NP_CF_ACCESS_AUD`, `iss` = `https://<NP_CF_ACCESS_TEAM_DOMAIN>`, `exp`/`nbf`, keys from
 * `https://<team>/cdn-cgi/access/certs` (cached, refetched on an unknown `kid`, so key rotation is
 * followed). The verified `email` maps to an enrolled operator (enrolled by email, `operator-add`); a
 * request without a valid assertion is refused, even from inside the network (no cookie session, no
 * anonymous console route in this mode).
 *
 * "Fresh re-authentication" for step-up routes = the Access token's `iat` within the last 5 minutes:
 * `step_up_until = iat + 300` and `ops_auth_at = iat`. The console sends the operator through
 * `/cdn-cgi/access/logout` and back to sign in again with Google.
 *
 * CSRF: Access authenticates by cookie, so unsafe requests carry `X-CSRF-Token` =
 * HMAC-SHA256(key, `<operator>:<iat>`) — returned by `getOpsSession`, bound to the Access login.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, type JWTVerifyGetKey, jwtVerify } from "jose";

/** Access tokens younger than this count as a fresh re-authentication (step-up). */
export const ACCESS_REAUTH_S = 300;
/** Where the console sends an operator to sign in again (then back to the console). */
export const ACCESS_REAUTH_URL = "/cdn-cgi/access/logout";
export const ACCESS_HEADER = "cf-access-jwt-assertion";

export interface AccessVerifier {
  readonly audience: string;
  /** `https://<team domain>` */
  readonly issuer: string;
  readonly keys: JWTVerifyGetKey;
  /** HMAC key of the console CSRF token in this mode. */
  readonly csrfKey: Buffer;
}

export interface AccessIdentity {
  readonly email: string;
  /** Unix seconds of the Google/Access login. */
  readonly iat: number;
  readonly exp: number;
}

/** `nearpay.cloudflareaccess.com` (an `https://` prefix or trailing slash is tolerated). */
export function normalizeTeamDomain(v: string): string {
  const d = v
    .trim()
    .replace(/^https:\/\//i, "")
    .replace(/\/+$/, "")
    .toLowerCase();
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) throw new Error(`NP_CF_ACCESS_TEAM_DOMAIN: not a host name: ${v}`);
  return d;
}

export function accessVerifier(o: {
  teamDomain: string;
  audience: string;
  csrfKey: Buffer;
  keys?: JWTVerifyGetKey;
}): AccessVerifier {
  const team = normalizeTeamDomain(o.teamDomain);
  return {
    audience: o.audience,
    issuer: `https://${team}`,
    keys:
      o.keys ??
      createRemoteJWKSet(new URL(`https://${team}/cdn-cgi/access/certs`), {
        cacheMaxAge: 10 * 60_000,
        cooldownDuration: 30_000,
        timeoutDuration: 5_000,
      }),
    csrfKey: o.csrfKey,
  };
}

/** The verified Access identity of a request, or null (missing, malformed, wrong key/aud/iss, expired). */
export async function verifyAccess(
  v: AccessVerifier,
  assertion: string | undefined,
  nowS: number,
): Promise<AccessIdentity | null> {
  if (!assertion || assertion.length > 8192) return null;
  try {
    const { payload } = await jwtVerify(assertion, v.keys, {
      algorithms: ["RS256"],
      audience: v.audience,
      issuer: v.issuer,
      currentDate: new Date(nowS * 1000),
      clockTolerance: 30,
      requiredClaims: ["exp", "iat", "email"],
    });
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    if (!email.includes("@") || typeof payload.iat !== "number" || typeof payload.exp !== "number") return null;
    // a token "issued" in the future is not a fresh login
    if (payload.iat > nowS + 30) return null;
    return { email, iat: Math.floor(payload.iat), exp: Math.floor(payload.exp) };
  } catch {
    return null;
  }
}

export function accessCsrf(v: AccessVerifier, operatorId: string, iat: number): string {
  return createHmac("sha256", v.csrfKey).update(`ops-access-csrf:${operatorId}:${iat}`).digest("base64url");
}

export function accessCsrfValid(v: AccessVerifier, operatorId: string, iat: number, presented: string | undefined) {
  if (!presented) return false;
  const want = Buffer.from(accessCsrf(v, operatorId, iat));
  const got = Buffer.from(presented);
  return want.length === got.length && timingSafeEqual(want, got);
}

/** Step-up freshness of an Access login: `iat + 5 min`, or none once older. */
export function accessStepUpUntil(iat: number, nowS: number): number | undefined {
  return iat + ACCESS_REAUTH_S > nowS ? iat + ACCESS_REAUTH_S : undefined;
}

/** Derives the CSRF key from the PII KEK (domain-separated; never used for anything else). */
export function deriveCsrfKey(kek: Buffer): Buffer {
  return createHmac("sha256", kek).update("nearpay/identity/ops-access-csrf/v1").digest();
}
