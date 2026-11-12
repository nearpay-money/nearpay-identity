/**
 * Google OpenID Connect client (ADR-0026, lld/identity.md §22): builds the authorization URL, exchanges
 * the code (PKCE verifier + client secret, server to server) and verifies the ID token with `jose` against
 * Google's JWKS (cached, refetched on an unknown `kid`). No Google SDK.
 */
import { createRemoteJWKSet, type JWTVerifyGetKey, jwtVerify } from "jose";
import {
  type ClaimCheck,
  checkIdTokenClaims,
  GOOGLE_ENDPOINTS,
  GOOGLE_ISSUERS,
  GOOGLE_PROMPT,
  GOOGLE_SCOPES,
} from "../../domain/google/google.js";

export interface GoogleEndpoints {
  readonly authorization: string;
  readonly token: string;
  readonly jwks: string;
}

export interface GoogleClientConfig {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly endpoints?: GoogleEndpoints;
  readonly fetch?: typeof fetch;
  /** Per call (token exchange, JWKS fetch); default 4 s — the callback's whole budget is 10 s. */
  readonly timeoutMs?: number;
  /** Tests: a local key set instead of the remote JWKS. */
  readonly keys?: JWTVerifyGetKey;
  readonly now?: () => number;
}

/** The code exchange failed because Google refused it (bad, used or foreign code, PKCE mismatch). */
export class GoogleRejected extends Error {}
/** Google could not be reached or answered with a server error. */
export class GoogleUnavailable extends Error {}

export interface GoogleOidc {
  readonly clientId: string;
  readonly redirectUri: string;
  /**
   * Always asks Google for the account chooser (`prompt=select_account`), for sign-in, sign-up and link:
   * otherwise a browser signed in to Google silently reuses the last account, and a user refused for that
   * account (e.g. `email_exists`) could never pick another one on retry.
   */
  authorizationUrl(p: { state: string; nonce: string; codeChallenge: string }): string;
  /** The ID token of an authorization code. */
  exchangeCode(code: string, codeVerifier: string): Promise<string>;
  /** Signature (JWKS, RS256), `iss`, `aud`, `exp`/`iat` (30 s tolerance), then the claim checks. */
  verifyIdToken(idToken: string, nonceHash: Buffer): Promise<ClaimCheck>;
}

export function googleOidc(c: GoogleClientConfig): GoogleOidc {
  const endpoints = c.endpoints ?? GOOGLE_ENDPOINTS;
  const f = c.fetch ?? fetch;
  const timeout = c.timeoutMs ?? 4_000;
  const keys =
    c.keys ??
    createRemoteJWKSet(new URL(endpoints.jwks), {
      cacheMaxAge: 10 * 60_000,
      cooldownDuration: 30_000,
      timeoutDuration: timeout,
    });
  return {
    clientId: c.clientId,
    redirectUri: c.redirectUri,
    authorizationUrl(p) {
      const u = new URL(endpoints.authorization);
      u.search = new URLSearchParams({
        response_type: "code",
        client_id: c.clientId,
        redirect_uri: c.redirectUri,
        scope: GOOGLE_SCOPES,
        state: p.state,
        nonce: p.nonce,
        code_challenge: p.codeChallenge,
        code_challenge_method: "S256",
        prompt: GOOGLE_PROMPT,
      }).toString();
      return u.toString();
    },
    async exchangeCode(code, codeVerifier) {
      let res: Response;
      try {
        res = await f(endpoints.token, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: c.redirectUri,
            client_id: c.clientId,
            client_secret: c.clientSecret,
            code_verifier: codeVerifier,
          }),
          signal: AbortSignal.timeout(timeout),
          redirect: "error",
        });
      } catch (e) {
        throw new GoogleUnavailable((e as Error).message);
      }
      if (res.status >= 500 || res.status === 429) throw new GoogleUnavailable(`token endpoint ${res.status}`);
      const body = (await res.json().catch(() => ({}))) as { id_token?: unknown; error?: unknown };
      if (!res.ok) throw new GoogleRejected(typeof body.error === "string" ? body.error.slice(0, 64) : `${res.status}`);
      if (typeof body.id_token !== "string" || body.id_token.length > 8192) throw new GoogleRejected("no id_token");
      return body.id_token;
    },
    async verifyIdToken(idToken, nonceHash) {
      let payload: Record<string, unknown>;
      try {
        ({ payload } = await jwtVerify(idToken, keys, {
          algorithms: ["RS256"],
          issuer: [...GOOGLE_ISSUERS],
          audience: c.clientId,
          clockTolerance: 30,
          requiredClaims: ["exp", "iat", "sub", "aud", "iss"],
          ...(c.now ? { currentDate: new Date(c.now()) } : {}),
        }));
      } catch (e) {
        const name = (e as { code?: string }).code ?? "";
        // a JWKS fetch failure (timeout, non-200, bad document, network error) is Google being unreachable,
        // not a bad token; every other jose error (signature, alg, iss, aud, exp, unknown kid) is a bad token
        if (!name || name === "ERR_JWKS_TIMEOUT" || name === "ERR_JOSE_GENERIC" || name === "ERR_JWKS_INVALID")
          throw new GoogleUnavailable(name || (e as Error).message);
        return { ok: false, error: "token_invalid", reason: name };
      }
      return checkIdTokenClaims(payload, { clientId: c.clientId, nonceHash });
    },
  };
}
