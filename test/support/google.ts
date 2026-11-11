/**
 * A local stand-in for Google's OpenID Connect endpoints (ADR-0026 tests): a token endpoint that enforces
 * client id/secret, redirect URI, single-use codes and the S256 PKCE verifier, and a JWKS endpoint. The
 * "user at Google" step is `authorize()`: it reads the authorization URL identity built and mints a code
 * whose ID token carries the given claims (overridable to test every verification rule).
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";

export const GOOGLE_CLIENT_ID = "1234567890-test.apps.googleusercontent.com";
export const GOOGLE_CLIENT_SECRET = "GOCSPX-test-secret-not-real";
const KID = "test-key-1";

type Claims = Record<string, unknown>;

interface PendingCode {
  readonly challenge: string;
  readonly redirectUri: string;
  readonly clientId: string;
  readonly claims: Claims;
  readonly rogue: boolean;
  used: boolean;
}

export interface MockGoogle {
  readonly url: string;
  readonly endpoints: { authorization: string; token: string; jwks: string };
  /** Token endpoint requests (form fields), newest last. */
  readonly tokenRequests: Record<string, string>[];
  /** Fail the token endpoint with this HTTP status (null = normal). */
  failToken: number | null;
  /**
   * Plays the user approving at Google: returns the code and state for the callback. `claims` override the
   * ID token (`sub`, `email`, `email_verified`, `nonce`, `aud`, `iss`, `exp`, `iat`); `rogue` signs with a
   * key that is not in the JWKS (same `kid`).
   */
  authorize(
    authorizationUrl: string,
    user: { sub: string; email: string; claims?: Claims; rogue?: boolean },
  ): {
    code: string;
    state: string;
    params: URLSearchParams;
  };
  stop(): Promise<void>;
}

const s256 = (v: string) => createHash("sha256").update(v).digest("base64url");

export async function startMockGoogle(): Promise<MockGoogle> {
  const good = await generateKeyPair("RS256", { extractable: true });
  const rogue = await generateKeyPair("RS256", { extractable: true });
  const jwk: JWK = { ...(await exportJWK(good.publicKey)), kid: KID, alg: "RS256", use: "sig" };
  const codes = new Map<string, PendingCode>();
  const tokenRequests: Record<string, string>[] = [];
  const state = { failToken: null as number | null };

  const server: Server = createServer((req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method === "GET" && req.url === "/jwks") return send(200, { keys: [jwk] });
    if (req.method === "POST" && req.url === "/token") {
      let raw = "";
      req.on("data", (c) => {
        raw += c;
      });
      req.on("end", async () => {
        const f = Object.fromEntries(new URLSearchParams(raw));
        tokenRequests.push(f);
        if (state.failToken) return send(state.failToken, { error: "server_error" });
        const c = f.code ? codes.get(f.code) : undefined;
        if (f.grant_type !== "authorization_code") return send(400, { error: "unsupported_grant_type" });
        if (f.client_id !== GOOGLE_CLIENT_ID || f.client_secret !== GOOGLE_CLIENT_SECRET)
          return send(401, { error: "invalid_client" });
        if (!c || c.used) return send(400, { error: "invalid_grant" });
        c.used = true; // single use, like Google
        if (f.redirect_uri !== c.redirectUri) return send(400, { error: "redirect_uri_mismatch" });
        if (!f.code_verifier || s256(f.code_verifier) !== c.challenge) return send(400, { error: "invalid_grant" });
        const id_token = await new SignJWT(c.claims)
          .setProtectedHeader({ alg: "RS256", kid: KID, typ: "JWT" })
          .sign(c.rogue ? rogue.privateKey : good.privateKey);
        send(200, { access_token: "ya29.test", expires_in: 3599, token_type: "Bearer", scope: "openid", id_token });
      });
      return;
    }
    send(404, { error: "not_found" });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  const mock: MockGoogle = {
    url,
    endpoints: {
      authorization: "https://accounts.google.test/o/oauth2/v2/auth",
      token: `${url}/token`,
      jwks: `${url}/jwks`,
    },
    tokenRequests,
    get failToken() {
      return state.failToken;
    },
    set failToken(v) {
      state.failToken = v;
    },
    authorize(authorizationUrl, user) {
      const p = new URL(authorizationUrl).searchParams;
      const code = `4/0A${randomBytes(24).toString("base64url")}`;
      const now = Math.floor(Date.now() / 1000);
      codes.set(code, {
        challenge: p.get("code_challenge") ?? "",
        redirectUri: p.get("redirect_uri") ?? "",
        clientId: p.get("client_id") ?? "",
        claims: {
          iss: "https://accounts.google.com",
          azp: GOOGLE_CLIENT_ID,
          aud: GOOGLE_CLIENT_ID,
          sub: user.sub,
          email: user.email,
          email_verified: true,
          nonce: p.get("nonce"),
          iat: now,
          exp: now + 3600,
          name: "Test User",
          ...user.claims,
        },
        rogue: user.rogue === true,
        used: false,
      });
      return { code, state: p.get("state") ?? "", params: p };
    },
    stop: () => new Promise<void>((r) => server.close(() => r())),
  };
  return mock;
}
