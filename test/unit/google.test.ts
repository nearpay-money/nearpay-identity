/** Continue with Google: pure rules, configuration and the OIDC client (ADR-0026, lld/identity.md §22). */
import { createHash } from "node:crypto";
import { createLocalJWKSet, exportJWK, generateKeyPair, type JWK, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { googleSettings } from "../../src/config.js";
import {
  checkIdTokenClaims,
  clearFlowCookie,
  decideLink,
  decideSignIn,
  errorPath,
  flowCookie,
  isSafeNext,
  passkeyAddGate,
  passkeySetupUntil,
  pkceChallenge,
  sameHash,
  successPath,
} from "../../src/domain/google/google.js";
import { GoogleRejected, GoogleUnavailable, googleOidc } from "../../src/infra/clients/google.js";

const sha = (s: string) => createHash("sha256").update(s).digest();
const CLIENT = "123-abc.apps.googleusercontent.com";

describe("PKCE and hashes", () => {
  it("S256 matches RFC 7636 appendix B", () => {
    expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
  });
  it("sameHash is strict about type and length", () => {
    expect(sameHash("n", sha("n"))).toBe(true);
    expect(sameHash("m", sha("n"))).toBe(false);
    expect(sameHash(undefined, sha("n"))).toBe(false);
    expect(sameHash("", sha(""))).toBe(false);
    expect(sameHash("x".repeat(513), sha("x".repeat(513)))).toBe(false);
    expect(sameHash("n", Buffer.alloc(3))).toBe(false);
  });
});

describe("next paths and cookies", () => {
  it.each([
    ["/", true],
    ["/payments?status=succeeded", true],
    ["//evil.test", false],
    ["/\\evil.test", false],
    ["https://evil.test", false],
    ["payments", false],
    ["/a b", false],
    [null, false],
    [`/${"a".repeat(512)}`, false],
  ])("%s → %s", (next, ok) => expect(isSafeNext(next as string | null)).toBe(ok));

  it("flow cookie: __Host-, HttpOnly, Secure, SameSite=Lax, 10 minutes", () => {
    expect(flowCookie("v")).toBe("__Host-np_google=v; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600");
    expect(clearFlowCookie()).toMatch(/Max-Age=0$/);
  });
});

describe("ID token claim checks", () => {
  const base = { sub: "1098", email: "Ana@Gmail.com ", email_verified: true, nonce: "n1", azp: CLIENT };
  const check = (p: Record<string, unknown>) => checkIdTokenClaims(p, { clientId: CLIENT, nonceHash: sha("n1") });
  it("accepts and normalises", () => {
    expect(check(base)).toEqual({ ok: true, identity: { sub: "1098", email: "ana@gmail.com" } });
    const { azp: _azp, ...noAzp } = base;
    expect(check(noAzp).ok).toBe(true);
  });
  it.each([
    ["nonce", { nonce: "other" }, "token_invalid"],
    ["missing nonce", { nonce: undefined }, "token_invalid"],
    ["azp", { azp: "x" }, "token_invalid"],
    ["sub", { sub: "" }, "token_invalid"],
    ["sub type", { sub: 5 }, "token_invalid"],
    ["email", { email: "nope" }, "token_invalid"],
    ["email type", { email: 7 }, "token_invalid"],
    ["long email", { email: `${"a".repeat(250)}@b.co` }, "token_invalid"],
    ["unverified", { email_verified: false }, "email_unverified"],
    ["verified as string", { email_verified: "true" }, "email_unverified"],
    ["verified missing", { email_verified: undefined }, "email_unverified"],
  ])("%s", (_n, over, error) => {
    const r = check({ ...base, ...over });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe(error);
  });
});

describe("decisions", () => {
  it("sign-in: linked user, new email, existing email (never auto-linked), disabled", () => {
    expect(decideSignIn({ linkedUser: { status: "active" }, emailUserExists: true })).toBe("sign_in");
    expect(decideSignIn({ linkedUser: { status: "disabled" }, emailUserExists: false })).toBe("account_disabled");
    expect(decideSignIn({ linkedUser: null, emailUserExists: true })).toBe("email_exists");
    expect(decideSignIn({ linkedUser: null, emailUserExists: false })).toBe("create");
  });
  it("link", () => {
    expect(decideLink({ userId: "u", subjectUserId: null, userSubject: null })).toBe("link");
    expect(decideLink({ userId: "u", subjectUserId: "u", userSubject: "s" })).toBe("already_linked_same");
    expect(decideLink({ userId: "u", subjectUserId: "v", userSubject: null })).toBe("identity_in_use");
    expect(decideLink({ userId: "u", subjectUserId: null, userSubject: "s" })).toBe("already_linked");
  });
  it("adding a passkey: step-up for passkey users, fresh Google sign-in for Google-only users", () => {
    const now = Date.UTC(2026, 10, 11, 12);
    const g = { authMethod: "google", createdAt: new Date(now - 60_000), now, stepUpMs: 600_000 };
    expect(passkeyAddGate({ ...g, passkeys: 1, stepUpAt: new Date(now - 1000) })).toBe("ok");
    expect(passkeyAddGate({ ...g, passkeys: 1, stepUpAt: null })).toBe("step_up_required");
    expect(passkeyAddGate({ ...g, passkeys: 1, stepUpAt: new Date(now - 700_000) })).toBe("step_up_required");
    expect(passkeyAddGate({ ...g, passkeys: 0, stepUpAt: null })).toBe("ok");
    expect(passkeyAddGate({ ...g, passkeys: 0, stepUpAt: null, createdAt: new Date(now - 601_000) })).toBe(
      "reauthentication_required",
    );
    expect(passkeyAddGate({ ...g, passkeys: 0, stepUpAt: null, authMethod: "recovery" })).toBe(
      "reauthentication_required",
    );
    expect(passkeySetupUntil({ passkeys: 0, authMethod: "google", createdAt: new Date(now), now })?.getTime()).toBe(
      now + 600_000,
    );
    expect(passkeySetupUntil({ passkeys: 2, authMethod: "google", createdAt: new Date(now), now })).toBeNull();
  });
  it("redirect targets", () => {
    expect(errorPath(null, null, "disabled")).toBe("/signin?google_error=disabled");
    expect(errorPath("signin", "signup", "email_exists")).toBe("/signup?google_error=email_exists");
    expect(errorPath("link", null, "identity_in_use")).toBe("/settings/account?google_error=identity_in_use");
    expect(successPath({ purpose: "link" })).toBe("/settings/account?google=linked");
    expect(successPath({ purpose: "signin", created: true, next: "/x" })).toBe("/setup");
    expect(successPath({ purpose: "signin", created: false, next: "/x?y=1" })).toBe("/x?y=1");
    expect(successPath({ purpose: "signin", created: false, next: "//evil" })).toBe("/");
    expect(successPath({ purpose: "signin", created: false, next: null })).toBe("/");
  });
});

describe("configuration", () => {
  const c = {
    env: "server" as "server" | "test" | "local",
    dashboardOrigin: "https://dashboard.nearpay.money/",
    googleClientId: "",
    googleClientSecret: undefined as string | undefined,
    googleAuthorizationUrl: undefined as string | undefined,
    googleTokenUrl: undefined as string | undefined,
    googleJwksUrl: undefined as string | undefined,
  };
  it("off without a client; off (not a crash) with only one half", () => {
    expect(googleSettings(c).settings).toBeNull();
    expect(googleSettings({ ...c, googleClientId: CLIENT }).reason).toMatch(/secret file is absent or empty/);
    expect(googleSettings({ ...c, googleClientId: CLIENT, googleClientSecret: "  " }).settings).toBeNull();
    expect(googleSettings({ ...c, googleClientSecret: "s" }).reason).toMatch(/NP_GOOGLE_CLIENT_ID is empty/);
  });
  it("on with both; redirect URI on the dashboard origin", () => {
    const r = googleSettings({ ...c, googleClientId: ` ${CLIENT} `, googleClientSecret: "GOCSPX-x\n" });
    expect(r.settings).toEqual({
      clientId: CLIENT,
      clientSecret: "GOCSPX-x",
      redirectUri: "https://dashboard.nearpay.money/api/auth/google/callback",
      endpoints: null,
    });
  });
  it("endpoint overrides only for local/test, all or none; a malformed client id fails", () => {
    const o = { googleAuthorizationUrl: "http://a", googleTokenUrl: "http://t", googleJwksUrl: "http://j" };
    expect(() => googleSettings({ ...c, ...o })).toThrow(/local\/test/);
    expect(() => googleSettings({ ...c, env: "test" as const, googleTokenUrl: "http://t" })).toThrow(/all of/);
    const t = googleSettings({ ...c, ...o, env: "test" as const, googleClientId: CLIENT, googleClientSecret: "s" });
    expect(t.settings?.endpoints).toEqual({ authorization: "http://a", token: "http://t", jwks: "http://j" });
    expect(() => googleSettings({ ...c, googleClientId: "bad id", googleClientSecret: "s" })).toThrow(/client id/);
  });
});

describe("OIDC client", () => {
  async function keys() {
    const k = await generateKeyPair("RS256", { extractable: true });
    const jwk: JWK = { ...(await exportJWK(k.publicKey)), kid: "k1", alg: "RS256" };
    return { k, jwks: createLocalJWKSet({ keys: [jwk] }) };
  }
  const token = (key: CryptoKey, claims: Record<string, unknown>, alg = "RS256") =>
    new SignJWT(claims).setProtectedHeader({ alg, kid: "k1" }).sign(key);
  const now = () => Math.floor(Date.now() / 1000);
  const claims = () => ({
    iss: "https://accounts.google.com",
    aud: CLIENT,
    sub: "1",
    email: "a@b.co",
    email_verified: true,
    nonce: "n",
    iat: now(),
    exp: now() + 600,
  });

  it("builds the authorization URL", async () => {
    const c = googleOidc({
      clientId: CLIENT,
      clientSecret: "s",
      redirectUri: "https://d/cb",
      keys: (await keys()).jwks,
    });
    const u = new URL(c.authorizationUrl({ state: "st", nonce: "no", codeChallenge: "ch", selectAccount: true }));
    expect(u.origin + u.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(Object.fromEntries(u.searchParams)).toEqual({
      response_type: "code",
      client_id: CLIENT,
      redirect_uri: "https://d/cb",
      scope: "openid email profile",
      state: "st",
      nonce: "no",
      code_challenge: "ch",
      code_challenge_method: "S256",
      prompt: "select_account",
    });
    expect(new URL(c.authorizationUrl({ state: "a", nonce: "b", codeChallenge: "c" })).searchParams.has("prompt")).toBe(
      false,
    );
  });

  it("verifies signature, iss, aud, exp and the nonce", async () => {
    const { k, jwks } = await keys();
    const c = googleOidc({ clientId: CLIENT, clientSecret: "s", redirectUri: "https://d/cb", keys: jwks });
    expect(await c.verifyIdToken(await token(k.privateKey, claims()), sha("n"))).toMatchObject({ ok: true });
    for (const bad of [{ aud: "x" }, { iss: "https://evil" }, { exp: now() - 120, iat: now() - 600 }, { nonce: "z" }])
      expect((await c.verifyIdToken(await token(k.privateKey, { ...claims(), ...bad }), sha("n"))).ok).toBe(false);
    const other = await keys();
    expect((await c.verifyIdToken(await token(other.k.privateKey, claims()), sha("n"))).ok).toBe(false);
    expect((await c.verifyIdToken("not.a.jwt", sha("n"))).ok).toBe(false);
  });

  it("an unreachable JWKS is 'unavailable', not a bad token", async () => {
    const { k } = await keys();
    const failing = async () => {
      throw new TypeError("fetch failed");
    };
    const c = googleOidc({ clientId: CLIENT, clientSecret: "s", redirectUri: "https://d/cb", keys: failing });
    await expect(c.verifyIdToken(await token(k.privateKey, claims()), sha("n"))).rejects.toBeInstanceOf(
      GoogleUnavailable,
    );
  });

  it("code exchange: form fields, Google refusals and outages", async () => {
    const seen: URLSearchParams[] = [];
    let answer: () => Response = () => Response.json({ id_token: "eyJ" });
    const f = (async (_u: string, init: RequestInit) => {
      seen.push(new URLSearchParams(init.body as URLSearchParams));
      return answer();
    }) as unknown as typeof fetch;
    const c = googleOidc({
      clientId: CLIENT,
      clientSecret: "sec",
      redirectUri: "https://d/cb",
      fetch: f,
      keys: (await keys()).jwks,
    });
    expect(await c.exchangeCode("code1", "verifier1")).toBe("eyJ");
    expect(Object.fromEntries(seen[0] as URLSearchParams)).toEqual({
      grant_type: "authorization_code",
      code: "code1",
      redirect_uri: "https://d/cb",
      client_id: CLIENT,
      client_secret: "sec",
      code_verifier: "verifier1",
    });
    answer = () => Response.json({ error: "invalid_grant" }, { status: 400 });
    await expect(c.exchangeCode("c", "v")).rejects.toBeInstanceOf(GoogleRejected);
    answer = () => Response.json({}, { status: 200 });
    await expect(c.exchangeCode("c", "v")).rejects.toBeInstanceOf(GoogleRejected);
    answer = () => new Response("oops", { status: 502 });
    await expect(c.exchangeCode("c", "v")).rejects.toBeInstanceOf(GoogleUnavailable);
    answer = () => {
      throw new TypeError("network");
    };
    await expect(c.exchangeCode("c", "v")).rejects.toBeInstanceOf(GoogleUnavailable);
  });
});
