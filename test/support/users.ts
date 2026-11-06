/** Drives the real sign-up and step-up flows through the gateway with a software passkey. */
import { sendMessage } from "@nearpay-internal/spec";
import { ORIGIN, RP_ID, type Stack } from "./stack.js";
import { type SoftPasskey, softPasskey } from "./webauthn.js";

export interface User {
  readonly email: string;
  readonly passkey: SoftPasskey;
  readonly cookie: string;
  readonly csrf: string;
  readonly userId: string;
  readonly accountId: string;
}

export function cookieOf(setCookie: string | string[] | undefined): string {
  const v = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  if (!v) throw new Error("no Set-Cookie");
  return v.split(";")[0] as string;
}

/** A distinct client IP per flow (anonymous routes are rate-limited per IP). */
export const freshIp = () => `198.51.100.${Math.floor(Math.random() * 250) + 1}`;

export async function magicToken(s: Stack, email: string, ip = freshIp()): Promise<string> {
  const r = await s.gateway("POST", "/v1/auth/signup", { body: { email, turnstile_token: "tok" }, ip });
  if (r.status !== 202) throw new Error(`signup ${r.status} ${JSON.stringify(r.body)}`);
  const call = s.notify
    .callsTo(sendMessage)
    .filter((c) => (c.body as { to: string }).to === email.toLowerCase())
    .at(-1);
  if (!call) throw new Error("no magic link was sent");
  const link = (call.body as { variables: { link_url: string } }).variables.link_url;
  return link.split("#token=")[1] as string;
}

export async function signUp(s: Stack, email: string, displayName = "Acme Test Shop"): Promise<User> {
  const token = await magicToken(s, email);
  const v = await s.gateway("POST", "/v1/auth/magic_links/verify", { body: { token } });
  const registration_token = v.body.registration_token as string;
  const opts = await s.gateway("POST", "/v1/auth/passkeys/registration/options", { body: { registration_token } });
  const passkey = softPasskey(RP_ID, ORIGIN);
  const r = await s.gateway("POST", "/v1/auth/passkeys/registration/verify", {
    body: {
      registration_token,
      credential: passkey.create(opts.body),
      display_name: displayName,
      passkey_name: "Laptop",
    },
  });
  if (r.status !== 200) throw new Error(`registration ${r.status} ${JSON.stringify(r.body)}`);
  return {
    email,
    passkey,
    cookie: cookieOf(r.headers["set-cookie"]),
    csrf: r.body.csrf_token,
    userId: r.body.user.id,
    accountId: r.body.account.id,
  };
}

/** A fresh step-up (10 minutes). */
export async function stepUp(s: Stack, u: User): Promise<void> {
  const o = await s.gateway("POST", "/v1/auth/step_up/options", { cookie: u.cookie, csrf: u.csrf, body: {} });
  const r = await s.gateway("POST", "/v1/auth/step_up/verify", {
    cookie: u.cookie,
    csrf: u.csrf,
    body: { credential: u.passkey.get(o.body) },
  });
  if (r.status !== 200) throw new Error(`step-up ${r.status} ${JSON.stringify(r.body)}`);
}

/** Session request helper (cookie + CSRF + mode). */
export const as = (u: User, mode: "test" | "live" = "test", body?: unknown) => ({
  cookie: u.cookie,
  csrf: u.csrf,
  mode,
  ...(body !== undefined ? { body } : {}),
});
