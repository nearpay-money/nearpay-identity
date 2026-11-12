/**
 * Continue with Google (ADR-0026, lld/identity.md §22). Pure rules: PKCE, the flow cookie, the claim
 * checks that follow the ID token's signature/iss/aud/exp verification, the sign-in and link decisions,
 * the passkey-setup window and where the callback sends the browser.
 *
 * A Google login is identified by the Google `sub` (a linked identity), never by the email alone: an
 * email that already has a NearPay user is never linked automatically (account-takeover risk).
 */
import { createHash, timingSafeEqual } from "node:crypto";
import {
  GOOGLE_FLOW_COOKIE,
  GOOGLE_FLOW_TTL_SECONDS,
  type GOOGLE_SIGNIN_ERRORS,
  PASSKEY_SETUP_WINDOW_SECONDS,
} from "@nearpay-money/spec";

export type GoogleSignInError = (typeof GOOGLE_SIGNIN_ERRORS)[number];

/** Issuers Google uses in ID tokens (OpenID Connect reference: both forms occur). */
export const GOOGLE_ISSUERS = ["https://accounts.google.com", "accounts.google.com"] as const;

/** Google's production endpoints (overridable only when NP_ENV is local/test, for the mock in tests). */
export const GOOGLE_ENDPOINTS = {
  authorization: "https://accounts.google.com/o/oauth2/v2/auth",
  token: "https://oauth2.googleapis.com/token",
  jwks: "https://www.googleapis.com/oauth2/v3/certs",
} as const;

export const GOOGLE_SCOPES = "openid email profile";
/**
 * Sent on every flow (sign-in, sign-up, link): Google shows its account chooser, so a user with several
 * Google accounts picks one each time instead of Google reusing the last one. Without it a refused
 * account (`email_exists`, `identity_in_use`, `email_unverified`) is selected again on every retry.
 */
export const GOOGLE_PROMPT = "select_account";
export const FLOW_MS = GOOGLE_FLOW_TTL_SECONDS * 1000;
export const PASSKEY_SETUP_MS = PASSKEY_SETUP_WINDOW_SECONDS * 1000;
/** Flow starts per client IP: 30 per 10 minutes (burst 30), before the gateway's anonymous limit. */
export const START_LIMIT = { rate: 30 / 600, burst: 30 } as const;

const b64url = (b: Buffer) => b.toString("base64url");
const sha = (s: string) => createHash("sha256").update(s, "utf8").digest();

/** RFC 7636 S256: BASE64URL(SHA256(ASCII(code_verifier))). */
export const pkceChallenge = (verifier: string): string => b64url(sha(verifier));

/** Constant-time comparison of a presented value with its stored SHA-256. */
export function sameHash(presented: unknown, hash: Buffer): boolean {
  if (typeof presented !== "string" || presented.length === 0 || presented.length > 512) return false;
  const h = sha(presented);
  return h.length === hash.length && timingSafeEqual(h, hash);
}

/** A same-origin dashboard path (`/x?y`), never `//host`, `/\host`, a scheme or whitespace. */
export function isSafeNext(next: string | null | undefined): next is string {
  return typeof next === "string" && next.length <= 512 && /^\/(?![/\\])[^\s\\]*$/.test(next);
}

/** The flow cookie: HttpOnly, Secure, SameSite=Lax (sent on Google's top-level redirect back), short-lived. */
export const flowCookie = (value: string, maxAgeSeconds = GOOGLE_FLOW_TTL_SECONDS) =>
  `${GOOGLE_FLOW_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
export const clearFlowCookie = () => `${GOOGLE_FLOW_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0`;

export interface GoogleIdentity {
  readonly sub: string;
  /** Lower-cased, trimmed. */
  readonly email: string;
}

export type ClaimCheck =
  | { readonly ok: true; readonly identity: GoogleIdentity }
  | {
      readonly ok: false;
      readonly error: Extract<GoogleSignInError, "token_invalid" | "email_unverified">;
      readonly reason: string;
    };

/**
 * Claim checks after the signature, `iss`, `aud`, `exp`/`iat` were verified: the `nonce` matches the flow,
 * `azp` (if present) is our client, a usable `sub`, and an email Google has verified (`email_verified ===
 * true`, strictly the boolean).
 */
export function checkIdTokenClaims(
  payload: Readonly<Record<string, unknown>>,
  expect: { readonly clientId: string; readonly nonceHash: Buffer },
): ClaimCheck {
  const bad = (reason: string): ClaimCheck => ({ ok: false, error: "token_invalid", reason });
  if (!sameHash(payload.nonce, expect.nonceHash)) return bad("nonce mismatch");
  if (payload.azp !== undefined && payload.azp !== expect.clientId) return bad("azp is another client");
  const sub = payload.sub;
  if (typeof sub !== "string" || !/^[\x21-\x7e]{1,255}$/.test(sub)) return bad("no usable sub");
  const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+$/.test(email)) return bad("no usable email");
  if (payload.email_verified !== true) return { ok: false, error: "email_unverified", reason: "email not verified" };
  return { ok: true, identity: { sub, email } };
}

export type SignInDecision = "sign_in" | "create" | "email_exists" | "account_disabled";

/**
 * Sign-in flow outcome: the user linked to the Google `sub` signs in (if active); with no link, a new
 * email creates a user and account; an email that already has a user is refused — never linked here.
 */
export function decideSignIn(o: {
  readonly linkedUser: { readonly status: string } | null;
  readonly emailUserExists: boolean;
}): SignInDecision {
  if (o.linkedUser) return o.linkedUser.status === "active" ? "sign_in" : "account_disabled";
  return o.emailUserExists ? "email_exists" : "create";
}

export type LinkDecision = "link" | "already_linked_same" | "identity_in_use" | "already_linked";

/** Link flow outcome for the signed-in user `userId`. */
export function decideLink(o: {
  readonly userId: string;
  /** User the Google `sub` is linked to, if any. */
  readonly subjectUserId: string | null;
  /** Subject of the user's current Google link, if any. */
  readonly userSubject: string | null;
}): LinkDecision {
  if (o.subjectUserId === o.userId) return "already_linked_same";
  if (o.subjectUserId !== null) return "identity_in_use";
  if (o.userSubject !== null) return "already_linked";
  return "link";
}

/**
 * Who may add a passkey from a session (ADR-0026): a user with a passkey after a fresh step-up (≤ 10 min,
 * passkey sign-in counts); a user without one (Google-only) only within 10 minutes of a Google sign-in.
 */
export function passkeyAddGate(o: {
  readonly passkeys: number;
  readonly stepUpAt: Date | null;
  readonly authMethod: string;
  readonly createdAt: Date;
  readonly now: number;
  readonly stepUpMs: number;
}): "ok" | "step_up_required" | "reauthentication_required" {
  if (o.passkeys > 0) return o.stepUpAt && o.now - o.stepUpAt.getTime() <= o.stepUpMs ? "ok" : "step_up_required";
  return passkeySetupUntil(o) ? "ok" : "reauthentication_required";
}

/** End of the first-passkey window of a Google session of a user without passkeys, or null. */
export function passkeySetupUntil(o: {
  readonly passkeys: number;
  readonly authMethod: string;
  readonly createdAt: Date;
  readonly now: number;
}): Date | null {
  if (o.passkeys > 0 || o.authMethod !== "google") return null;
  const until = o.createdAt.getTime() + PASSKEY_SETUP_MS;
  return until > o.now ? new Date(until) : null;
}

export type FlowPurpose = "signin" | "link";
export type FlowIntent = "signin" | "signup";

/**
 * Dashboard page for a failed flow (`?google_error=`). A sign-in page error keeps the flow's safe `next`
 * path, so a retry from that page still lands where the user was going.
 */
export function errorPath(
  purpose: FlowPurpose | null,
  intent: FlowIntent | null,
  error: GoogleSignInError,
  next: string | null = null,
): string {
  const page = purpose === "link" ? "/settings/account" : intent === "signup" ? "/signup" : "/signin";
  const keep = page === "/signin" && isSafeNext(next) ? `&next=${encodeURIComponent(next)}` : "";
  return `${page}?google_error=${error}${keep}`;
}

/** Dashboard page after success: new accounts go to onboarding, links back to settings. */
export function successPath(
  o: { purpose: "link" } | { purpose: "signin"; created: boolean; next: string | null },
): string {
  if (o.purpose === "link") return "/settings/account?google=linked";
  if (o.created) return "/setup";
  return isSafeNext(o.next) ? o.next : "/";
}
