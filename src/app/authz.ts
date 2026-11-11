/**
 * `GET /internal/authz` — Traefik ForwardAuth (lld/identity.md §8.1). Authenticates the request
 * (API key, dashboard/console session, or anonymous on open routes), enforces CSRF, suspension,
 * live-mode gating and rate limits, and mints the 60-second request token the routed service
 * verifies. Route-level authorization (scopes, roles, step-up) stays in each service, from the spec.
 */

import type { ClaimsInput } from "@nearpay-internal/auth";
import { fromUuid, isId, newId } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { OPS_ROUTES } from "@nearpay-internal/spec";
import { KEY_SCOPES, OPS_ROLE_SCOPES, type OpsRole, PUBLIC_ROUTES } from "@nearpay-money/spec";
import {
  expandScopes,
  ipAllowed,
  keyHash,
  PUBLISHABLE_SCOPES,
  parseKey,
  restrictedAllows,
} from "../domain/api-key/key.js";
import {
  anonymousAllowed,
  clientIp,
  isConsoleHost,
  isConsolePath,
  isUnsafe,
  publishableAllowed,
  RATE_LIMITS,
  type RateClass,
  type RouteRef,
  requiresLiveEnabled,
  routeMatcher,
  sessionMode,
} from "../domain/authz/authz.js";
import {
  matchesHash,
  OPS_COOKIE,
  readCookie,
  SESSION_COOKIE,
  sessionState,
  sha256,
  stepUpUntil,
  TOUCH_EVERY_MS,
} from "../domain/session/session.js";
import type { CachedKey } from "../infra/cache.js";
import { accessCsrfValid, accessStepUpUntil, verifyAccess } from "./console-access.js";
import { accessMode, type Identity } from "./context.js";
import { activeAdminCount, activeOperatorByEmail } from "./operators.js";

const match = routeMatcher(PUBLIC_ROUTES as readonly RouteRef[]);
/** Console host: only `/ops/*` routes (spec `OPS_ROUTES`) are routed there (§8.1 step 3). */
const matchOps = routeMatcher(OPS_ROUTES as readonly RouteRef[]);

/** Request-token claims; `ops_role` (spec 0.2.0 `InternalTokenClaims`) rides along for ops principals. */
export type MintedClaims = ClaimsInput & {
  ops_role?: OpsRole;
  /** Adaptive two-person rule (app/operators.ts): active `ops_admin` operators now. */
  ops_admins?: number;
  /** Unix seconds of the operator's last user verification (passkey step-up/sign-in, or Access login). */
  ops_auth_at?: number;
};

export interface AuthzHeaders {
  method?: string | undefined;
  uri?: string | undefined;
  host?: string | undefined;
  authorization?: string | undefined;
  cookie?: string | undefined;
  csrf?: string | undefined;
  mode?: string | undefined;
  requestId?: string | undefined;
  xForwardedFor?: string | undefined;
  /** TCP peer of identity (the gateway); forwarding headers count only from a trusted proxy. */
  peer?: string | undefined;
  cfConnectingIp?: string | undefined;
  /** `Cf-Access-Jwt-Assertion` (console host, `NP_OPS_AUTH_MODE=cloudflare_access`). */
  cfAccessJwt?: string | undefined;
}

interface AccountState {
  status: string;
  live_enabled: boolean;
  kyb_status: string;
}

interface SessionRecord {
  id: string;
  kind: "dashboard" | "ops";
  user_id: string;
  account_id: string | null;
  csrf_hash: Buffer;
  step_up_at: number | null;
  expires_at: number;
  last_seen_at: number;
  revoked_at: number | null;
  role: string | null;
  operator: OpsRole | null;
}

/** Batched `last_used_at` / `last_seen_at` writes (at most once a minute per key or session). */
export function touches(id: Identity) {
  const keys = new Map<string, number>();
  const sessions = new Map<string, number>();
  const seen = id.cache.local<{ at: number }>("touched", TOUCH_EVERY_MS);
  return {
    key(keyId: string, now: number) {
      if (seen.has(`k:${keyId}`)) return;
      seen.set(`k:${keyId}`, { at: now });
      keys.set(keyId, now);
    },
    session(sessionId: string, now: number) {
      if (seen.has(`s:${sessionId}`)) return;
      seen.set(`s:${sessionId}`, { at: now });
      sessions.set(sessionId, now);
    },
    async flush() {
      const k = [...keys];
      const s = [...sessions];
      keys.clear();
      sessions.clear();
      for (const [kid, at] of k)
        await id.db
          .updateTable("api_keys")
          .set({ last_used_at: new Date(at) })
          .where("id", "=", kid)
          .execute();
      for (const [sid, at] of s)
        await id.db
          .updateTable("sessions")
          .set({ last_seen_at: new Date(at) })
          .where("id", "=", sid)
          .where("revoked_at", "is", null)
          .execute();
    },
  };
}

export type Touches = ReturnType<typeof touches>;

async function accountState(id: Identity, accountUuid: string): Promise<AccountState> {
  const cache = id.cache.local<AccountState>("accounts", 10_000);
  const hit = cache.get(accountUuid);
  if (hit) return hit;
  const a = await id.db
    .selectFrom("accounts")
    .select(["status", "live_enabled", "kyb_status"])
    .where("id", "=", accountUuid)
    .executeTakeFirst();
  const v = a ?? { status: "closed", live_enabled: false, kyb_status: "not_started" };
  cache.set(accountUuid, v);
  return v;
}

async function keyRecord(id: Identity, secret: string): Promise<CachedKey | null> {
  const hash = keyHash(secret).toString("hex");
  return id.cache.getKey(hash, async () => {
    const k = await id.db
      .selectFrom("api_keys")
      .select(["id", "account_id", "livemode", "type", "scopes", "ip_allowlist", "expires_at", "revoked_at"])
      .where("key_hash", "=", Buffer.from(hash, "hex"))
      .executeTakeFirst();
    if (!k) return null;
    return {
      id: k.id,
      account_id: k.account_id,
      livemode: k.livemode,
      type: k.type,
      scopes: k.scopes,
      ip_allowlist: k.ip_allowlist,
      expires_at: k.expires_at?.getTime() ?? null,
      revoked_at: k.revoked_at?.getTime() ?? null,
    };
  });
}

async function sessionRecord(id: Identity, token: string, kind: "dashboard" | "ops"): Promise<SessionRecord | null> {
  const hash = sha256(token);
  const cache = id.cache.local<{ v: SessionRecord | null }>("sessions", 10_000);
  const hit = cache.get(hash.toString("hex"));
  // the cookie name decides the session kind: a dashboard token presented as a console cookie is no session
  if (hit) return hit.v?.kind === kind ? hit.v : null;
  const s = await id.db
    .selectFrom("sessions")
    .leftJoin("memberships", (j) =>
      j
        .onRef("memberships.user_id", "=", "sessions.user_id")
        .onRef("memberships.account_id", "=", "sessions.account_id"),
    )
    .leftJoin("ops_operators", (j) =>
      j.onRef("ops_operators.user_id", "=", "sessions.user_id").on("ops_operators.revoked_at", "is", null),
    )
    .innerJoin("users", "users.id", "sessions.user_id")
    .select([
      "sessions.id",
      "sessions.kind",
      "sessions.user_id",
      "sessions.account_id",
      "sessions.csrf_hash",
      "sessions.step_up_at",
      "sessions.expires_at",
      "sessions.last_seen_at",
      "sessions.revoked_at",
      "memberships.role",
      "ops_operators.role as operator",
      "users.status as user_status",
    ])
    .where("sessions.token_hash", "=", hash)
    .executeTakeFirst();
  const v: SessionRecord | null =
    s && s.user_status === "active"
      ? {
          id: s.id,
          kind: s.kind,
          user_id: s.user_id,
          account_id: s.account_id,
          csrf_hash: s.csrf_hash,
          step_up_at: s.step_up_at?.getTime() ?? null,
          expires_at: s.expires_at.getTime(),
          last_seen_at: s.last_seen_at.getTime(),
          revoked_at: s.revoked_at?.getTime() ?? null,
          role: s.role,
          operator: s.operator as OpsRole | null,
        }
      : null;
  cache.set(hash.toString("hex"), { v });
  return v?.kind === kind ? v : null;
}

const deny = (code: "authentication_required" | "invalid_api_key" | "permission_denied", message?: string) =>
  new ApiError(code, message ? { message } : {});

export async function authorize(
  id: Identity,
  h: AuthzHeaders,
  touch: Touches,
): Promise<{ token: string; requestId: string; claims: MintedClaims }> {
  const started = performance.now();
  try {
    const r = await decide(id, h, touch);
    id.metrics.authz("ok", (performance.now() - started) / 1000);
    return r;
  } catch (e) {
    id.metrics.authz(e instanceof ApiError ? e.code : "error", (performance.now() - started) / 1000);
    throw e;
  }
}

async function decide(id: Identity, h: AuthzHeaders, touch: Touches) {
  const now = id.now();
  const method = (h.method ?? "GET").toUpperCase();
  const consoleHost = isConsoleHost(h.host);
  const opsPath = isConsolePath(h.uri);
  // the console host serves only console routes, and console routes are served only there
  if (consoleHost !== opsPath)
    throw deny(
      "permission_denied",
      consoleHost
        ? "Only console routes are served on the console host."
        : "Console routes are served only on the console host.",
    );
  const route = consoleHost ? matchOps(method, h.uri ?? "/") : match(method, h.uri ?? "/");
  const requestId = isId("req", h.requestId) ? (h.requestId as string) : newId("req");
  const ip = clientIp(
    id.env,
    { cfConnectingIp: h.cfConnectingIp, xForwardedFor: h.xForwardedFor, peer: h.peer },
    id.clientIp,
  );
  const unsafe = isUnsafe(method);
  let claims: MintedClaims;
  let rateKey: string;
  let rateClass: RateClass;
  let accountUuid: string | null = null;

  const bearer = /^Bearer\s+(\S+)$/i.exec(h.authorization?.trim() ?? "")?.[1];
  // merchant credentials never reach console routes
  if (bearer && consoleHost) throw deny("permission_denied", "API keys cannot call console routes.");
  if (consoleHost && accessMode(id.console)) {
    // ---- console through Cloudflare Access: only a verified assertion, never a cookie or anonymous ----
    const v = id.console.access;
    if (!v) throw deny("authentication_required", "Cloudflare Access is not configured.");
    const who = await verifyAccess(v, h.cfAccessJwt, Math.floor(now / 1000));
    if (!who) throw deny("authentication_required", "A valid Cloudflare Access assertion is required.");
    const op = await activeOperatorByEmail(id.db, who.email);
    if (!op) throw deny("permission_denied", "This account is not an enrolled NearPay operator.");
    const sub = fromUuid("usr", op.user_id);
    if (unsafe && !accessCsrfValid(v, sub, who.iat, h.csrf)) throw new ApiError("csrf_token_invalid");
    const stepUp = accessStepUpUntil(who.iat, Math.floor(now / 1000));
    claims = {
      sub,
      ptype: "ops",
      ops_role: op.role,
      scp: [...OPS_ROLE_SCOPES[op.role]],
      rid: requestId,
      ...(stepUp ? { step_up_until: stepUp } : {}),
      ops_admins: await activeAdminCount(id.db),
      ops_auth_at: who.iat,
    };
    rateKey = `usr:${op.user_id}`;
    rateClass = "test";
  } else if (bearer) {
    // ---- API key -----------------------------------------------------------------------------
    const shape = parseKey(bearer);
    const k = shape ? await keyRecord(id, bearer) : null;
    if (!k || k.revoked_at !== null || (k.expires_at !== null && k.expires_at <= now)) throw deny("invalid_api_key");
    if (!ipAllowed(ip, k.ip_allowlist)) throw new ApiError("ip_not_allowed");
    if (k.type === "publishable" && !publishableAllowed(route))
      throw deny("permission_denied", "Publishable keys can only call checkout and elements routes.");
    accountUuid = k.account_id;
    const ptype = k.type === "secret" ? "secret_key" : k.type === "publishable" ? "publishable_key" : "restricted_key";
    // restricted keys hold their scopes (write implies read); refused early on routes they cannot call
    const scp =
      k.type === "publishable"
        ? [...PUBLISHABLE_SCOPES]
        : k.type === "restricted"
          ? expandScopes(k.scopes, KEY_SCOPES)
          : [];
    if (k.type === "restricted" && route && !restrictedAllows(route.auth, scp))
      throw deny("permission_denied", "This restricted key does not hold a scope for this route.");
    claims = {
      sub: fromUuid("key", k.id),
      acct: fromUuid("acct", k.account_id),
      lm: k.livemode,
      ptype,
      scp,
      rid: requestId,
    };
    rateKey = `key:${k.id}`;
    rateClass = k.livemode ? "live" : "test";
    touch.key(k.id, now);
  } else {
    const token = readCookie(h.cookie, consoleHost ? OPS_COOKIE : SESSION_COOKIE);
    const s = token ? await sessionRecord(id, token, consoleHost ? "ops" : "dashboard") : null;
    if (
      s &&
      sessionState(
        {
          expires_at: new Date(s.expires_at),
          last_seen_at: new Date(s.last_seen_at),
          revoked_at: s.revoked_at ? new Date(s.revoked_at) : null,
        },
        now,
        s.kind,
      ) === "valid"
    ) {
      // ---- session ---------------------------------------------------------------------------
      if (unsafe && !matchesHash(h.csrf, s.csrf_hash)) throw new ApiError("csrf_token_invalid");
      const stepUp = stepUpUntil(s.step_up_at ? new Date(s.step_up_at) : null, now);
      if (s.kind === "ops") {
        // an operator revoked after sign-in loses the console at once (the cached record joins ops_operators)
        if (!s.operator) throw deny("authentication_required");
        claims = {
          sub: fromUuid("usr", s.user_id),
          ptype: "ops",
          ops_role: s.operator,
          scp: [...OPS_ROLE_SCOPES[s.operator]],
          rid: requestId,
          ...(stepUp ? { step_up_until: stepUp } : {}),
          // adaptive two-person rule: identity's count and the last verification (sign-in counts as one)
          ops_admins: await activeAdminCount(id.db),
          ...(s.step_up_at ? { ops_auth_at: Math.floor(s.step_up_at / 1000) } : {}),
        };
      } else {
        if (!s.account_id || !s.role) throw deny("authentication_required");
        accountUuid = s.account_id;
        claims = {
          sub: fromUuid("usr", s.user_id),
          acct: fromUuid("acct", s.account_id),
          lm: sessionMode(h.mode),
          ptype: "session",
          scp: [],
          rid: requestId,
          role: s.role as NonNullable<ClaimsInput["role"]>,
          ...(stepUp ? { step_up_until: stepUp } : {}),
        };
      }
      rateKey = `usr:${s.user_id}`;
      rateClass = claims.lm ? "live" : "test";
      touch.session(s.id, now);
    } else if (anonymousAllowed(route)) {
      // ---- anonymous (open routes; client-secret routes check the secret themselves) ------------
      claims = { sub: "anonymous", ptype: "anonymous", scp: [], rid: requestId };
      rateKey = `ip:${ip ?? "unknown"}`;
      rateClass = "anonymous";
    } else {
      throw deny("authentication_required");
    }
  }

  // ---- account state: suspension and live-mode gating ---------------------------------------
  if (accountUuid) {
    const a = await accountState(id, accountUuid);
    if (a.status === "closed") throw deny("authentication_required");
    if (a.status === "suspended" && claims.lm && unsafe) throw new ApiError("account_suspended");
    if (claims.lm && unsafe && requiresLiveEnabled(route) && !a.live_enabled) {
      const missing = [a.kyb_status === "approved" ? null : "kyb", a.status === "active" ? null : "account_status"]
        .filter(Boolean)
        .join(", ");
      throw new ApiError("account_not_live", { params: { missing: missing || "destination" } });
    }
  }

  // ---- rate limit ------------------------------------------------------------------------------
  const r = await id.cache.take(rateKey, RATE_LIMITS[rateClass], now);
  if (!r.allowed) {
    id.metrics.rateLimited(claims.ptype);
    throw new ApiError("rate_limited", {
      params: { retry_after: String(r.retryAfter) },
      headers: { "Retry-After": String(r.retryAfter) },
    });
  }

  const token = await id.signer.sign(claims as ClaimsInput);
  return { token, requestId, claims };
}
