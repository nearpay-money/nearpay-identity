/** Spec route bindings (lld/identity.md §6). Auth, roles and step-up are enforced from the spec by the bootstrap. */

import type { ServiceName } from "@nearpay/spec";
import {
  attestSettlementDestination,
  createApiKey,
  createSettlementDestination,
  disableSettlementDestination,
  getAccount,
  getAccountRequirements,
  getSettlementDestination,
  listApiKeys,
  listSettlementDestinations,
  logout,
  passkeyAuthenticationOptions,
  passkeyAuthenticationVerify,
  passkeyRegistrationOptions,
  passkeyRegistrationVerify,
  revokeApiKey,
  rollApiKey,
  SERVICE_CLIENT_SCOPES,
  setDefaultSettlementDestination,
  signup,
  stepUpOptions,
  stepUpVerify,
  TOKEN_TTL_SECONDS,
  updateAccount,
  verifyMagicLink,
} from "@nearpay/spec";
import type { InternalClaims } from "@nearpay-internal/auth";
import { toUuid } from "@nearpay-internal/ids";
import { ApiError, implement, type RequestContext, type RouteBinding, respond } from "@nearpay-internal/service";
import {
  authorize as authorizeRoute,
  getInternalSettlementDestination,
  getJwks,
  getNotificationRecipients,
  getSettlementContext,
  mintServiceToken,
} from "@nearpay-internal/spec";
import { getRequirements, updateAccount as patchAccount, getAccount as readAccount } from "../app/accounts.js";
import { createKey, listKeys, revokeKey, rollKey } from "../app/api-keys.js";
import * as auth from "../app/auth.js";
import { authorize, type Touches } from "../app/authz.js";
import type { Actor, Identity } from "../app/context.js";
import {
  attestDestination,
  createDestination,
  disableDestination,
  getDestination,
  getInternalDestination,
  listDestinations,
  setDefaultDestination,
} from "../app/destinations.js";
import { notificationRecipients, settlementContext } from "../app/internal.js";
import { authenticateClient } from "../app/tokens.js";
import { clientIp } from "../domain/authz/authz.js";

export interface RouteDeps {
  readonly touches: Touches;
  readonly serviceClients: ReadonlyMap<ServiceName, Buffer>;
}

const header = (ctx: RequestContext, name: string): string | undefined => {
  const v = ctx.request.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

function meta(id: Identity, ctx: RequestContext): auth.RequestMeta {
  return {
    host: header(ctx, "x-forwarded-host") ?? header(ctx, "host"),
    ip: clientIp(id.env, {
      cfConnectingIp: header(ctx, "cf-connecting-ip"),
      xForwardedFor: header(ctx, "x-forwarded-for"),
    }),
    userAgent: header(ctx, "user-agent"),
    cookie: header(ctx, "cookie"),
  };
}

/** The account principal of a session or key route. */
function principal(ctx: RequestContext): InternalClaims & { acct: string } {
  const p = ctx.principal;
  if (!p?.acct) throw new ApiError("authentication_required");
  return p as InternalClaims & { acct: string };
}

function actorOf(id: Identity, ctx: RequestContext): Actor & { userUuid: string } {
  const p = principal(ctx);
  const ip = meta(id, ctx).ip;
  if (p.ptype === "session") return { type: "user", id: p.sub, ip, userUuid: toUuid(p.sub, "usr") };
  throw new ApiError("permission_denied", { params: { action: "change this with an API key" } });
}

export function identityRoutes(id: Identity, deps: RouteDeps): RouteBinding[] {
  return [
    // ---- auth -----------------------------------------------------------------------------------
    implement(signup, async (ctx) => {
      await auth.signup(id, ctx.body, meta(id, ctx));
    }),
    implement(verifyMagicLink, async (ctx) => auth.verifyMagicLink(id, ctx.body.token)),
    implement(
      passkeyRegistrationOptions,
      async (ctx) => (await auth.registrationOptions(id, ctx.body, ctx.principal)) as never,
    ),
    implement(passkeyRegistrationVerify, async (ctx) =>
      auth.registrationVerify(id, ctx.body as auth.RegistrationBody, ctx.principal, meta(id, ctx)),
    ),
    implement(
      passkeyAuthenticationOptions,
      async (ctx) => (await auth.authenticationOptions(id, meta(id, ctx))) as never,
    ),
    implement(passkeyAuthenticationVerify, async (ctx) =>
      auth.authenticationVerify(id, ctx.body.credential as never, meta(id, ctx)),
    ),
    implement(stepUpOptions, async (ctx) => (await auth.stepUpOptions(id, principal(ctx), meta(id, ctx))) as never),
    implement(stepUpVerify, async (ctx) =>
      auth.stepUpVerify(id, principal(ctx), ctx.body.credential as never, meta(id, ctx)),
    ),
    implement(logout, async (ctx) => {
      const r = await auth.logout(id, principal(ctx), meta(id, ctx));
      return r as never;
    }),

    // ---- account ----------------------------------------------------------------------------------
    implement(getAccount, async (ctx) => readAccount(id, principal(ctx).acct)),
    implement(updateAccount, async (ctx) => {
      const p = principal(ctx);
      const steppedUp = p.step_up_until !== undefined && p.step_up_until > Math.floor(id.now() / 1000);
      return patchAccount(id, p.acct, ctx.body, { actor: actorOf(id, ctx), steppedUp });
    }),
    implement(getAccountRequirements, async (ctx) => getRequirements(id, principal(ctx).acct)),

    // ---- API keys ----------------------------------------------------------------------------------
    implement(listApiKeys, async (ctx) => {
      const p = principal(ctx);
      return listKeys(id, p.acct, p.lm === true, ctx.query);
    }),
    implement(createApiKey, async (ctx) =>
      respond(201, await createKey(id, principal(ctx).acct, ctx.body, actorOf(id, ctx))),
    ),
    implement(rollApiKey, async (ctx) =>
      respond(
        201,
        await rollKey(id, principal(ctx).acct, ctx.params.id, ctx.body.expire_old_in_seconds, actorOf(id, ctx)),
      ),
    ),
    implement(revokeApiKey, async (ctx) => {
      await revokeKey(id, principal(ctx).acct, ctx.params.id, actorOf(id, ctx));
    }),

    // ---- settlement destinations ---------------------------------------------------------------------
    implement(listSettlementDestinations, async (ctx) => {
      const p = principal(ctx);
      return listDestinations(id, p.acct, p.lm === true, ctx.query);
    }),
    implement(getSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return getDestination(id, p.acct, p.lm === true, ctx.params.id);
    }),
    implement(createSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return respond(201, await createDestination(id, p.acct, p.lm === true, ctx.body, actorOf(id, ctx)));
    }),
    implement(attestSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return attestDestination(id, p.acct, p.lm === true, ctx.params.id, ctx.body, actorOf(id, ctx));
    }),
    implement(setDefaultSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return setDefaultDestination(id, p.acct, p.lm === true, ctx.params.id, ctx.body.scope, actorOf(id, ctx));
    }),
    implement(disableSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return disableDestination(id, p.acct, p.lm === true, ctx.params.id, actorOf(id, ctx));
    }),

    // ---- internal ------------------------------------------------------------------------------------
    implement(authorizeRoute, async (ctx) => {
      const r = await authorize(
        id,
        {
          method: header(ctx, "x-forwarded-method"),
          uri: header(ctx, "x-forwarded-uri"),
          host: header(ctx, "x-forwarded-host"),
          authorization: header(ctx, "authorization"),
          cookie: header(ctx, "cookie"),
          csrf: header(ctx, "x-csrf-token"),
          mode: header(ctx, "nearpay-mode"),
          requestId: header(ctx, "x-request-id"),
          xForwardedFor: header(ctx, "x-forwarded-for"),
          cfConnectingIp: header(ctx, "cf-connecting-ip"),
        },
        deps.touches,
      );
      return respond(200, undefined, { "x-nearpay-token": r.token, "x-request-id": r.requestId }) as never;
    }),
    implement(getJwks, async () => (await id.signer.jwks()) as never),
    implement(mintServiceToken, async (ctx) => {
      const client = authenticateClient(deps.serviceClients, header(ctx, "authorization"));
      if (!client) throw new ApiError("invalid_client");
      const ttl = TOKEN_TTL_SECONDS.service;
      const token = await id.signer.sign(
        { sub: client, ptype: "service", scp: [...SERVICE_CLIENT_SCOPES[client]] },
        ttl,
      );
      return { access_token: token, token_type: "Bearer" as const, expires_in: ttl };
    }),
    implement(getSettlementContext, async (ctx) => settlementContext(id, ctx.params.id, ctx.query.livemode)),
    implement(getInternalSettlementDestination, async (ctx) => getInternalDestination(id, ctx.params.id)),
    implement(getNotificationRecipients, async (ctx) => notificationRecipients(id, ctx.params.id, ctx.query.kind)),
  ];
}
