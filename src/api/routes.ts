/** Spec route bindings (lld/identity.md §6). Auth, roles and step-up are enforced from the spec by the bootstrap. */

import type { ServiceName } from "@nearpay/spec";
import {
  acceptInvitation,
  approveCliLogin,
  approveSettlementDestination,
  attestSettlementDestination,
  challengeSettlementDestination,
  createApiKey,
  createCliLogin,
  createInvitation,
  createSettlementDestination,
  denyCliLogin,
  disableSettlementDestination,
  getAccount,
  getAccountRequirements,
  getCliLogin,
  getDashboardSession,
  getSettlementDestination,
  listAccountAuditEvents,
  listApiKeys,
  listInvitations,
  listMembers,
  listMemberships,
  listSettlementDestinations,
  logout,
  passkeyAuthenticationOptions,
  passkeyAuthenticationVerify,
  passkeyRegistrationOptions,
  passkeyRegistrationVerify,
  pollCliLogin,
  removeMember,
  revokeApiKey,
  revokeInvitation,
  rollApiKey,
  SERVICE_CLIENT_SCOPES,
  setDefaultSettlementDestination,
  signup,
  startRecovery,
  stepUpOptions,
  stepUpVerify,
  switchSessionAccount,
  TOKEN_TTL_SECONDS,
  updateAccount,
  updateApiKey,
  updateMember,
  verifyMagicLink,
} from "@nearpay/spec";
import type { InternalClaims } from "@nearpay-internal/auth";
import { toUuid } from "@nearpay-internal/ids";
import { ApiError, implement, type RequestContext, type RouteBinding, respond } from "@nearpay-internal/service";
import {
  authorize as authorizeRoute,
  getInternalOpsOperator,
  getInternalSettlementDestination,
  getJwks,
  getNotificationRecipients,
  getOpsMerchant,
  getOpsSession,
  getSettlementContext,
  listOpsAuditEvents,
  listOpsMerchants,
  mintServiceToken,
  opsEnrolmentVerify,
  opsLogout,
  opsPasskeyAuthenticationOptions,
  opsPasskeyAuthenticationVerify,
  opsPasskeyRegistrationOptions,
  opsPasskeyRegistrationVerify,
  opsStepUpOptions,
  opsStepUpVerify,
} from "@nearpay-internal/spec";
import { getRequirements, updateAccount as patchAccount, getAccount as readAccount } from "../app/accounts.js";
import { createKey, listKeys, revokeKey, rollKey, updateKey } from "../app/api-keys.js";
import * as audits from "../app/audit.js";
import * as auth from "../app/auth.js";
import { authorize, type Touches } from "../app/authz.js";
import * as cli from "../app/cli-logins.js";
import * as consoleAuth from "../app/console.js";
import type { Actor, Identity } from "../app/context.js";
import {
  approveDestination,
  attestDestination,
  challengeDestination,
  createDestination,
  disableDestination,
  getDestination,
  getInternalDestination,
  listDestinations,
  setDefaultDestination,
} from "../app/destinations.js";
import { internalOpsOperator, notificationRecipients, settlementContext } from "../app/internal.js";
import * as team from "../app/team.js";
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
    ip: clientIp(
      id.env,
      {
        cfConnectingIp: header(ctx, "cf-connecting-ip"),
        xForwardedFor: header(ctx, "x-forwarded-for"),
        peer: ctx.request.socket?.remoteAddress,
      },
      id.clientIp,
    ),
    userAgent: header(ctx, "user-agent"),
    cookie: header(ctx, "cookie"),
    accessJwt: header(ctx, "cf-access-jwt-assertion"),
  };
}

/** The account principal of a session or key route. */
function principal(ctx: RequestContext): InternalClaims & { acct: string } {
  const p = ctx.principal;
  if (!p?.acct) throw new ApiError("authentication_required");
  return p as InternalClaims & { acct: string };
}

/** The ops principal of a console route. */
function operator(ctx: RequestContext): InternalClaims {
  const p = ctx.principal;
  if (p?.ptype !== "ops") throw new ApiError("authentication_required");
  return p;
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
    implement(getDashboardSession, async (ctx) => auth.getDashboardSession(id, principal(ctx), meta(id, ctx))),
    implement(logout, async (ctx) => {
      const r = await auth.logout(id, principal(ctx), meta(id, ctx));
      return r as never;
    }),
    implement(startRecovery, async (ctx) => {
      await auth.startRecovery(id, ctx.body, meta(id, ctx));
    }),
    implement(acceptInvitation, async (ctx) =>
      team.acceptInvitation(id, principal(ctx), ctx.body.token, meta(id, ctx)),
    ),
    implement(listMemberships, async (ctx) => team.listMemberships(id, principal(ctx))),
    implement(switchSessionAccount, async (ctx) =>
      team.switchSessionAccount(id, principal(ctx), ctx.body.account, meta(id, ctx)),
    ),

    // ---- team --------------------------------------------------------------------------------------
    implement(listMembers, async (ctx) => team.listMembers(id, principal(ctx).acct, ctx.query)),
    implement(updateMember, async (ctx) =>
      team.updateMember(id, principal(ctx).acct, ctx.params.user, ctx.body.role, actorOf(id, ctx)),
    ),
    implement(removeMember, async (ctx) => {
      await team.removeMember(id, principal(ctx).acct, ctx.params.user, actorOf(id, ctx));
    }),
    implement(listInvitations, async (ctx) => team.listInvitations(id, principal(ctx).acct, ctx.query)),
    implement(createInvitation, async (ctx) =>
      respond(201, await team.createInvitation(id, principal(ctx).acct, ctx.body, actorOf(id, ctx))),
    ),
    implement(revokeInvitation, async (ctx) => {
      await team.revokeInvitation(id, principal(ctx).acct, ctx.params.id, actorOf(id, ctx));
    }),
    implement(listAccountAuditEvents, async (ctx) => audits.listAccountAuditEvents(id, principal(ctx).acct, ctx.query)),

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
    implement(updateApiKey, async (ctx) => {
      const p = principal(ctx);
      return updateKey(id, p.acct, p.lm === true, ctx.params.id, ctx.body, actorOf(id, ctx));
    }),

    // ---- CLI login (Stage 3, §6.2) ------------------------------------------------------------------
    implement(createCliLogin, async (ctx) =>
      respond(
        201,
        await cli.createCliLogin(id, ctx.body, {
          ip: meta(id, ctx).ip,
          country: header(ctx, "cf-ipcountry"),
          userAgent: header(ctx, "user-agent"),
        }),
      ),
    ),
    implement(pollCliLogin, async (ctx) => cli.pollCliLogin(id, ctx.body.device_code)),
    implement(getCliLogin, async (ctx) => cli.getCliLogin(id, principal(ctx).acct, ctx.params.code)),
    implement(approveCliLogin, async (ctx) =>
      cli.approveCliLogin(id, principal(ctx).acct, ctx.params.code, actorOf(id, ctx)),
    ),
    implement(denyCliLogin, async (ctx) =>
      cli.denyCliLogin(id, principal(ctx).acct, ctx.params.code, actorOf(id, ctx)),
    ),

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
    implement(challengeSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return challengeDestination(id, p.acct, p.lm === true, ctx.params.id, actorOf(id, ctx));
    }),
    implement(setDefaultSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return setDefaultDestination(id, p.acct, p.lm === true, ctx.params.id, ctx.body.scope, actorOf(id, ctx));
    }),
    implement(disableSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return disableDestination(id, p.acct, p.lm === true, ctx.params.id, actorOf(id, ctx));
    }),
    implement(approveSettlementDestination, async (ctx) => {
      const p = principal(ctx);
      return approveDestination(id, p.acct, p.lm === true, ctx.params.id, ctx.body.decision, actorOf(id, ctx));
    }),

    // ---- console (ops host only; authz mints ptype ops) -------------------------------------------------
    implement(opsEnrolmentVerify, async (ctx) => consoleAuth.enrolmentVerify(id, ctx.body.token)),
    implement(
      opsPasskeyRegistrationOptions,
      async (ctx) => (await consoleAuth.registrationOptions(id, ctx.body)) as never,
    ),
    implement(
      opsPasskeyRegistrationVerify,
      async (ctx) => consoleAuth.registrationVerify(id, ctx.body as never, meta(id, ctx)) as never,
    ),
    implement(
      opsPasskeyAuthenticationOptions,
      async (ctx) => (await consoleAuth.authenticationOptions(id, meta(id, ctx))) as never,
    ),
    implement(
      opsPasskeyAuthenticationVerify,
      async (ctx) => consoleAuth.authenticationVerify(id, ctx.body.credential as never, meta(id, ctx)) as never,
    ),
    implement(
      opsStepUpOptions,
      async (ctx) => (await consoleAuth.stepUpOptions(id, operator(ctx), meta(id, ctx))) as never,
    ),
    implement(opsStepUpVerify, async (ctx) =>
      consoleAuth.stepUpVerify(id, operator(ctx), ctx.body.credential as never, meta(id, ctx)),
    ),
    implement(getOpsSession, async (ctx) => consoleAuth.getOpsSession(id, operator(ctx), meta(id, ctx))),
    implement(opsLogout, async (ctx) => (await consoleAuth.logout(id, operator(ctx), meta(id, ctx))) as never),
    implement(listOpsMerchants, async (ctx) => {
      operator(ctx);
      return audits.listOpsMerchants(id, ctx.query);
    }),
    implement(getOpsMerchant, async (ctx) => {
      operator(ctx);
      return audits.getOpsMerchant(id, ctx.params.id) as never;
    }),
    implement(listOpsAuditEvents, async (ctx) => {
      operator(ctx);
      return audits.listOpsAuditEvents(id, ctx.query);
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
          peer: ctx.request.socket?.remoteAddress,
          cfAccessJwt: header(ctx, "cf-access-jwt-assertion"),
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
    implement(getNotificationRecipients, async (ctx) =>
      notificationRecipients(id, ctx.params.id, ctx.query.kind, ctx.query.user),
    ),
    implement(getInternalOpsOperator, async (ctx) => internalOpsOperator(id, ctx.params.id)),
  ];
}
