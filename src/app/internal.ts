/**
 * Internal reads (lld/identity.md §6, §8.3): settlement context for payments/agentpay, a single
 * destination in any status, and notification recipients for notify (PII; never in events).
 */
import { fromUuid, toUuid } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { Role } from "../infra/db/schema.js";
import type { Identity } from "./context.js";
import { accountView, internalDestinationView } from "./views.js";

export async function settlementContext(id: Identity, accountId: string, livemode: boolean) {
  const acct = toUuid(accountId, "acct");
  const account = await id.db.selectFrom("accounts").selectAll().where("id", "=", acct).executeTakeFirst();
  if (!account) throw ApiError.missing("account", accountId, "id");
  const [schedule, destinations, defaults] = await Promise.all([
    id.db.selectFrom("fee_schedules").selectAll().where("id", "=", account.fee_schedule_id).executeTakeFirstOrThrow(),
    id.db
      .selectFrom("settlement_destinations")
      .selectAll()
      .where("account_id", "=", acct)
      .where("livemode", "=", livemode)
      .where("status", "=", "active")
      .orderBy("created_at")
      .execute(),
    id.db
      .selectFrom("account_default_destinations")
      .selectAll()
      .where("account_id", "=", acct)
      .where("livemode", "=", livemode)
      .execute(),
  ]);
  const versions = [
    account.updated_at,
    schedule.updated_at,
    ...destinations.map((d) => d.updated_at),
    ...defaults.map((d) => d.updated_at),
  ];
  const contextVersion = new Date(Math.max(...versions.map((d) => d.getTime())));
  const defaultIds = new Set(defaults.map((d) => d.destination_id));
  return {
    account: accountView(account),
    fee_schedule: {
      id: fromUuid("fs", schedule.id),
      name: schedule.name,
      rules: schedule.rules,
      provider_split: schedule.provider_split,
    },
    destinations: destinations.map((d) =>
      internalDestinationView(d, { isDefault: defaultIds.has(d.id), minUsdMicros: null }),
    ),
    defaults: Object.fromEntries(defaults.map((d) => [d.asset_id ?? "*", fromUuid("sd", d.destination_id)])) as Record<
      string,
      `sd_${string}`
    >,
    context_version: contextVersion.toISOString(),
  };
}

const KIND_ROLES = {
  security: ["owner", "admin"],
  developer: ["owner", "admin", "developer"],
  billing: ["owner", "finance"],
} as const;

/** How long a removed member is still found by `?user=` (notify mails them about their removal). */
export const REMOVED_MEMBER_WINDOW_MS = 7 * 86_400_000;

export async function notificationRecipients(
  id: Identity,
  accountId: string,
  kind: keyof typeof KIND_ROLES,
  user?: string | undefined,
) {
  const acct = toUuid(accountId, "acct");
  const account = await id.db.selectFrom("accounts").select("id").where("id", "=", acct).executeTakeFirst();
  if (!account) throw ApiError.missing("account", accountId, "id");
  if (user !== undefined) return { recipients: await oneRecipient(id, acct, user) };
  const rows = await id.db
    .selectFrom("memberships")
    .innerJoin("users", "users.id", "memberships.user_id")
    .select(["users.id", "users.email", "memberships.role"])
    .where("memberships.account_id", "=", acct)
    .where("memberships.role", "in", [...KIND_ROLES[kind]])
    .where("users.status", "=", "active")
    .where("users.email_verified_at", "is not", null)
    .orderBy("memberships.created_at")
    .execute();
  return { recipients: rows.map((r) => ({ user_id: fromUuid("usr", r.id), email: r.email, role: r.role })) };
}

/**
 * `?user=` (spec 0.2.1): that user only, in any role (`kind` not applied): a current member, or a member
 * removed from this account in the last 7 days with the role they had (identity LLD "Spec 0.2.1":
 * notify mails the removed member, whose membership row is already gone). Otherwise an empty list.
 * Only active users with a verified email, like the role lists.
 */
async function oneRecipient(id: Identity, acct: string, userId: string) {
  const userUuid = toUuid(userId, "usr");
  const u = await id.db
    .selectFrom("users")
    .select(["id", "email"])
    .where("id", "=", userUuid)
    .where("status", "=", "active")
    .where("email_verified_at", "is not", null)
    .executeTakeFirst();
  if (!u) return [];
  const m = await id.db
    .selectFrom("memberships")
    .select("role")
    .where("account_id", "=", acct)
    .where("user_id", "=", userUuid)
    .executeTakeFirst();
  let role = m?.role;
  if (!role) {
    const removed = await id.db
      .selectFrom("audit_events")
      .select("details")
      .where("account_id", "=", acct)
      .where("action", "=", "member.removed")
      .where("target_id", "=", fromUuid("usr", userUuid))
      .where("created_at", ">", new Date(id.now() - REMOVED_MEMBER_WINDOW_MS))
      .orderBy("created_at", "desc")
      .limit(1)
      .executeTakeFirst();
    const r = (removed?.details as { role?: unknown } | undefined)?.role;
    if (typeof r === "string" && (ROLES as readonly string[]).includes(r)) role = r as Role;
  }
  return role ? [{ user_id: fromUuid("usr", u.id), email: u.email, role }] : [];
}

const ROLES = ["owner", "admin", "developer", "finance", "support", "viewer"] as const;

/** `getInternalOpsOperator` (spec 0.2.1, compliance's assignee check): never an operator → 404. */
export async function internalOpsOperator(id: Identity, userId: string) {
  const o = await id.db
    .selectFrom("ops_operators")
    .selectAll()
    .where("user_id", "=", toUuid(userId, "usr"))
    .executeTakeFirst();
  if (!o) throw ApiError.missing("ops_operator", userId, "id");
  return {
    user_id: fromUuid("usr", o.user_id),
    role: o.role,
    active: o.revoked_at === null,
    created_at: o.created_at.toISOString(),
    revoked_at: o.revoked_at ? o.revoked_at.toISOString() : null,
  };
}
