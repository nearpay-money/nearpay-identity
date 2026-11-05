/**
 * Internal reads (lld/identity.md §6, §8.3): settlement context for payments/agentpay, a single
 * destination in any status, and notification recipients for notify (PII; never in events).
 */
import { fromUuid, toUuid } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
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

export async function notificationRecipients(id: Identity, accountId: string, kind: keyof typeof KIND_ROLES) {
  const acct = toUuid(accountId, "acct");
  const account = await id.db.selectFrom("accounts").select("id").where("id", "=", acct).executeTakeFirst();
  if (!account) throw ApiError.missing("account", accountId, "id");
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
