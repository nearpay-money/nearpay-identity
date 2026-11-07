/**
 * Audit log reads and the console's merchant reads (lld/identity.md §6, §6.1, §12).
 *
 * `listAccountAuditEvents` (owners/admins) lists the account's own audit trail, without operator
 * actions (operator ids stay internal); `listOpsAuditEvents` is the platform trail across services
 * (identity's own rows plus every `*.ops_action.recorded` event). Cursor pagination over the
 * time-ordered UUIDv7 ids, newest first.
 */

import { type Selectable, sql } from "@nearpay-internal/db";
import { fromUuid, toUuid } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { AuditActorType, AuditEventsTable, KybStatus } from "../infra/db/schema.js";
import type { Identity } from "./context.js";
import { type AccountRow, accountView } from "./views.js";

type AuditRow = Selectable<AuditEventsTable>;

const unix = (d: Date) => Math.floor(d.getTime() / 1000);

/** Stage 1 ops-CLI rows carry `ops`; both read as `operator` in the contract. */
const actorTypeOut = (t: AuditActorType) => (t === "ops" ? "operator" : t);

export function auditView(r: AuditRow) {
  return {
    id: fromUuid("aud", r.id),
    object: "audit_event" as const,
    created: unix(r.created_at),
    account: r.account_id ? fromUuid("acct", r.account_id) : null,
    actor: { type: actorTypeOut(r.actor_type), id: r.actor_id },
    action: r.action,
    target: r.target_type && r.target_id ? { type: r.target_type, id: r.target_id } : null,
    details: r.details ?? {},
  };
}

interface AuditQuery {
  limit: number;
  starting_after?: string | undefined;
  ending_before?: string | undefined;
  "created[gte]"?: number | undefined;
  "created[lte]"?: number | undefined;
  action?: string | undefined;
  actor?: string | undefined;
}

function page(id: Identity, q: AuditQuery) {
  let query = id.db
    .selectFrom("audit_events")
    .selectAll()
    .orderBy("id", "desc")
    .limit(q.limit + 1);
  if (q["created[gte]"] !== undefined) query = query.where("created_at", ">=", new Date(q["created[gte]"] * 1000));
  if (q["created[lte]"] !== undefined) query = query.where("created_at", "<=", new Date(q["created[lte]"] * 1000));
  if (q.action) query = query.where("action", "=", q.action);
  if (q.actor) query = query.where("actor_id", "=", q.actor);
  if (q.starting_after) query = query.where("id", "<", toUuid(q.starting_after, "aud"));
  if (q.ending_before) query = query.where("id", ">", toUuid(q.ending_before, "aud"));
  return query;
}

export async function listAccountAuditEvents(id: Identity, accountId: string, q: AuditQuery) {
  const rows = await page(id, q)
    .where("account_id", "=", toUuid(accountId, "acct"))
    .where("actor_type", "not in", ["ops", "operator"])
    .execute();
  return {
    object: "list" as const,
    data: rows.slice(0, q.limit).map(auditView),
    has_more: rows.length > q.limit,
    url: "/v1/account/audit_events",
  };
}

export async function listOpsAuditEvents(
  id: Identity,
  q: AuditQuery & { account?: string | undefined; actor_type?: string | undefined; target?: string | undefined },
) {
  let query = page(id, q);
  if (q.account) query = query.where("account_id", "=", toUuid(q.account, "acct"));
  if (q.actor_type)
    query =
      q.actor_type === "operator"
        ? query.where("actor_type", "in", ["ops", "operator"])
        : query.where("actor_type", "=", q.actor_type as AuditActorType);
  if (q.target) query = query.where("target_id", "=", q.target);
  const rows = await query.execute();
  return {
    object: "list" as const,
    data: rows.slice(0, q.limit).map(auditView),
    has_more: rows.length > q.limit,
    url: "/ops/audit_events",
  };
}

// ---------------------------------------------------------------------------------------------
// Console merchants
// ---------------------------------------------------------------------------------------------

async function merchantViews(id: Identity, accounts: AccountRow[]) {
  if (!accounts.length) return [];
  const ids = accounts.map((a) => a.id);
  const [owners, counts, live] = await Promise.all([
    id.db
      .selectFrom("memberships")
      .innerJoin("users", "users.id", "memberships.user_id")
      .select(["memberships.account_id", "users.id", "users.email"])
      .where("memberships.account_id", "in", ids)
      .where("memberships.role", "=", "owner")
      .orderBy("memberships.created_at")
      .execute(),
    id.db
      .selectFrom("memberships")
      .select(["account_id", (eb) => eb.fn.countAll<string>().as("n")])
      .where("account_id", "in", ids)
      .groupBy("account_id")
      .execute(),
    id.db
      .selectFrom("settlement_destinations")
      .select(["account_id", (eb) => eb.fn.countAll<string>().as("n")])
      .where("account_id", "in", ids)
      .where("livemode", "=", true)
      .where("status", "=", "active")
      .groupBy("account_id")
      .execute(),
  ]);
  return accounts.map((a) => ({
    ...accountView(a),
    owners: owners.filter((o) => o.account_id === a.id).map((o) => ({ id: fromUuid("usr", o.id), email: o.email })),
    member_count: Number(counts.find((c) => c.account_id === a.id)?.n ?? 0),
    active_live_destinations: Number(live.find((c) => c.account_id === a.id)?.n ?? 0),
    recovered_at: a.recovered_at ? unix(a.recovered_at) : null,
  }));
}

export async function listOpsMerchants(
  id: Identity,
  q: {
    limit: number;
    starting_after?: string | undefined;
    ending_before?: string | undefined;
    "created[gte]"?: number | undefined;
    "created[lte]"?: number | undefined;
    q?: string | undefined;
    status?: string | undefined;
    kyb_status?: string | undefined;
    live_enabled?: "true" | "false" | undefined;
  },
) {
  let query = id.db
    .selectFrom("accounts")
    .selectAll()
    .orderBy("id", "desc")
    .limit(q.limit + 1);
  const term = q.q?.trim();
  if (term) {
    if (/^acct_[0-9A-Za-z]+$/.test(term)) {
      let uuid: string | null = null;
      try {
        uuid = toUuid(term, "acct");
      } catch {}
      query = uuid ? query.where("id", "=", uuid) : query.where(sql<boolean>`false`);
    } else if (term.includes("@")) {
      // exact member email (never logged: it is a query value, compared in the database only)
      query = query.where("id", "in", (eb) =>
        eb
          .selectFrom("memberships")
          .innerJoin("users", "users.id", "memberships.user_id")
          .select("memberships.account_id")
          .where("users.email", "=", term.toLowerCase()),
      );
    } else {
      const prefix = `${term.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      query = query.where((eb) =>
        eb.or([eb("display_name", "ilike", prefix), eb("verified_legal_name", "ilike", prefix)]),
      );
    }
  }
  if (q.status) query = query.where("status", "=", q.status as AccountRow["status"]);
  if (q.kyb_status) query = query.where("kyb_status", "=", q.kyb_status as KybStatus);
  if (q.live_enabled) query = query.where("live_enabled", "=", q.live_enabled === "true");
  if (q["created[gte]"] !== undefined) query = query.where("created_at", ">=", new Date(q["created[gte]"] * 1000));
  if (q["created[lte]"] !== undefined) query = query.where("created_at", "<=", new Date(q["created[lte]"] * 1000));
  if (q.starting_after) query = query.where("id", "<", toUuid(q.starting_after, "acct"));
  if (q.ending_before) query = query.where("id", ">", toUuid(q.ending_before, "acct"));
  const rows = await query.execute();
  return {
    object: "list" as const,
    data: await merchantViews(id, rows.slice(0, q.limit)),
    has_more: rows.length > q.limit,
    url: "/ops/merchants",
  };
}

export async function getOpsMerchant(id: Identity, accountId: string) {
  const a = await id.db
    .selectFrom("accounts")
    .selectAll()
    .where("id", "=", toUuid(accountId, "acct"))
    .executeTakeFirst();
  if (!a) throw ApiError.missing("account", accountId, "id");
  return (await merchantViews(id, [a]))[0];
}
