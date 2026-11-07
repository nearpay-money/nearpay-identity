/**
 * Domain-event consumers (lld/identity.md §7). Each runs inside the inbox transaction; compliance
 * events are ordered by their aggregate version (a stale event never undoes a newer decision).
 *
 * | subject                                    | handler                                              |
 * |--------------------------------------------|------------------------------------------------------|
 * | evt.compliance.kyb.approved/rejected/needs_info | set `kyb_status`, recompute `live_enabled`;     |
 * |                                            | approved: read the case, copy the ops-approved legal name |
 * | evt.compliance.kyb.submitted               | `kyb_status = pending`                               |
 * | evt.{compliance,sentinel,payments,rails}.ops_action.recorded | one `audit_events` row per action (id = action id) |
 * | evt.compliance.destination.blocked         | disable the destination (reason `compliance`)        |
 * | evt.compliance.account.suspended/reinstated | set the account status                              |
 * | evt.identity.api_key.created/revoked       | purge the key from Valkey and every api replica's LRU |
 */
import type { Envelope, EventHandler } from "@nearpay-internal/bus";
import { deadLetterSink, inboxHandler, type Kysely } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { OpsActionEvent, type Subject } from "@nearpay-internal/spec";
import { setAccountStatus, setKybStatus } from "../app/accounts.js";
import type { Identity, Tx } from "../app/context.js";
import { blockDestination } from "../app/destinations.js";
import type { DB, KybStatus } from "../infra/db/schema.js";

type OpsSource = "compliance" | "sentinel" | "payments" | "rails";

export const CACHE_PURGE_SUBJECT = "ctl.identity.cache.purge";

export interface ConsumerDeps {
  /** Deletes a key hash from Valkey and broadcasts the LRU purge (after the inbox commit is fine: idempotent). */
  purgeKey(hashHex: string): Promise<void>;
}

const obj = <T>(e: Envelope) => e.data.object as unknown as T;

export function identityHandlers(id: Identity, deps: ConsumerDeps): Partial<Record<Subject, EventHandler>> {
  const h = (fn: (tx: Tx, e: Envelope) => Promise<void>) => inboxHandler(id.db, fn);
  const kyb = h(async (tx, e) => {
    const k = obj<{ account_id: string; status: KybStatus }>(e);
    await setKybStatus(tx, toUuid(k.account_id, "acct"), k.status, e.aggregate.version);
  });
  // approval: the legal name and country stay off the bus (personal data for sole proprietors), so the
  // case is read first; compliance unavailable → the message is redelivered (live mode waits, fail closed)
  const kybApproved: EventHandler = async (e) => {
    const k = obj<{ account_id: string }>(e);
    const c = await id.peers.kybCase(k.account_id);
    if (c.status === "approved" && !c.profile.legal_name)
      throw new Error(`KYB case of ${k.account_id} is approved without a legal name`);
    return h(async (tx, env) => {
      // a later decision already superseded this approval; its own event will be applied
      if (c.status !== "approved") {
        id.log.info({ account: k.account_id, status: c.status }, "KYB approval superseded; skipped");
        return;
      }
      await setKybStatus(tx, toUuid(k.account_id, "acct"), "approved", env.aggregate.version, {
        legalName: c.profile.legal_name as string,
        country: c.profile.country_of_incorporation ?? null,
      });
    })(e);
  };
  const submitted = h(async (tx, e) => {
    const k = obj<{ account_id: string }>(e);
    await setKybStatus(tx, toUuid(k.account_id, "acct"), "pending", e.aggregate.version);
  });
  // unified console audit trail (T-12): operator actions of other services, ids only, deduped on the action id
  const opsAction = (source: OpsSource) =>
    h(async (tx, e) => {
      const a = OpsActionEvent.parse(e.data.object);
      await tx
        .insertInto("audit_events")
        .values({
          id: a.id,
          account_id: a.account_id ? toUuid(a.account_id, "acct") : null,
          actor_type: "operator",
          actor_id: a.actor.sub,
          action: a.action,
          target_type: a.target.type,
          target_id: a.target.id,
          details: JSON.stringify({ ops_role: a.actor.ops_role, approval: a.approval, source }),
          created_at: a.occurred_at,
        })
        .onConflict((oc) => oc.column("id").doNothing())
        .execute();
    });
  const status = (to: "active" | "suspended") =>
    h(async (tx, e) => {
      const a = obj<{ account_id: string }>(e);
      await setAccountStatus(tx, toUuid(a.account_id, "acct"), to, e.aggregate.version);
    });
  const keyPurge: EventHandler = async (e) => {
    const k = obj<{ id: string }>(e);
    const row = await id.db
      .selectFrom("api_keys")
      .select("key_hash")
      .where("id", "=", toUuid(k.id, "key"))
      .executeTakeFirst();
    if (row) await deps.purgeKey(row.key_hash.toString("hex"));
  };
  return {
    "evt.compliance.kyb.approved": kybApproved,
    "evt.compliance.kyb.submitted": submitted,
    "evt.compliance.ops_action.recorded": opsAction("compliance"),
    "evt.sentinel.ops_action.recorded": opsAction("sentinel"),
    "evt.payments.ops_action.recorded": opsAction("payments"),
    "evt.rails.ops_action.recorded": opsAction("rails"),
    "evt.compliance.kyb.rejected": kyb,
    "evt.compliance.kyb.needs_info": kyb,
    "evt.compliance.destination.blocked": h(async (tx, e) => {
      const d = obj<{ destination_id: string }>(e);
      const blocked = await blockDestination(id, tx, toUuid(d.destination_id, "sd"));
      if (blocked) id.log.warn({ destination: d.destination_id }, "destination blocked by compliance");
    }),
    "evt.compliance.account.suspended": status("suspended"),
    "evt.compliance.account.reinstated": status("active"),
    "evt.identity.api_key.created": keyPurge,
    "evt.identity.api_key.revoked": keyPurge,
  };
}

export const deadLetters = (db: Kysely<DB>) => deadLetterSink(db, "consumer:identity");
