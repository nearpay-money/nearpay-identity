/**
 * Domain-event consumers (lld/identity.md §7). Each runs inside the inbox transaction; compliance
 * events are ordered by their aggregate version (a stale event never undoes a newer decision).
 *
 * | subject                                    | handler                                              |
 * |--------------------------------------------|------------------------------------------------------|
 * | evt.compliance.kyb.approved/rejected/needs_info | set `kyb_status`, recompute `live_enabled`      |
 * | evt.compliance.destination.blocked         | disable the destination (reason `compliance`)        |
 * | evt.compliance.account.suspended/reinstated | set the account status                              |
 * | evt.identity.api_key.created/revoked       | purge the key from Valkey and every api replica's LRU |
 */
import type { Envelope, EventHandler } from "@nearpay-internal/bus";
import { deadLetterSink, inboxHandler, type Kysely } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import type { Subject } from "@nearpay-internal/spec";
import { setAccountStatus, setKybStatus } from "../app/accounts.js";
import type { Identity, Tx } from "../app/context.js";
import { blockDestination } from "../app/destinations.js";
import type { DB, KybStatus } from "../infra/db/schema.js";

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
    "evt.compliance.kyb.approved": kyb,
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
