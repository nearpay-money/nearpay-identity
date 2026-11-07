/**
 * Accounts (lld/identity.md §5–§7): read/update, live-mode requirements, and the state compliance
 * drives (KYB status, suspension). Every change bumps the version and emits
 * `evt.identity.account.updated` in the same transaction; `live_enabled` is recomputed on every
 * relevant change.
 */
import { withTx } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { type AccountFields, type AccountPatch, applyPatch, SettingError } from "../domain/account/account.js";
import { liveEnabled, missingRequirements } from "../domain/settlement-destination/destination.js";
import type { AccountStatus, KybStatus } from "../infra/db/schema.js";
import { type Actor, audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";
import { type AccountRow, accountView } from "./views.js";

export async function loadAccount(tx: Tx | Identity["db"], accountUuid: string, lock = false): Promise<AccountRow> {
  let q = tx.selectFrom("accounts").selectAll().where("id", "=", accountUuid);
  if (lock) q = q.forUpdate();
  const a = await q.executeTakeFirst();
  if (!a) throw ApiError.missing("account", accountUuid);
  return a;
}

async function hasActiveLiveDestination(tx: Tx, accountUuid: string): Promise<boolean> {
  const r = await tx
    .selectFrom("settlement_destinations")
    .select("id")
    .where("account_id", "=", accountUuid)
    .where("livemode", "=", true)
    .where("status", "=", "active")
    .limit(1)
    .executeTakeFirst();
  return r !== undefined;
}

/**
 * Writes account changes (plus the recomputed `live_enabled`) and emits `account.updated` when
 * anything changed. `prev` must be the row locked in `tx`.
 */
export async function saveAccount(
  tx: Tx,
  prev: AccountRow,
  changes: Partial<
    Pick<
      AccountRow,
      "display_name" | "country" | "fee_bearer" | "settings" | "kyb_status" | "status" | "verified_legal_name"
    >
  >,
): Promise<AccountRow> {
  const merged = { ...prev, ...changes };
  const live = liveEnabled(merged, await hasActiveLiveDestination(tx, prev.id));
  const next = { ...merged, live_enabled: live };
  const changed =
    (
      ["display_name", "country", "fee_bearer", "kyb_status", "status", "live_enabled", "verified_legal_name"] as const
    ).some((k) => next[k] !== prev[k]) || JSON.stringify(next.settings) !== JSON.stringify(prev.settings);
  if (!changed) return prev;
  const now = await dbNow(tx);
  const updated = await tx
    .updateTable("accounts")
    .set({
      display_name: next.display_name,
      country: next.country,
      fee_bearer: next.fee_bearer,
      settings: JSON.stringify(next.settings),
      kyb_status: next.kyb_status,
      status: next.status,
      live_enabled: next.live_enabled,
      verified_legal_name: next.verified_legal_name,
      updated_at: now,
      version: prev.version + 1,
    })
    .where("id", "=", prev.id)
    .returningAll()
    .executeTakeFirstOrThrow();
  const previous: Record<string, unknown> = {};
  for (const k of [
    "display_name",
    "country",
    "fee_bearer",
    "kyb_status",
    "status",
    "live_enabled",
    "verified_legal_name",
  ] as const)
    if (updated[k] !== prev[k]) previous[k] = prev[k];
  if (JSON.stringify(updated.settings) !== JSON.stringify(prev.settings)) previous.settings = prev.settings;
  const view = accountView(updated);
  await emitEvent(tx, {
    subject: "evt.identity.account.updated",
    aggregate: { type: "account", id: view.id, version: updated.version },
    accountUuid: updated.id,
    livemode: null,
    object: view,
    previous,
  });
  return updated;
}

/** Recomputes `live_enabled` (after a destination change). */
export async function refreshLiveEnabled(tx: Tx, accountUuid: string): Promise<void> {
  await saveAccount(tx, await loadAccount(tx, accountUuid, true), {});
}

export async function getAccount(id: Identity, accountId: string) {
  return accountView(await loadAccount(id.db, toUuid(accountId, "acct")));
}

export async function updateAccount(
  id: Identity,
  accountId: string,
  patch: AccountPatch,
  o: { actor: Actor; steppedUp: boolean },
) {
  return withTx(id.db, async (tx) => {
    const a = await loadAccount(tx, toUuid(accountId, "acct"), true);
    const current: AccountFields = {
      display_name: a.display_name,
      country: a.country ? a.country.trim() : null,
      fee_bearer: a.fee_bearer,
      settings: a.settings,
    };
    let r: ReturnType<typeof applyPatch>;
    try {
      r = applyPatch(current, patch);
    } catch (e) {
      if (e instanceof SettingError)
        throw new ApiError("invalid_setting", { params: { setting: e.param }, param: e.param });
      throw e;
    }
    if (r.moneyChanged && !o.steppedUp) throw new ApiError("step_up_required");
    if (!r.changed) return accountView(a);
    const updated = await saveAccount(tx, a, r.next);
    await audit(id, tx, {
      accountUuid: a.id,
      actor: o.actor,
      action: "account.updated",
      target: { type: "account", id: accountId },
      details: { fields: Object.keys(patch), money: r.moneyChanged },
    });
    return accountView(updated);
  });
}

export async function getRequirements(id: Identity, accountId: string) {
  const a = await loadAccount(id.db, toUuid(accountId, "acct"));
  const active = await withTx(id.db, (tx) => hasActiveLiveDestination(tx, a.id));
  return {
    object: "account_requirements" as const,
    live_enabled: a.live_enabled,
    missing: missingRequirements(a, active),
  };
}

/**
 * `evt.compliance.kyb.*` (consumer): applied only when newer than the last applied KYB event.
 * On `approved` the ops-approved, self-declared legal name and country of incorporation (read from
 * compliance before the transaction) become `verified_legal_name` / `country` (ADR-0020: reviewed by
 * NearPay ops, not third-party verified). Leaving `approved` clears `verified_legal_name`, so checkout
 * and sentinel's `kyb_verified` never show a name ops no longer stands behind.
 */
export async function setKybStatus(
  tx: Tx,
  accountUuid: string,
  status: KybStatus,
  sourceVersion: number,
  approved?: { legalName: string; country: string | null },
): Promise<boolean> {
  const a = await tx.selectFrom("accounts").selectAll().where("id", "=", accountUuid).forUpdate().executeTakeFirst();
  if (!a || sourceVersion <= a.kyb_source_version) return false;
  await tx.updateTable("accounts").set({ kyb_source_version: sourceVersion }).where("id", "=", a.id).execute();
  const name =
    status === "approved"
      ? {
          verified_legal_name: approved?.legalName ?? a.verified_legal_name,
          ...(approved?.country ? { country: approved.country } : {}),
        }
      : { verified_legal_name: null };
  await saveAccount(tx, { ...a, kyb_source_version: sourceVersion }, { kyb_status: status, ...name });
  return true;
}

/** `evt.compliance.account.suspended|reinstated` (consumer), ordered by the compliance version. */
export async function setAccountStatus(
  tx: Tx,
  accountUuid: string,
  status: AccountStatus,
  sourceVersion: number,
): Promise<boolean> {
  const a = await tx.selectFrom("accounts").selectAll().where("id", "=", accountUuid).forUpdate().executeTakeFirst();
  if (!a || a.status === "closed" || sourceVersion <= a.status_source_version) return false;
  await tx.updateTable("accounts").set({ status_source_version: sourceVersion }).where("id", "=", a.id).execute();
  await saveAccount(tx, { ...a, status_source_version: sourceVersion }, { status });
  return true;
}
