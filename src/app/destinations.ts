/**
 * Settlement destinations (lld/identity.md §5, §8.2, FR-SET-01…04, INV-1). Every transition writes
 * the row, a transition row and the outbox event in one transaction.
 *
 * Live: create (screening allow, unique, no recovery lock) → pending_verification + challenge →
 * attest (NEP-413 / EIP-191 ownership proof) → cooling_off (`active_at = now + cool-off`, every
 * owner/admin notified) → job `destination.activate` (re-screen) → active. Test mode: active at
 * once with `verification: test`. Only a stepped-up owner/admin session can change destinations;
 * API keys never can.
 */
import { randomBytes } from "node:crypto";
import type { DESTINATION_SIGNING_STANDARDS } from "@nearpay/spec";
import { getChain, validateAddress } from "@nearpay-internal/chains";
import { enqueueJob, sql, withTx } from "@nearpay-internal/db";
import { HttpError } from "@nearpay-internal/http";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import type { Subject } from "@nearpay-internal/spec";
import {
  type ApprovalContext,
  afterAttestation,
  atActivation,
  type Decision,
  decide,
  effectiveRequired,
  isExpired,
  type ManagerGrant,
  PENDING_DESTINATION_TTL_MS,
} from "../domain/approval/approval.js";
import {
  approvalsRequired,
  attestationMessage,
  BITCOIN_DESTINATION_HINT,
  bitcoinAddressType,
  bitcoinDestinationAllowed,
  CHALLENGE_TTL_MS,
  NEP413_RECIPIENT,
  type SigningStandard,
  signingStandard,
  transition,
  VERIFIABLE_STANDARDS,
} from "../domain/settlement-destination/destination.js";
import { AttestationUnavailable, verifyAttestation } from "../infra/crypto/attestation.js";
import type { DestinationStatus } from "../infra/db/schema.js";
import { refreshLiveEnabled } from "./accounts.js";
import { type Actor, audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";
import {
  type ApprovalRow,
  type DestinationRow,
  destinationView,
  fingerprintOf,
  internalDestinationView,
} from "./views.js";

export const ACTIVATE_JOB = "destination.activate";

type DestinationEvent = "created" | "pending_approval" | "cooling_off" | "activated" | "disabled" | "default_changed";

// ---------------------------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------------------------

async function defaultsOf(db: Identity["db"] | Tx, accountUuid: string, livemode: boolean) {
  const rows = await db
    .selectFrom("account_default_destinations")
    .select(["asset_id", "destination_id"])
    .where("account_id", "=", accountUuid)
    .where("livemode", "=", livemode)
    .execute();
  return rows;
}

const isDefaultIn = (defs: { destination_id: string }[], d: DestinationRow) =>
  defs.some((x) => x.destination_id === d.id);

/** Approval rows per destination, oldest first (two-approver rule, §5). */
async function approvalsOf(db: Identity["db"] | Tx, ids: readonly string[]): Promise<Map<string, ApprovalRow[]>> {
  const out = new Map<string, ApprovalRow[]>(ids.map((i) => [i, []]));
  if (!ids.length) return out;
  const rows = await db
    .selectFrom("destination_approvals")
    .select(["destination_id", "user_id", "decision"])
    .where("destination_id", "in", [...ids])
    .orderBy("created_at")
    .orderBy("user_id")
    .execute();
  for (const r of rows) out.get(r.destination_id)?.push({ user_id: r.user_id, decision: r.decision });
  return out;
}

const approvalsFor = async (db: Identity["db"] | Tx, d: DestinationRow) =>
  (await approvalsOf(db, [d.id])).get(d.id) ?? [];

/** The account's owner/admin grant history (migration 0005; written by the memberships trigger). */
async function managerGrants(db: Identity["db"] | Tx, accountUuid: string): Promise<ManagerGrant[]> {
  const rows = await db
    .selectFrom("manager_grants")
    .select(["user_id", "granted_at", "qualifies_at", "revoked_at"])
    .where("account_id", "=", accountUuid)
    .execute();
  return rows.map((g) => ({
    userId: g.user_id,
    grantedAt: g.granted_at.getTime(),
    qualifiesAt: g.qualifies_at.getTime(),
    revokedAt: g.revoked_at ? g.revoked_at.getTime() : null,
  }));
}

/** What the two-approver rule is evaluated against, on the database clock (the trigger's clock). */
async function approvalContext(id: Identity, tx: Tx, d: DestinationRow): Promise<ApprovalContext> {
  return {
    createdAt: d.created_at.getTime(),
    now: (await dbNow(tx)).getTime(),
    cooloffMs: id.cooloffMs,
    grants: await managerGrants(tx, d.account_id),
  };
}

const records = (approvals: ApprovalRow[]) => approvals.map((a) => ({ userId: a.user_id, decision: a.decision }));

const expiredConflict = () =>
  new ApiError("state_conflict", {
    params: { object: "settlement_destination", state: "expired" },
    message: `The settlement_destination expired ${PENDING_DESTINATION_TTL_MS / 86_400_000} days after creation; add it again.`,
  });

/** Rails minimums for active destinations (cached 1 h; unavailable → null, §10). */
async function minimumsFor(id: Identity, rows: DestinationRow[]): Promise<Map<string, number | null>> {
  const out = new Map<string, number | null>();
  const cache = id.cache.local<{ v: number | null }>("minimums", 3_600_000);
  const missing: DestinationRow[] = [];
  for (const d of rows) {
    if (d.status !== "active") continue;
    const k = `${d.chain}|${d.address_norm}|${d.asset_id}`;
    const hit = cache.get(k);
    if (hit) out.set(d.id, hit.v);
    else missing.push(d);
  }
  if (missing.length) {
    try {
      const keys = missing.map((d) => `${d.chain}|${d.address_norm}|${d.asset_id}`);
      const r = await id.peers.minimums(keys);
      missing.forEach((d, i) => {
        const v = r[keys[i] as string]?.min_usd_micros ?? null;
        cache.set(keys[i] as string, { v });
        out.set(d.id, v);
      });
    } catch (e) {
      id.log.warn({ err: e }, "destination minimums unavailable");
    }
  }
  return out;
}

export async function listDestinations(
  id: Identity,
  accountId: string,
  livemode: boolean,
  q: {
    limit: number;
    starting_after?: string | undefined;
    ending_before?: string | undefined;
    status?: string | undefined;
  },
) {
  const acct = toUuid(accountId, "acct");
  let query = id.db
    .selectFrom("settlement_destinations")
    .selectAll()
    .where("account_id", "=", acct)
    .where("livemode", "=", livemode)
    .orderBy("created_at", "desc")
    .orderBy("id", "desc")
    .limit(q.limit + 1);
  if (q.status) query = query.where("status", "=", q.status as DestinationStatus);
  if (q.starting_after) query = query.where("id", "<", toUuid(q.starting_after, "sd"));
  if (q.ending_before) query = query.where("id", ">", toUuid(q.ending_before, "sd"));
  const rows = await query.execute();
  const page = rows.slice(0, q.limit);
  const [defs, mins, approvals] = await Promise.all([
    defaultsOf(id.db, acct, livemode),
    minimumsFor(id, page),
    approvalsOf(
      id.db,
      page.map((d) => d.id),
    ),
  ]);
  return {
    object: "list" as const,
    data: page.map((d) =>
      destinationView(d, {
        isDefault: isDefaultIn(defs, d),
        minUsdMicros: mins.get(d.id) ?? null,
        approvals: approvals.get(d.id) ?? [],
      }),
    ),
    has_more: rows.length > q.limit,
    url: "/v1/settlement_destinations",
  };
}

async function loadOwn(
  db: Identity["db"] | Tx,
  accountId: string,
  livemode: boolean,
  destinationId: string,
  lock = false,
) {
  let q = db
    .selectFrom("settlement_destinations")
    .selectAll()
    .where("id", "=", toUuid(destinationId, "sd"))
    .where("account_id", "=", toUuid(accountId, "acct"))
    .where("livemode", "=", livemode);
  if (lock) q = q.forUpdate();
  const d = await q.executeTakeFirst();
  if (!d) throw ApiError.missing("settlement_destination", destinationId, "id");
  return d;
}

export async function getDestination(id: Identity, accountId: string, livemode: boolean, destinationId: string) {
  const d = await loadOwn(id.db, accountId, livemode, destinationId);
  const [defs, mins, approvals] = await Promise.all([
    defaultsOf(id.db, d.account_id, d.livemode),
    minimumsFor(id, [d]),
    approvalsFor(id.db, d),
  ]);
  return destinationView(d, { isDefault: isDefaultIn(defs, d), minUsdMicros: mins.get(d.id) ?? null, approvals });
}

/** `GET /internal/settlement-destinations/{id}` (any status, any account). */
export async function getInternalDestination(id: Identity, destinationId: string) {
  const d = await id.db
    .selectFrom("settlement_destinations")
    .selectAll()
    .where("id", "=", toUuid(destinationId, "sd"))
    .executeTakeFirst();
  if (!d) throw ApiError.missing("settlement_destination", destinationId, "id");
  const defs = await defaultsOf(id.db, d.account_id, d.livemode);
  return internalDestinationView(d, {
    isDefault: isDefaultIn(defs, d),
    minUsdMicros: null,
    approvals: await approvalsFor(id.db, d),
  });
}

// ---------------------------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------------------------

async function record(
  id: Identity,
  tx: Tx,
  d: DestinationRow,
  to: DestinationStatus,
  cause: string,
  actor: string,
  set: Partial<
    Pick<
      DestinationRow,
      | "active_at"
      | "attestation"
      | "verification"
      | "disabled_at"
      | "disabled_reason"
      | "screening_id"
      | "approvals_required"
    >
  > = {},
): Promise<DestinationRow> {
  const now = await dbNow(tx);
  let updated: DestinationRow;
  try {
    updated = await tx
      .updateTable("settlement_destinations")
      .set({
        status: to,
        ...set,
        attestation:
          set.attestation === undefined ? undefined : set.attestation === null ? null : JSON.stringify(set.attestation),
        updated_at: now,
        version: d.version + 1,
      } as never)
      .where("id", "=", d.id)
      .where("version", "=", d.version)
      .returningAll()
      .executeTakeFirstOrThrow();
  } catch (e) {
    // the database's two-approver check (migration 0004) caught a transition without enough approvers
    if ((e as { constraint?: string }).constraint === "destination_approvals_complete")
      throw new ApiError("approver_conflict", { params: { reason: "a second owner or admin must approve it" } });
    throw e;
  }
  await tx
    .insertInto("settlement_destination_transitions")
    .values({ id: uuidv7(), destination_id: d.id, from_state: d.status, to_state: to, cause, actor })
    .execute();
  id.metrics.destinationTransition(to);
  return updated;
}

async function emitDestination(tx: Tx, d: DestinationRow, event: DestinationEvent, previous?: Record<string, unknown>) {
  const defs = await defaultsOf(tx, d.account_id, d.livemode);
  await emitEvent(tx, {
    subject: `evt.identity.settlement_destination.${event}` as Subject,
    aggregate: { type: "settlement_destination", id: fromUuid("sd", d.id), version: d.version },
    accountUuid: d.account_id,
    livemode: d.livemode,
    object: internalDestinationView(d, {
      isDefault: isDefaultIn(defs, d),
      minUsdMicros: null,
      approvals: await approvalsFor(tx, d),
    }),
    ...(previous ? { previous } : {}),
  });
}

/** Makes `d` the default for its asset (and the account when none is set) if it is the first. */
async function adoptAsDefaultIfFirst(tx: Tx, d: DestinationRow): Promise<boolean> {
  const defs = await defaultsOf(tx, d.account_id, d.livemode);
  let changed = false;
  if (!defs.some((x) => x.asset_id === d.asset_id)) {
    await tx
      .insertInto("account_default_destinations")
      .values({ account_id: d.account_id, livemode: d.livemode, asset_id: d.asset_id, destination_id: d.id })
      .execute();
    changed = true;
  }
  if (!defs.some((x) => x.asset_id === null)) {
    await tx
      .insertInto("account_default_destinations")
      .values({ account_id: d.account_id, livemode: d.livemode, asset_id: null, destination_id: d.id })
      .execute();
    changed = true;
  }
  return changed;
}

async function becomeActive(
  id: Identity,
  tx: Tx,
  d: DestinationRow,
  cause: string,
  actor: string,
  set: Parameters<typeof record>[6],
) {
  const active = await record(id, tx, d, "active", cause, actor, { active_at: await dbNow(tx), ...set });
  await emitDestination(tx, active, "activated");
  if (await adoptAsDefaultIfFirst(tx, active)) await emitDestination(tx, active, "default_changed");
  if (active.livemode) await refreshLiveEnabled(tx, active.account_id);
  return active;
}

function addressInvalid(address: string, chain: string, detail?: string) {
  return new ApiError("address_invalid", {
    params: { address, chain },
    param: "address",
    ...(detail ? { message: `${address} is not a valid address on ${chain}: ${detail}.` } : {}),
  });
}

export interface CreateDestinationInput {
  asset_id: string;
  type: "chain_address" | "intents_account";
  chain: string;
  address: string;
  label: string;
}

export async function createDestination(
  id: Identity,
  accountId: string,
  livemode: boolean,
  b: CreateDestinationInput,
  actor: Actor & { userUuid: string },
) {
  const acct = toUuid(accountId, "acct");
  // 1. shape: Intents accounts live on near:mainnet; addresses must be valid for their chain
  if (b.type === "intents_account" && b.chain !== "near:mainnet")
    throw ApiError.invalid("Intents accounts use chain near:mainnet", "chain");
  const info = getChain(b.chain);
  if (!info) throw addressInvalid(b.address, b.chain, "unsupported chain");
  const v = validateAddress(b.chain, b.address);
  if (!v.ok) throw addressInvalid(b.address, b.chain, v.reason);
  const addressNorm = v.normalized;
  // Bitcoin: P2WPKH / P2TR only, both modes (§20) — BIP-322 simple cannot prove the other types
  if (info.family === "bitcoin" && !bitcoinDestinationAllowed(addressNorm))
    throw new ApiError("address_invalid", {
      params: { address: b.address, chain: b.chain },
      param: "address",
      message: `${BITCOIN_DESTINATION_HINT}: ${b.address} is a ${bitcoinAddressType(addressNorm)} address, which cannot prove ownership with BIP-322.`,
    });

  // 2. asset and chain support (rails catalogue)
  const asset = await id.peers.asset(b.asset_id).catch((e: unknown) => {
    throw e instanceof HttpError ? ApiError.fromUpstream(e) : e;
  });
  if (!asset || (b.type === "chain_address" && asset.chain !== b.chain))
    throw new ApiError("asset_unsupported", { params: { asset_id: b.asset_id }, param: "asset_id" });
  if (b.type === "chain_address") {
    const { profiles } = await id.peers.chainProfiles();
    const profile = profiles.find((p) => p.chain === b.chain);
    if (profile?.memo_mode === "required") throw new ApiError("memo_destination_unsupported");
  }
  const standard = signingStandard(b.type, info.family, addressNorm);
  if (livemode && !VERIFIABLE_STANDARDS.includes(standard))
    throw ApiError.invalid(`live destinations on ${info.name} cannot be attested`, "chain");

  // 3. recovery lock (48 h after an account recovery, §12)
  const account = await id.db.selectFrom("accounts").selectAll().where("id", "=", acct).executeTakeFirstOrThrow();
  if (account.recovered_at && account.recovered_at.getTime() + id.recoveryLockMs > id.now())
    throw new ApiError("recovery_lock", {
      params: { until: new Date(account.recovered_at.getTime() + id.recoveryLockMs).toISOString() },
    });

  // 4. screening (fail closed, §10)
  let screening: Awaited<ReturnType<Identity["peers"]["screen"]>>;
  try {
    screening = await id.peers.screen({
      subject_type: "destination",
      chain: b.chain,
      subject: addressNorm,
      context: "destination",
      account_id: accountId,
      livemode,
    });
  } catch (e) {
    id.log.error({ err: e }, "destination screening unavailable");
    throw new ApiError("screening_unavailable");
  }
  if (screening.decision === "block") throw new ApiError("screening_blocked");

  // 5. insert under the (chain, address, asset) advisory lock (L-ID-06)
  return withTx(id.db, async (tx) => {
    await sql`select pg_advisory_xact_lock(hashtext(${`${b.chain}|${addressNorm}|${b.asset_id}`}))`.execute(tx);
    if (livemode) {
      const taken = await tx
        .selectFrom("settlement_destinations")
        .select(["id", "account_id"])
        .where("chain", "=", b.chain)
        .where("address_norm", "=", addressNorm)
        .where("asset_id", "=", b.asset_id)
        .where("livemode", "=", true)
        .where("status", "in", ["pending_approval", "cooling_off", "active"])
        .executeTakeFirst();
      if (taken) throw new ApiError("destination_in_use");
    } else {
      const dup = await tx
        .selectFrom("settlement_destinations")
        .select("id")
        .where("account_id", "=", acct)
        .where("livemode", "=", false)
        .where("chain", "=", b.chain)
        .where("address_norm", "=", addressNorm)
        .where("asset_id", "=", b.asset_id)
        .where("status", "<>", "disabled")
        .executeTakeFirst();
      if (dup) throw new ApiError("destination_in_use");
    }
    // two-approver rule (§5): fixed at creation from the owners/admins of the account now
    const managers = livemode
      ? Number(
          (
            await tx
              .selectFrom("memberships")
              .innerJoin("users", "users.id", "memberships.user_id")
              .select((eb) => eb.fn.countAll<string>().as("n"))
              .where("memberships.account_id", "=", acct)
              .where("memberships.role", "in", ["owner", "admin"])
              .where("users.status", "=", "active")
              .executeTakeFirstOrThrow()
          ).n,
        )
      : 0;
    // … and never below the 30-day high-water mark of owners/admins (removing them first does not help)
    const required = livemode
      ? effectiveRequired(approvalsRequired(managers, true), await managerGrants(tx, acct), (await dbNow(tx)).getTime())
      : 1;
    const created = await tx
      .insertInto("settlement_destinations")
      .values({
        id: uuidv7(),
        account_id: acct,
        livemode,
        asset_id: b.asset_id,
        type: b.type,
        chain: b.chain,
        address: b.address,
        address_norm: addressNorm,
        label: b.label,
        status: "pending_verification",
        verification: livemode ? "signature" : "test",
        screening_id: screening.screening_id,
        created_by: actor.userUuid,
        approvals_required: required,
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    // the creator's creation is the first approval: the (destination, user) key refuses them a second one
    if (livemode)
      await tx
        .insertInto("destination_approvals")
        .values({ destination_id: created.id, user_id: actor.userUuid, decision: "approve" })
        .execute();
    await tx
      .insertInto("settlement_destination_transitions")
      .values({
        id: uuidv7(),
        destination_id: created.id,
        from_state: null,
        to_state: "pending_verification",
        cause: "created",
        actor: actor.id,
      })
      .execute();
    await emitDestination(tx, created, "created");
    await audit(id, tx, {
      accountUuid: acct,
      actor,
      action: "destination.created",
      target: { type: "settlement_destination", id: fromUuid("sd", created.id) },
      details: { chain: b.chain, asset_id: b.asset_id, livemode, approvals_required: created.approvals_required },
    });

    if (!livemode) {
      const active = await becomeActive(id, tx, created, "test_mode", actor.id, {});
      const defs = await defaultsOf(tx, acct, false);
      return destinationView(active, { isDefault: isDefaultIn(defs, active), minUsdMicros: null, approvals: [] });
    }

    return destinationView(created, {
      isDefault: false,
      minUsdMicros: null,
      approvals: await approvalsFor(tx, created),
      challenge: await issueChallenge(tx, accountId, created, standard),
    });
  });
}

/**
 * A fresh attestation challenge for a live destination (10 minutes, single use): a random nonce and
 * the §8.2 message, stored with the signing standard. Returned in the spec's `AttestationChallenge`
 * shape (create and `…/challenge` answer the same way).
 */
async function issueChallenge(tx: Tx, accountId: string, d: DestinationRow, standard: SigningStandard) {
  const nonce = randomBytes(32);
  // whole seconds: the signed message and `expires_at` (unix seconds) state the same instant
  const expiresAt = new Date(Math.floor(((await dbNow(tx)).getTime() + CHALLENGE_TTL_MS) / 1000) * 1000);
  const message = attestationMessage({
    account: accountId,
    livemode: d.livemode,
    assetId: d.asset_id,
    chain: d.chain,
    address: d.address,
    nonceHex: nonce.toString("hex"),
    expiresAt,
  });
  const challengeId = uuidv7();
  await tx
    .insertInto("attestation_challenges")
    .values({ id: challengeId, destination_id: d.id, standard, message, nonce, expires_at: expiresAt })
    .execute();
  return {
    id: fromUuid("chl", challengeId),
    message,
    signing_standard: standard,
    nonce: standard === "nep413" ? nonce.toString("base64") : null,
    recipient: standard === "nep413" ? NEP413_RECIPIENT : null,
    expires_at: Math.floor(expiresAt.getTime() / 1000),
  };
}

/**
 * `POST /v1/settlement_destinations/{id}/challenge` (spec 0.1.5, CR-15-03): a new attestation
 * challenge for a destination still in `pending_verification` (its earlier challenge expired or was
 * lost), instead of disabling and re-adding it. Earlier unused challenges are superseded in the same
 * transaction and stop being accepted by `…/attest`. Any other status → `409 state_conflict`. The
 * route itself requires a stepped-up owner/admin session (spec, enforced by the bootstrap) and is
 * idempotent on `Idempotency-Key` (a replay returns the same challenge without superseding it).
 */
export async function challengeDestination(
  id: Identity,
  accountId: string,
  livemode: boolean,
  destinationId: string,
  actor: Actor,
) {
  return withTx(id.db, async (tx) => {
    const d = await loadOwn(tx, accountId, livemode, destinationId, true);
    if (!transition(d.status, "challenge").ok)
      throw new ApiError("state_conflict", { params: { object: "settlement_destination", state: d.status } });
    if (isExpired(d.created_at.getTime(), (await dbNow(tx)).getTime())) throw expiredConflict();
    const info = getChain(d.chain);
    if (!info) throw new Error(`destination ${destinationId} is on an unsupported chain ${d.chain}`);
    const standard = signingStandard(d.type, info.family, d.address_norm);
    const now = await dbNow(tx);
    const superseded = await tx
      .updateTable("attestation_challenges")
      .set({ superseded_at: now })
      .where("destination_id", "=", d.id)
      .where("used_at", "is", null)
      .where("superseded_at", "is", null)
      .executeTakeFirst();
    const challenge = await issueChallenge(tx, accountId, d, standard);
    await audit(id, tx, {
      accountUuid: d.account_id,
      actor,
      action: "destination.challenge_issued",
      target: { type: "settlement_destination", id: destinationId },
      details: { challenge: challenge.id, superseded: Number(superseded.numUpdatedRows) },
    });
    return destinationView(d, {
      isDefault: false,
      minUsdMicros: null,
      approvals: await approvalsFor(tx, d),
      challenge,
    });
  });
}

export async function attestDestination(
  id: Identity,
  accountId: string,
  livemode: boolean,
  destinationId: string,
  b: {
    challenge_id: string;
    /** spec 0.4.0 `attestSettlementDestination.body.standard`: nep413 | eip191 | solana | bip322 */
    standard: (typeof DESTINATION_SIGNING_STANDARDS)[number];
    signature: string;
    public_key?: string | undefined;
  },
  actor: Actor,
) {
  const d0 = await loadOwn(id.db, accountId, livemode, destinationId);
  const step = transition(d0.status, "attest");
  if (!step.ok)
    throw new ApiError("state_conflict", { params: { object: "settlement_destination", state: d0.status } });
  const c = await id.db
    .selectFrom("attestation_challenges")
    .selectAll()
    .where("id", "=", toUuid(b.challenge_id, "chl"))
    .where("destination_id", "=", d0.id)
    .executeTakeFirst();
  if (!c || c.used_at || c.superseded_at || c.expires_at.getTime() <= id.now()) throw new ApiError("challenge_expired");
  if (c.standard !== b.standard) {
    id.metrics.attestationFailure(b.standard);
    throw new ApiError("attestation_invalid", { message: `This destination signs with ${c.standard}.` });
  }

  let result: Awaited<ReturnType<typeof verifyAttestation>>;
  try {
    result = await verifyAttestation(
      {
        standard: b.standard,
        chain: d0.chain,
        addressNorm: d0.address_norm,
        message: c.message,
        nonce: new Uint8Array(c.nonce),
        signature: b.signature,
        publicKey: b.public_key,
      },
      id.lookups,
    );
  } catch (e) {
    if (e instanceof AttestationUnavailable) {
      id.log.warn({ err: e }, "attestation could not be checked");
      throw new ApiError("api_error", {
        message: "Ownership could not be checked right now (chain RPC unavailable); retry.",
      });
    }
    throw e;
  }
  if (!result.ok) {
    id.metrics.attestationFailure(b.standard);
    id.log.info({ destination: destinationId, standard: b.standard, reason: result.reason }, "attestation rejected");
    throw new ApiError("attestation_invalid", result.hint ? { message: result.hint } : {});
  }

  return withTx(id.db, async (tx) => {
    const d = await loadOwn(tx, accountId, livemode, destinationId, true);
    const s = transition(d.status, "attest");
    if (!s.ok) throw new ApiError("state_conflict", { params: { object: "settlement_destination", state: d.status } });
    const ctx = await approvalContext(id, tx, d);
    if (isExpired(ctx.createdAt, ctx.now)) throw expiredConflict();
    const used = await tx
      .updateTable("attestation_challenges")
      .set({ used_at: await dbNow(tx) })
      .where("id", "=", c.id)
      .where("used_at", "is", null)
      // a challenge superseded while its signature was being checked is no longer accepted
      .where("superseded_at", "is", null)
      .executeTakeFirst();
    if (Number(used.numUpdatedRows) !== 1) throw new ApiError("challenge_expired");
    const now = await dbNow(tx);
    const approvals = await approvalsFor(tx, d);
    // two approvers required (now, not only at creation) and not enough qualifying approvals: wait
    const { required, to } = afterAttestation(ctx, d.approvals_required, records(approvals));
    const activeAt = new Date(now.getTime() + id.cooloffMs);
    const attestation = {
      standard: b.standard,
      message: c.message,
      signature: b.signature,
      public_key: result.publicKey,
      verified_at: now.toISOString(),
      method: result.method,
    };
    // a concurrent attestation of the same address by another account loses on the unique index
    let next: DestinationRow;
    try {
      next = await record(id, tx, d, to, "attested", actor.id, {
        attestation,
        approvals_required: required,
        ...(to === "cooling_off" ? { active_at: activeAt } : {}),
      });
    } catch (e) {
      if ((e as { code?: string }).code === "23505") throw new ApiError("destination_in_use");
      throw e;
    }
    if (to === "cooling_off") await startCooloff(tx, next, activeAt);
    else await emitDestination(tx, next, "pending_approval");
    await audit(id, tx, {
      accountUuid: d.account_id,
      actor,
      action: "destination.attested",
      target: { type: "settlement_destination", id: destinationId },
      details: {
        standard: b.standard,
        method: result.method,
        ...(to === "cooling_off" ? { active_at: activeAt.toISOString() } : { awaiting_approval: true }),
      },
    });
    return destinationView(next, { isDefault: false, minUsdMicros: null, approvals });
  });
}

/** Cool-off start (after attestation or the last approval): event, then the activation job at `active_at`. */
async function startCooloff(tx: Tx, d: DestinationRow, activeAt: Date) {
  await emitDestination(tx, d, "cooling_off");
  await enqueueJob(tx, {
    kind: ACTIVATE_JOB,
    payload: { destination_id: d.id },
    runAt: activeAt,
    dedupeKey: `${ACTIVATE_JOB}:sd:${d.id}`,
    maxAttempts: 50,
  });
}

/**
 * `POST /v1/settlement_destinations/{id}/approve` (spec 0.2.0, §5 two-approver rule). Checked on the
 * session's user id: the approver must be a current owner/admin other than the creator and every
 * earlier approver, and (to approve) hold the role under a grant older than the destination and past
 * its tenure (`403 approver_conflict`; domain/approval/approval.ts, repeated by the approvals primary
 * key and the `destination_approvals_complete` trigger); the requirement is re-derived from today's
 * team and its 30-day high-water mark; destinations pending 7 days are expired (`409 state_conflict`). The last approval starts the cool-off (job at
 * `active_at`); a rejection disables the destination (`merchant`). Only `pending_approval`.
 */
export async function approveDestination(
  id: Identity,
  accountId: string,
  livemode: boolean,
  destinationId: string,
  decision: Decision,
  actor: Actor & { userUuid: string },
) {
  return withTx(id.db, async (tx) => {
    const d = await loadOwn(tx, accountId, livemode, destinationId, true);
    // the role in the request token may be up to 10 s old: re-check the membership in this transaction
    const m = await tx
      .selectFrom("memberships")
      .select("role")
      .where("account_id", "=", d.account_id)
      .where("user_id", "=", actor.userUuid)
      .executeTakeFirst();
    if (m?.role !== "owner" && m?.role !== "admin")
      throw new ApiError("permission_denied", { params: { action: "approve settlement destinations" } });
    // an approval is a destination change: refused for 48 h after an account recovery (§12); a reject is not
    if (decision === "approve") {
      const a = await tx
        .selectFrom("accounts")
        .select("recovered_at")
        .where("id", "=", d.account_id)
        .executeTakeFirstOrThrow();
      if (a.recovered_at && a.recovered_at.getTime() + id.recoveryLockMs > id.now())
        throw new ApiError("recovery_lock", {
          params: { until: new Date(a.recovered_at.getTime() + id.recoveryLockMs).toISOString() },
        });
    }
    const approvals = await approvalsFor(tx, d);
    const out = decide(
      {
        ...(await approvalContext(id, tx, d)),
        status: d.status,
        required: d.approvals_required,
        createdBy: d.created_by,
        approvals: records(approvals),
      },
      actor.userUuid,
      decision,
    );
    if (!out.ok) {
      if (out.error === "state_conflict") {
        if (out.reason === "expired") throw expiredConflict();
        throw new ApiError("state_conflict", { params: { object: "settlement_destination", state: d.status } });
      }
      throw new ApiError("approver_conflict", { params: { reason: out.reason } });
    }
    try {
      await tx
        .insertInto("destination_approvals")
        .values({ destination_id: d.id, user_id: actor.userUuid, decision })
        .execute();
    } catch (e) {
      if ((e as { code?: string }).code === "23505")
        throw new ApiError("approver_conflict", { params: { reason: "this user already decided on the destination" } });
      throw e;
    }
    let next = d;
    if (out.to === "disabled") next = await disableRow(id, tx, d, "merchant", actor.id);
    else if (out.to === "cooling_off") {
      const activeAt = new Date((await dbNow(tx)).getTime() + id.cooloffMs);
      next = await record(id, tx, d, "cooling_off", "approved", actor.id, {
        active_at: activeAt,
        approvals_required: out.required,
      });
      await startCooloff(tx, next, activeAt);
    } else if (out.required > d.approvals_required)
      // the requirement only ever rises (the public `approval.required` shows it)
      next = await tx
        .updateTable("settlement_destinations")
        .set({ approvals_required: out.required })
        .where("id", "=", d.id)
        .returningAll()
        .executeTakeFirstOrThrow();
    await audit(id, tx, {
      accountUuid: d.account_id,
      actor,
      action: decision === "approve" ? "destination.approved" : "destination.rejected",
      target: { type: "settlement_destination", id: destinationId },
      details: { status: next.status, approvals_required: d.approvals_required },
    });
    return destinationView(next, { isDefault: false, minUsdMicros: null, approvals: await approvalsFor(tx, next) });
  });
}

/**
 * Job `destination.activate` (§9): at `active_at`, re-screen and activate. A block disables the
 * destination (compliance); unavailable screening keeps it cooling off and retries (throws).
 */
export async function activateDestination(
  id: Identity,
  destinationUuid: string,
): Promise<"activated" | "skipped" | "blocked" | "reapproval"> {
  const d0 = await id.db
    .selectFrom("settlement_destinations")
    .selectAll()
    .where("id", "=", destinationUuid)
    .executeTakeFirst();
  if (d0?.status !== "cooling_off") return "skipped";
  if (d0.active_at && d0.active_at.getTime() > id.now() + 1_000) throw new Error("activation is not due yet");
  const screening = await id.peers.screen({
    subject_type: "destination",
    chain: d0.chain,
    subject: d0.address_norm,
    context: "destination",
    account_id: fromUuid("acct", d0.account_id),
    livemode: d0.livemode,
  });
  return withTx(id.db, async (tx) => {
    const d = await tx
      .selectFrom("settlement_destinations")
      .selectAll()
      .where("id", "=", destinationUuid)
      .forUpdate()
      .executeTakeFirstOrThrow();
    if (!transition(d.status, "activate").ok) return "skipped";
    if (screening.decision === "block") {
      await disableRow(id, tx, d, "compliance", "system:activation-screening");
      return "blocked";
    }
    // the approvals are checked again on today's team: a new owner/admin (or a lost approver) sends the
    // destination back to approval instead of activating it
    const check = atActivation(
      await approvalContext(id, tx, d),
      d.approvals_required,
      records(await approvalsFor(tx, d)),
    );
    if (check.to === "pending_approval") {
      const back = await record(id, tx, d, "pending_approval", "approvals_incomplete", "system", {
        active_at: null,
        approvals_required: check.required,
      });
      await emitDestination(tx, back, "pending_approval");
      await audit(id, tx, {
        accountUuid: d.account_id,
        actor: { type: "system", id: "system:activation" },
        action: "destination.approval_required",
        target: { type: "settlement_destination", id: fromUuid("sd", d.id) },
        details: { approvals_required: check.required },
      });
      return "reapproval";
    }
    await becomeActive(id, tx, d, "cooloff_elapsed", "system", {
      screening_id: screening.screening_id,
      approvals_required: check.required,
    });
    return "activated";
  });
}

async function disableRow(
  id: Identity,
  tx: Tx,
  d: DestinationRow,
  reason: "merchant" | "compliance" | "replaced" | "expired",
  actor: string,
  cause = `disabled:${reason}`,
) {
  const now = await dbNow(tx);
  const disabled = await record(id, tx, d, "disabled", cause, actor, {
    disabled_at: now,
    disabled_reason: reason,
  });
  const defs = await defaultsOf(tx, d.account_id, d.livemode);
  const wasDefault = isDefaultIn(defs, d);
  if (wasDefault)
    await tx
      .deleteFrom("account_default_destinations")
      .where("account_id", "=", d.account_id)
      .where("livemode", "=", d.livemode)
      .where("destination_id", "=", d.id)
      .execute();
  await emitDestination(tx, disabled, "disabled", { status: d.status });
  if (wasDefault) await emitDestination(tx, disabled, "default_changed");
  if (d.livemode) await refreshLiveEnabled(tx, d.account_id);
  return disabled;
}

export const EXPIRE_JOB = "destination.expire";

/**
 * Job `destination.expire` (hourly, §9): live destinations still pending (verification or approval)
 * 7 days after creation are disabled (`disabled_reason: expired` since spec 0.2.1, transition cause `expired`, audit
 * `destination.expired`), so a stale pending change cannot be approved later on a changed team.
 */
export async function expirePendingDestinations(id: Identity): Promise<number> {
  const due = await id.db
    .selectFrom("settlement_destinations")
    .select("id")
    .where("livemode", "=", true)
    .where("status", "in", ["pending_verification", "pending_approval"])
    .where("created_at", "<=", sql<Date>`now() - ${`${PENDING_DESTINATION_TTL_MS} milliseconds`}::interval`)
    .limit(500)
    .execute();
  let n = 0;
  for (const { id: sd } of due)
    n += await withTx(id.db, async (tx) => {
      const d = await tx
        .selectFrom("settlement_destinations")
        .selectAll()
        .where("id", "=", sd)
        .forUpdate()
        .executeTakeFirst();
      if (!d || !transition(d.status, "expire").ok || !isExpired(d.created_at.getTime(), (await dbNow(tx)).getTime()))
        return 0;
      await disableRow(id, tx, d, "expired", "system:expiry", "expired");
      await audit(id, tx, {
        accountUuid: d.account_id,
        actor: { type: "system", id: "system:expiry" },
        action: "destination.expired",
        target: { type: "settlement_destination", id: fromUuid("sd", d.id) },
        details: { status: d.status },
      });
      return 1;
    });
  return n;
}

export async function disableDestination(
  id: Identity,
  accountId: string,
  livemode: boolean,
  destinationId: string,
  actor: Actor,
) {
  return withTx(id.db, async (tx) => {
    const d = await loadOwn(tx, accountId, livemode, destinationId, true);
    if (!transition(d.status, "disable").ok)
      throw new ApiError("state_conflict", { params: { object: "settlement_destination", state: d.status } });
    const disabled = await disableRow(id, tx, d, "merchant", actor.id);
    await audit(id, tx, {
      accountUuid: d.account_id,
      actor,
      action: "destination.disabled",
      target: { type: "settlement_destination", id: destinationId },
    });
    return destinationView(disabled, { isDefault: false, minUsdMicros: null, approvals: await approvalsFor(tx, d) });
  });
}

/** `evt.compliance.destination.blocked` (consumer): disable with reason `compliance`. */
export async function blockDestination(id: Identity, tx: Tx, destinationUuid: string): Promise<boolean> {
  const d = await tx
    .selectFrom("settlement_destinations")
    .selectAll()
    .where("id", "=", destinationUuid)
    .forUpdate()
    .executeTakeFirst();
  if (!d || d.status === "disabled") return false;
  await disableRow(id, tx, d, "compliance", "compliance");
  return true;
}

export async function setDefaultDestination(
  id: Identity,
  accountId: string,
  livemode: boolean,
  destinationId: string,
  scope: "asset" | "account",
  actor: Actor,
) {
  return withTx(id.db, async (tx) => {
    const d = await loadOwn(tx, accountId, livemode, destinationId, true);
    if (!transition(d.status, "set_default").ok)
      throw new ApiError("destination_not_active", { params: { destination: destinationId } });
    const assetKey = scope === "asset" ? d.asset_id : null;
    const existing = await tx
      .selectFrom("account_default_destinations")
      .selectAll()
      .where("account_id", "=", d.account_id)
      .where("livemode", "=", d.livemode)
      .where("coalesce_asset", "=", assetKey ?? "*")
      .executeTakeFirst();
    if (existing?.destination_id !== d.id) {
      if (existing)
        await tx
          .updateTable("account_default_destinations")
          .set({ destination_id: d.id, updated_at: await dbNow(tx) })
          .where("account_id", "=", d.account_id)
          .where("livemode", "=", d.livemode)
          .where("coalesce_asset", "=", assetKey ?? "*")
          .execute();
      else
        await tx
          .insertInto("account_default_destinations")
          .values({ account_id: d.account_id, livemode: d.livemode, asset_id: assetKey, destination_id: d.id })
          .execute();
      // the version moves so consumers order default changes
      const bumped = await tx
        .updateTable("settlement_destinations")
        .set({ version: d.version + 1, updated_at: await dbNow(tx) })
        .where("id", "=", d.id)
        .returningAll()
        .executeTakeFirstOrThrow();
      await emitDestination(
        tx,
        bumped,
        "default_changed",
        existing ? { default_was: fromUuid("sd", existing.destination_id) } : undefined,
      );
      await audit(id, tx, {
        accountUuid: d.account_id,
        actor,
        action: "destination.default_set",
        target: { type: "settlement_destination", id: destinationId },
        details: { scope },
      });
    }
    return destinationView(d, { isDefault: true, minUsdMicros: null, approvals: await approvalsFor(tx, d) });
  });
}

export { fingerprintOf };
