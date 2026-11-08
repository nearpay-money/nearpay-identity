/**
 * Team members, invitations and multi-account sessions (lld/identity.md §5 "Invitation", §6, spec 0.2.0).
 *
 * Owners/admins list and manage members; only owners grant, take away or remove the owner role, and
 * the last owner stays (`409 last_owner`, serialised by locking the account's owner rows). Removing a
 * member revokes their sessions for the account at once; a role change purges their cached sessions.
 * Invitations (7 days, one pending per account and email) mail a single-use link through notify; a
 * signed-in user whose email matches accepts it and the session switches to the joined account
 * (a new user joins through magic-link verification + passkey registration, auth.ts). Team changes emit
 * `evt.identity.member.*` (ids only) in the same transaction and are audited without emails. For 48 h
 * after an account recovery no owner/admin can be invited, promoted, demoted or removed
 * (`403 recovery_lock`); every owner/admin grant is recorded in `manager_grants` by a database trigger
 * (two-approver rule tenure, migration 0005).
 */

import type { Selectable } from "@nearpay-internal/db";
import { sql, withTx } from "@nearpay-internal/db";
import { fromUuid, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { newSecret, sha256 } from "../domain/session/session.js";
import {
  acceptProblem,
  canChangeRole,
  canInvite,
  canRemove,
  effectiveStatus,
  INVITATION_MS,
  isOwnerOrAdmin,
  type Role,
  type TeamCheck,
} from "../domain/team/team.js";
import type { InvitationStatus, InvitationsTable } from "../infra/db/schema.js";
import { currentSessionTx, type RequestMeta, sessionBody } from "./auth.js";
import { type Actor, audit, dbNow, emitEvent, type Identity, type Tx } from "./context.js";

type InvitationRow = Selectable<InvitationsTable>;

const unix = (d: Date) => Math.floor(d.getTime() / 1000);

export interface TeamActor extends Actor {
  readonly userUuid: string;
}

function enforce(c: TeamCheck) {
  if (c.ok) return;
  if (c.error === "last_owner") throw new ApiError("last_owner");
  throw new ApiError("permission_denied", { params: { action: c.reason } });
}

/** The acting user's role in the account, read in the transaction (the token's role may be 10 s old). */
async function actorRole(tx: Tx, accountUuid: string, userUuid: string): Promise<Role> {
  const m = await tx
    .selectFrom("memberships")
    .select("role")
    .where("account_id", "=", accountUuid)
    .where("user_id", "=", userUuid)
    .executeTakeFirst();
  if (!m) throw new ApiError("authentication_required");
  return m.role;
}

/**
 * Recovery lock (§12, audit fix): for 48 h after an account recovery nobody may invite, promote,
 * demote or remove an owner/admin — a recovered attacker must not reshape who approves destinations.
 */
async function assertNoRecoveryLock(id: Identity, tx: Tx, accountUuid: string): Promise<void> {
  const a = await tx
    .selectFrom("accounts")
    .select("recovered_at")
    .where("id", "=", accountUuid)
    .executeTakeFirstOrThrow();
  if (a.recovered_at && a.recovered_at.getTime() + id.recoveryLockMs > id.now()) {
    const until = new Date(a.recovered_at.getTime() + id.recoveryLockMs).toISOString();
    throw new ApiError("recovery_lock", {
      params: { until },
      message: `Owners and admins cannot change until ${until} after account recovery.`,
    });
  }
}

/** Locks the account's owner rows (serialises last-owner checks) and returns their number. */
async function lockOwners(tx: Tx, accountUuid: string): Promise<number> {
  const rows = await tx
    .selectFrom("memberships")
    .select("user_id")
    .where("account_id", "=", accountUuid)
    .where("role", "=", "owner")
    .forUpdate()
    .execute();
  return rows.length;
}

async function emitMember(
  tx: Tx,
  subject: "evt.identity.member.added" | "evt.identity.member.removed" | "evt.identity.member.role_changed",
  m: { accountUuid: string; userUuid: string; role: Role; previousRole: Role | null; actorUserUuid: string | null },
) {
  const v = await sql<{ v: string }>`select nextval('membership_event_version') as v`.execute(tx);
  await emitEvent(tx, {
    subject,
    // aggregate = the member (the envelope carries the account); a sequence orders a member's events
    // (memberships are deleted on removal, so a row version would restart on re-join)
    aggregate: { type: "membership", id: fromUuid("usr", m.userUuid), version: Number(v.rows[0]?.v) },
    accountUuid: m.accountUuid,
    livemode: null,
    object: {
      account_id: fromUuid("acct", m.accountUuid),
      user_id: fromUuid("usr", m.userUuid),
      role: m.role,
      previous_role: m.previousRole,
      actor_user_id: m.actorUserUuid ? fromUuid("usr", m.actorUserUuid) : null,
    },
  });
}

/** Purges the cached authz records of a user's sessions for an account (role or membership changed). */
async function purgeSessions(id: Identity, db: Identity["db"] | Tx, accountUuid: string, userUuid: string) {
  const rows = await db
    .selectFrom("sessions")
    .select("token_hash")
    .where("user_id", "=", userUuid)
    .where("account_id", "=", accountUuid)
    .execute();
  for (const r of rows) id.cache.purgeSession(r.token_hash.toString("hex"));
}

// ---------------------------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------------------------

type MemberRow = {
  user_id: string;
  email: string;
  role: Role;
  created_at: Date;
  last_login_at: Date | null;
  recovered_at: Date | null;
  passkeys: number | string | bigint | null;
};

const memberView = (m: MemberRow) => ({
  object: "member" as const,
  user: { id: fromUuid("usr", m.user_id), email: m.email },
  role: m.role,
  created: unix(m.created_at),
  last_login_at: m.last_login_at ? unix(m.last_login_at) : null,
  // spec 0.2.1: dashboard passkeys only (console hardware keys are not the member's sign-in)
  security: { passkeys: Number(m.passkeys), recovered_at: m.recovered_at ? unix(m.recovered_at) : null },
});

function membersQuery(db: Identity["db"] | Tx, accountUuid: string) {
  return db
    .selectFrom("memberships")
    .innerJoin("users", "users.id", "memberships.user_id")
    .select([
      "memberships.user_id",
      "users.email",
      "memberships.role",
      "memberships.created_at",
      "users.last_login_at",
      "users.recovered_at",
    ])
    .select((eb) =>
      eb
        .selectFrom("passkeys")
        .select(eb.fn.countAll<string>().as("n"))
        .whereRef("passkeys.user_id", "=", "memberships.user_id")
        .where("passkeys.kind", "=", "dashboard")
        .as("passkeys"),
    )
    .where("memberships.account_id", "=", accountUuid);
}

export async function listMembers(
  id: Identity,
  accountId: string,
  q: { limit: number; starting_after?: string | undefined; ending_before?: string | undefined },
) {
  let query = membersQuery(id.db, toUuid(accountId, "acct"))
    .orderBy("memberships.user_id", "desc")
    .limit(q.limit + 1);
  if (q.starting_after) query = query.where("memberships.user_id", "<", toUuid(q.starting_after, "usr"));
  if (q.ending_before) query = query.where("memberships.user_id", ">", toUuid(q.ending_before, "usr"));
  const rows = await query.execute();
  return {
    object: "list" as const,
    data: rows.slice(0, q.limit).map(memberView),
    has_more: rows.length > q.limit,
    url: "/v1/account/members",
  };
}

async function lockMember(tx: Tx, accountUuid: string, userId: string) {
  const m = await tx
    .selectFrom("memberships")
    .selectAll()
    .where("account_id", "=", accountUuid)
    .where("user_id", "=", toUuid(userId, "usr"))
    .forUpdate()
    .executeTakeFirst();
  if (!m) throw ApiError.missing("member", userId, "user");
  return m;
}

export async function updateMember(id: Identity, accountId: string, userId: string, role: Role, actor: TeamActor) {
  const acct = toUuid(accountId, "acct");
  const out = await withTx(id.db, async (tx) => {
    const owners = await lockOwners(tx, acct);
    const me = await actorRole(tx, acct, actor.userUuid);
    const m = await lockMember(tx, acct, userId);
    enforce(canChangeRole(me, m.role, role, owners));
    if (m.role !== role && (isOwnerOrAdmin(m.role) || isOwnerOrAdmin(role))) await assertNoRecoveryLock(id, tx, acct);
    if (m.role !== role) {
      await tx
        .updateTable("memberships")
        .set({ role })
        .where("account_id", "=", acct)
        .where("user_id", "=", m.user_id)
        .execute();
      await emitMember(tx, "evt.identity.member.role_changed", {
        accountUuid: acct,
        userUuid: m.user_id,
        role,
        previousRole: m.role,
        actorUserUuid: actor.userUuid,
      });
      await audit(id, tx, {
        accountUuid: acct,
        actor,
        action: "member.role_changed",
        target: { type: "user", id: userId },
        details: { role, previous_role: m.role },
      });
    }
    return (await membersQuery(tx, acct)
      .where("memberships.user_id", "=", m.user_id)
      .executeTakeFirstOrThrow()) as MemberRow;
  });
  await purgeSessions(id, id.db, acct, out.user_id);
  return memberView(out);
}

export async function removeMember(id: Identity, accountId: string, userId: string, actor: TeamActor) {
  const acct = toUuid(accountId, "acct");
  const hashes = await withTx(id.db, async (tx) => {
    const owners = await lockOwners(tx, acct);
    const me = await actorRole(tx, acct, actor.userUuid);
    const m = await lockMember(tx, acct, userId);
    enforce(canRemove(me, m.role, owners));
    if (isOwnerOrAdmin(m.role)) await assertNoRecoveryLock(id, tx, acct);
    await tx.deleteFrom("memberships").where("account_id", "=", acct).where("user_id", "=", m.user_id).execute();
    // their sessions for this account end at once
    const revoked = await tx
      .updateTable("sessions")
      .set({ revoked_at: await dbNow(tx) })
      .where("user_id", "=", m.user_id)
      .where("account_id", "=", acct)
      .where("revoked_at", "is", null)
      .returning("token_hash")
      .execute();
    await emitMember(tx, "evt.identity.member.removed", {
      accountUuid: acct,
      userUuid: m.user_id,
      role: m.role,
      previousRole: null,
      actorUserUuid: actor.userUuid,
    });
    await audit(id, tx, {
      accountUuid: acct,
      actor,
      action: "member.removed",
      target: { type: "user", id: userId },
      details: { role: m.role, sessions_revoked: revoked.length },
    });
    return revoked.map((r) => r.token_hash.toString("hex"));
  });
  for (const h of hashes) id.cache.purgeSession(h);
}

// ---------------------------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------------------------

export function invitationView(i: InvitationRow, now: number) {
  return {
    id: fromUuid("inv", i.id),
    object: "invitation" as const,
    created: unix(i.created_at),
    email: i.email,
    role: i.role,
    status: effectiveStatus(i, now),
    invited_by: fromUuid("usr", i.invited_by),
    expires_at: unix(i.expires_at),
    accepted_at: i.accepted_at ? unix(i.accepted_at) : null,
  };
}

export async function listInvitations(
  id: Identity,
  accountId: string,
  q: {
    limit: number;
    starting_after?: string | undefined;
    ending_before?: string | undefined;
    status?: string | undefined;
  },
) {
  let query = id.db
    .selectFrom("invitations")
    .selectAll()
    .where("account_id", "=", toUuid(accountId, "acct"))
    .orderBy("id", "desc")
    .limit(q.limit + 1);
  const now = new Date(id.now());
  // `expired` includes pending invitations past expiry that the hourly purge has not marked yet
  if (q.status === "expired")
    query = query.where((eb) =>
      eb.or([eb("status", "=", "expired"), eb.and([eb("status", "=", "pending"), eb("expires_at", "<=", now)])]),
    );
  else if (q.status === "pending") query = query.where("status", "=", "pending").where("expires_at", ">", now);
  else if (q.status) query = query.where("status", "=", q.status as InvitationStatus);
  if (q.starting_after) query = query.where("id", "<", toUuid(q.starting_after, "inv"));
  if (q.ending_before) query = query.where("id", ">", toUuid(q.ending_before, "inv"));
  const rows = await query.execute();
  return {
    object: "list" as const,
    data: rows.slice(0, q.limit).map((i) => invitationView(i, id.now())),
    has_more: rows.length > q.limit,
    url: "/v1/account/invitations",
  };
}

export async function createInvitation(
  id: Identity,
  accountId: string,
  b: { email: string; role: Role },
  actor: TeamActor,
) {
  const acct = toUuid(accountId, "acct");
  const email = b.email.trim().toLowerCase();
  return withTx(id.db, async (tx) => {
    const me = await actorRole(tx, acct, actor.userUuid);
    enforce(canInvite(me, b.role));
    if (isOwnerOrAdmin(b.role)) await assertNoRecoveryLock(id, tx, acct);
    const now = await dbNow(tx);
    // expire stale pending invitations of this address first, so the one-pending index only counts live ones
    await tx
      .updateTable("invitations")
      .set({ status: "expired" })
      .where("account_id", "=", acct)
      .where("email", "=", email)
      .where("status", "=", "pending")
      .where("expires_at", "<=", now)
      .execute();
    const member = await tx
      .selectFrom("memberships")
      .innerJoin("users", "users.id", "memberships.user_id")
      .select("users.id")
      .where("memberships.account_id", "=", acct)
      .where("users.email", "=", email)
      .executeTakeFirst();
    // the address stays out of the message: error messages may be logged
    const exists = () => new ApiError("member_exists", { params: { email: "this address" }, param: "email" });
    if (member) throw exists();
    const account = await tx
      .selectFrom("accounts")
      .select("display_name")
      .where("id", "=", acct)
      .executeTakeFirstOrThrow();
    const invId = uuidv7();
    const expires = new Date(now.getTime() + INVITATION_MS);
    let inv: InvitationRow;
    try {
      inv = await tx
        .insertInto("invitations")
        .values({
          id: invId,
          account_id: acct,
          email,
          role: b.role,
          status: "pending",
          invited_by: actor.userUuid,
          expires_at: expires,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
    } catch (e) {
      if ((e as { code?: string }).code === "23505") throw exists();
      throw e;
    }
    const token = newSecret(32);
    await tx
      .insertInto("magic_links")
      .values({
        token_hash: sha256(token),
        email,
        purpose: "invite",
        account_id: acct,
        role: b.role,
        invitation_id: invId,
        expires_at: expires,
      })
      .execute();
    await audit(id, tx, {
      accountUuid: acct,
      actor,
      action: "member.invited",
      target: { type: "invitation", id: fromUuid("inv", invId) },
      details: { role: b.role },
    });
    // queued before commit: if notify refuses, nothing is stored and the caller can retry
    try {
      await id.peers.sendInvitation({
        to: email,
        link_url: `${id.dashboardOrigin.replace(/\/$/, "")}/auth/invite#token=${token}`,
        account_display_name: account.display_name.slice(0, 100),
        role: b.role,
        expires_in_minutes: INVITATION_MS / 60_000,
        dedupe_key: `invitation:${fromUuid("inv", invId)}`,
      });
    } catch (e) {
      id.log.error({ err: e, invitation: fromUuid("inv", invId) }, "invitation mail could not be queued");
      throw new ApiError("api_error", { message: "Email delivery is unavailable right now; try again shortly." });
    }
    return invitationView(inv, id.now());
  });
}

export async function revokeInvitation(id: Identity, accountId: string, invitationId: string, actor: TeamActor) {
  const acct = toUuid(accountId, "acct");
  await withTx(id.db, async (tx) => {
    const inv = await tx
      .selectFrom("invitations")
      .selectAll()
      .where("id", "=", toUuid(invitationId, "inv"))
      .where("account_id", "=", acct)
      .forUpdate()
      .executeTakeFirst();
    if (!inv) throw ApiError.missing("invitation", invitationId, "id");
    const status = effectiveStatus(inv, id.now());
    if (status !== "pending") throw new ApiError("state_conflict", { params: { object: "invitation", state: status } });
    const now = await dbNow(tx);
    await tx.updateTable("invitations").set({ status: "revoked", revoked_at: now }).where("id", "=", inv.id).execute();
    await tx
      .updateTable("magic_links")
      .set({ used_at: now })
      .where("invitation_id", "=", inv.id)
      .where("used_at", "is", null)
      .execute();
    await audit(id, tx, {
      accountUuid: acct,
      actor,
      action: "invitation.revoked",
      target: { type: "invitation", id: invitationId },
    });
  });
}

/**
 * Joins `inv` for `userUuid` inside `tx`: membership with the invited role, invitation accepted, link
 * used, `member.added` (actor null: the user accepted), audit. Shared by `acceptInvitation` and the
 * new-user registration of an invite link.
 */
export async function joinInvitation(
  id: Identity,
  tx: Tx,
  inv: InvitationRow,
  userUuid: string,
  ip: string | null,
): Promise<void> {
  const now = await dbNow(tx);
  const already = await tx
    .selectFrom("memberships")
    .select("role")
    .where("account_id", "=", inv.account_id)
    .where("user_id", "=", userUuid)
    .executeTakeFirst();
  if (already)
    throw new ApiError("invitation_invalid", { params: { reason: "you are already a member of this account" } });
  await tx
    .insertInto("memberships")
    .values({ account_id: inv.account_id, user_id: userUuid, role: inv.role, last_used_at: now })
    .execute();
  await tx
    .updateTable("invitations")
    .set({ status: "accepted", accepted_at: now, accepted_by: userUuid })
    .where("id", "=", inv.id)
    .execute();
  await tx
    .updateTable("magic_links")
    .set({ used_at: now })
    .where("invitation_id", "=", inv.id)
    .where("used_at", "is", null)
    .execute();
  await emitMember(tx, "evt.identity.member.added", {
    accountUuid: inv.account_id,
    userUuid,
    role: inv.role,
    previousRole: null,
    actorUserUuid: null,
  });
  await audit(id, tx, {
    accountUuid: inv.account_id,
    actor: { type: "user", id: fromUuid("usr", userUuid), ip },
    action: "member.joined",
    target: { type: "invitation", id: fromUuid("inv", inv.id) },
    details: { role: inv.role },
  });
}

/** The pending invitation behind an invite-link token, locked; every problem is `invitation_invalid`. */
export async function invitationForToken(tx: Tx, token: string, now: number): Promise<InvitationRow> {
  const invalid = (reason: string) => new ApiError("invitation_invalid", { params: { reason } });
  const link = await tx
    .selectFrom("magic_links")
    .selectAll()
    .where("token_hash", "=", sha256(token))
    .where("purpose", "=", "invite")
    .forUpdate()
    .executeTakeFirst();
  if (!link?.invitation_id) throw invalid("the link is unknown");
  const inv = await tx
    .selectFrom("invitations")
    .selectAll()
    .where("id", "=", link.invitation_id)
    .forUpdate()
    .executeTakeFirst();
  if (!inv) throw invalid("the link is unknown");
  const status = effectiveStatus(inv, now);
  if (status !== "pending") throw invalid(`it is ${status}`);
  if (link.used_at) throw invalid("the link was used");
  return inv;
}

// ---------------------------------------------------------------------------------------------
// Multi-account sessions
// ---------------------------------------------------------------------------------------------

/** Points the caller's session at `accountUuid` (step-up cleared), marks the membership used, re-issues the session. */
async function reissueFor(id: Identity, tx: Tx, meta: RequestMeta, userUuid: string, accountUuid: string) {
  const s = await currentSessionTx(tx, meta, userUuid);
  const now = await dbNow(tx);
  await tx.updateTable("sessions").set({ account_id: accountUuid, step_up_at: null }).where("id", "=", s.id).execute();
  await tx
    .updateTable("memberships")
    .set({ last_used_at: now })
    .where("account_id", "=", accountUuid)
    .where("user_id", "=", userUuid)
    .execute();
  id.cache.purgeSession(s.token_hash.toString("hex"));
  const csrf = id.cipher.decrypt(s.csrf_enc, `session:${s.id}:csrf`).toString("utf8");
  return sessionBody(tx, userUuid, accountUuid, { token: "", csrf, expiresAt: s.expires_at });
}

/** `POST /v1/auth/invitations/accept`: the signed-in user whose email matches joins; the session switches to it. */
export async function acceptInvitation(id: Identity, principal: { sub: string }, token: string, meta: RequestMeta) {
  const userUuid = toUuid(principal.sub, "usr");
  return withTx(id.db, async (tx) => {
    const inv = await invitationForToken(tx, token, id.now());
    const user = await tx.selectFrom("users").select(["email"]).where("id", "=", userUuid).executeTakeFirstOrThrow();
    const problem = acceptProblem(inv, user.email, id.now());
    if (problem) throw new ApiError("invitation_invalid", { params: { reason: problem } });
    await joinInvitation(id, tx, inv, userUuid, meta.ip);
    return reissueFor(id, tx, meta, userUuid, inv.account_id);
  });
}

export async function listMemberships(id: Identity, principal: { sub: string; acct: string }) {
  const rows = await id.db
    .selectFrom("memberships")
    .innerJoin("accounts", "accounts.id", "memberships.account_id")
    .select(["memberships.account_id", "accounts.display_name", "memberships.role"])
    .where("memberships.user_id", "=", toUuid(principal.sub, "usr"))
    .where("accounts.status", "<>", "closed")
    .orderBy((eb) => eb.fn.coalesce("memberships.last_used_at", "memberships.created_at"), "desc")
    .execute();
  const current = toUuid(principal.acct, "acct");
  return {
    object: "list" as const,
    data: rows.map((r) => ({
      object: "membership" as const,
      account: { id: fromUuid("acct", r.account_id), display_name: r.display_name },
      role: r.role,
      current: r.account_id === current,
    })),
  };
}

/** `POST /v1/auth/session/account`: the same cookie acts for another account of the user (step-up cleared). */
export async function switchSessionAccount(
  id: Identity,
  principal: { sub: string },
  accountId: string,
  meta: RequestMeta,
) {
  const userUuid = toUuid(principal.sub, "usr");
  const acct = toUuid(accountId, "acct");
  return withTx(id.db, async (tx) => {
    const m = await tx
      .selectFrom("memberships")
      .innerJoin("accounts", "accounts.id", "memberships.account_id")
      .select(["memberships.role", "accounts.status"])
      .where("memberships.user_id", "=", userUuid)
      .where("memberships.account_id", "=", acct)
      .executeTakeFirst();
    // not a member (or closed): indistinguishable from an unknown account
    if (!m || m.status === "closed") throw ApiError.missing("account", accountId, "account");
    const body = await reissueFor(id, tx, meta, userUuid, acct);
    await audit(id, tx, {
      accountUuid: acct,
      actor: { type: "user", id: principal.sub, ip: meta.ip },
      action: "session.account_switched",
    });
    return body;
  });
}
