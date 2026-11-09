/**
 * Console operators (lld/identity.md §6.1): the active-approver count behind the adaptive two-person rule,
 * operator lookup by email (Cloudflare Access mode) and the first-operator bootstrap.
 *
 * Adaptive two-person rule: identity signs `ops_admins` (active `ops_admin` operators whose user is active)
 * into every console request token, and `ops_auth_at` (the operator's last user verification). Compliance
 * and sentinel require a second, different operator only while `ops_admins ≥ 2` — recorded when a request
 * is made and checked again at completion (compliance §5.1, sentinel §6).
 */
import { sql, withTx } from "@nearpay-internal/db";
import { fromUuid, uuidv7 } from "@nearpay-internal/ids";
import { audit, type Identity, type Tx } from "./context.js";

type Db = Identity["db"] | Tx;

/** Active operators who can approve two-person actions (`ops_admin`, not revoked, user active). */
export async function activeAdminCount(db: Db): Promise<number> {
  const r = await db
    .selectFrom("ops_operators")
    .innerJoin("users", "users.id", "ops_operators.user_id")
    .select((eb) => eb.fn.countAll<string>().as("n"))
    .where("ops_operators.revoked_at", "is", null)
    .where("ops_operators.role", "=", "ops_admin")
    .where("users.status", "=", "active")
    .executeTakeFirstOrThrow();
  return Number(r.n);
}

/** Active operators by role (gauge `nearpay_identity_ops_operators_active{role}`). */
export async function activeOperatorsByRole(db: Db): Promise<Record<"ops" | "ops_admin", number>> {
  const rows = await db
    .selectFrom("ops_operators")
    .innerJoin("users", "users.id", "ops_operators.user_id")
    .select(["ops_operators.role", (eb) => eb.fn.countAll<string>().as("n")])
    .where("ops_operators.revoked_at", "is", null)
    .where("users.status", "=", "active")
    .groupBy("ops_operators.role")
    .execute();
  const out = { ops: 0, ops_admin: 0 };
  for (const r of rows) out[r.role] = Number(r.n);
  return out;
}

/** The active operator with this (verified) email, or undefined. */
export async function activeOperatorByEmail(db: Db, email: string) {
  return db
    .selectFrom("ops_operators")
    .innerJoin("users", "users.id", "ops_operators.user_id")
    .select(["ops_operators.user_id", "ops_operators.role", "users.email"])
    .where("users.email", "=", email.toLowerCase())
    .where("ops_operators.revoked_at", "is", null)
    .where("users.status", "=", "active")
    .executeTakeFirst();
}

/** The user of an operator email, created when missing (operators need no merchant account). */
export async function operatorUser(tx: Tx, email: string) {
  const existing = await tx.selectFrom("users").selectAll().where("email", "=", email).executeTakeFirst();
  if (existing) return existing;
  return tx.insertInto("users").values({ id: uuidv7(), email }).returningAll().executeTakeFirstOrThrow();
}

/**
 * `NP_OPS_BOOTSTRAP_EMAIL` (Access mode): enrols the first operator as `ops_admin` — only while the
 * platform has never had an operator (an empty `ops_operators`), so it can never re-add a revoked operator
 * or add one beside existing ones. Serialised by an advisory lock across replicas; audited
 * `operator.bootstrapped`. Returns the new operator id, or null when nothing was done.
 */
export async function bootstrapOperator(id: Identity, email: string): Promise<string | null> {
  const e = email.trim().toLowerCase();
  return withTx(id.db, async (tx) => {
    await sql`select pg_advisory_xact_lock(7311001)`.execute(tx); // a fixed key: one bootstrap at a time
    const any = await tx.selectFrom("ops_operators").select("user_id").limit(1).executeTakeFirst();
    if (any) return null;
    const u = await operatorUser(tx, e);
    await tx.insertInto("ops_operators").values({ user_id: u.id, role: "ops_admin" }).execute();
    await audit(id, tx, {
      accountUuid: null,
      actor: { type: "system", id: "system:ops-bootstrap" },
      action: "operator.bootstrapped",
      target: { type: "user", id: fromUuid("usr", u.id) },
      details: { role: "ops_admin", source: "NP_OPS_BOOTSTRAP_EMAIL" },
    });
    return fromUuid("usr", u.id);
  });
}
