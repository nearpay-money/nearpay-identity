/**
 * Stage 1 ops CLI (platform §3): `docker compose exec identity-api node dist/ops.js <command> …`.
 * There is no network path to these actions in Stage 1; Stage 2 moves operator management to the
 * console. Every command prints one JSON document; errors print `{"error": …}` and exit 1 (2: usage).
 */
import { parseArgs } from "node:util";
import { enqueueJob, withTx } from "@nearpay-internal/db";
import { fromUuid, isId, toUuid, uuidv7 } from "@nearpay-internal/ids";
import { ApiError } from "@nearpay-internal/service";
import { API_VERSION } from "@nearpay-money/spec";
import { createKey, revokeKey } from "../app/api-keys.js";
import { DEFAULT_FEE_SCHEDULE } from "../app/auth.js";
import { sendEnrolment } from "../app/console.js";
import { accessMode, audit, dbNow, emitEvent, type Identity } from "../app/context.js";
import { ACTIVATE_JOB, createDestination } from "../app/destinations.js";
import { activeAdminCount, operatorUser } from "../app/operators.js";
import { accountView } from "../app/views.js";
import { DEFAULT_SETTINGS } from "../domain/account/account.js";
import { isDevEnv } from "../domain/env.js";

export const USAGE = `usage: ops.js <command> [arguments] [--actor <name>]

  account-show <acct_… | email>
  operator-add <email> ops|ops_admin       (emails a 24 h console enrolment link; NP_OPS_ORIGIN —
                                            NP_OPS_AUTH_MODE=cloudflare_access: enrolled by email, no link)
  operator-revoke <email>
  operator-list                            (active and revoked operators, their passkey policy, the two-person mode)
  destination-cooloff-skip <sd_…>          (NP_ENV=local only)
  seed-demo [--email <email>] [--name <display name>] [--destination <near account>]   (NP_ENV=local only)`;

class UsageError extends Error {}

export interface OpsDeps {
  actor: string;
  out?: (line: string) => void;
  err?: (line: string) => void;
}

const OPTIONS = {
  actor: { type: "string" },
  email: { type: "string" },
  name: { type: "string" },
  destination: { type: "string" },
} as const;

const need = (v: string | undefined, what: string) => {
  if (!v?.trim()) throw new UsageError(`missing ${what}`);
  return v.trim();
};

function localOnly(id: Identity, what: string) {
  if (!isDevEnv(id.env)) throw new UsageError(`${what} is available only when NP_ENV=local`);
}

async function userByEmail(id: Identity, email: string) {
  const u = await id.db.selectFrom("users").selectAll().where("email", "=", email.toLowerCase()).executeTakeFirst();
  if (!u) throw ApiError.missing("user", email);
  return u;
}

export async function runOps(argv: readonly string[], id: Identity, deps: OpsDeps): Promise<number> {
  const out = deps.out ?? ((l: string) => process.stdout.write(`${l}\n`));
  const err = deps.err ?? ((l: string) => process.stderr.write(`${l}\n`));
  let parsed: ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true; strict: true }>>;
  try {
    parsed = parseArgs({ args: [...argv], options: OPTIONS, allowPositionals: true, strict: true });
  } catch (e) {
    err(`${(e as Error).message}\n\n${USAGE}`);
    return 2;
  }
  const [command, ...args] = parsed.positionals;
  const v = parsed.values;
  const actor = { type: "ops" as const, id: `ops:${v.actor?.trim() || deps.actor}` };
  const print = (x: unknown) => out(JSON.stringify(x, null, 2));
  try {
    switch (command) {
      case "account-show": {
        const ref = need(args[0], "account id or email");
        let acct: string;
        if (isId("acct", ref)) acct = toUuid(ref, "acct");
        else {
          const u = await userByEmail(id, ref);
          const m = await id.db
            .selectFrom("memberships")
            .select("account_id")
            .where("user_id", "=", u.id)
            .executeTakeFirst();
          if (!m) throw ApiError.missing("account", ref);
          acct = m.account_id;
        }
        const a = await id.db.selectFrom("accounts").selectAll().where("id", "=", acct).executeTakeFirst();
        if (!a) throw ApiError.missing("account", ref);
        const members = await id.db
          .selectFrom("memberships")
          .innerJoin("users", "users.id", "memberships.user_id")
          .select(["users.email", "memberships.role"])
          .where("memberships.account_id", "=", acct)
          .execute();
        const destinations = await id.db
          .selectFrom("settlement_destinations")
          .select(["id", "livemode", "status", "chain", "asset_id", "address"])
          .where("account_id", "=", acct)
          .execute();
        print({
          ...accountView(a),
          members,
          destinations: destinations.map((d) => ({ ...d, id: fromUuid("sd", d.id) })),
        });
        return 0;
      }
      case "operator-add": {
        const email = need(args[0], "email").toLowerCase();
        const role = need(args[1], "role");
        if (role !== "ops" && role !== "ops_admin") throw new UsageError("role must be ops or ops_admin");
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new UsageError("not an email address");
        // operators need no merchant account: the user is created when missing (email verified at enrolment)
        const u = await withTx(id.db, (tx) => operatorUser(tx, email));
        await withTx(id.db, async (tx) => {
          await tx
            .insertInto("ops_operators")
            .values({ user_id: u.id, role })
            .onConflict((oc) => oc.column("user_id").doUpdateSet({ role, revoked_at: null }))
            .execute();
          await audit(id, tx, {
            accountUuid: null,
            actor,
            action: "operator.added",
            target: { type: "user", id: fromUuid("usr", u.id) },
            details: { role, auth_mode: accessMode(id.console) ? "cloudflare_access" : "passkey" },
          });
        });
        if (accessMode(id.console)) {
          // Cloudflare Access mode: the operator signs in with this email through Access (add it to the
          // Access policy too); there is no passkey to enrol
          print({ user: fromUuid("usr", u.id), role, enrolment: "by email (Cloudflare Access)" });
          return 0;
        }
        // the 24 h enrolment link for the operator's hardware key (console host)
        await sendEnrolment(id, { id: u.id, email: u.email }, role);
        print({ user: fromUuid("usr", u.id), role, enrolment: "sent (24 h link)" });
        return 0;
      }
      case "operator-list": {
        const rows = await id.db
          .selectFrom("ops_operators")
          .innerJoin("users", "users.id", "ops_operators.user_id")
          .select([
            "ops_operators.user_id",
            "users.email",
            "users.status",
            "ops_operators.role",
            "ops_operators.created_at",
            "ops_operators.revoked_at",
            "ops_operators.passkey_policy",
            "ops_operators.passkey_attachment",
            "ops_operators.passkey_synced",
            "ops_operators.passkey_registered_at",
          ])
          .orderBy("ops_operators.created_at")
          .execute();
        const admins = await activeAdminCount(id.db);
        print({
          auth_mode: accessMode(id.console) ? "cloudflare_access" : "passkey",
          // adaptive two-person rule: a second operator is required while two or more can approve
          two_person: admins >= 2 ? "required (2+ active ops_admin)" : "single operator (1 active ops_admin)",
          active_ops_admins: admins,
          operators: rows.map((r) => ({
            user: fromUuid("usr", r.user_id),
            email: r.email,
            role: r.role,
            active: r.revoked_at === null && r.status === "active",
            revoked_at: r.revoked_at?.toISOString() ?? null,
            passkey: r.passkey_policy
              ? {
                  policy: r.passkey_policy,
                  label: r.passkey_policy === "platform_beta" ? "platform passkey — beta" : "hardware security key",
                  attachment: r.passkey_attachment,
                  synced: r.passkey_synced,
                  registered_at: r.passkey_registered_at?.toISOString() ?? null,
                }
              : null,
          })),
        });
        return 0;
      }
      case "operator-revoke": {
        const u = await userByEmail(id, need(args[0], "email"));
        await withTx(id.db, async (tx) => {
          await tx
            .updateTable("ops_operators")
            .set({ revoked_at: await dbNow(tx) })
            .where("user_id", "=", u.id)
            .execute();
          await tx
            .updateTable("sessions")
            .set({ revoked_at: await dbNow(tx) })
            .where("user_id", "=", u.id)
            .where("kind", "=", "ops")
            .execute();
          await audit(id, tx, {
            accountUuid: null,
            actor,
            action: "operator.revoked",
            target: { type: "user", id: fromUuid("usr", u.id) },
          });
        });
        print({ user: fromUuid("usr", u.id), revoked: true });
        return 0;
      }
      case "destination-cooloff-skip": {
        localOnly(id, "destination-cooloff-skip");
        const ref = need(args[0], "destination id");
        if (!isId("sd", ref)) throw new UsageError("expected an sd_… id");
        const r = await withTx(id.db, async (tx) => {
          const d = await tx
            .selectFrom("settlement_destinations")
            .selectAll()
            .where("id", "=", toUuid(ref, "sd"))
            .forUpdate()
            .executeTakeFirst();
          if (!d) throw ApiError.missing("settlement_destination", ref);
          if (d.status !== "cooling_off")
            throw new ApiError("state_conflict", { params: { object: "settlement_destination", state: d.status } });
          const now = await dbNow(tx);
          await tx.updateTable("settlement_destinations").set({ active_at: now }).where("id", "=", d.id).execute();
          await tx
            .updateTable("jobs")
            .set({ run_at: now })
            .where("dedupe_key", "=", `${ACTIVATE_JOB}:sd:${d.id}`)
            .where("done_at", "is", null)
            .execute();
          await enqueueJob(tx, {
            kind: ACTIVATE_JOB,
            payload: { destination_id: d.id },
            dedupeKey: `${ACTIVATE_JOB}:sd:${d.id}`,
            maxAttempts: 50,
          });
          await audit(id, tx, {
            accountUuid: d.account_id,
            actor,
            action: "destination.cooloff_skipped",
            target: { type: "settlement_destination", id: ref },
          });
          return { id: ref, active_at: now.toISOString(), note: "the worker activates it after re-screening" };
        });
        print(r);
        return 0;
      }
      case "seed-demo": {
        localOnly(id, "seed-demo");
        print(
          await seedDemo(id, {
            email: v.email ?? "demo@merchant.test",
            name: v.name ?? "Demo Shop",
            destination: v.destination ?? "merchant-demo.near",
          }),
        );
        return 0;
      }
      default:
        err(`${command ? `unknown command "${command}"\n\n` : ""}${USAGE}`);
        return 2;
    }
  } catch (e) {
    if (e instanceof UsageError) {
      err(`${e.message}\n\n${USAGE}`);
      return 2;
    }
    if (e instanceof ApiError) {
      err(JSON.stringify({ error: { code: e.code, message: e.message, ...(e.param ? { param: e.param } : {}) } }));
      return 1;
    }
    err(JSON.stringify({ error: { message: e instanceof Error ? e.message : String(e) } }));
    return 1;
  }
}

const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";

/**
 * The demo merchant for local stacks (`seed.sh data`): an owner without a passkey (sign-in needs a
 * new passkey via sign-up of another email), test-mode secret + publishable keys (printed once;
 * earlier demo keys are revoked) and an active test-mode Intents destination for USDC.
 */
export async function seedDemo(id: Identity, o: { email: string; name: string; destination: string }) {
  const email = o.email.toLowerCase();
  const { accountId, userId, created } = await withTx(id.db, async (tx) => {
    const existing = await tx.selectFrom("users").select("id").where("email", "=", email).executeTakeFirst();
    if (existing) {
      const m = await tx
        .selectFrom("memberships")
        .select("account_id")
        .where("user_id", "=", existing.id)
        .executeTakeFirstOrThrow();
      return { accountId: m.account_id, userId: existing.id, created: false };
    }
    const now = await dbNow(tx);
    const user = uuidv7();
    const acct = uuidv7();
    await tx.insertInto("users").values({ id: user, email, email_verified_at: now }).execute();
    const account = await tx
      .insertInto("accounts")
      .values({
        id: acct,
        display_name: o.name,
        fee_schedule_id: DEFAULT_FEE_SCHEDULE,
        api_version: API_VERSION,
        settings: JSON.stringify(DEFAULT_SETTINGS),
      })
      .returningAll()
      .executeTakeFirstOrThrow();
    await tx.insertInto("memberships").values({ account_id: acct, user_id: user, role: "owner" }).execute();
    const view = accountView(account);
    await emitEvent(tx, {
      subject: "evt.identity.account.created",
      aggregate: { type: "account", id: view.id, version: account.version },
      accountUuid: acct,
      livemode: null,
      object: view,
    });
    return { accountId: acct, userId: user, created: true };
  });
  const acct = fromUuid("acct", accountId);
  const actor = { type: "ops" as const, id: "ops:seed-demo", userUuid: userId };
  const old = await id.db
    .selectFrom("api_keys")
    .select("id")
    .where("account_id", "=", accountId)
    .where("name", "like", "demo %")
    .where("revoked_at", "is", null)
    .execute();
  for (const k of old) await revokeKey(id, acct, fromUuid("key", k.id), actor);
  const secret = await createKey(id, acct, { type: "secret", livemode: false, name: "demo secret" }, actor);
  const publishable = await createKey(
    id,
    acct,
    { type: "publishable", livemode: false, name: "demo publishable" },
    actor,
  );
  let destination = await id.db
    .selectFrom("settlement_destinations")
    .select(["id", "status"])
    .where("account_id", "=", accountId)
    .where("livemode", "=", false)
    .where("status", "=", "active")
    .executeTakeFirst();
  if (!destination) {
    const d = await createDestination(
      id,
      acct,
      false,
      {
        asset_id: USDC_NEAR,
        type: "intents_account",
        chain: "near:mainnet",
        address: o.destination,
        label: "Demo (test)",
      },
      actor,
    );
    destination = { id: toUuid(d.id, "sd"), status: d.status };
  }
  return {
    account: acct,
    created,
    owner: email,
    secret_key: secret.secret,
    publishable_key: publishable.secret,
    destination: fromUuid("sd", destination.id),
  };
}
