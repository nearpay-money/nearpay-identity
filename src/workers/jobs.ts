/**
 * Jobs (lld/identity.md §9), run by the job worker (leases, backoff, dead letters):
 *
 * | kind                 | when                     | what                                                  |
 * |----------------------|--------------------------|-------------------------------------------------------|
 * | destination.activate | at `active_at` (per sd)  | re-screen, activate (or disable on block; retry when screening is down) |
 * | destination.expire   | hourly (+20 min offset)  | disable live destinations still pending 7 days after creation |
 * | purge.auth           | hourly                   | expired magic links, registration tokens, challenges, Google flows, sessions; marks invitations expired |
 * | kit.purge            | hourly                   | published outbox, old inbox, expired idempotency keys  |
 * | cli_logins.expire    | every minute             | overdue CLI logins → expired; uncollected keys revoked (§6.2) |
 *
 * JWT key rotation (`keys.rotate_jwt`) is an operator action in Stage 1: both mounted keys are
 * published in the JWKS, and promoting `next` is a secret swap + restart (platform runbook).
 */
import { type JobHandler, purgeKitTables, type RecurringJob, sql } from "@nearpay-internal/db";
import { CLI_EXPIRE_JOB, expireCliLogins } from "../app/cli-logins.js";
import type { Identity } from "../app/context.js";
import { ACTIVATE_JOB, activateDestination, EXPIRE_JOB, expirePendingDestinations } from "../app/destinations.js";

const HOUR = 3_600_000;

export const RECURRING: readonly RecurringJob[] = [
  { kind: "purge.auth", everyMs: HOUR, offsetMs: 10 * 60_000 },
  { kind: "kit.purge", everyMs: HOUR },
  { kind: EXPIRE_JOB, everyMs: HOUR, offsetMs: 20 * 60_000 },
  { kind: CLI_EXPIRE_JOB, everyMs: 60_000 },
];

export async function purgeAuth(id: Identity) {
  const one = async (q: ReturnType<typeof sql>) => Number((await q.execute(id.db)).numAffectedRows ?? 0n);
  return {
    magic_links: await one(sql`delete from magic_links where expires_at < now() - interval '1 day'`),
    registration_tokens: await one(sql`delete from registration_tokens where expires_at < now() - interval '1 day'`),
    webauthn_challenges: await one(sql`delete from webauthn_challenges where expires_at < now() - interval '1 day'`),
    attestation_challenges: await one(
      sql`delete from attestation_challenges where expires_at < now() - interval '30 days' and used_at is null`,
    ),
    // Google flows (ADR-0026): 10 minutes, single use; kept a day for diagnosis (hashes only)
    oauth_flows: await one(sql`delete from oauth_flows where expires_at < now() - interval '1 day'`),
    sessions: await one(sql`delete from sessions where expires_at < now() - interval '30 days'`),
    // CLI logins (§6.2): purged 7 days after creation once settled (approved rows are settled by cli_logins.expire)
    cli_logins: await one(
      sql`delete from cli_logins where created_at < now() - interval '7 days' and status in ('denied','expired','redeemed')`,
    ),
    invitations_expired: await one(
      sql`update invitations set status = 'expired' where status = 'pending' and expires_at <= now()`,
    ),
  };
}

export function jobHandlers(id: Identity): Record<string, JobHandler> {
  return {
    [ACTIVATE_JOB]: async (payload) => {
      const r = await activateDestination(id, (payload as { destination_id: string }).destination_id);
      id.log.info(
        { destination: (payload as { destination_id: string }).destination_id, result: r },
        "destination activation",
      );
    },
    [EXPIRE_JOB]: async () => {
      id.log.info({ expired: await expirePendingDestinations(id) }, "pending destinations expired");
    },
    [CLI_EXPIRE_JOB]: async () => {
      const r = await expireCliLogins(id);
      if (r.expired || r.uncollected) id.log.info(r, "cli logins expired");
    },
    "purge.auth": async () => {
      id.log.info(await purgeAuth(id), "auth tables purged");
    },
    "kit.purge": async () => {
      id.log.info(await purgeKitTables(id.db), "kit tables purged");
    },
  };
}
