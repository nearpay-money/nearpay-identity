/**
 * Jobs (lld/identity.md §9), run by the job worker (leases, backoff, dead letters):
 *
 * | kind                 | when                     | what                                                  |
 * |----------------------|--------------------------|-------------------------------------------------------|
 * | destination.activate | at `active_at` (per sd)  | re-screen, activate (or disable on block; retry when screening is down) |
 * | purge.auth           | hourly                   | expired magic links, registration tokens, challenges, sessions |
 * | kit.purge            | hourly                   | published outbox, old inbox, expired idempotency keys  |
 *
 * JWT key rotation (`keys.rotate_jwt`) is an operator action in Stage 1: both mounted keys are
 * published in the JWKS, and promoting `next` is a secret swap + restart (platform runbook).
 */
import { type JobHandler, purgeKitTables, type RecurringJob, sql } from "@nearpay-internal/db";
import type { Identity } from "../app/context.js";
import { ACTIVATE_JOB, activateDestination } from "../app/destinations.js";

const HOUR = 3_600_000;

export const RECURRING: readonly RecurringJob[] = [
  { kind: "purge.auth", everyMs: HOUR, offsetMs: 10 * 60_000 },
  { kind: "kit.purge", everyMs: HOUR },
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
    sessions: await one(sql`delete from sessions where expires_at < now() - interval '30 days'`),
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
    "purge.auth": async () => {
      id.log.info(await purgeAuth(id), "auth tables purged");
    },
    "kit.purge": async () => {
      id.log.info(await purgeKitTables(id.db), "kit tables purged");
    },
  };
}
