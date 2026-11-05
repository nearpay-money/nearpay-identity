/**
 * Process wiring (lld/identity.md §2): `api` serves the public auth/account/key/destination routes
 * and the internal routes (authz, JWKS, service tokens, context); `worker` runs the consumers, the
 * job worker (activations, purges), the recurring-job scheduler and the outbox relay.
 */
import { hostname } from "node:os";
import { connect, type NatsConnection } from "@nats-io/transport-node";
import type { KeySource } from "@nearpay-internal/auth";
import { staticKeys } from "@nearpay-internal/auth";
import {
  type Bus,
  busReady,
  connectBus,
  consumerLag,
  domainConsumersTask,
  durablesOf,
  ensureStreams,
  publish,
} from "@nearpay-internal/bus";
import {
  createDb,
  createEnvelopeCipher,
  type Database,
  deadLettersOpen,
  idempotencyStore,
  jobsDue,
  jobWorkerTask,
  migrationStatus,
  outboxLagSeconds,
  outboxRelayTask,
  parseKek,
  recurringJobsTask,
  sql,
} from "@nearpay-internal/db";
import { type BackgroundTask, createService, type Service } from "@nearpay-internal/service";
import { STREAMS, type Subject } from "@nearpay-internal/spec";
import { identityRoutes } from "../api/routes.js";
import type { ApiConfig, WorkerConfig } from "../config.js";
import { CACHE_PURGE_SUBJECT, deadLetters, identityHandlers } from "../consumers/handlers.js";
import { type AuthzCache, createAuthzCache } from "../infra/cache.js";
import { chainLookups } from "../infra/clients/chain-rpc.js";
import { httpPeers, type Peers } from "../infra/clients/peers.js";
import { type TurnstileVerifier, turnstile } from "../infra/clients/turnstile.js";
import type { OwnershipLookups } from "../infra/crypto/attestation.js";
import { MIGRATIONS_DIR } from "../infra/db/migrations.js";
import type { DB } from "../infra/db/schema.js";
import { jobHandlers, RECURRING } from "../workers/jobs.js";
import { touches } from "./authz.js";
import { type Identity, identityMetrics } from "./context.js";
import { loadServiceClients, loadSigner, type Signer } from "./tokens.js";

export interface ServiceDeps {
  database?: Database<DB>;
  signer?: Signer;
  peers?: Peers;
  lookups?: OwnershipLookups;
  turnstile?: TurnstileVerifier;
  cache?: AuthzCache;
  /** Verifies request tokens on identity's own routes; default: its own signing keys. */
  keys?: KeySource;
  now?: () => number;
}

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

function readiness(database: Database<DB>) {
  return {
    db: () => sql`select 1`.execute(database.db),
    migrations: async () => {
      const s = await migrationStatus(database.db, MIGRATIONS_DIR);
      if (s.pending.length || s.drift.length)
        throw new Error(`pending ${s.pending.join(",") || "-"} drift ${s.drift.join(",") || "-"}`);
    },
  };
}

function base(
  config: ApiConfig | WorkerConfig,
  database: Database<DB>,
  signer: Signer,
  peers: Peers,
  extra: Pick<Identity, "lookups" | "turnstile" | "cache" | "dashboardOrigin" | "webauthn" | "recoveryLockMs">,
  now: () => number,
): Mutable<Identity> {
  return {
    env: config.env,
    db: database.db,
    cipher: createEnvelopeCipher(parseKek(config.piiKek)),
    log: undefined as unknown as Identity["log"],
    metrics: undefined as unknown as Identity["metrics"],
    signer,
    peers,
    cooloffMs: config.cooloffSeconds * 1000,
    now,
    ...extra,
  };
}

const unavailable = (what: string) => () => {
  throw new Error(`${what} is not available in this process`);
};

function defaultPeers(config: { complianceUrl: string; railsUrl?: string; notifyUrl?: string }, signer: Signer): Peers {
  return httpPeers({
    complianceUrl: config.complianceUrl,
    railsUrl: config.railsUrl ?? "http://rails-api:8080",
    notifyUrl: config.notifyUrl ?? "http://notify-api:8080",
    serviceToken: () => signer.serviceToken(),
  });
}

/**
 * Cross-replica LRU purge over core NATS (`ctl.identity.cache.purge`): revoked keys, step-ups and
 * logouts reach every api replica at once. Optional — without NATS the LRU TTLs bound staleness
 * (keys 30 s, sessions 10 s).
 */
function purgeChannel(natsUrl: string, cache: AuthzCache, log: Identity["log"]): BackgroundTask {
  return {
    name: "cache-purge",
    async start() {
      let nc: NatsConnection | null = null;
      try {
        nc = await connect({ servers: natsUrl, name: `identity-api@${hostname()}` });
        const conn = nc;
        const sub = conn.subscribe(CACHE_PURGE_SUBJECT);
        (async () => {
          for await (const m of sub) cache.applyPurge(m.string());
        })().catch(() => {});
        cache.setBroadcast((msg) => conn.publish(CACHE_PURGE_SUBJECT, msg));
      } catch (e) {
        log.warn({ err: e }, "cache purge channel unavailable; LRU TTLs bound revocation instead");
      }
      return {
        async stop() {
          cache.setBroadcast(null);
          await nc?.drain().catch(() => {});
        },
      };
    },
  };
}

export function createApi(config: ApiConfig, deps: ServiceDeps = {}): { service: Service; identity: Identity } {
  const database = deps.database ?? createDb<DB>({ url: config.dbUrl, applicationName: "identity-api" });
  const signer = deps.signer ?? loadSigner(config.jwtKeysDir);
  const cache = deps.cache ?? createAuthzCache({ valkeyUrl: config.valkeyUrl });
  const id = base(
    config,
    database,
    signer,
    deps.peers ?? defaultPeers(config, signer),
    {
      lookups: deps.lookups ?? chainLookups({ nearRpcUrls: config.nearRpcUrls, evmRpcUrls: config.evmRpcUrls }),
      turnstile: deps.turnstile ?? turnstile({ secret: config.turnstileSecret, env: config.env }),
      cache,
      dashboardOrigin: config.dashboardOrigin,
      webauthn: { rpId: config.webauthnRpId, rpName: "NearPay", origins: config.webauthnOrigins },
      recoveryLockMs: config.recoveryLockSeconds * 1000,
    },
    deps.now ?? Date.now,
  );
  const t = touches(id);
  const service = createService({
    name: "identity",
    config,
    keys: deps.keys ?? staticKeys([signer.current, signer.next]),
    idempotency: idempotencyStore(database.db, id.cipher),
    routes: identityRoutes(id, { touches: t, serviceClients: loadServiceClients(config.serviceClientsFile) }),
    readiness: {
      ...readiness(database),
      valkey: () =>
        cache.valkeyUp() ? undefined : Promise.reject(new Error("valkey is down (per-pod limits in use)")),
    },
  });
  id.log = service.log;
  id.metrics = identityMetrics(service.metrics);
  service.addBackground({
    name: "touch-flush",
    start() {
      const timer = setInterval(
        () => void t.flush().catch((e) => service.log.warn({ err: e }, "touch flush failed")),
        15_000,
      );
      return {
        async stop() {
          clearInterval(timer);
          await t.flush().catch(() => {});
        },
      };
    },
  });
  if (config.natsUrl) service.addBackground(purgeChannel(config.natsUrl, cache, service.log));
  service.onShutdown(async () => {
    await cache.close();
    if (!deps.database) await database.close();
  });
  return { service, identity: id };
}

export async function createWorker(
  config: WorkerConfig,
  deps: ServiceDeps & { bus?: Bus; tickMs?: number } = {},
): Promise<{ service: Service; identity: Identity }> {
  const database = deps.database ?? createDb<DB>({ url: config.dbUrl, applicationName: "identity-worker" });
  const signer = deps.signer ?? loadSigner(config.jwtKeysDir);
  const cache = deps.cache ?? createAuthzCache({ valkeyUrl: config.valkeyUrl ?? null });
  const id = base(
    config,
    database,
    signer,
    deps.peers ?? defaultPeers(config, signer),
    {
      lookups: deps.lookups ?? { nearAccessKey: unavailable("attestation") },
      turnstile: deps.turnstile ?? unavailable("turnstile"),
      cache,
      dashboardOrigin: "",
      webauthn: { rpId: "", rpName: "NearPay", origins: [] },
      recoveryLockMs: 0,
    },
    deps.now ?? Date.now,
  );
  const service = createService({ name: "identity", config, readiness: readiness(database) });
  id.log = service.log;
  id.metrics = identityMetrics(service.metrics);

  const bus = deps.bus ?? (await connectBus({ url: config.natsUrl, name: `identity-worker@${hostname()}` }));
  await ensureStreams(bus, [STREAMS.identity]);
  service.addReadiness("bus", () => {
    if (!busReady(bus)) throw new Error("NATS connection is closed");
  });
  const handlers = identityHandlers(id, {
    async purgeKey(hash) {
      await cache.purgeKey(hash);
      bus.nc.publish(CACHE_PURGE_SUBJECT, `key:${hash}`);
    },
  });
  const durables = durablesOf("identity", Object.keys(handlers) as Subject[]);
  service.metrics.collectConsumerLag(async () =>
    Object.fromEntries(
      await Promise.all(durables.map(async (d) => [d.durable, await consumerLag(bus, d.stream, d.durable)])),
    ),
  );
  service.metrics.collectOutboxLag(() => outboxLagSeconds(database.db));
  service.metrics.collectJobsDue(() => jobsDue(database.db));
  service.metrics.collectDeadLettersOpen(() => deadLettersOpen(database.db));

  const onError = (e: unknown) => service.log.error({ err: e }, "background error");
  service.addBackground(
    outboxRelayTask({
      db: database.db,
      pool: database.pool,
      publish: (s, e, mid) => publish(bus, s, e, mid).then(() => {}),
      onError,
    }),
  );
  service.addBackground(
    domainConsumersTask({ bus, consumer: "identity", handlers, onDeadLetter: deadLetters(database.db), onError }),
  );
  service.addBackground(
    jobWorkerTask({
      db: database.db,
      workerId: `identity-worker@${hostname()}:${process.pid}`,
      handlers: jobHandlers(id),
      onError: (e, job) => service.log.warn({ err: e, job }, "job failed"),
      onDeadLetter: (j) => service.log.error({ job: j }, "job dead-lettered"),
      ...(deps.tickMs ? { pollMs: deps.tickMs } : {}),
    }),
  );
  service.addBackground(
    recurringJobsTask({
      db: database.db,
      pool: database.pool,
      name: "identity:recurring-jobs",
      jobs: RECURRING,
      onError,
      ...(deps.tickMs ? { tickMs: deps.tickMs } : {}),
    }),
  );
  service.onShutdown(async () => {
    await cache.close();
    if (!deps.bus) await bus.close();
    if (!deps.database) await database.close();
  });
  return { service, identity: id };
}
