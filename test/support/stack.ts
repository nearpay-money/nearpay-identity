/**
 * Integration harness: Postgres (migrator/app roles), Valkey, optionally NATS + the worker, and
 * spec-generated mocks of compliance, rails and notify. `gateway()` reproduces Traefik: it calls
 * `/internal/authz` with the forwarded headers, then the routed identity endpoint with the minted
 * `X-NearPay-Token` (or returns the authz error) — the same two hops as production.
 */
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadSigningKey } from "@nearpay-internal/auth";
import { type Bus, connectBus, type Envelope, publish } from "@nearpay-internal/bus";
import { createDb, type Database, migrate } from "@nearpay-internal/db";
import { newId } from "@nearpay-internal/ids";
import type { Service } from "@nearpay-internal/service";
import {
  createScreening,
  getDestinationMinimums,
  getInternalAsset,
  getInternalKybCase,
  INTERNAL_ROUTES,
  listChainProfiles,
  sendMessage,
} from "@nearpay-internal/spec";
import {
  type EventProbe,
  eventProbe,
  type MockPeer,
  mockError,
  mockPeer,
  provisionServiceDatabase,
  type Started,
  startNats,
  startPostgres,
  startValkey,
  testSigningKey,
} from "@nearpay-internal/testing";
import type { ConsoleConfig, Identity } from "../../src/app/context.js";
import { createApi, createWorker } from "../../src/app/services.js";
import { signerFrom } from "../../src/app/tokens.js";
import type { ApiConfig, WorkerConfig } from "../../src/config.js";
import { createAuthzCache } from "../../src/infra/cache.js";
import { httpPeers } from "../../src/infra/clients/peers.js";
import type { OwnershipLookups } from "../../src/infra/crypto/attestation.js";
import { MIGRATIONS_DIR } from "../../src/infra/db/migrations.js";
import type { DB } from "../../src/infra/db/schema.js";

export const RP_ID = "nearpay.localhost";
export const ORIGIN = "https://dashboard.nearpay.localhost";
export const USDC_NEAR = "nep141:17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
export const USDC_BASE = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
export const PAYMENTS_CLIENT_SECRET = "payments-client-secret-for-tests";
export const BILLING_CLIENT_SECRET = "billing-client-secret-for-tests";
export const OPS_ORIGIN = "https://ops.nearpay.localhost";
export const OPS_HOST = "ops.nearpay.localhost";
/** AAGUID of the test "hardware key" (YubiKey 5 series); the only allow-listed model in tests. */
export const TEST_AAGUID = "cb69481e-8ff7-4039-93ec-0a2729a154a8";

export interface GatewayRequest {
  cookie?: string;
  csrf?: string;
  bearer?: string;
  mode?: "live" | "test";
  body?: unknown;
  ip?: string;
  host?: string;
  /** Extra request headers passed to the service after authz (e.g. `idempotency-key`). */
  headers?: Record<string, string>;
  /** `Cf-Access-Jwt-Assertion` (Cloudflare Access console mode), sent to authz and the route. */
  accessJwt?: string;
}

export interface Response {
  status: number;
  // biome-ignore lint/suspicious/noExplicitAny: response bodies are asserted field by field in tests
  body: any;
  headers: Record<string, string | string[] | undefined>;
}

export interface Stack {
  readonly pg: Started;
  readonly admin: Database<DB>;
  readonly api: Service;
  readonly identity: Identity;
  readonly worker: { service: Service; identity: Identity } | null;
  readonly bus: Bus | null;
  readonly compliance: MockPeer;
  readonly rails: MockPeer;
  readonly notify: MockPeer;
  readonly nearKeys: Map<string, "FullAccess" | "FunctionCall">;
  readonly natsUrl: string | null;
  /** Through the gateway (authz → route). */
  gateway(method: string, path: string, r?: GatewayRequest): Promise<Response>;
  /** Directly to identity (internal routes). */
  direct(
    method: string,
    path: string,
    o?: { headers?: Record<string, string>; body?: unknown; token?: string },
  ): Promise<Response>;
  publishEvent(e: Envelope): Promise<void>;
  probe(): Promise<EventProbe>;
  resetMocks(): void;
  stop(): Promise<void>;
}

export interface StackOptions {
  worker?: boolean;
  cooloffSeconds?: number;
  now?: () => number;
  /** Console settings over the test defaults (platform passkeys, Cloudflare Access mode, …). */
  console?: Partial<ConsoleConfig>;
}

/** Default mock answers: every asset/chain supported, screening allows, mail accepted. */
function defaultMocks(compliance: MockPeer, rails: MockPeer, notify: MockPeer) {
  compliance.on(createScreening, async (ctx) => ({
    screening_id: newId("scr"),
    decision: (ctx.body.subject.includes("sanctioned") ? "block" : "allow") as "block" | "allow",
    risk: null,
    reasons: ctx.body.subject.includes("sanctioned") ? ["sandbox_magic"] : [],
    cached: false,
    post_screen_required: false,
  }));
  rails.on(getInternalAsset, async (ctx) => {
    const id = ctx.params.asset_id;
    if (id.includes("unknown")) mockError("resource_missing", { params: { object: "asset", id } });
    const chain = id.startsWith("nep141:base-")
      ? "eip155:8453"
      : id.startsWith("nep141:xrp")
        ? "xrp:mainnet"
        : "near:mainnet";
    return {
      asset_id: id,
      chain,
      blockchain: chain === "eip155:8453" ? "base" : chain === "xrp:mainnet" ? "xrp" : "near",
      symbol: "USDC",
      decimals: 6,
      family: chain === "eip155:8453" ? "evm" : "near",
      is_usd_stable: true,
      price_usd: "1",
      price_ok: true,
      as_of: new Date().toISOString(),
    };
  });
  const profile = (chain: string, blockchain: string, family: "near" | "evm", memo: "none" | "required") => ({
    chain,
    blockchain,
    family,
    tier: "A" as const,
    min_deadline_s: 600,
    default_deadline_s: 1800,
    finality: "final",
    verification_timeout_s: 3600,
    memo_mode: memo,
    explorer_tx_url: "https://explorer.example/tx/{tx}",
  });
  rails.on(listChainProfiles, async () => ({
    profiles: [
      profile("near:mainnet", "near", "near", "none"),
      profile("eip155:8453", "base", "evm", "none"),
      profile("eip155:1", "eth", "evm", "none"),
    ],
  }));
  rails.on(getDestinationMinimums, async (ctx) =>
    Object.fromEntries(
      ctx.query.keys
        .split(",")
        .map((k) => [k, { min_amount_base: "500000", min_usd_micros: 500_000, computed_at: new Date().toISOString() }]),
    ),
  );
  notify.on(sendMessage, async () => ({ message_id: `msg_${"0".repeat(26)}` as `msg_${string}` }));
  compliance.on(getInternalKybCase, async (ctx) => ({
    account_id: ctx.params.id,
    status: "approved" as const,
    profile: {
      legal_name: "Acme Trading GmbH",
      country_of_incorporation: "DE",
      registration_number: "HRB 12345",
      business_type: null,
      website: null,
      business_address: null,
      representative: null,
      expected_monthly_volume: null,
    },
    decided_at: new Date().toISOString(),
  }));
}

export async function startStack(o: StackOptions = {}): Promise<Stack> {
  const [pg, valkey, nats] = await Promise.all([
    startPostgres({ database: "postgres" }),
    startValkey(),
    o.worker ? startNats() : Promise.resolve(null),
  ]);
  const { migratorUrl, appUrl } = await provisionServiceDatabase(pg.url, "identity");
  const migrator = createDb<DB>({ url: migratorUrl });
  await migrate(migrator.db, MIGRATIONS_DIR);
  await migrator.close();

  const [compliance, rails, notify] = await Promise.all(
    (["compliance", "rails", "notify"] as const).map((service) => mockPeer({ service, routes: INTERNAL_ROUTES })),
  );
  defaultMocks(compliance as MockPeer, rails as MockPeer, notify as MockPeer);

  const nextPem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const signer = signerFrom(testSigningKey(), loadSigningKey("test-next", nextPem));
  const dir = mkdtempSync(join(tmpdir(), "identity-"));
  const clientsFile = join(dir, "service_clients.json");
  writeFileSync(
    clientsFile,
    JSON.stringify({
      clients: [
        { client_id: "payments", secret_sha256: createHash("sha256").update(PAYMENTS_CLIENT_SECRET).digest("hex") },
        { client_id: "billing", secret_sha256: createHash("sha256").update(BILLING_CLIENT_SECRET).digest("hex") },
      ],
    }),
  );
  const nearKeys = new Map<string, "FullAccess" | "FunctionCall">();
  const lookups: OwnershipLookups = {
    nearAccessKey: async (account, key) => nearKeys.get(`${account}|${key}`) ?? null,
    erc1271: async () => null,
  };
  const peers = httpPeers({
    complianceUrl: (compliance as MockPeer).url,
    railsUrl: (rails as MockPeer).url,
    notifyUrl: (notify as MockPeer).url,
    serviceToken: () => signer.serviceToken(),
  });

  const admin = createDb<DB>({ url: appUrl, applicationName: "identity-test" });
  const apiDb = createDb<DB>({ url: appUrl, applicationName: "identity-api-test" });
  const base = {
    env: "test" as const,
    logLevel: (process.env.NP_TEST_LOG ?? "silent") as "silent",
    host: "127.0.0.1",
    port: 0,
    metricsPort: 0,
    dbUrl: appUrl,
    piiKek: randomBytes(32).toString("base64"),
    jwtKeysDir: dir,
    complianceUrl: (compliance as MockPeer).url,
    cooloffSeconds: o.cooloffSeconds ?? 0,
  };
  const apiConfig: ApiConfig = {
    ...base,
    valkeyUrl: valkey.url,
    natsUrl: nats?.url,
    serviceClientsFile: clientsFile,
    turnstileSecret: "1x0000000000000000000000000000000AA",
    webauthnRpId: RP_ID,
    webauthnOrigins: [ORIGIN],
    dashboardOrigin: ORIGIN,
    recoveryLockSeconds: 172_800,
    railsUrl: (rails as MockPeer).url,
    notifyUrl: (notify as MockPeer).url,
    nearRpcUrls: ["https://rpc.invalid"],
    evmRpcUrls: {},
    opsAllowPlatformPasskeys: false,
    opsAuthMode: "passkey",
  };
  const apiCache = createAuthzCache({ valkeyUrl: valkey.url });
  const { service: api, identity } = createApi(apiConfig, {
    console: {
      origin: OPS_ORIGIN,
      rpId: OPS_HOST,
      aaguids: new Set([TEST_AAGUID]),
      attestationRoots: [],
      ...o.console,
    },
    database: apiDb,
    signer,
    peers,
    lookups,
    cache: apiCache,
    ...(o.now ? { now: o.now } : {}),
  });
  await api.start();

  let worker: Stack["worker"] = null;
  let bus: Bus | null = null;
  let workerDb: Database<DB> | null = null;
  if (o.worker && nats) {
    bus = await connectBus({ url: nats.url, name: "identity-test-publisher" });
    workerDb = createDb<DB>({ url: appUrl, applicationName: "identity-worker-test" });
    const wc: WorkerConfig = { ...base, natsUrl: nats.url, valkeyUrl: valkey.url };
    worker = await createWorker(wc, { database: workerDb, signer, peers, tickMs: 50 });
    await worker.service.start();
  }

  const inject = async (
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: unknown,
  ): Promise<Response> => {
    const r = await api.app.inject({
      method: method as "GET",
      url,
      headers,
      ...(body !== undefined ? { payload: body as object } : {}),
    });
    let parsed: unknown;
    try {
      parsed = r.body ? JSON.parse(r.body) : undefined;
    } catch {
      parsed = r.body;
    }
    return { status: r.statusCode, body: parsed, headers: r.headers as Response["headers"] };
  };

  return {
    pg,
    admin,
    api,
    identity,
    worker,
    bus,
    compliance: compliance as MockPeer,
    rails: rails as MockPeer,
    notify: notify as MockPeer,
    nearKeys,
    natsUrl: nats?.url ?? null,
    async gateway(method, path, r = {}) {
      // a fresh client IP per call unless given (anonymous routes are limited per IP)
      const ip = r.ip ?? `192.0.2.${Math.floor(Math.random() * 250) + 1}`;
      const fwd: Record<string, string> = {
        "x-forwarded-method": method,
        "x-forwarded-uri": path,
        "x-forwarded-host": r.host ?? "dashboard.nearpay.localhost",
        "x-forwarded-for": ip,
      };
      if (r.cookie) fwd.cookie = r.cookie;
      if (r.csrf) fwd["x-csrf-token"] = r.csrf;
      if (r.bearer) fwd.authorization = `Bearer ${r.bearer}`;
      if (r.mode) fwd["nearpay-mode"] = r.mode;
      if (r.accessJwt) fwd["cf-access-jwt-assertion"] = r.accessJwt;
      const authz = await inject("GET", "/internal/authz", fwd);
      if (authz.status !== 200) return authz;
      const token = authz.headers["x-nearpay-token"] as string;
      const headers: Record<string, string> = {
        "x-nearpay-token": token,
        "x-request-id": authz.headers["x-request-id"] as string,
        host: r.host ?? "dashboard.nearpay.localhost",
        "x-forwarded-for": ip,
        ...(r.cookie ? { cookie: r.cookie } : {}),
        ...(r.accessJwt ? { "cf-access-jwt-assertion": r.accessJwt } : {}),
        ...r.headers,
      };
      return inject(method, path, headers, r.body);
    },
    async direct(method, path, opts = {}) {
      return inject(
        method,
        path,
        { ...(opts.token ? { "x-nearpay-token": opts.token } : {}), ...(opts.headers ?? {}) },
        opts.body,
      );
    },
    async publishEvent(e) {
      if (!bus) throw new Error("no NATS in this stack");
      await publish(bus, e.subject, e);
    },
    async probe() {
      if (!nats) throw new Error("no NATS in this stack");
      return eventProbe(nats.url);
    },
    resetMocks() {
      for (const m of [compliance, rails, notify] as MockPeer[]) m.reset();
      defaultMocks(compliance as MockPeer, rails as MockPeer, notify as MockPeer);
    },
    async stop() {
      await worker?.service.stop();
      await api.stop();
      await bus?.close();
      await workerDb?.close();
      await apiDb.close();
      await admin.close();
      await Promise.all(([compliance, rails, notify] as MockPeer[]).map((m) => m.stop()));
      await Promise.all([pg.stop(), valkey.stop(), nats?.stop()]);
    },
  };
}

export async function eventually<T>(fn: () => Promise<T | null | undefined | false>, timeoutMs = 15_000): Promise<T> {
  const until = Date.now() + timeoutMs;
  let last: unknown;
  for (;;) {
    try {
      const v = await fn();
      if (v !== null && v !== undefined && v !== false) return v as T;
    } catch (e) {
      last = e;
    }
    if (Date.now() > until)
      throw new Error(`condition not met within ${timeoutMs} ms${last ? `: ${String(last)}` : ""}`);
    await new Promise((r) => setTimeout(r, 50));
  }
}
