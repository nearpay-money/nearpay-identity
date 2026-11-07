/**
 * Ops CLI entry (platform §3): `docker compose exec identity-api /nodejs/bin/node dist/ops.js …`.
 * Reads the api container's configuration; logs go to stderr, results to stdout.
 */
import { hostname } from "node:os";
import { createDb, createEnvelopeCipher, parseKek } from "@nearpay-internal/db";
import { ConfigError, createLogger } from "@nearpay-internal/service";
import { NO_CONSOLE, noMetrics } from "./app/context.js";
import { loadSigner } from "./app/tokens.js";
import { readOpsConfig } from "./config.js";
import { createAuthzCache } from "./infra/cache.js";
import { httpPeers } from "./infra/clients/peers.js";
import type { DB } from "./infra/db/schema.js";
import { runOps } from "./ops/cli.js";

let code = 1;
try {
  const config = readOpsConfig();
  const database = createDb<DB>({ url: config.dbUrl, applicationName: "identity-ops" });
  const signer = loadSigner(config.jwtKeysDir);
  const cache = createAuthzCache({ valkeyUrl: null });
  try {
    code = await runOps(
      process.argv.slice(2),
      {
        env: config.env,
        db: database.db,
        cipher: createEnvelopeCipher(parseKek(config.piiKek)),
        log: createLogger({
          service: "identity-ops",
          env: config.env,
          level: config.logLevel,
          destination: process.stderr,
        }),
        metrics: noMetrics,
        signer,
        peers: httpPeers({
          complianceUrl: config.complianceUrl,
          railsUrl: config.railsUrl,
          notifyUrl: config.notifyUrl,
          serviceToken: () => signer.serviceToken(),
        }),
        cooloffMs: 0,
        recoveryLockMs: 0,
        dashboardOrigin: "",
        webauthn: { rpId: "", rpName: "NearPay", origins: [] },
        console: { ...NO_CONSOLE, origin: config.opsOrigin?.replace(/\/$/, "") ?? null },
        lookups: {
          nearAccessKey: () => {
            throw new Error("not available in the ops CLI");
          },
        },
        turnstile: async () => false,
        cache,
        now: Date.now,
      },
      { actor: config.opsActor ?? `cli@${hostname()}` },
    );
  } finally {
    await cache.close();
    await database.close();
  }
} catch (e) {
  process.stderr.write(
    `${e instanceof ConfigError ? e.message : e instanceof Error ? (e.stack ?? e.message) : String(e)}\n`,
  );
}
process.exit(code);
