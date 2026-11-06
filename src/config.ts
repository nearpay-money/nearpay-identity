/** Configuration (lld/identity.md §11, foundations §13). */
import { baseConfigShape, list, loadConfig, secret, url } from "@nearpay-internal/service";
import { z } from "zod";

const shared = {
  ...baseConfigShape,
  dbUrl: secret(url(["postgres:", "postgresql:"])),
  /** KEK for PII at rest (names, IPs) and idempotent responses. */
  piiKek: secret(),
  /** Directory with `current.pem` and `next.pem` (Ed25519) — internal JWT signing keys. */
  jwtKeysDir: z.string().min(1).default("/run/secrets/jwt"),
  complianceUrl: url(["http:", "https:"]),
  /** 86 400 s; 0 is allowed only when NP_ENV=local (checked in readConfig). */
  cooloffSeconds: z.coerce
    .number()
    .int()
    .min(0)
    .max(30 * 86_400)
    .default(86_400),
};

export const apiShape = {
  ...shared,
  valkeyUrl: url(["redis:", "rediss:"]),
  /** Core NATS for the cross-replica cache purge (`ctl.identity.cache.purge`); optional. */
  natsUrl: url(["nats:", "tls:"]).optional(),
  /** `{"clients":[{"client_id","secret_sha256"}]}` (scopes come from the spec). */
  serviceClientsFile: z.string().min(1),
  turnstileSecret: secret(),
  webauthnRpId: z.string().min(1).default("nearpay.localhost"),
  webauthnOrigins: list(url(["https:", "http:"])),
  dashboardOrigin: url(["https:", "http:"]),
  recoveryLockSeconds: z.coerce.number().int().min(0).default(172_800),
  railsUrl: url(["http:", "https:"]),
  notifyUrl: url(["http:", "https:"]),
  nearRpcUrls: list(url(["https:", "http:"])),
  /** `{"<chain id>": ["https://…"]}` for ERC-1271 contract-wallet attestations (optional). */
  evmRpcUrls: z
    .string()
    .default("{}")
    .transform((s, ctx) => {
      try {
        const v = JSON.parse(s) as unknown;
        const r = z.record(z.string().regex(/^\d+$/), z.array(z.url())).safeParse(v);
        if (r.success) return r.data;
      } catch {}
      ctx.addIssue({ code: "custom", message: 'expected {"<chain id>": ["https://…"]}' });
      return z.NEVER;
    }),
};

export const workerShape = {
  ...shared,
  natsUrl: url(["nats:", "tls:"]),
  /** Revoked keys are purged from Valkey too (optional). */
  valkeyUrl: url(["redis:", "rediss:"]).optional(),
};

export const opsShape = {
  ...baseConfigShape,
  dbUrl: secret(url(["postgres:", "postgresql:"])),
  piiKek: secret(),
  jwtKeysDir: z.string().min(1).default("/run/secrets/jwt"),
  complianceUrl: url(["http:", "https:"]).default("http://compliance-api:8080"),
  railsUrl: url(["http:", "https:"]).default("http://rails-api:8080"),
  notifyUrl: url(["http:", "https:"]).default("http://notify-api:8080"),
  opsActor: z.string().min(1).max(100).optional(),
};

export const migrateShape = { ...baseConfigShape, dbUrl: secret(url(["postgres:", "postgresql:"])) };

export type ApiConfig = z.output<z.ZodObject<typeof apiShape>>;
export type WorkerConfig = z.output<z.ZodObject<typeof workerShape>>;
export type OpsConfig = z.output<z.ZodObject<typeof opsShape>>;

/** A zero cool-off would let a stolen session redirect live funds at once: local stacks only. */
export function checkCooloff(c: { env: string; cooloffSeconds: number }): void {
  if (c.cooloffSeconds === 0 && c.env !== "local" && c.env !== "test")
    throw new Error("NP_COOLOFF_SECONDS=0 is allowed only when NP_ENV=local");
}

export const readApiConfig = () => {
  const c = loadConfig(apiShape);
  checkCooloff(c);
  return c;
};
export const readWorkerConfig = () => {
  const c = loadConfig(workerShape);
  checkCooloff(c);
  return c;
};
export const readOpsConfig = () => loadConfig(opsShape);
