import { defineWorkspace } from "vitest/config";

// unit: pure code (domain, property tests). integration: real Postgres/NATS/Valkey (Testcontainers),
// spec contract tests and scenario runs against the service over HTTP.
export default defineWorkspace([
  {
    test: {
      name: "unit",
      include: ["test/unit/**/*.test.ts", "test/property/**/*.test.ts"],
    },
  },
  {
    test: {
      name: "integration",
      include: ["test/integration/**/*.test.ts", "test/contract/**/*.test.ts", "test/scenario/**/*.test.ts"],
      testTimeout: 120_000,
      hookTimeout: 180_000,
      pool: "forks",
      poolOptions: { forks: { singleFork: true } },
    },
  },
]);
