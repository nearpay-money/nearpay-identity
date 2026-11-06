import { defineConfig } from "vitest/config";

// Coverage gate (foundations §16): ≥ 90% branch coverage on src/domain.
export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/domain/**/*.ts"],
      reporter: ["text", "json-summary"],
      thresholds: { branches: 90 },
    },
  },
});
