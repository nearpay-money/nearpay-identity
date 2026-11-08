/**
 * Spec test vectors. Stage 4 vectors ship in `@nearpay/spec` 0.4.0; until it is published the files are
 * copied byte for byte from nearpay-spec `stage-4/4.1-chains` (25ab1af) into `test/fixtures/spec-0.4.0/`
 * (PLACEHOLDER — delete that directory and the fallback in Phase B).
 */
import { existsSync, readFileSync } from "node:fs";

export function specVector<T = unknown>(name: string): T {
  const pkg = new URL(`../../node_modules/@nearpay/spec/test-vectors/${name}`, import.meta.url);
  const copy = new URL(`../fixtures/spec-0.4.0/${name}`, import.meta.url);
  return JSON.parse(readFileSync(existsSync(pkg) ? pkg : copy, "utf8")) as T;
}
