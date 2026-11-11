/** Spec test vectors, read from the installed `@nearpay-money/spec` package (Stage 4 vectors since 0.4.0). */
import { readFileSync } from "node:fs";

export function specVector<T = unknown>(name: string): T {
  return JSON.parse(
    readFileSync(new URL(`../../node_modules/@nearpay-money/spec/test-vectors/${name}`, import.meta.url), "utf8"),
  ) as T;
}
