/**
 * Cloudflare Turnstile (sign-up, lld/identity.md §6). Cloudflare's documented test secrets behave
 * deterministically, so they are answered locally only when NP_ENV is `local`/`test` (no egress needed):
 * `1x…AA` always passes, `2x…AA` always fails, `3x…AA` reports a spent token.
 */
import { isDevEnv } from "../../domain/env.js";

export type TurnstileVerifier = (token: string, ip: string | null) => Promise<boolean>;

const TEST_SECRETS: Record<string, boolean> = {
  "1x0000000000000000000000000000000AA": true,
  "2x0000000000000000000000000000000AA": false,
  "3x0000000000000000000000000000000AA": false,
};

export function turnstile(o: {
  secret: string;
  env: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}): TurnstileVerifier {
  const f = o.fetch ?? fetch;
  if (isDevEnv(o.env) && Object.hasOwn(TEST_SECRETS, o.secret)) {
    const result = TEST_SECRETS[o.secret] as boolean;
    return async () => result;
  }
  return async (token, ip) => {
    const body = new URLSearchParams({ secret: o.secret, response: token, ...(ip ? { remoteip: ip } : {}) });
    const res = await f("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
      signal: AbortSignal.timeout(o.timeoutMs ?? 3_000),
    });
    if (!res.ok) throw new Error(`turnstile responded ${res.status}`);
    return ((await res.json()) as { success?: boolean }).success === true;
  };
}
