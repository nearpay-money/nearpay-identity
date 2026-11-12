/**
 * Cloudflare Turnstile (sign-up and recovery, lld/identity.md §6). Cloudflare's documented test secrets behave
 * deterministically, so they are answered locally only when NP_ENV is `local`/`test` (no egress needed):
 * `1x…AA` always passes, `2x…AA` always fails, `3x…AA` reports a spent token.
 *
 * An outage of siteverify (network error, timeout, 5xx, 429, an unreadable answer) is reported as `unavailable`,
 * never as a pass: the caller then applies a stricter per-IP limit instead of the challenge (as payments does,
 * F-12), so onboarding keeps working while Cloudflare is down without opening sign-up to bots. Any other answer
 * (`success: false`, a 4xx such as a bad secret) is `failed`.
 */
import { isDevEnv } from "../../domain/env.js";

export type TurnstileResult = "ok" | "failed" | "unavailable";
export type TurnstileVerifier = (token: string, ip: string | null) => Promise<TurnstileResult>;

const TEST_SECRETS: Record<string, TurnstileResult> = {
  "1x0000000000000000000000000000000AA": "ok",
  "2x0000000000000000000000000000000AA": "failed",
  "3x0000000000000000000000000000000AA": "failed",
};

export function turnstile(o: {
  secret: string;
  env: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}): TurnstileVerifier {
  const f = o.fetch ?? fetch;
  if (isDevEnv(o.env) && Object.hasOwn(TEST_SECRETS, o.secret)) {
    const result = TEST_SECRETS[o.secret] as TurnstileResult;
    return async () => result;
  }
  return async (token, ip) => {
    const body = new URLSearchParams({ secret: o.secret, response: token, ...(ip ? { remoteip: ip } : {}) });
    try {
      const res = await f("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body,
        signal: AbortSignal.timeout(o.timeoutMs ?? 3_000),
      });
      if (res.status >= 500 || res.status === 429) return "unavailable";
      if (!res.ok) return "failed";
      return ((await res.json()) as { success?: boolean }).success === true ? "ok" : "failed";
    } catch {
      return "unavailable";
    }
  };
}
