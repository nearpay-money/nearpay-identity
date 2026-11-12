/**
 * Turnstile siteverify outage on sign-up and recovery (audit 2026-11-12 IDENTITY-1): the challenge is never skipped
 * silently. While siteverify is down a request goes on under a stricter per-IP limit (5 per 10 minutes, as payments'
 * F-12); a failed challenge is still refused.
 */
import { sendMessage } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { turnstile } from "../../src/infra/clients/turnstile.js";
import { type Stack, startStack } from "../support/stack.js";
import { freshIp } from "../support/users.js";

let mode: "down" | "fail" | "pass" = "down";
let siteverifyCalls = 0;
const siteverify = (async () => {
  siteverifyCalls++;
  if (mode === "down") return new Response("upstream unavailable", { status: 503 });
  return new Response(JSON.stringify({ success: mode === "pass" }), {
    headers: { "content-type": "application/json" },
  });
}) as unknown as typeof fetch;

let s: Stack;
beforeAll(async () => {
  // the real client against a fake siteverify (a non-test secret on a server-like stage)
  s = await startStack({ turnstile: turnstile({ secret: "0x4AAAAAAA-real", env: "server", fetch: siteverify }) });
  // the limit is shared through Valkey; before the connection is up the cache counts locally (a stricter, separate bucket)
  for (let i = 0; i < 100 && !s.identity.cache.valkeyUp(); i++) await new Promise((r) => setTimeout(r, 50));
});
afterAll(async () => {
  await s?.stop();
});

const signup = (email: string, ip: string) =>
  s.gateway("POST", "/v1/auth/signup", { body: { email, turnstile_token: "tok" }, ip });
const linksTo = (email: string) =>
  s.notify.callsTo(sendMessage).filter((c) => (c.body as { to: string }).to === email).length;

describe("Turnstile siteverify outage", () => {
  it("siteverify 503: sign-up proceeds under the outage limit; the 6th from the same IP gets 429", async () => {
    mode = "down";
    const ip = freshIp();
    const before = siteverifyCalls;
    for (let i = 1; i <= 5; i++) {
      const r = await signup(`outage${i}@shop.test`, ip);
      expect(r.status, `sign-up ${i}`).toBe(202);
      expect(linksTo(`outage${i}@shop.test`)).toBe(1);
    }
    expect(siteverifyCalls - before).toBe(5); // the challenge was asked every time, not skipped
    const sixth = await signup("outage6@shop.test", ip);
    expect(sixth.status).toBe(429);
    expect((sixth.body as { error: { code: string } }).error.code).toBe("rate_limited");
    expect(Number(sixth.headers["retry-after"])).toBeGreaterThan(0);
    expect(linksTo("outage6@shop.test")).toBe(0);
    // another client IP has its own allowance
    expect((await signup("outage7@shop.test", freshIp())).status).toBe(202);
  });

  it("recovery shares the per-IP outage limit", async () => {
    mode = "down";
    const ip = freshIp();
    for (let i = 0; i < 5; i++)
      expect(
        (await s.gateway("POST", "/v1/auth/recovery", { body: { email: "lost@shop.test", turnstile_token: "t" }, ip }))
          .status,
      ).toBe(202);
    expect((await signup("after-recovery@shop.test", ip)).status).toBe(429);
  });

  it("a failed challenge is still refused, outage or not; a passed one is not counted against the outage limit", async () => {
    mode = "fail";
    const r = await signup("bot@shop.test", freshIp());
    expect(r.status).toBe(403);
    expect((r.body as { error: { code: string } }).error.code).toBe("turnstile_failed");
    mode = "pass";
    const ip = freshIp();
    for (let i = 0; i < 7; i++) expect((await signup(`fine${i}@shop.test`, ip)).status).toBe(202);
  });

  it("counts the outage decisions in nearpay_identity_turnstile_outage_total", async () => {
    const text = await s.api.metrics.render();
    expect(text).toMatch(/nearpay_identity_turnstile_outage_total\{result="allowed"\} 11/);
    expect(text).toMatch(/nearpay_identity_turnstile_outage_total\{result="limited"\} 2/);
  });
});
