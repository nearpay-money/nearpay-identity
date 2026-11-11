import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { authenticateClient, kidOf, loadServiceClients, loadSigner } from "../../src/app/tokens.js";
import { cooloffNotice } from "../../src/config.js";
import { isDevEnv } from "../../src/domain/env.js";
import { turnstile } from "../../src/infra/clients/turnstile.js";

const pem = () => generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();

describe("signing keys", () => {
  it("kid = local- + 12 hex of sha256(raw public key); JWKS has current and next", async () => {
    const dir = mkdtempSync(join(tmpdir(), "jwt-"));
    const [cur, next] = [pem(), pem()];
    writeFileSync(join(dir, "current.pem"), cur);
    writeFileSync(join(dir, "next.pem"), next);
    const s = loadSigner(dir);
    expect(s.current.kid).toMatch(/^local-[0-9a-f]{12}$/);
    expect(s.current.kid).toBe(kidOf(cur));
    expect(s.next.kid).not.toBe(s.current.kid);
    const jwks = await s.jwks();
    expect(jwks.keys.map((k) => k.kid)).toEqual([s.current.kid, s.next.kid]);
    const token = await s.sign({ sub: "anonymous", ptype: "anonymous", scp: [] });
    const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet(jwks as never), {
      issuer: "nearpay-identity",
      audience: "nearpay",
    });
    expect(protectedHeader.kid).toBe(s.current.kid);
    expect((payload.exp as number) - (payload.iat as number)).toBe(60);
    // identity's own service token: cached, 5 minutes, identity's scopes
    const st = await s.serviceToken();
    expect(await s.serviceToken()).toBe(st);
    const { payload: sp } = await jwtVerify(st, createLocalJWKSet(jwks as never));
    expect(sp).toMatchObject({
      sub: "identity",
      ptype: "service",
      scp: ["compliance.screen", "rails.read", "notify.send", "compliance.read"],
    });
  });
  it("a missing key file fails startup", () => {
    expect(() => loadSigner(mkdtempSync(join(tmpdir(), "nojwt-")))).toThrow();
  });
});

describe("service clients", () => {
  const secret = "s3cret-for-payments";
  const dir = mkdtempSync(join(tmpdir(), "sc-"));
  const file = join(dir, "clients.json");
  writeFileSync(
    file,
    JSON.stringify({
      clients: [
        { client_id: "payments", secret_sha256: createHash("sha256").update(secret).digest("hex") },
        { client_id: "intruder", secret_sha256: "00".repeat(32) },
        { client_id: "rails", secret_sha256: "not-hex" },
      ],
    }),
  );
  const clients = loadServiceClients(file);
  const basic = (id: string, s: string) => `Basic ${Buffer.from(`${id}:${s}`).toString("base64")}`;
  it("loads known services only", () => {
    expect([...clients.keys()]).toEqual(["payments"]);
  });
  it("authenticates HTTP Basic client credentials", () => {
    expect(authenticateClient(clients, basic("payments", secret))).toBe("payments");
    expect(authenticateClient(clients, basic("payments", "wrong"))).toBeNull();
    expect(authenticateClient(clients, basic("rails", secret))).toBeNull();
    expect(authenticateClient(clients, "Bearer x")).toBeNull();
    expect(authenticateClient(clients, `Basic ${Buffer.from("nocolon").toString("base64")}`)).toBeNull();
    expect(authenticateClient(clients, undefined)).toBeNull();
  });
});

describe("turnstile", () => {
  it("answers Cloudflare's test secrets locally outside the server stage", async () => {
    expect(await turnstile({ secret: "1x0000000000000000000000000000000AA", env: "local" })("t", null)).toBe(true);
    expect(await turnstile({ secret: "2x0000000000000000000000000000000AA", env: "local" })("t", null)).toBe(false);
  });
  it("calls siteverify otherwise", async () => {
    const calls: string[] = [];
    const f = (async (_u: string, init: RequestInit) => {
      calls.push(String(init.body));
      return new Response(JSON.stringify({ success: true }), { headers: { "content-type": "application/json" } });
    }) as unknown as typeof fetch;
    expect(
      await turnstile({ secret: "1x0000000000000000000000000000000AA", env: "server", fetch: f })("tok", "1.2.3.4"),
    ).toBe(true);
    expect(calls[0]).toContain("response=tok");
    expect(calls[0]).toContain("remoteip=1.2.3.4");
    const bad = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
    await expect(turnstile({ secret: "real", env: "local", fetch: bad })("tok", null)).rejects.toThrow(/500/);
  });
  // audit finding 2: the always-pass test secret is answered locally only for NP_ENV local/test
  it("never answers a test secret locally on any stage other than local/test", async () => {
    for (const env of ["staging", "production", "", "Local"]) {
      const calls: string[] = [];
      const f = (async (_u: string, init: RequestInit) => {
        calls.push(String(init.body));
        return new Response(JSON.stringify({ success: false }), { headers: { "content-type": "application/json" } });
      }) as unknown as typeof fetch;
      expect(await turnstile({ secret: "1x0000000000000000000000000000000AA", env, fetch: f })("tok", null)).toBe(
        false,
      );
      expect(calls).toHaveLength(1);
    }
    expect(await turnstile({ secret: "1x0000000000000000000000000000000AA", env: "test" })("t", null)).toBe(true);
  });
});

describe("configuration", () => {
  it("no cool-off by default and on every stage; the boot line is informational (owner decision 2026-11-11)", () => {
    expect(cooloffNotice({ env: "server", cooloffSeconds: 0 })).toMatch(
      /cool-off: none .*as soon as they are attested/,
    );
    expect(cooloffNotice({ env: "local", cooloffSeconds: 0 })).toMatch(/cool-off: none/);
    expect(cooloffNotice({ env: "server", cooloffSeconds: 600 })).toMatch(
      /NP_COOLOFF_SECONDS=600 .*600 s after attestation/,
    );
    expect(cooloffNotice({ env: "server", cooloffSeconds: 86_400 })).toMatch(/86400 s after attestation/);
    expect(isDevEnv("test") && isDevEnv("local") && !isDevEnv("server") && !isDevEnv("staging")).toBe(true);
  });
});
