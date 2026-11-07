/** The Stage 1 identity ops CLI (platform §3) against Postgres with spec-mocked peers. */
import { toUuid } from "@nearpay-internal/ids";
import { sendMessage } from "@nearpay-internal/spec";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runOps, USAGE } from "../../src/ops/cli.js";
import { nearSigner } from "../support/signers.js";
import { eventually, type Stack, startStack, USDC_NEAR } from "../support/stack.js";
import { as, signUp } from "../support/users.js";

let s: Stack;
beforeAll(async () => {
  s = await startStack({ worker: true, cooloffSeconds: 3600 });
});
afterAll(async () => {
  await s?.stop();
});

async function ops(...argv: string[]) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await runOps(argv, s.identity, { actor: "cli@test", out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, json: out.length ? JSON.parse(out.join("\n")) : undefined, err: err.join("\n") };
}

describe("ops CLI", () => {
  it("prints usage for bad commands", async () => {
    for (const argv of [[], ["nope"], ["operator-add", "x@y.z", "god"], ["account-show", "--bogus"]]) {
      const r = await ops(...argv);
      expect(r.code, argv.join(" ")).toBe(2);
      expect(r.err).toContain(USAGE.split("\n")[0]);
    }
  });

  it("seeds the demo merchant idempotently (new demo keys each run, one active test destination)", async () => {
    const a = await ops("seed-demo");
    expect(a.code, a.err).toBe(0);
    expect(a.json).toMatchObject({ created: true, owner: "demo@merchant.test" });
    expect(a.json.secret_key).toMatch(/^sk_test_/);
    expect(a.json.publishable_key).toMatch(/^pk_test_/);
    const b = await ops("seed-demo");
    expect(b.json).toMatchObject({ created: false, account: a.json.account, destination: a.json.destination });
    expect(b.json.secret_key).not.toBe(a.json.secret_key);
    expect((await s.gateway("GET", "/v1/settlement_destinations", { bearer: a.json.secret_key })).status).toBe(401);
    const list = await s.gateway("GET", "/v1/settlement_destinations", { bearer: b.json.secret_key });
    expect(list.body.data).toMatchObject([{ id: a.json.destination, status: "active", livemode: false }]);
    const show = await ops("account-show", "demo@merchant.test");
    expect(show.json).toMatchObject({
      id: a.json.account,
      display_name: "Demo Shop",
      members: [{ email: "demo@merchant.test", role: "owner" }],
    });
  });

  it("adds and revokes operators", async () => {
    const u = await signUp(s, "op@nearpay.test");
    expect((await ops("operator-add", "op@nearpay.test", "ops_admin")).json).toMatchObject({ role: "ops_admin" });
    const row = await s.admin.db
      .selectFrom("ops_operators")
      .selectAll()
      .where("user_id", "=", toUuid(u.userId, "usr"))
      .executeTakeFirstOrThrow();
    expect(row.role).toBe("ops_admin");
    expect((await ops("operator-revoke", "op@nearpay.test")).json).toMatchObject({ revoked: true });
    // Stage 2: an operator needs no merchant account; the user is created and an enrolment link mailed
    const fresh = await ops("operator-add", "nobody@nearpay.test", "ops");
    expect(fresh.code, fresh.err).toBe(0);
    const mail = s.notify
      .callsTo(sendMessage)
      .map((c) => c.body as { template: string; to: string; variables: { link_url: string; role: string } })
      .filter((m) => m.template === "ops.enrolment" && m.to === "nobody@nearpay.test");
    expect(mail).toHaveLength(1);
    expect(mail[0]?.variables.link_url).toMatch(/^https:\/\/ops\.nearpay\.localhost\/auth\/enrol#token=/);
    expect((await ops("operator-add", "not-an-email", "ops")).code).toBe(2);
  });

  it("destination-cooloff-skip activates a cooling-off destination now (local only)", async () => {
    const u = await signUp(s, "cool@shop.test");
    const near = nearSigner();
    const r = await s.gateway(
      "POST",
      "/v1/settlement_destinations",
      as(u, "live", {
        asset_id: USDC_NEAR,
        type: "intents_account",
        chain: "near:mainnet",
        address: near.implicitAccount,
        label: "x",
      }),
    );
    const c = r.body.attestation_challenge;
    const att = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", {
        challenge_id: c.id,
        standard: "nep413",
        signature: near.sign(c.message, Buffer.from(c.nonce, "base64")),
        public_key: near.publicKey,
      }),
    );
    expect(att.body.status).toBe("cooling_off");
    expect(att.body.active_at).toBeGreaterThan(Date.now() / 1000 + 3000);
    const skip = await ops("destination-cooloff-skip", r.body.id);
    expect(skip.code, skip.err).toBe(0);
    await eventually(
      async () =>
        (await s.gateway("GET", `/v1/settlement_destinations/${r.body.id}`, { cookie: u.cookie, mode: "live" })).body
          .status === "active",
    );
    expect((await ops("destination-cooloff-skip", r.body.id)).code).toBe(1);
  });
});
