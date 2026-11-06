/**
 * Settlement destinations end to end (lld/identity.md §5, §8.2, §9) with the worker running:
 * creation, attestation (NEP-413 / EIP-191), cool-off activation, defaults, disable, live mode,
 * and the compliance consumers.
 */
import { connect } from "@nats-io/transport-node";
import { SettlementDestination } from "@nearpay/spec";
import { sql } from "@nearpay-internal/db";
import { newId, toUuid } from "@nearpay-internal/ids";
import { createScreening, getInternalAsset, listChainProfiles } from "@nearpay-internal/spec";
import { domainEvent, type EventProbe, mintServiceToken, mockError } from "@nearpay-internal/testing";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { evmSigner, nearSigner } from "../support/signers.js";
import { eventually, type Stack, startStack, USDC_BASE, USDC_NEAR } from "../support/stack.js";
import { as, signUp, stepUp, type User } from "../support/users.js";

let s: Stack;
let u: User;
let probe: EventProbe;
beforeAll(async () => {
  s = await startStack({ worker: true, cooloffSeconds: 0 });
  probe = await s.probe();
  u = await signUp(s, "dest@shop.test", "Dest Shop");
});
afterAll(async () => {
  await probe?.close();
  await s?.stop();
});
beforeEach(() => s.resetMocks());

const create = (body: Record<string, unknown>, mode: "test" | "live" = "test", who = u) =>
  s.gateway("POST", "/v1/settlement_destinations", as(who, mode, { label: "Main", ...body }));
const outbox = async (id: string) =>
  (
    await sql<{
      subject: string;
    }>`select subject from outbox where aggregate_id = ${toUuid(id, "sd")} order by created_at`.execute(s.admin.db)
  ).rows.map((r) => r.subject.replace("evt.identity.settlement_destination.", ""));
const status = async (id: string, mode: "test" | "live") =>
  (await s.gateway("GET", `/v1/settlement_destinations/${id}`, { cookie: u.cookie, mode })).body;

describe("test mode", () => {
  it("is active at once (verification test), becomes the default, shows the fingerprint and minimum", async () => {
    const r = await create({
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: "merchant.near",
    });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({
      object: "settlement_destination",
      livemode: false,
      status: "active",
      verification: "test",
      is_default: true,
      address: "merchant.near",
      disabled_reason: null,
    });
    expect(r.body.fingerprint).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{2}$/);
    expect(r.body.attestation_challenge).toBeUndefined();
    expect(await outbox(r.body.id)).toEqual(["created", "activated", "default_changed"]);
    const got = await status(r.body.id, "test");
    expect(got.min_payment_amount).toEqual({ amount: 50, currency: "usd" });
    const list = await s.gateway("GET", "/v1/settlement_destinations?status=active", { cookie: u.cookie });
    expect(list.body.data.map((d: { id: string }) => d.id)).toContain(r.body.id);
    expect(
      (await s.gateway("GET", "/v1/settlement_destinations", { cookie: u.cookie, mode: "live" })).body.data,
    ).toEqual([]);
    const ev = await probe.next("evt.identity.settlement_destination.activated", (e) => e.aggregate.id === r.body.id);
    expect(ev.data.object).toMatchObject({
      account: u.accountId,
      address_norm: "merchant.near",
      attestation_hash: null,
      status: "active",
    });
  });

  it("screens the address (test-mode magic blocks) and fails closed when compliance is down", async () => {
    const blocked = await create({
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: "sanctioned.near",
    });
    expect(blocked.status).toBe(402);
    expect(blocked.body).toMatchObject({ error: { code: "screening_blocked" } });
    s.compliance.on(createScreening, async () => mockError("api_error"));
    const down = await create({
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: "other.near",
    });
    expect(down.status).toBe(503);
    expect(down.body).toMatchObject({ error: { code: "screening_unavailable" } });
    expect(s.compliance.callsTo(createScreening).at(-1)?.body).toMatchObject({
      subject_type: "destination",
      context: "destination",
      livemode: false,
      account_id: u.accountId,
    });
  });

  it("validates address, chain, asset and memo support", async () => {
    const bad = await create({ asset_id: USDC_BASE, type: "chain_address", chain: "eip155:8453", address: "0x1234" });
    expect(bad.body).toMatchObject({ error: { code: "address_invalid", param: "address" } });
    const intentsOnBase = await create({
      asset_id: USDC_BASE,
      type: "intents_account",
      chain: "eip155:8453",
      address: "merchant.near",
    });
    expect(intentsOnBase.body).toMatchObject({ error: { code: "invalid_request", param: "chain" } });
    const unknown = await create({
      asset_id: "nep141:unknown.near",
      type: "intents_account",
      chain: "near:mainnet",
      address: "merchant.near",
    });
    expect(unknown.body).toMatchObject({ error: { code: "asset_unsupported", param: "asset_id" } });
    const wrongChain = await create({
      asset_id: USDC_NEAR,
      type: "chain_address",
      chain: "eip155:8453",
      address: "0x52908400098527886e0f7030069857d2e4169ee7",
    });
    expect(wrongChain.body).toMatchObject({ error: { code: "asset_unsupported" } });
    s.rails.on(listChainProfiles, async () => ({
      profiles: [
        {
          chain: "eip155:8453",
          blockchain: "base",
          family: "evm" as const,
          tier: "A" as const,
          min_deadline_s: 1,
          default_deadline_s: 1,
          finality: "f",
          verification_timeout_s: 1,
          memo_mode: "required" as const,
          explorer_tx_url: "x",
        },
      ],
    }));
    const memo = await create({
      asset_id: USDC_BASE,
      type: "chain_address",
      chain: "eip155:8453",
      address: "0x52908400098527886e0f7030069857d2e4169ee7",
    });
    expect(memo.body).toMatchObject({ error: { code: "memo_destination_unsupported" } });
  });

  it("set_default switches the asset default; disable removes it and emits default_changed", async () => {
    const a = await create({
      asset_id: USDC_BASE,
      type: "chain_address",
      chain: "eip155:8453",
      address: "0x1111111111111111111111111111111111111111",
    });
    const b = await create({
      asset_id: USDC_BASE,
      type: "chain_address",
      chain: "eip155:8453",
      address: "0x2222222222222222222222222222222222222222",
    });
    expect(a.body.is_default).toBe(true);
    expect(b.body.is_default).toBe(false);
    const d = await s.gateway("POST", `/v1/settlement_destinations/${b.body.id}/set_default`, as(u, "test", {}));
    expect(d.status).toBe(200);
    expect(d.body.is_default).toBe(true);
    expect((await status(a.body.id, "test")).is_default).toBe(false);
    const off = await s.gateway("POST", `/v1/settlement_destinations/${b.body.id}/disable`, as(u, "test", {}));
    expect(off.body).toMatchObject({ status: "disabled", disabled_reason: "merchant", is_default: false });
    expect(await outbox(b.body.id)).toEqual(["created", "activated", "default_changed", "disabled", "default_changed"]);
    expect(
      (await s.gateway("POST", `/v1/settlement_destinations/${b.body.id}/disable`, as(u, "test", {}))).status,
    ).toBe(409);
    const notActive = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${b.body.id}/set_default`,
      as(u, "test", {}),
    );
    expect(notActive.body).toMatchObject({ error: { code: "destination_not_active" } });
    const dup = await create({
      asset_id: USDC_BASE,
      type: "chain_address",
      chain: "eip155:8453",
      address: "0x1111111111111111111111111111111111111111",
    });
    expect(dup.body).toMatchObject({ error: { code: "destination_in_use" } });
  });
});

describe("live mode", () => {
  it("NEP-413 (implicit account): challenge → attest → cooling_off → activated by the worker", async () => {
    const near = nearSigner();
    const r = await create(
      { asset_id: USDC_NEAR, type: "intents_account", chain: "near:mainnet", address: near.implicitAccount },
      "live",
    );
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ status: "pending_verification", verification: "signature", is_default: false });
    const c = r.body.attestation_challenge;
    expect(c).toMatchObject({ signing_standard: "nep413", recipient: "nearpay.money" });
    expect(c.id).toMatch(/^chl_/);
    expect(c.message).toBe(
      [
        "NearPay settlement destination",
        `Account: ${u.accountId}`,
        "Mode: live",
        `Asset: ${USDC_NEAR}`,
        "Network: near:mainnet",
        `Address: ${near.implicitAccount}`,
        `Nonce: ${Buffer.from(c.nonce, "base64").toString("hex")}`,
        `Expires: ${new Date(c.expires_at * 1000).toISOString()}`,
      ].join("\n"),
    );
    const sig = near.sign(c.message, Buffer.from(c.nonce, "base64"));
    const wrong = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", {
        challenge_id: c.id,
        standard: "nep413",
        signature: near.sign("other", Buffer.from(c.nonce, "base64")),
        public_key: near.publicKey,
      }),
    );
    expect(wrong.body).toMatchObject({ error: { code: "attestation_invalid" } });
    const mismatch = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", { challenge_id: c.id, standard: "eip191", signature: `0x${"00".repeat(65)}` }),
    );
    expect(mismatch.body).toMatchObject({ error: { code: "attestation_invalid" } });
    const ok = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", { challenge_id: c.id, standard: "nep413", signature: sig, public_key: near.publicKey }),
    );
    expect(ok.status).toBe(200);
    expect(ok.body.status).toBe("cooling_off");
    const replay = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", { challenge_id: c.id, standard: "nep413", signature: sig, public_key: near.publicKey }),
    );
    expect(replay.status).toBe(409);
    await eventually(async () => (await status(r.body.id, "live")).status === "active");
    expect(await outbox(r.body.id)).toEqual(["created", "cooling_off", "activated", "default_changed"]);
    const row = await s.admin.db
      .selectFrom("settlement_destinations")
      .selectAll()
      .where("id", "=", toUuid(r.body.id, "sd"))
      .executeTakeFirstOrThrow();
    expect(row.attestation).toMatchObject({ standard: "nep413", method: "implicit", public_key: near.publicKey });
    const internal = await s.direct("GET", `/internal/settlement-destinations/${r.body.id}`, {
      token: await mintServiceToken("payments"),
    });
    expect(internal.body.attestation_hash).toMatch(/^[0-9a-f]{64}$/);
    // re-screened at activation
    expect(
      s.compliance
        .callsTo(createScreening)
        .filter((x) => (x.body as { subject: string }).subject === near.implicitAccount),
    ).toHaveLength(2);
  });

  it("EIP-191 on Base, and a named NEAR account needs a full-access key", async () => {
    const evm = evmSigner();
    const r = await create(
      { asset_id: USDC_BASE, type: "chain_address", chain: "eip155:8453", address: evm.address },
      "live",
    );
    const c = r.body.attestation_challenge;
    expect(c).toMatchObject({ signing_standard: "eip191", nonce: null, recipient: null });
    const ok = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", { challenge_id: c.id, standard: "eip191", signature: evm.sign(c.message) }),
    );
    expect(ok.body.status).toBe("cooling_off");

    const near = nearSigner();
    const named = await create(
      { asset_id: USDC_NEAR, type: "intents_account", chain: "near:mainnet", address: "payouts.acme.near" },
      "live",
    );
    const nc = named.body.attestation_challenge;
    const body = {
      challenge_id: nc.id,
      standard: "nep413",
      signature: near.sign(nc.message, Buffer.from(nc.nonce, "base64")),
      public_key: near.publicKey,
    };
    s.nearKeys.set(`payouts.acme.near|${near.publicKey}`, "FunctionCall");
    expect(
      (await s.gateway("POST", `/v1/settlement_destinations/${named.body.id}/attest`, as(u, "live", body))).body,
    ).toMatchObject({ error: { code: "attestation_invalid" } });
    s.nearKeys.set(`payouts.acme.near|${near.publicKey}`, "FullAccess");
    expect(
      (await s.gateway("POST", `/v1/settlement_destinations/${named.body.id}/attest`, as(u, "live", body))).body.status,
    ).toBe("cooling_off");
  });

  it("an expired challenge cannot be used; Solana/Bitcoin live destinations wait for Stage 4", async () => {
    const near = nearSigner();
    const r = await create(
      { asset_id: USDC_NEAR, type: "intents_account", chain: "near:mainnet", address: near.implicitAccount },
      "live",
    );
    const c = r.body.attestation_challenge;
    await s.admin.db
      .updateTable("attestation_challenges")
      .set({ expires_at: new Date(Date.now() - 1000) })
      .where("id", "=", toUuid(c.id, "chl"))
      .execute();
    const late = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", {
        challenge_id: c.id,
        standard: "nep413",
        signature: near.sign(c.message, Buffer.from(c.nonce, "base64")),
        public_key: near.publicKey,
      }),
    );
    expect(late.status).toBe(410);
    expect(late.body).toMatchObject({ error: { code: "challenge_expired" } });
    s.rails.on(getInternalAsset, async () => ({
      asset_id: "nep141:sol.omft.near",
      chain: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      blockchain: "sol",
      symbol: "SOL",
      decimals: 9,
      family: "solana",
      is_usd_stable: false,
      price_usd: "150",
      price_ok: true,
      as_of: null,
    }));
    s.rails.on(listChainProfiles, async () => ({ profiles: [] }));
    const sol = await create(
      {
        asset_id: "nep141:sol.omft.near",
        type: "chain_address",
        chain: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        address: "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
      },
      "live",
    );
    expect(sol.body).toMatchObject({ error: { code: "invalid_request", param: "chain" } });
  });

  it("the same live address can belong to one account only", async () => {
    const other = await signUp(s, "squatter@shop.test", "Squatter");
    const evm = evmSigner();
    const mine = await create(
      { asset_id: USDC_BASE, type: "chain_address", chain: "eip155:8453", address: evm.address },
      "live",
    );
    const c = mine.body.attestation_challenge;
    await s.gateway(
      "POST",
      `/v1/settlement_destinations/${mine.body.id}/attest`,
      as(u, "live", { challenge_id: c.id, standard: "eip191", signature: evm.sign(c.message) }),
    );
    const theirs = await create(
      { asset_id: USDC_BASE, type: "chain_address", chain: "eip155:8453", address: evm.address },
      "live",
      other,
    );
    expect(theirs.body).toMatchObject({ error: { code: "destination_in_use" } });
  });

  it("KYB approval (compliance event) + an active live destination enable live mode", async () => {
    expect((await s.gateway("GET", "/v1/account/requirements", { cookie: u.cookie })).body).toEqual({
      object: "account_requirements",
      live_enabled: false,
      missing: ["kyb"],
    });
    const approved = domainEvent(
      "evt.compliance.kyb.approved",
      { account_id: u.accountId, status: "approved", reason: "ok" },
      { accountUuid: toUuid(u.accountId, "acct"), livemode: null, version: 2 },
    );
    await s.publishEvent(approved);
    const updated = await probe.next(
      "evt.identity.account.updated",
      (e) => e.aggregate.id === u.accountId && (e.data.object as { live_enabled: boolean }).live_enabled,
    );
    expect(updated.data.object).toMatchObject({ kyb_status: "approved", live_enabled: true });
    expect(updated.data).toMatchObject({ previous: { kyb_status: "not_started", live_enabled: false } });
    expect((await s.gateway("GET", "/v1/account/requirements", { cookie: u.cookie })).body).toMatchObject({
      live_enabled: true,
      missing: [],
    });
    // a stale (older) KYB event never undoes the newer decision
    await s.publishEvent(
      domainEvent(
        "evt.compliance.kyb.needs_info",
        { account_id: u.accountId, status: "needs_info", reason: null },
        { accountUuid: toUuid(u.accountId, "acct"), livemode: null, version: 1 },
      ),
    );
    await new Promise((r) => setTimeout(r, 500));
    expect((await s.gateway("GET", "/v1/account", { cookie: u.cookie })).body.kyb_status).toBe("approved");
  });
});

describe("re-issued attestation challenges (POST /v1/settlement_destinations/{id}/challenge)", () => {
  const challenge = (id: string, o: { who?: User; mode?: "test" | "live"; key?: string } = {}) =>
    s.gateway("POST", `/v1/settlement_destinations/${id}/challenge`, {
      ...as(o.who ?? u, o.mode ?? "live", {}),
      ...(o.key ? { headers: { "idempotency-key": o.key } } : {}),
    });
  const attest = (id: string, near: ReturnType<typeof nearSigner>, c: { id: string; message: string; nonce: string }) =>
    s.gateway(
      "POST",
      `/v1/settlement_destinations/${id}/attest`,
      as(u, "live", {
        challenge_id: c.id,
        standard: "nep413",
        signature: near.sign(c.message, Buffer.from(c.nonce, "base64")),
        public_key: near.publicKey,
      }),
    );
  const setRole = async (role: "owner" | "admin" | "developer" | "viewer") => {
    await s.admin.db.updateTable("memberships").set({ role }).where("user_id", "=", toUuid(u.userId, "usr")).execute();
    s.identity.cache.local<object>("sessions", 10_000).clear();
  };

  it("issues a fresh challenge (same shape as on create); earlier unused ones stop being accepted", async () => {
    const near = nearSigner();
    const r = await create(
      { asset_id: USDC_NEAR, type: "intents_account", chain: "near:mainnet", address: near.implicitAccount },
      "live",
    );
    const c1 = r.body.attestation_challenge;
    const k1 = `chl-${r.body.id}`;
    const r2 = await challenge(r.body.id, { key: k1 });
    expect(r2.status).toBe(200);
    expect(SettlementDestination.safeParse(r2.body).success).toBe(true);
    const { attestation_challenge: c2, ...dest2 } = r2.body;
    const { attestation_challenge: _c1, ...dest1 } = r.body;
    expect(dest2).toEqual(dest1); // the destination itself is unchanged
    expect(Object.keys(c2).sort()).toEqual(Object.keys(c1).sort());
    expect(c2).toMatchObject({ signing_standard: "nep413", recipient: "nearpay.money" });
    expect(c2.id).toMatch(/^chl_/);
    expect(c2.id).not.toBe(c1.id);
    expect(c2.nonce).not.toBe(c1.nonce);
    expect(c2.expires_at).toBeGreaterThanOrEqual(c1.expires_at);
    expect(c2.expires_at - Math.floor(Date.now() / 1000)).toBeGreaterThan(9 * 60);
    expect(c2.message).toBe(
      [
        "NearPay settlement destination",
        `Account: ${u.accountId}`,
        "Mode: live",
        `Asset: ${USDC_NEAR}`,
        "Network: near:mainnet",
        `Address: ${near.implicitAccount}`,
        `Nonce: ${Buffer.from(c2.nonce, "base64").toString("hex")}`,
        `Expires: ${new Date(c2.expires_at * 1000).toISOString()}`,
      ].join("\n"),
    );
    // an idempotent replay returns the same challenge and supersedes nothing
    const replay = await challenge(r.body.id, { key: k1 });
    expect(replay.status).toBe(200);
    expect(replay.headers["idempotent-replayed"]).toBe("true");
    expect(replay.body).toEqual(r2.body);
    const rows = async () =>
      s.admin.db
        .selectFrom("attestation_challenges")
        .select(["id", "used_at", "superseded_at"])
        .where("destination_id", "=", toUuid(r.body.id, "sd"))
        .orderBy("created_at")
        .execute();
    expect((await rows()).map((x) => x.superseded_at === null)).toEqual([false, true]);
    // a new key issues a third challenge; the first two are no longer accepted
    const r3 = await challenge(r.body.id, { key: `${k1}-2` });
    const c3 = r3.body.attestation_challenge;
    expect(c3.id).not.toBe(c2.id);
    for (const old of [c1, c2]) {
      const late = await attest(r.body.id, near, old);
      expect(late.status).toBe(410);
      expect(late.body.error).toMatchObject({
        code: "challenge_expired",
        message: "The attestation challenge has expired or was used; request a new challenge for the destination.",
      });
    }
    const ok = await attest(r.body.id, near, c3);
    expect(ok.status).toBe(200);
    expect(ok.body.status).toBe("cooling_off");
    const after = await rows();
    expect(after.map((x) => [x.used_at !== null, x.superseded_at !== null])).toEqual([
      [false, true],
      [false, true],
      [true, false],
    ]);
    // no state change → no outbox event; each issue is audited
    expect((await outbox(r.body.id)).slice(0, 2)).toEqual(["created", "cooling_off"]);
    const audits = await s.admin.db
      .selectFrom("audit_events")
      .selectAll()
      .where("action", "=", "destination.challenge_issued")
      .where("target_id", "=", r.body.id)
      .execute();
    expect(audits).toHaveLength(2);
    // once attested, a challenge is a state conflict
    const conflict = await challenge(r.body.id);
    expect(conflict.status).toBe(409);
    expect(conflict.body.error).toMatchObject({ code: "state_conflict" });
  });

  it("EIP-191 challenges have no nonce/recipient; only pending_verification destinations get one", async () => {
    const evm = evmSigner();
    const r = await create(
      { asset_id: USDC_BASE, type: "chain_address", chain: "eip155:8453", address: evm.address },
      "live",
    );
    const c = (await challenge(r.body.id)).body.attestation_challenge;
    expect(c).toMatchObject({ signing_standard: "eip191", nonce: null, recipient: null });
    const ok = await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", { challenge_id: c.id, standard: "eip191", signature: evm.sign(c.message) }),
    );
    expect(ok.body.status).toBe("cooling_off");
    // test-mode destinations are active at once; disabled ones are final
    const t = await create({
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: nearSigner().implicitAccount,
    });
    expect(t.body.status).toBe("active");
    const active = await challenge(t.body.id, { mode: "test" });
    expect(active.status).toBe(409);
    expect(active.body.error).toMatchObject({ code: "state_conflict" });
    await s.gateway("POST", `/v1/settlement_destinations/${t.body.id}/disable`, as(u, "test", {}));
    expect((await challenge(t.body.id, { mode: "test" })).status).toBe(409);
  });

  it("needs a stepped-up owner/admin session of the destination's account and mode", async () => {
    const near = nearSigner();
    const r = await create(
      { asset_id: USDC_NEAR, type: "intents_account", chain: "near:mainnet", address: near.implicitAccount },
      "live",
    );
    // other account, other mode, unknown id → 404
    const other = await signUp(s, "chl-other@shop.test", "Other");
    expect((await challenge(r.body.id, { who: other })).status).toBe(404);
    expect((await challenge(r.body.id, { mode: "test" })).status).toBe(404);
    expect((await challenge(newId("sd"))).status).toBe(404);
    // no CSRF token → 403; an API key never → 403
    const noCsrf = await s.gateway("POST", `/v1/settlement_destinations/${r.body.id}/challenge`, {
      cookie: u.cookie,
      mode: "live",
      body: {},
    });
    expect(noCsrf.body).toMatchObject({ error: { code: "csrf_token_invalid" } });
    const k = await s.gateway("POST", "/v1/api_keys", as(u, "test", { type: "secret", livemode: false, name: "chl" }));
    const key = await s.gateway("POST", `/v1/settlement_destinations/${r.body.id}/challenge`, {
      bearer: k.body.secret,
      body: {},
    });
    expect(key.status).toBe(403);
    // developer / viewer → 403; admin → 200
    for (const role of ["developer", "viewer"] as const) {
      await setRole(role);
      const denied = await challenge(r.body.id);
      expect(denied.status, role).toBe(403);
      expect(denied.body.error.code).toBe("permission_denied");
    }
    await setRole("admin");
    expect((await challenge(r.body.id)).status).toBe(200);
    await setRole("owner");
    // a step-up older than 10 minutes → 401 step_up_required, and nothing is superseded
    const before = await s.admin.db
      .selectFrom("attestation_challenges")
      .select("id")
      .where("destination_id", "=", toUuid(r.body.id, "sd"))
      .where("superseded_at", "is", null)
      .execute();
    await s.admin.db
      .updateTable("sessions")
      .set({ step_up_at: new Date(Date.now() - 11 * 60_000) })
      .where("user_id", "=", toUuid(u.userId, "usr"))
      .execute();
    s.identity.cache.local<object>("sessions", 10_000).clear();
    const stale = await challenge(r.body.id);
    expect(stale.status).toBe(401);
    expect(stale.body.error.code).toBe("step_up_required");
    const unchanged = await s.admin.db
      .selectFrom("attestation_challenges")
      .select("id")
      .where("destination_id", "=", toUuid(r.body.id, "sd"))
      .where("superseded_at", "is", null)
      .execute();
    expect(unchanged).toEqual(before);
    await stepUp(s, u);
    expect((await challenge(r.body.id)).status).toBe(200);
  });
});

describe("compliance consumers", () => {
  it("destination.blocked disables the destination (reason compliance)", async () => {
    const r = await create({
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: "blockme.near",
    });
    await s.publishEvent(
      domainEvent(
        "evt.compliance.destination.blocked",
        { destination_id: r.body.id, account_id: u.accountId, reason: "x" },
        { accountUuid: toUuid(u.accountId, "acct"), livemode: false, version: 1 },
      ),
    );
    await eventually(async () => (await status(r.body.id, "test")).status === "disabled");
    expect((await status(r.body.id, "test")).disabled_reason).toBe("compliance");
  });

  it("account suspended / reinstated follow the compliance version", async () => {
    const ev = (subject: "evt.compliance.account.suspended" | "evt.compliance.account.reinstated", version: number) =>
      domainEvent(
        subject,
        { account_id: u.accountId, reason: "r" },
        { accountUuid: toUuid(u.accountId, "acct"), livemode: null, version },
      );
    await s.publishEvent(ev("evt.compliance.account.suspended", 1));
    await eventually(
      async () =>
        (
          await s.admin.db
            .selectFrom("accounts")
            .select("status")
            .where("id", "=", toUuid(u.accountId, "acct"))
            .executeTakeFirstOrThrow()
        ).status === "suspended",
    );
    await s.publishEvent(ev("evt.compliance.account.reinstated", 2));
    await eventually(
      async () =>
        (
          await s.admin.db
            .selectFrom("accounts")
            .select("status")
            .where("id", "=", toUuid(u.accountId, "acct"))
            .executeTakeFirstOrThrow()
        ).status === "active",
    );
    await s.publishEvent(ev("evt.compliance.account.suspended", 1));
    await new Promise((r) => setTimeout(r, 500));
    expect(
      (
        await s.admin.db
          .selectFrom("accounts")
          .select("status")
          .where("id", "=", toUuid(u.accountId, "acct"))
          .executeTakeFirstOrThrow()
      ).status,
    ).toBe("active");
  });

  it("api_key.revoked purges every replica's cache over NATS", async () => {
    const nc = await connect({ servers: s.natsUrl as string });
    const got: string[] = [];
    const sub = nc.subscribe("ctl.identity.cache.purge");
    (async () => {
      for await (const m of sub) got.push(m.string());
    })();
    await stepUp(s, u);
    const k = await s.gateway(
      "POST",
      "/v1/api_keys",
      as(u, "test", { type: "secret", livemode: false, name: "purge" }),
    );
    await s.gateway("DELETE", `/v1/api_keys/${k.body.id}`, as(u));
    await eventually(async () => got.filter((m) => m.startsWith("key:")).length >= 2);
    expect(got.every((m) => /^(key|session):[0-9a-f]{64}$/.test(m))).toBe(true);
    await nc.drain();
  });
});

describe("activation", () => {
  it("a block at the activation re-screen disables the destination instead", async () => {
    let calls = 0;
    s.compliance.on(createScreening, async () => ({
      screening_id: newId("scr"),
      decision: (++calls === 1 ? "allow" : "block") as "allow" | "block",
      risk: null,
      reasons: calls === 1 ? [] : ["sanctions"],
      cached: false,
      post_screen_required: false,
    }));
    const near = nearSigner();
    const r = await create(
      { asset_id: USDC_NEAR, type: "intents_account", chain: "near:mainnet", address: near.implicitAccount },
      "live",
    );
    const c = r.body.attestation_challenge;
    await s.gateway(
      "POST",
      `/v1/settlement_destinations/${r.body.id}/attest`,
      as(u, "live", {
        challenge_id: c.id,
        standard: "nep413",
        signature: near.sign(c.message, Buffer.from(c.nonce, "base64")),
        public_key: near.publicKey,
      }),
    );
    await eventually(async () => (await status(r.body.id, "live")).status === "disabled");
    expect((await status(r.body.id, "live")).disabled_reason).toBe("compliance");
    expect(await outbox(r.body.id)).toEqual(["created", "cooling_off", "disabled"]);
  });

  it("purges expired auth material", async () => {
    const { purgeAuth } = await import("../../src/workers/jobs.js");
    await s.admin.db
      .insertInto("magic_links")
      .values({
        token_hash: Buffer.alloc(32, 7),
        email: "old@x.test",
        purpose: "signup",
        expires_at: new Date(Date.now() - 3 * 86_400_000),
      })
      .execute();
    const r = await purgeAuth(s.identity);
    expect(r.magic_links).toBeGreaterThanOrEqual(1);
    expect(
      await s.admin.db.selectFrom("magic_links").select("email").where("email", "=", "old@x.test").execute(),
    ).toEqual([]);
  });
});

describe("recovery lock", () => {
  it("destination changes wait 48 h after an account recovery", async () => {
    await s.admin.db
      .updateTable("accounts")
      .set({ recovered_at: new Date() })
      .where("id", "=", toUuid(u.accountId, "acct"))
      .execute();
    const r = await create({
      asset_id: USDC_NEAR,
      type: "intents_account",
      chain: "near:mainnet",
      address: "late.near",
    });
    expect(r.body).toMatchObject({ error: { code: "recovery_lock" } });
    await s.admin.db
      .updateTable("accounts")
      .set({ recovered_at: null })
      .where("id", "=", toUuid(u.accountId, "acct"))
      .execute();
  });
});
