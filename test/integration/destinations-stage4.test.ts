/**
 * Stage 4 settlement destinations on Solana and Bitcoin end to end (lld/identity.md §20) with the worker:
 * live creation and challenge, `standard: solana` / `standard: bip322` attestation → cooling_off → active,
 * P2WPKH/P2TR-only Bitcoin destinations, off-curve Solana addresses, the stored attestation.
 * Attestations go through the gateway and the spec 0.4.0 `attestSettlementDestination` route.
 */

import { sql } from "@nearpay-internal/db";
import { toUuid } from "@nearpay-internal/ids";
import { getInternalAsset } from "@nearpay-internal/spec";
import { BITCOIN_MAINNET, type DESTINATION_SIGNING_STANDARDS, SOLANA_MAINNET } from "@nearpay-money/spec";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { bip322Signer, solanaSigner } from "../support/signers.js";
import { eventually, type Stack, startStack } from "../support/stack.js";
import { as, signUp, type User } from "../support/users.js";

const SOL = "nep141:sol.omft.near";
const USDC_SOL = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";
const BTC = "nep141:btc.omft.near";

let s: Stack;
let u: User;
beforeAll(async () => {
  s = await startStack({ worker: true, cooloffSeconds: 0 });
  u = await signUp(s, "chains@shop.test", "Chains Shop");
});
afterAll(async () => {
  await s?.stop();
});
beforeEach(() => {
  s.resetMocks();
  s.rails.on(getInternalAsset, async (ctx) => {
    const id = ctx.params.asset_id;
    const btc = id === BTC;
    return {
      asset_id: id,
      chain: btc ? BITCOIN_MAINNET : SOLANA_MAINNET,
      blockchain: btc ? "btc" : "sol",
      symbol: btc ? "BTC" : id === SOL ? "SOL" : "USDC",
      decimals: btc ? 8 : id === SOL ? 9 : 6,
      family: btc ? "bitcoin" : "solana",
      is_usd_stable: id === USDC_SOL,
      price_usd: btc ? "90000" : id === SOL ? "150" : "1",
      price_ok: true,
      as_of: new Date().toISOString(),
    };
  });
});

const create = (body: Record<string, unknown>, mode: "test" | "live" = "live") =>
  s.gateway("POST", "/v1/settlement_destinations", as(u, mode, { label: "Chain", type: "chain_address", ...body }));
const status = async (id: string) =>
  (await s.gateway("GET", `/v1/settlement_destinations/${id}`, { cookie: u.cookie, mode: "live" })).body;

/** `POST /v1/settlement_destinations/{id}/attest` (live) through the gateway. */
async function attestHttp(
  id: string,
  body: { challenge_id: string; standard: (typeof DESTINATION_SIGNING_STANDARDS)[number]; signature: string },
): Promise<{ status: number; body: Record<string, unknown> & { error?: { code: string; message: string } } }> {
  return s.gateway("POST", `/v1/settlement_destinations/${id}/attest`, as(u, "live", body));
}

describe("Solana (standard: solana)", () => {
  it("live: challenge → raw-message ed25519 signature → cooling_off → active; attestation stored", async () => {
    const w = solanaSigner();
    const r = await create({ asset_id: USDC_SOL, chain: SOLANA_MAINNET, address: w.address });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ status: "pending_verification", verification: "signature", address: w.address });
    const c = r.body.attestation_challenge;
    expect(c).toMatchObject({ signing_standard: "solana", nonce: null, recipient: null });
    expect(c.message).toContain("\nMode: live\n");
    expect(c.message).toContain(`\nNetwork: ${SOLANA_MAINNET}\nAddress: ${w.address}\n`);

    // the test-mode message, base64, the wrong standard: refused, and the challenge stays usable
    const testMsg = c.message.replace("\nMode: live\n", "\nMode: test\n");
    for (const bad of [
      { standard: "solana" as const, signature: w.sign(testMsg) },
      { standard: "solana" as const, signature: Buffer.from(w.sign(c.message)).toString("base64") },
      { standard: "bip322" as const, signature: w.sign(c.message) },
    ]) {
      const res = await attestHttp(r.body.id, { challenge_id: c.id, ...bad });
      expect(res.body, bad.signature).toMatchObject({ error: { code: "attestation_invalid" } });
    }
    const ok = await attestHttp(r.body.id, { challenge_id: c.id, standard: "solana", signature: w.sign(c.message) });
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ status: "cooling_off" });
    await eventually(async () => (await status(r.body.id)).status === "active");
    const row = await s.admin.db
      .selectFrom("settlement_destinations")
      .selectAll()
      .where("id", "=", toUuid(r.body.id, "sd"))
      .executeTakeFirstOrThrow();
    expect(row.attestation).toMatchObject({ standard: "solana", method: "solana_ed25519", public_key: null });
    // single use
    const replay = await attestHttp(r.body.id, {
      challenge_id: c.id,
      standard: "solana",
      signature: w.sign(c.message),
    });
    expect(replay.status).toBe(409);
  });

  it("an off-curve (program-derived) address is a valid destination but its signature path is refused with a hint", async () => {
    const pda = "DN5C7q7RzxDXor5jNHDBxfHU5yp3M58XJXcWR4WvvyAp";
    const r = await create({ asset_id: SOL, chain: SOLANA_MAINNET, address: pda });
    expect(r.status).toBe(201);
    const c = r.body.attestation_challenge;
    const res = await attestHttp(r.body.id, {
      challenge_id: c.id,
      standard: "solana",
      signature: solanaSigner().sign(c.message),
    });
    expect(res.body).toMatchObject({ error: { code: "attestation_invalid" } });
    expect(res.body.error?.message).toMatch(/program-derived/);
  });

  it("refuses addresses that do not decode to 32 bytes", async () => {
    const r = await create({
      asset_id: SOL,
      chain: SOLANA_MAINNET,
      address: "7DUeBUtEcb7nujVZRJmeBju3X1mo6PpnWNtJ9EBhdY",
    });
    expect(r.body).toMatchObject({ error: { code: "address_invalid", param: "address" } });
  });
});

describe("Bitcoin (standard: bip322)", () => {
  for (const type of ["p2wpkh", "p2tr"] as const)
    it(`live ${type}: BIP-322 simple → cooling_off → active`, async () => {
      const k = bip322Signer(type);
      const r = await create({ asset_id: BTC, chain: BITCOIN_MAINNET, address: k.address });
      expect(r.status).toBe(201);
      const c = r.body.attestation_challenge;
      expect(c).toMatchObject({ signing_standard: "bip322", nonce: null, recipient: null });
      const other = await attestHttp(r.body.id, {
        challenge_id: c.id,
        standard: "bip322",
        signature: bip322Signer(type).sign(c.message),
      });
      expect(other.body).toMatchObject({ error: { code: "attestation_invalid" } });
      const ok = await attestHttp(r.body.id, {
        challenge_id: c.id,
        standard: "bip322",
        signature: k.sign(c.message),
      });
      expect(ok.body).toMatchObject({ status: "cooling_off" });
      await eventually(async () => (await status(r.body.id)).status === "active");
      const row = await s.admin.db
        .selectFrom("settlement_destinations")
        .select("attestation")
        .where("id", "=", toUuid(r.body.id, "sd"))
        .executeTakeFirstOrThrow();
      expect(row.attestation).toMatchObject({ standard: "bip322", method: `bip322_${type}` });
    });

  it("upper-case bech32: the message carries the address as entered, ownership is checked on the normalised one", async () => {
    const k = bip322Signer("p2wpkh");
    const upper = k.address.toUpperCase();
    const r = await create({ asset_id: BTC, chain: BITCOIN_MAINNET, address: upper });
    expect(r.status).toBe(201);
    const c = r.body.attestation_challenge;
    expect(c.message).toContain(`\nAddress: ${upper}\n`);
    const row = await s.admin.db
      .selectFrom("settlement_destinations")
      .select("address_norm")
      .where("id", "=", toUuid(r.body.id, "sd"))
      .executeTakeFirstOrThrow();
    expect(row.address_norm).toBe(k.address);
    const ok = await attestHttp(r.body.id, { challenge_id: c.id, standard: "bip322", signature: k.sign(c.message) });
    expect(ok.body).toMatchObject({ status: "cooling_off" });
  });

  for (const mode of ["live", "test"] as const)
    it(`${mode}: P2PKH, P2SH and P2WSH destinations are refused with address_invalid`, async () => {
      for (const address of [
        "12HWMKcfvshJ1dJo1kBX3jaguexKF5UeXY",
        "3EdC2tokZbqft8jYFdvN58YaCetzMUBRji",
        "bc1qppsup2haejt8whm43a32rgwqtrvv0h46ts3ld6gje2xqrrczzj2sz0eetu",
      ]) {
        const r = await create({ asset_id: BTC, chain: BITCOIN_MAINNET, address }, mode);
        expect(r.status, address).toBe(400);
        expect(r.body, address).toMatchObject({ error: { code: "address_invalid", param: "address" } });
        expect(r.body.error.message).toMatch(/native SegWit \(bc1q…\) or Taproot \(bc1p…\)/);
      }
    });

  it("test mode: a P2TR destination is active at once (no attestation)", async () => {
    const r = await create({ asset_id: BTC, chain: BITCOIN_MAINNET, address: bip322Signer("p2tr").address }, "test");
    expect(r.body).toMatchObject({ status: "active", verification: "test" });
    expect(r.body.attestation_challenge).toBeUndefined();
  });

  it("the database refuses a live Bitcoin row that is not P2WPKH/P2TR (migration 0008)", async () => {
    const acct = toUuid(u.accountId, "acct");
    await expect(
      sql`insert into settlement_destinations (id, account_id, livemode, asset_id, type, chain, address, address_norm, label, status, verification, created_by, approvals_required)
          values (gen_random_uuid(), ${acct}, true, ${BTC}, 'chain_address', ${BITCOIN_MAINNET}, '3EdC2tokZbqft8jYFdvN58YaCetzMUBRji', '3EdC2tokZbqft8jYFdvN58YaCetzMUBRji', 'x', 'pending_verification', 'signature', ${toUuid(u.userId, "usr")}, 1)`.execute(
        s.admin.db,
      ),
    ).rejects.toThrow(/settlement_destinations_bitcoin_live_type/);
  });
});
