import { randomBytes } from "node:crypto";
import bs58 from "bs58";
import { describe, expect, it } from "vitest";
import {
  AttestationUnavailable,
  type OwnershipLookups,
  recoverEip191,
  verifyAttestation,
  verifyNep413Signature,
} from "../../src/infra/crypto/attestation.js";
import { evmSigner, nearSigner } from "../support/signers.js";

const MESSAGE = "NearPay settlement destination\nAccount: acct_1\nMode: live";
const nonce = randomBytes(32);
const lookups = (
  permission: "FullAccess" | "FunctionCall" | null,
  erc1271: boolean | null = null,
): OwnershipLookups => ({
  nearAccessKey: async () => permission,
  erc1271: async () => erc1271,
});

describe("NEP-413", () => {
  const near = nearSigner();
  const sig = near.sign(MESSAGE, nonce);

  it("verifies the borsh payload signature (base64 or ed25519:base58)", () => {
    expect(verifyNep413Signature(MESSAGE, nonce, sig, near.publicKey)).toBe(true);
    const b58 = `ed25519:${bs58.encode(Buffer.from(sig, "base64"))}`;
    expect(verifyNep413Signature(MESSAGE, nonce, b58, near.publicKey)).toBe(true);
  });
  it("rejects a different message, nonce, recipient or key", () => {
    expect(verifyNep413Signature(`${MESSAGE}x`, nonce, sig, near.publicKey)).toBe(false);
    expect(verifyNep413Signature(MESSAGE, randomBytes(32), sig, near.publicKey)).toBe(false);
    expect(verifyNep413Signature(MESSAGE, nonce, near.sign(MESSAGE, nonce, "evil.near"), near.publicKey)).toBe(false);
    expect(verifyNep413Signature(MESSAGE, nonce, sig, nearSigner().publicKey)).toBe(false);
    expect(verifyNep413Signature(MESSAGE, nonce, sig, undefined)).toBe(false);
    expect(verifyNep413Signature(MESSAGE, nonce, "not-base64!!", near.publicKey)).toBe(false);
    expect(verifyNep413Signature(MESSAGE, nonce, sig, "ed25519:111")).toBe(false);
    expect(verifyNep413Signature(MESSAGE, randomBytes(31), sig, near.publicKey)).toBe(false);
  });
  const input = (o: Partial<Parameters<typeof verifyAttestation>[0]> = {}) => ({
    standard: "nep413" as const,
    chain: "near:mainnet",
    addressNorm: near.implicitAccount,
    message: MESSAGE,
    nonce,
    signature: sig,
    publicKey: near.publicKey,
    ...o,
  });
  it("implicit accounts must equal hex(public key)", async () => {
    expect(await verifyAttestation(input(), lookups(null))).toEqual({
      ok: true,
      method: "implicit",
      publicKey: near.publicKey,
    });
    expect(await verifyAttestation(input({ addressNorm: nearSigner().implicitAccount }), lookups(null))).toMatchObject({
      ok: false,
    });
  });
  it("named accounts need the key as a full-access key", async () => {
    const named = input({ addressNorm: "merchant.near" });
    expect(await verifyAttestation(named, lookups("FullAccess"))).toMatchObject({
      ok: true,
      method: "full_access_key",
    });
    expect(await verifyAttestation(named, lookups("FunctionCall"))).toEqual({
      ok: false,
      reason: "the key is not a full-access key",
    });
    expect(await verifyAttestation(named, lookups(null))).toEqual({
      ok: false,
      reason: "the key is not an access key of the account",
    });
    const down: OwnershipLookups = {
      nearAccessKey: async () => Promise.reject(new AttestationUnavailable("rpc down")),
    };
    await expect(verifyAttestation(named, down)).rejects.toBeInstanceOf(AttestationUnavailable);
  });
  it("a 0x account must use EIP-191; a bad signature never reaches the RPC", async () => {
    expect(
      await verifyAttestation(
        input({ addressNorm: "0x52908400098527886e0f7030069857d2e4169ee7" }),
        lookups("FullAccess"),
      ),
    ).toMatchObject({ ok: false });
    let called = false;
    const spy: OwnershipLookups = {
      nearAccessKey: async () => {
        called = true;
        return "FullAccess";
      },
    };
    expect(
      await verifyAttestation(input({ addressNorm: "merchant.near", signature: near.sign("other", nonce) }), spy),
    ).toMatchObject({ ok: false });
    expect(called).toBe(false);
  });
});

describe("EIP-191", () => {
  const evm = evmSigner();
  it("recovers the signer for v = 27/28 and 0/1", () => {
    expect(recoverEip191(MESSAGE, evm.sign(MESSAGE))).toBe(evm.address);
    expect(recoverEip191(MESSAGE, evm.sign(MESSAGE, 0))).toBe(evm.address);
    expect(recoverEip191(`${MESSAGE}x`, evm.sign(MESSAGE))).not.toBe(evm.address);
  });
  it("rejects malformed signatures", () => {
    expect(recoverEip191(MESSAGE, "0x1234")).toBeNull();
    expect(recoverEip191(MESSAGE, `0x${"00".repeat(64)}05`)).toBeNull();
    expect(recoverEip191(MESSAGE, `0x${"00".repeat(65)}`)).toBeNull();
  });
  const input = (o: Partial<Parameters<typeof verifyAttestation>[0]> = {}) => ({
    standard: "eip191" as const,
    chain: "eip155:8453",
    addressNorm: evm.address,
    message: MESSAGE,
    nonce,
    signature: evm.sign(MESSAGE),
    ...o,
  });
  it("ecrecover must equal the address; ERC-1271 covers contract wallets", async () => {
    expect(await verifyAttestation(input(), lookups(null))).toEqual({ ok: true, method: "ecrecover", publicKey: null });
    const other = input({ addressNorm: evmSigner().address });
    expect(await verifyAttestation(other, lookups(null, null))).toMatchObject({ ok: false });
    expect(await verifyAttestation(other, lookups(null, false))).toMatchObject({ ok: false });
    expect(await verifyAttestation(other, lookups(null, true))).toEqual({
      ok: true,
      method: "erc1271",
      publicKey: null,
    });
    // an Intents 0x account has no contract wallet: no ERC-1271 on near:mainnet
    expect(await verifyAttestation({ ...other, chain: "near:mainnet" }, lookups(null, true))).toMatchObject({
      ok: false,
    });
    expect(await verifyAttestation(input({ addressNorm: "merchant.near" }), lookups(null, true))).toEqual({
      ok: false,
      reason: "eip191 needs a 0x address",
    });
  });
});
