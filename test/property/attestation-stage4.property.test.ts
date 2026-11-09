/**
 * Properties of the Stage 4 ownership attestations (lld/identity.md §20): a signature binds exactly one
 * key and one challenge message (account, mode, asset, network, address, nonce, expiry), and nothing a
 * client can send makes a verifier throw or accept something else.
 */

import { BITCOIN_MAINNET, SOLANA_MAINNET } from "@nearpay/spec";
import { base64 } from "@scure/base";
import bs58 from "bs58";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  attestationMessage,
  bitcoinAddressType,
  bitcoinDestinationAllowed,
} from "../../src/domain/settlement-destination/destination.js";
import { verifyBip322Simple } from "../../src/infra/crypto/bip322.js";
import { verifySolanaSignature } from "../../src/infra/crypto/solana.js";
import { bip322Signer, solanaSigner } from "../support/signers.js";

const RUNS = { numRuns: 60 };
const seed32 = fc.uint8Array({ minLength: 32, maxLength: 32 }).filter((b) => b.some((x) => x !== 0));
const challenge = fc.record({
  account: fc.stringMatching(/^acct_[0-9a-hjkmnp-tv-z]{26}$/),
  livemode: fc.boolean(),
  assetId: fc.constantFrom(
    "nep141:sol.omft.near",
    "nep141:btc.omft.near",
    "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near",
  ),
  nonceHex: fc.uint8Array({ minLength: 32, maxLength: 32 }).map((b) => Buffer.from(b).toString("hex")),
  expiresAt: fc.integer({ min: 1_700_000_000, max: 2_000_000_000 }).map((s) => new Date(s * 1000)),
});
/** A different message: one challenge field changed, or the mode flipped. */
const mutate = (m: string, i: number) => {
  const lines = m.split("\n");
  const k = 1 + (i % (lines.length - 1));
  lines[k] = k === 2 ? (lines[k] === "Mode: live" ? "Mode: test" : "Mode: live") : `${lines[k]}x`;
  return lines.join("\n");
};

describe("standard: solana", () => {
  it("a wallet's signature verifies for its own message only, and only for its own address", () => {
    fc.assert(
      fc.property(seed32, seed32, challenge, fc.nat(), (a, b, c, i) => {
        const s = solanaSigner(a);
        const other = solanaSigner(b);
        const message = attestationMessage({ ...c, chain: SOLANA_MAINNET, address: s.address });
        const sig = s.sign(message);
        expect(verifySolanaSignature(s.address, message, sig).ok).toBe(true);
        expect(verifySolanaSignature(s.address, mutate(message, i), sig).ok).toBe(false);
        if (other.address !== s.address) expect(verifySolanaSignature(other.address, message, sig).ok).toBe(false);
      }),
      RUNS,
    );
  });
  it("any string as a signature never throws and never verifies", () => {
    const s = solanaSigner();
    fc.assert(
      fc.property(fc.string({ maxLength: 120 }), (junk) => {
        expect(verifySolanaSignature(s.address, "NearPay", junk).ok).toBe(false);
      }),
    );
  });
  it("flipping any bit of a valid signature makes it invalid", () => {
    const s = solanaSigner();
    const sig = s.sign("NearPay settlement destination");
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 511 }), (bit) => {
        const raw = bs58.decode(sig);
        raw[bit >> 3] = (raw[bit >> 3] as number) ^ (1 << (bit & 7));
        expect(verifySolanaSignature(s.address, "NearPay settlement destination", bs58.encode(raw)).ok).toBe(false);
      }),
      { numRuns: 100 },
    );
  });
});

describe("standard: bip322", () => {
  const type = fc.constantFrom<"p2wpkh" | "p2tr">("p2wpkh", "p2tr");
  it("a key's signature verifies for its own message only, and only for its own address", () => {
    fc.assert(
      fc.property(type, challenge, fc.nat(), (t, c, i) => {
        const s = bip322Signer(t);
        const other = bip322Signer(t);
        const message = attestationMessage({ ...c, chain: BITCOIN_MAINNET, address: s.address });
        const sig = s.sign(message);
        expect(verifyBip322Simple(s.address, message, sig)).toEqual({ ok: true, addressType: t });
        expect(verifyBip322Simple(s.address, mutate(message, i), sig).ok).toBe(false);
        expect(verifyBip322Simple(other.address, message, sig).ok).toBe(false);
      }),
      { numRuns: 30 },
    );
  });
  it("arbitrary bytes as a witness never throw and never verify", () => {
    const s = bip322Signer("p2wpkh");
    const t = bip322Signer("p2tr");
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 200 }), (bytes) => {
        const b64 = base64.encode(bytes);
        expect(verifyBip322Simple(s.address, "m", b64).ok).toBe(false);
        expect(verifyBip322Simple(t.address, "m", b64).ok).toBe(false);
      }),
    );
  });
  it("only P2WPKH and P2TR addresses are destinations", () => {
    fc.assert(
      fc.property(type, (t) => {
        const a = bip322Signer(t).address;
        expect(bitcoinAddressType(a)).toBe(t);
        expect(bitcoinDestinationAllowed(a)).toBe(true);
        expect(bitcoinDestinationAllowed(a.toUpperCase())).toBe(true);
      }),
      { numRuns: 20 },
    );
  });
});

describe("challenge message", () => {
  it("live and test messages for the same destination always differ, so one signature never serves both", () => {
    fc.assert(
      fc.property(seed32, challenge, (a, c) => {
        const s = solanaSigner(a);
        const live = attestationMessage({ ...c, livemode: true, chain: SOLANA_MAINNET, address: s.address });
        const test = attestationMessage({ ...c, livemode: false, chain: SOLANA_MAINNET, address: s.address });
        expect(live).not.toBe(test);
        expect(verifySolanaSignature(s.address, live, s.sign(test)).ok).toBe(false);
      }),
      RUNS,
    );
  });
});
