/**
 * Stage 4 ownership attestations (lld/identity.md §20): `standard: solana` and `standard: bip322`,
 * checked case by case against spec 0.4.0 `test-vectors/destination-attestation.json` and the address
 * rules of `chains-solana-bitcoin.json`.
 */
import { getChain, validateAddress } from "@nearpay-internal/chains";
import { base64 } from "@scure/base";
import * as btc from "@scure/btc-signer";
import bs58 from "bs58";
import { describe, expect, it } from "vitest";
import {
  attestationMessage,
  BITCOIN_DESTINATION_HINT,
  bitcoinAddressType,
  bitcoinDestinationAllowed,
  signingStandard,
  VERIFIABLE_STANDARDS,
} from "../../src/domain/settlement-destination/destination.js";
import { type OwnershipLookups, verifyAttestation } from "../../src/infra/crypto/attestation.js";
import { bip322MessageHash, bip322VirtualTxs, verifyBip322Simple } from "../../src/infra/crypto/bip322.js";
import { solanaSigningKey, verifySolanaSignature } from "../../src/infra/crypto/solana.js";
import { BITCOIN_MAINNET, SOLANA_MAINNET } from "../../src/spec-0.4.0-placeholder.js";
import { bip322Signer, solanaSigner } from "../support/signers.js";
import { specVector } from "../support/vectors.js";

interface MessageInput {
  account: string;
  livemode: boolean;
  nonce_hex: string;
  expires_at: string;
  asset_id: string;
  chain: string;
  address: string;
}
interface Case {
  name: string;
  signature: string;
  valid: boolean;
}
interface AttestationVectors {
  message: { input: MessageInput; text: string };
  solana: { seed_hex: string; address: string; message: string; cases: Case[] };
  bip322: {
    upstream: {
      message_hashes: { message: string; hash: string }[];
      transactions: { address: string; message: string; to_spend_txid: string; to_sign_txid: string }[];
      signatures: { address: string; message: string; signature: string }[];
    };
    nearpay: {
      type: "p2wpkh" | "p2tr";
      secret_hex: string;
      address: string;
      input: MessageInput;
      message: string;
      message_hash: string;
      to_spend_txid: string;
      to_sign_txid: string;
      cases: Case[];
    }[];
  };
}
interface AddressVectors {
  addresses: {
    solana: { address: string; valid: boolean; normalized?: string; on_curve?: boolean }[];
    bitcoin: { address: string; valid: boolean; type?: string; destination_allowed?: boolean; normalized?: string }[];
  };
}

const V = specVector<AttestationVectors>("destination-attestation.json");
const A = specVector<AddressVectors>("chains-solana-bitcoin.json");
const noRpc: OwnershipLookups = {
  nearAccessKey: async () => {
    throw new Error("Solana and Bitcoin attestations must not call any RPC");
  },
};
const messageOf = (i: MessageInput) =>
  attestationMessage({
    account: i.account,
    livemode: i.livemode,
    assetId: i.asset_id,
    chain: i.chain,
    address: i.address,
    nonceHex: i.nonce_hex,
    expiresAt: new Date(i.expires_at),
  });
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("challenge message (§8.2)", () => {
  it("is exactly the vector text for the Solana and both Bitcoin inputs", () => {
    expect(messageOf(V.message.input)).toBe(V.message.text);
    expect(V.solana.message).toBe(V.message.text);
    for (const v of V.bip322.nearpay) expect(messageOf(v.input), v.type).toBe(v.message);
  });
  it("differs between live and test mode only in the Mode line", () => {
    const live = messageOf(V.message.input);
    const test = messageOf({ ...V.message.input, livemode: false });
    expect(test).toBe(live.replace("\nMode: live\n", "\nMode: test\n"));
    expect(test).not.toBe(live);
  });
});

describe("standard: solana — destination-attestation.json", () => {
  it("the vector address derives from the seed", () => {
    expect(solanaSigner(Buffer.from(V.solana.seed_hex, "hex")).address).toBe(V.solana.address);
  });
  for (const c of V.solana.cases)
    it(`${c.valid ? "accepts" : "refuses"}: ${c.name}`, async () => {
      expect(verifySolanaSignature(V.solana.address, V.solana.message, c.signature).ok).toBe(c.valid);
      const r = await verifyAttestation(
        {
          standard: "solana",
          chain: SOLANA_MAINNET,
          addressNorm: V.solana.address,
          message: V.solana.message,
          nonce: new Uint8Array(32),
          signature: c.signature,
        },
        noRpc,
      );
      expect(r.ok).toBe(c.valid);
      if (r.ok) expect(r).toEqual({ ok: true, method: "solana_ed25519", publicKey: null });
    });
  it("tells the off-chain (Ledger) format apart and gives the merchant a hint", async () => {
    const c = V.solana.cases.find((x) => x.name.startsWith("off-chain")) as Case;
    const r = verifySolanaSignature(V.solana.address, V.solana.message, c.signature);
    expect(r).toMatchObject({ ok: false, hint: "offchain_format" });
    const a = await verifyAttestation(
      {
        standard: "solana",
        chain: SOLANA_MAINNET,
        addressNorm: V.solana.address,
        message: V.solana.message,
        nonce: new Uint8Array(32),
        signature: c.signature,
      },
      noRpc,
    );
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.hint).toMatch(/off-chain message/);
  });
  it("a wallet signing the test-mode message is refused on the live challenge (and accepted on its own)", () => {
    const s = solanaSigner(Buffer.from(V.solana.seed_hex, "hex"));
    const testMessage = messageOf({ ...V.message.input, livemode: false });
    const sig = s.sign(testMessage);
    expect(sig).toBe(V.solana.cases.find((c) => c.name === "signed the test-mode message")?.signature);
    expect(verifySolanaSignature(s.address, testMessage, sig).ok).toBe(true);
    expect(verifySolanaSignature(s.address, V.solana.message, sig).ok).toBe(false);
  });
  it("refuses an off-curve (program-derived) address with the unverified-path hint", () => {
    const pda = "DN5C7q7RzxDXor5jNHDBxfHU5yp3M58XJXcWR4WvvyAp";
    expect(verifySolanaSignature(pda, "m", bs58.encode(new Uint8Array(64)))).toMatchObject({
      ok: false,
      hint: "off_curve",
    });
  });
  it("refuses a small-order key (the all-zero System Program address) although it is on the curve", () => {
    const zero = "11111111111111111111111111111111";
    const k = solanaSigningKey(zero);
    expect(k).toMatchObject({ offCurve: false });
    expect(verifySolanaSignature(zero, "m", bs58.encode(new Uint8Array(64))).ok).toBe(false);
  });
  it("refuses malformed signatures without throwing", () => {
    const s = solanaSigner();
    const good = s.sign("m");
    for (const bad of [
      "",
      " ",
      `${good} `,
      `0${good.slice(1)}`,
      bs58.encode(new Uint8Array(63)),
      bs58.encode(new Uint8Array(65)),
    ])
      expect(verifySolanaSignature(s.address, "m", bad).ok, JSON.stringify(bad)).toBe(false);
    expect(verifySolanaSignature("not-an-address", "m", good).ok).toBe(false);
    expect(verifySolanaSignature(s.address, "m", good).ok).toBe(true);
  });
  it("is refused for a non-Solana chain", async () => {
    const s = solanaSigner();
    const r = await verifyAttestation(
      {
        standard: "solana",
        chain: BITCOIN_MAINNET,
        addressNorm: s.address,
        message: "m",
        nonce: new Uint8Array(32),
        signature: s.sign("m"),
      },
      noRpc,
    );
    expect(r.ok).toBe(false);
  });
});

describe("standard: bip322 — upstream BIP-322 vectors", () => {
  it("message hashes match the BIP", () => {
    for (const h of V.bip322.upstream.message_hashes) expect(hex(bip322MessageHash(h.message))).toBe(h.hash);
  });
  it("virtual to_spend / to_sign txids match the BIP", () => {
    for (const t of V.bip322.upstream.transactions) {
      const spk = btc.OutScript.encode(btc.Address(btc.NETWORK).decode(t.address));
      const { toSpend, toSign } = bip322VirtualTxs(spk, t.message);
      expect(toSpend.id).toBe(t.to_spend_txid);
      expect(toSign.id).toBe(t.to_sign_txid);
    }
  });
  it("upstream P2WPKH and P2TR signatures verify; a signature on another message does not", () => {
    for (const s of V.bip322.upstream.signatures)
      expect(verifyBip322Simple(s.address, s.message, s.signature).ok, `${s.address} "${s.message}"`).toBe(true);
    const [empty] = V.bip322.upstream.signatures;
    expect(verifyBip322Simple(empty?.address as string, "Hello World", empty?.signature as string).ok).toBe(false);
  });
});

describe("standard: bip322 — NearPay challenge cases", () => {
  for (const v of V.bip322.nearpay) {
    it(`${v.type}: message hash and virtual txids`, () => {
      expect(hex(bip322MessageHash(v.message))).toBe(v.message_hash);
      const spk = btc.OutScript.encode(btc.Address(btc.NETWORK).decode(v.address));
      const { toSpend, toSign } = bip322VirtualTxs(spk, v.message);
      expect([toSpend.id, toSign.id]).toEqual([v.to_spend_txid, v.to_sign_txid]);
    });
    it(`${v.type}: the address derives from the test key`, () => {
      expect(bip322Signer(v.type, Buffer.from(v.secret_hex, "hex")).address).toBe(v.address);
    });
    for (const c of v.cases)
      it(`${v.type}: ${c.valid ? "accepts" : "refuses"} ${c.name}`, async () => {
        const r = await verifyAttestation(
          {
            standard: "bip322",
            chain: BITCOIN_MAINNET,
            addressNorm: v.address,
            message: v.message,
            nonce: new Uint8Array(32),
            signature: c.signature,
          },
          noRpc,
        );
        expect(r.ok).toBe(c.valid);
        if (r.ok) expect(r).toEqual({ ok: true, method: `bip322_${v.type}`, publicKey: null });
      });
  }
});

describe("standard: bip322 — shapes and encodings", () => {
  const msg = "NearPay settlement destination\nMode: live";
  const wpkh = bip322Signer("p2wpkh");
  const tr = bip322Signer("p2tr");

  it("accepts what wallets produce: P2WPKH SIGHASH_ALL, P2TR SIGHASH_DEFAULT (64 bytes) and SIGHASH_ALL (65 bytes)", () => {
    expect(verifyBip322Simple(wpkh.address, msg, wpkh.sign(msg))).toEqual({ ok: true, addressType: "p2wpkh" });
    expect(verifyBip322Simple(tr.address, msg, tr.sign(msg))).toEqual({ ok: true, addressType: "p2tr" });
    expect(verifyBip322Simple(tr.address, msg, tr.sign(msg, { sighash: btc.SigHash.ALL })).ok).toBe(true);
  });
  it("accepts a high-S ECDSA signature (verification, not relay policy)", () => {
    expect(verifyBip322Simple(wpkh.address, msg, wpkh.sign(msg, { highS: true })).ok).toBe(true);
  });
  it("refuses other sighash types", () => {
    for (const t of [btc.SigHash.NONE, btc.SigHash.SINGLE, btc.SigHash.ALL_ANYONECANPAY])
      expect(verifyBip322Simple(wpkh.address, msg, wpkh.sign(msg, { sighash: t })).ok, `p2wpkh ${t}`).toBe(false);
    for (const t of [btc.SigHash.NONE, btc.SigHash.SINGLE, btc.SigHash.ALL_ANYONECANPAY])
      expect(verifyBip322Simple(tr.address, msg, tr.sign(msg, { sighash: t })).ok, `p2tr ${t}`).toBe(false);
    // SIGHASH_DEFAULT spelled out as a 65th byte 0x00 is not a valid BIP-341 encoding
    expect(verifyBip322Simple(tr.address, msg, tr.sign(msg, { explicitDefault: true })).ok).toBe(false);
  });
  it("refuses extra witness items (script path, annex, padding)", () => {
    expect(verifyBip322Simple(tr.address, msg, tr.sign(msg, { extraWitness: [Uint8Array.of(0x50, 1)] })).ok).toBe(
      false,
    );
    expect(verifyBip322Simple(wpkh.address, msg, wpkh.sign(msg, { extraWitness: [new Uint8Array(0)] })).ok).toBe(false);
  });
  it("refuses a P2WPKH witness whose key does not hash to the address, or an uncompressed key", () => {
    const other = bip322Signer("p2wpkh");
    expect(verifyBip322Simple(wpkh.address, msg, other.sign(msg)).ok).toBe(false);
    const raw = btc.RawWitness.decode(base64.decode(wpkh.sign(msg)));
    const uncompressed = btc.RawWitness.encode([raw[0] as Uint8Array, new Uint8Array(65).fill(4)]);
    expect(verifyBip322Simple(wpkh.address, msg, base64.encode(uncompressed)).ok).toBe(false);
  });
  it("refuses a P2TR signature by the internal (untweaked) key's address", () => {
    expect(verifyBip322Simple(bip322Signer("p2tr").address, msg, tr.sign(msg)).ok).toBe(false);
  });
  it("refuses non-canonical encodings: unpadded base64, trailing bytes, non-minimal lengths, legacy/full formats", () => {
    const good = wpkh.sign(msg);
    expect(verifyBip322Simple(wpkh.address, msg, good.replace(/=+$/, "")).ok).toBe(!good.endsWith("="));
    const bytes = base64.decode(good);
    expect(verifyBip322Simple(wpkh.address, msg, base64.encode(new Uint8Array([...bytes, 0]))).ok).toBe(false);
    // the witness item count as a non-minimal CompactSize (0xfd 0x0200)
    const nonMinimal = new Uint8Array([0xfd, 0x02, 0x00, ...bytes.subarray(1)]);
    expect(verifyBip322Simple(wpkh.address, msg, base64.encode(nonMinimal)).ok).toBe(false);
    // legacy signmessage: 65-byte compact recoverable signature
    expect(verifyBip322Simple(wpkh.address, msg, base64.encode(new Uint8Array(65).fill(0x1f))).ok).toBe(false);
    expect(verifyBip322Simple(wpkh.address, msg, "").ok).toBe(false);
    expect(verifyBip322Simple(wpkh.address, msg, "not base64 at all!").ok).toBe(false);
  });
  it("refuses DER with trailing garbage inside the signature item", () => {
    const raw = btc.RawWitness.decode(base64.decode(wpkh.sign(msg)));
    const sig = raw[0] as Uint8Array;
    const padded = new Uint8Array([...sig.subarray(0, -1), 0x00, 0x01]);
    expect(
      verifyBip322Simple(wpkh.address, msg, base64.encode(btc.RawWitness.encode([padded, raw[1] as Uint8Array]))).ok,
    ).toBe(false);
  });
  it("refuses addresses other than mainnet P2WPKH / P2TR", () => {
    const sig = wpkh.sign(msg);
    for (const a of [
      "12HWMKcfvshJ1dJo1kBX3jaguexKF5UeXY",
      "3EdC2tokZbqft8jYFdvN58YaCetzMUBRji",
      "bc1qppsup2haejt8whm43a32rgwqtrvv0h46ts3ld6gje2xqrrczzj2sz0eetu",
      "tb1qpct5sxzppv204tth290uen85nqkhzw9s2jqud0",
      "garbage",
    ])
      expect(verifyBip322Simple(a, msg, sig).ok, a).toBe(false);
  });
  it("is refused for a non-Bitcoin chain", async () => {
    const r = await verifyAttestation(
      {
        standard: "bip322",
        chain: SOLANA_MAINNET,
        addressNorm: wpkh.address,
        message: msg,
        nonce: new Uint8Array(32),
        signature: wpkh.sign(msg),
      },
      noRpc,
    );
    expect(r.ok).toBe(false);
  });
});

describe("destination address rules — chains-solana-bitcoin.json", () => {
  it("Solana: kit validity and normalisation; off-curve addresses cannot sign", () => {
    for (const c of A.addresses.solana) {
      const v = validateAddress(SOLANA_MAINNET, c.address);
      expect(v.ok, JSON.stringify(c.address)).toBe(c.valid);
      if (!c.valid || !v.ok) continue;
      expect(v.normalized).toBe(c.normalized);
      const k = solanaSigningKey(c.address);
      expect(k instanceof Uint8Array || !k.offCurve, c.address).toBe(c.on_curve);
    }
  });
  it("Bitcoin: kit validity, type, and P2WPKH/P2TR-only destinations", () => {
    for (const c of A.addresses.bitcoin) {
      const v = validateAddress(BITCOIN_MAINNET, c.address);
      expect(v.ok, c.address).toBe(c.valid);
      if (!c.valid || !v.ok) continue;
      expect(v.normalized, c.address).toBe(c.normalized);
      expect(bitcoinAddressType(v.normalized), c.address).toBe(c.type);
      expect(bitcoinDestinationAllowed(v.normalized), c.address).toBe(c.destination_allowed);
    }
  });
  it("other address shapes are `other`", () => {
    expect(bitcoinAddressType("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs")).toBe("other");
    expect(bitcoinAddressType(`bc1q${"q".repeat(50)}`)).toBe("other");
    expect(bitcoinAddressType(`bc1p${"q".repeat(40)}`)).toBe("other");
    expect(bitcoinAddressType("xyz")).toBe("other");
    expect(BITCOIN_DESTINATION_HINT).toMatch(/bc1q.*bc1p/);
  });
  it("Solana and Bitcoin chains sign with solana / bip322, and identity verifies all four standards", () => {
    expect(signingStandard("chain_address", getChain(SOLANA_MAINNET)?.family as string, V.solana.address)).toBe(
      "solana",
    );
    expect(
      signingStandard(
        "chain_address",
        getChain(BITCOIN_MAINNET)?.family as string,
        "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      ),
    ).toBe("bip322");
    expect([...VERIFIABLE_STANDARDS].sort()).toEqual(["bip322", "eip191", "nep413", "solana"]);
  });
});
