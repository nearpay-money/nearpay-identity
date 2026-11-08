/** Test signers for destination attestations (NEP-413, EIP-191, Solana, BIP-322), built like wallets do. */

import { erc191Hash, nep413Hash } from "@nearpay-internal/intents";
import { ed25519 } from "@noble/curves/ed25519.js";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import * as btc from "@scure/btc-signer";
import bs58 from "bs58";
import { bip322VirtualTxs } from "../../src/infra/crypto/bip322.js";

export function nearSigner(seed?: Uint8Array) {
  const secret = seed ?? ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(secret);
  return {
    publicKey: `ed25519:${bs58.encode(pub)}`,
    implicitAccount: Buffer.from(pub).toString("hex"),
    /** NEP-413 `signMessage` result: base64 signature over the borsh payload. */
    sign(message: string, nonce: Uint8Array, recipient = "nearpay.money") {
      return Buffer.from(ed25519.sign(nep413Hash(message, nonce, recipient), secret)).toString("base64");
    },
  };
}

export function evmSigner(priv?: Uint8Array) {
  const secret = priv ?? secp256k1.utils.randomSecretKey();
  const uncompressed = secp256k1.getPublicKey(secret, false);
  const address = `0x${Buffer.from(keccak_256(uncompressed.slice(1)).slice(-20)).toString("hex")}`;
  return {
    address,
    /** `personal_sign`: 0x r ‖ s ‖ v (v = 27/28 like MetaMask, or 0/1). */
    sign(message: string, vBase: 27 | 0 = 27) {
      const rec = secp256k1.sign(erc191Hash(message), secret, { prehash: false, format: "recovered" });
      return `0x${Buffer.from(rec.slice(1)).toString("hex")}${((rec[0] as number) + vBase).toString(16).padStart(2, "0")}`;
    },
  };
}

/** Solana wallet (`solana:signMessage`): base58 ed25519 over the raw UTF-8 message bytes. */
export function solanaSigner(seed?: Uint8Array) {
  const secret = seed ?? ed25519.utils.randomSecretKey();
  return {
    address: bs58.encode(ed25519.getPublicKey(secret)),
    sign(message: string | Uint8Array) {
      const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
      return bs58.encode(ed25519.sign(bytes, secret));
    },
  };
}

const SECP_N = secp256k1.Point.CURVE().n;
const taggedHash = (tag: string, ...parts: Uint8Array[]) => {
  const t = sha256(new TextEncoder().encode(tag));
  return sha256(concatBytes(t, t, ...parts));
};

/**
 * BIP-322 "simple" signer (what Unisat / Xverse / Sparrow produce): P2WPKH (ECDSA, BIP-143, SIGHASH_ALL)
 * or P2TR key path (BIP-86 tweak, BIP-341 sighash). `opts` produce the shapes verifiers must refuse.
 */
export function bip322Signer(type: "p2wpkh" | "p2tr", priv?: Uint8Array) {
  const secret = priv ?? secp256k1.utils.randomSecretKey();
  const pub = secp256k1.getPublicKey(secret, true);
  const payment = type === "p2wpkh" ? btc.p2wpkh(pub) : btc.p2tr(pub.subarray(1));
  const address = payment.address as string;
  return {
    address,
    pub,
    sign(
      message: string,
      opts: { sighash?: number; extraWitness?: Uint8Array[]; highS?: boolean; explicitDefault?: boolean } = {},
    ): string {
      const { toSign } = bip322VirtualTxs(payment.script, message);
      if (type === "p2wpkh") {
        const sighashType = opts.sighash ?? btc.SigHash.ALL;
        const digest = toSign.preimageWitnessV0(0, btc.p2pkh(pub).script, sighashType, 0n);
        let sig = secp256k1.Signature.fromBytes(secp256k1.sign(digest, secret, { prehash: false }), "compact");
        if (opts.highS) sig = new secp256k1.Signature(sig.r, SECP_N - sig.s);
        const der = sig.toBytes("der");
        return base64.encode(
          btc.RawWitness.encode([new Uint8Array([...der, sighashType]), pub, ...(opts.extraWitness ?? [])]),
        );
      }
      // BIP-86 key-path tweak of the private key
      const P = secp256k1.Point.BASE.multiply(bytesToNumberBE(secret));
      const d = P.y % 2n === 0n ? bytesToNumberBE(secret) : SECP_N - bytesToNumberBE(secret);
      const t = bytesToNumberBE(taggedHash("TapTweak", pub.subarray(1)));
      const tweaked = numberToBytesBE((d + t) % SECP_N, 32);
      const hashType = opts.sighash ?? btc.SigHash.DEFAULT;
      const digest = toSign.preimageWitnessV1(0, [payment.script], hashType, [0n]);
      const sig = schnorr.sign(digest, tweaked, new Uint8Array(32));
      const item = hashType === btc.SigHash.DEFAULT && !opts.explicitDefault ? sig : new Uint8Array([...sig, hashType]);
      return base64.encode(btc.RawWitness.encode([item, ...(opts.extraWitness ?? [])]));
    },
  };
}
