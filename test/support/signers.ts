/** Test signers for destination attestations (NEP-413 and EIP-191), built like wallets do. */

import { erc191Hash, nep413Hash } from "@nearpay-internal/intents";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import bs58 from "bs58";

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
