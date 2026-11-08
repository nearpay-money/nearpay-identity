/**
 * BIP-322 "simple" ownership signatures for Bitcoin settlement destinations (lld/identity.md §20).
 *
 * The signature is base64 of the consensus-serialized witness stack of the virtual `to_sign`
 * transaction, which spends output 0 of the virtual `to_spend` transaction committing to the message
 * (`scriptSig = OP_0 PUSH32 <tagged hash "BIP0322-signed-message" of the message bytes>`). Accepted:
 *
 * - P2WPKH: witness exactly `[DER ECDSA ‖ 0x01, 33-byte compressed pubkey]`, `hash160(pubkey)` = the
 *   witness program, ECDSA over the BIP-143 sighash of input 0 (scriptCode = P2PKH of the program,
 *   amount 0, `SIGHASH_ALL` only). High-S is accepted (this is verification, not relay policy).
 * - P2TR (key path): witness exactly `[64-byte Schnorr]` (`SIGHASH_DEFAULT`) or `[65 bytes ending 0x01]`
 *   (`SIGHASH_ALL`), BIP-340 over the BIP-341 key-path sighash (amount 0, the destination's
 *   scriptPubKey), against the output key = the witness program.
 *
 * Refused: other address types (P2PKH, P2SH, P2WSH, future witness versions), the "full" format (a
 * serialized transaction), the legacy `signmessage` format, any other witness shape or sighash type,
 * script-path spends and annexes, non-canonical base64 / witness / DER encodings.
 *
 * Pure: no network. Sighashes come from `@scure/btc-signer`, curves from `@noble/curves`.
 */

import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64 } from "@scure/base";
import * as btc from "@scure/btc-signer";

export type Bip322Result = { readonly ok: true; readonly addressType: "p2wpkh" | "p2tr" } | Bip322Failure;
export interface Bip322Failure {
  readonly ok: false;
  readonly reason: string;
}

const enc = new TextEncoder();
const TAG = sha256(enc.encode("BIP0322-signed-message"));
const OP_RETURN = Uint8Array.of(0x6a);
const fail = (reason: string): Bip322Failure => ({ ok: false, reason });

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= (a[i] as number) ^ (b[i] as number);
  return d === 0;
}

/** BIP-322 message hash: tagged SHA-256 `BIP0322-signed-message` of the message bytes. */
export function bip322MessageHash(message: string): Uint8Array {
  const m = enc.encode(message);
  const buf = new Uint8Array(64 + m.length);
  buf.set(TAG, 0);
  buf.set(TAG, 32);
  buf.set(m, 64);
  return sha256(buf);
}

/** The virtual `to_spend` and `to_sign` transactions of BIP-322 for `scriptPubKey` and `message`. */
export function bip322VirtualTxs(
  scriptPubKey: Uint8Array,
  message: string,
): { toSpend: btc.Transaction; toSign: btc.Transaction } {
  const toSpend = new btc.Transaction({
    version: 0,
    allowUnknownInputs: true,
    allowUnknownOutputs: true,
    disableScriptCheck: true,
    allowUnknownVersion: true,
  });
  // output first: a finalized input (scriptSig set) locks the outputs
  toSpend.addOutput({ script: scriptPubKey, amount: 0n });
  toSpend.addInput({
    txid: new Uint8Array(32),
    index: 0xffffffff,
    sequence: 0,
    finalScriptSig: new Uint8Array([0x00, 0x20, ...bip322MessageHash(message)]),
  });
  const toSign = new btc.Transaction({ version: 0, allowUnknownOutputs: true, allowUnknownVersion: true });
  toSign.addInput({ txid: toSpend.id, index: 0, sequence: 0, witnessUtxo: { script: scriptPubKey, amount: 0n } });
  toSign.addOutput({ script: OP_RETURN, amount: 0n });
  return { toSpend, toSign };
}

/** Destination scriptPubKey for a mainnet P2WPKH / P2TR address; null for anything else. */
function destinationScript(
  address: string,
):
  | { type: "p2wpkh"; script: Uint8Array; hash: Uint8Array }
  | { type: "p2tr"; script: Uint8Array; pubkey: Uint8Array }
  | null {
  try {
    const script = btc.OutScript.encode(btc.Address(btc.NETWORK).decode(address));
    const out = btc.OutScript.decode(script);
    if (out.type === "wpkh") return { type: "p2wpkh", script, hash: out.hash };
    if (out.type === "tr") return { type: "p2tr", script, pubkey: out.pubkey };
  } catch {
    // not a mainnet address
  }
  return null;
}

/** Strict base64 → witness stack; null unless it is exactly one canonical witness serialization. */
function decodeWitness(signature: string): Uint8Array[] | null {
  let raw: Uint8Array;
  try {
    raw = base64.decode(signature);
  } catch {
    return null;
  }
  if (raw.length === 0) return null;
  try {
    const witness = btc.RawWitness.decode(raw);
    // the re-encoding must give back the exact bytes: no trailing data, minimal CompactSize lengths
    return equal(btc.RawWitness.encode(witness), raw) ? witness : null;
  } catch {
    return null;
  }
}

/**
 * Verifies a BIP-322 "simple" signature by the key that controls `address` (mainnet P2WPKH / P2TR,
 * lower-case or as validated by kit `chains`) over the exact UTF-8 bytes of `message`.
 */
export function verifyBip322Simple(address: string, message: string, signature: string): Bip322Result {
  const dest = destinationScript(address);
  if (!dest) return fail("BIP-322 ownership is accepted for P2WPKH (bc1q…) and P2TR (bc1p…) addresses only");
  const witness = decodeWitness(signature);
  if (!witness) return fail("the signature is not a base64 BIP-322 simple witness");
  const { toSign } = bip322VirtualTxs(dest.script, message);

  if (dest.type === "p2wpkh") {
    if (witness.length !== 2) return fail("a P2WPKH witness has exactly two items (signature, public key)");
    const [sigWithType, pub] = witness as [Uint8Array, Uint8Array];
    if (pub.length !== 33 || (pub[0] !== 0x02 && pub[0] !== 0x03)) return fail("the public key is not compressed");
    if (sigWithType.length < 9 || sigWithType[sigWithType.length - 1] !== btc.SigHash.ALL)
      return fail("P2WPKH signatures must use SIGHASH_ALL");
    let pubScript: Uint8Array;
    try {
      pubScript = btc.p2wpkh(pub).script;
    } catch {
      return fail("the public key is not a valid secp256k1 point");
    }
    if (!equal(pubScript, dest.script)) return fail("the public key does not hash to the address");
    const der = sigWithType.subarray(0, -1);
    try {
      // strict DER (BIP-66): the parsed signature must serialize back to the same bytes
      const parsed = secp256k1.Signature.fromBytes(der, "der");
      if (!equal(parsed.toBytes("der"), der)) return fail("the ECDSA signature is not strict DER");
      const sighash = toSign.preimageWitnessV0(0, btc.p2pkh(pub).script, btc.SigHash.ALL, 0n);
      return secp256k1.verify(der, sighash, pub, { prehash: false, format: "der", lowS: false })
        ? { ok: true, addressType: "p2wpkh" }
        : fail("the ECDSA signature does not verify");
    } catch {
      return fail("the ECDSA signature is malformed");
    }
  }

  // P2TR key path: exactly one witness item (more items = script path or annex)
  if (witness.length !== 1) return fail("a P2TR key-path witness has exactly one item");
  const sig = witness[0] as Uint8Array;
  let hashType: number;
  if (sig.length === 64) hashType = btc.SigHash.DEFAULT;
  else if (sig.length === 65 && sig[64] === btc.SigHash.ALL) hashType = btc.SigHash.ALL;
  else return fail("P2TR signatures must be 64 bytes (SIGHASH_DEFAULT) or 65 bytes ending SIGHASH_ALL");
  try {
    const sighash = toSign.preimageWitnessV1(0, [dest.script], hashType, [0n]);
    return schnorr.verify(sig.subarray(0, 64), sighash, dest.pubkey)
      ? { ok: true, addressType: "p2tr" }
      : fail("the Schnorr signature does not verify");
  } catch {
    return fail("the Schnorr signature is malformed");
  }
}
