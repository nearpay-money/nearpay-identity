/**
 * Solana ownership signatures for settlement destinations (lld/identity.md §20, `standard: solana`).
 *
 * `signature` = base58 of the 64-byte ed25519 signature over the exact UTF-8 bytes of the challenge
 * message (wallet-standard `solana:signMessage`, raw bytes — Phantom, Solflare, Backpack). Valid iff
 * the address base58-decodes to an on-curve, non-small-order ed25519 public key and the signature
 * verifies (RFC 8032 strict: canonical `R`/`S` encodings). Not accepted in v1: base64 signatures,
 * the Solana off-chain message format (`\xffsolana offchain` header — what the Ledger Solana app
 * signs; Ledger users take the `mark_unverified` path), Sign-In-With-Solana messages. An off-curve
 * (program-derived) address such as a Squads vault cannot sign at all.
 *
 * Pure: no network.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";

export type SolanaResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string; readonly hint?: "offchain_format" | "off_curve" };

const enc = new TextEncoder();
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;

function decodeBase58(s: string, length: number): Uint8Array | null {
  if (!BASE58.test(s)) return null;
  try {
    const raw = bs58.decode(s);
    return raw.length === length ? raw : null;
  } catch {
    return null;
  }
}

/** The ed25519 public key of a Solana address when it can sign: 32 bytes, on the curve, not small-order. */
export function solanaSigningKey(address: string): Uint8Array | { reason: string; offCurve: boolean } {
  const pk = decodeBase58(address, 32);
  if (!pk) return { reason: "the address is not base58 of 32 bytes", offCurve: false };
  try {
    // a small-order key verifies forged signatures for any message: such an address has no owner
    if (ed25519.Point.fromBytes(pk, false).isSmallOrder())
      return { reason: "the address is a small-order point and cannot prove ownership", offCurve: false };
  } catch {
    return { reason: "the address is program-derived (off-curve) and cannot sign", offCurve: true };
  }
  return pk;
}

/**
 * The Solana off-chain message envelope (short v0 header, as signed by the Ledger Solana app):
 * `\xff "solana offchain" version(0) format(0) length(u16 LE) message`. Only used to tell such a
 * signature apart in the rejection reason; it is never accepted.
 */
function offchainEnvelope(message: Uint8Array): Uint8Array | null {
  if (message.length > 0xffff) return null;
  const head = enc.encode("solana offchain");
  const out = new Uint8Array(1 + head.length + 2 + 2 + message.length);
  out[0] = 0xff;
  out.set(head, 1);
  let o = 1 + head.length;
  out[o++] = 0; // header version
  out[o++] = 0; // message format: restricted ASCII
  out[o++] = message.length & 0xff;
  out[o++] = message.length >> 8;
  out.set(message, o);
  return out;
}

function verifyStrict(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, pk, { zip215: false });
  } catch {
    return false;
  }
}

/** Verifies a `standard: solana` attestation signature by `address` over `message`. */
export function verifySolanaSignature(address: string, message: string, signature: string): SolanaResult {
  const key = solanaSigningKey(address);
  if (!(key instanceof Uint8Array))
    return { ok: false, reason: key.reason, ...(key.offCurve ? { hint: "off_curve" as const } : {}) };
  const sig = decodeBase58(signature, 64);
  if (!sig) return { ok: false, reason: "the signature is not base58 of 64 bytes" };
  const msg = enc.encode(message);
  if (verifyStrict(sig, msg, key)) return { ok: true };
  const envelope = offchainEnvelope(msg);
  if (envelope && verifyStrict(sig, envelope, key))
    return {
      ok: false,
      reason: "the signature uses the Solana off-chain message format, which is not accepted",
      hint: "offchain_format",
    };
  return { ok: false, reason: "the ed25519 signature does not verify for this address" };
}
