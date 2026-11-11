/**
 * Destination ownership attestation (lld/identity.md §8.2, FR-SET-02).
 *
 * - NEP-413 (NEAR accounts, NEAR Intents accounts owned by a NEAR key): ed25519 over the NEP-413
 *   borsh payload `{message, nonce, recipient: "nearpay.money"}`; an implicit account must equal
 *   `hex(public key)`; a named account must hold the key as a **full-access key** at final block.
 * - EIP-191 (EVM addresses and `0x…` Intents accounts): `personal_sign`, `ecrecover == address`;
 *   ERC-1271 `isValidSignature` for contract wallets on the stated chain when an RPC is configured.
 * - Solana (Stage 4, §20): ed25519 over the raw message bytes, base58 signature, on-curve address
 *   (`solana.ts`).
 * - BIP-322 "simple" (Stage 4, §20): P2WPKH / P2TR Bitcoin addresses, base64 witness (`bip322.ts`).
 *
 * The signature checks are pure; ownership lookups go through the injected RPC functions (NEAR named
 * accounts and ERC-1271 only — Solana and Bitcoin need no RPC, so they are never "unavailable").
 */

import { erc191Hash, nep413Hash } from "@nearpay-internal/intents";
import type { DESTINATION_SIGNING_STANDARDS } from "@nearpay-money/spec";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import bs58 from "bs58";
import { NEP413_RECIPIENT } from "../../domain/settlement-destination/destination.js";
import { verifyBip322Simple } from "./bip322.js";
import { verifySolanaSignature } from "./solana.js";

export type AttestationMethod =
  | "ed25519"
  | "implicit"
  | "full_access_key"
  | "ecrecover"
  | "erc1271"
  | "solana_ed25519"
  | "bip322_p2wpkh"
  | "bip322_p2tr";

export type AttestationResult =
  | { readonly ok: true; readonly method: AttestationMethod; readonly publicKey: string | null }
  | { readonly ok: false; readonly reason: string; readonly hint?: string };

/** User-facing advice for a rejection the merchant can fix (the reason itself is only logged). */
const HINTS: Record<string, string> = {
  offchain_format:
    "This looks like a Solana off-chain message signature (e.g. from a Ledger). Sign the message as raw bytes with a wallet such as Phantom, Solflare or Backpack.",
  off_curve:
    "This Solana address is program-derived (for example a multisig vault) and cannot sign a message, so its ownership cannot be proven with a signature. Use a wallet address you can sign with.",
};

/** An ownership lookup that could not be completed (RPC down): retryable, not a rejection. */
export class AttestationUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AttestationUnavailable";
  }
}

export interface OwnershipLookups {
  /** `FullAccess` | `FunctionCall` | null (no such key); throws AttestationUnavailable when RPC fails. */
  nearAccessKey(accountId: string, publicKey: string): Promise<"FullAccess" | "FunctionCall" | null>;
  /** ERC-1271 on `chain`, or null when no RPC is configured for it. */
  erc1271?(chain: string, address: string, hash: Uint8Array, signature: Uint8Array): Promise<boolean | null>;
}

const IMPLICIT_RE = /^[0-9a-f]{64}$/;
const ETH_RE = /^0x[0-9a-f]{40}$/;

function decodeEd25519Signature(s: string): Uint8Array | null {
  try {
    const raw = s.startsWith("ed25519:") ? bs58.decode(s.slice(8)) : Uint8Array.from(Buffer.from(s, "base64"));
    return raw.length === 64 ? raw : null;
  } catch {
    return null;
  }
}

function decodeNearKey(k: string | undefined): Uint8Array | null {
  if (!k?.startsWith("ed25519:")) return null;
  try {
    const raw = bs58.decode(k.slice(8));
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}

/** Pure NEP-413 signature check. */
export function verifyNep413Signature(
  message: string,
  nonce: Uint8Array,
  signature: string,
  publicKey: string | undefined,
): boolean {
  const sig = decodeEd25519Signature(signature);
  const pk = decodeNearKey(publicKey);
  if (!sig || !pk || nonce.length !== 32) return false;
  try {
    return ed25519.verify(sig, nep413Hash(message, nonce, NEP413_RECIPIENT), pk);
  } catch {
    return false;
  }
}

/** Pure EIP-191 recovery: the lower-case 0x address that signed, or null. */
export function recoverEip191(message: string, signature: string): string | null {
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) return null;
  const raw = Buffer.from(signature.slice(2), "hex");
  const v = raw[64] as number;
  const recovery = v >= 27 ? v - 27 : v;
  if (recovery !== 0 && recovery !== 1) return null;
  try {
    const rec = new Uint8Array([recovery, ...raw.subarray(0, 64)]);
    const pub = secp256k1.recoverPublicKey(rec, erc191Hash(message), { prehash: false });
    const uncompressed = secp256k1.Point.fromBytes(pub).toBytes(false);
    return `0x${Buffer.from(keccak_256(uncompressed.slice(1)).slice(-20)).toString("hex")}`;
  } catch {
    return null;
  }
}

export interface AttestInput {
  readonly standard: (typeof DESTINATION_SIGNING_STANDARDS)[number];
  readonly chain: string;
  readonly addressNorm: string;
  readonly message: string;
  readonly nonce: Uint8Array;
  readonly signature: string;
  readonly publicKey?: string | undefined;
}

/** Verifies the signature and that the signer controls the destination address. */
export async function verifyAttestation(i: AttestInput, rpc: OwnershipLookups): Promise<AttestationResult> {
  if (i.standard === "solana") {
    if (!i.chain.startsWith("solana:")) return { ok: false, reason: "solana signatures are for Solana addresses" };
    const r = verifySolanaSignature(i.addressNorm, i.message, i.signature);
    if (r.ok) return { ok: true, method: "solana_ed25519", publicKey: null };
    return { ok: false, reason: r.reason, ...(r.hint ? { hint: HINTS[r.hint] } : {}) };
  }
  if (i.standard === "bip322") {
    if (!i.chain.startsWith("bip122:")) return { ok: false, reason: "bip322 signatures are for Bitcoin addresses" };
    const r = verifyBip322Simple(i.addressNorm, i.message, i.signature);
    return r.ok ? { ok: true, method: `bip322_${r.addressType}`, publicKey: null } : { ok: false, reason: r.reason };
  }
  if (i.standard === "nep413") {
    if (ETH_RE.test(i.addressNorm)) return { ok: false, reason: "a 0x account signs with eip191" };
    if (!verifyNep413Signature(i.message, i.nonce, i.signature, i.publicKey))
      return { ok: false, reason: "the NEP-413 signature does not verify" };
    const pk = decodeNearKey(i.publicKey) as Uint8Array;
    if (IMPLICIT_RE.test(i.addressNorm)) {
      return Buffer.from(pk).toString("hex") === i.addressNorm
        ? { ok: true, method: "implicit", publicKey: i.publicKey ?? null }
        : { ok: false, reason: "the key does not match the implicit account" };
    }
    const permission = await rpc.nearAccessKey(i.addressNorm, i.publicKey as string);
    if (permission === "FullAccess") return { ok: true, method: "full_access_key", publicKey: i.publicKey ?? null };
    return {
      ok: false,
      reason: permission === null ? "the key is not an access key of the account" : "the key is not a full-access key",
    };
  }
  if (!ETH_RE.test(i.addressNorm)) return { ok: false, reason: "eip191 needs a 0x address" };
  const signer = recoverEip191(i.message, i.signature);
  if (signer === i.addressNorm) return { ok: true, method: "ecrecover", publicKey: null };
  if (rpc.erc1271 && /^0x[0-9a-fA-F]{130,}$/.test(i.signature) && i.chain.startsWith("eip155:")) {
    const ok = await rpc.erc1271(
      i.chain,
      i.addressNorm,
      erc191Hash(i.message),
      Buffer.from(i.signature.slice(2), "hex"),
    );
    if (ok) return { ok: true, method: "erc1271", publicKey: null };
  }
  return { ok: false, reason: "the signature was not made by the destination address" };
}
