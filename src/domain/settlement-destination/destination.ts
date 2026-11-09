/**
 * Settlement destination lifecycle (lld/identity.md §5, FR-SET-01…04). Pure.
 *
 * | from                 | command            | guard                                    | to                              |
 * |----------------------|--------------------|------------------------------------------|---------------------------------|
 * | —                    | create (test mode) | screening allow                          | active (verification `test`)    |
 * | —                    | create (live)      | screening allow, unique, no recovery lock | pending_verification            |
 * | pending_verification | challenge          | earlier unused challenges superseded     | pending_verification (fresh challenge) |
 * | pending_verification | attest             | signature valid, challenge fresh         | cooling_off (1 approver, Stage 1) / pending_approval (2) |
 * | pending_approval     | approve            | qualifying approvers ≥ required (approval.ts) | cooling_off                |
 * | cooling_off          | activate (job)     | not disabled, re-screen allow, approvals still complete | active           |
 * | cooling_off          | require_approval (job) | approvals no longer complete (team changed) | pending_approval         |
 * | pending_verification / pending_approval | expire (job) | 7 days after creation           | disabled                        |
 * | any but disabled     | disable / blocked  | —                                        | disabled                        |
 */

export type DestinationStatus = "pending_verification" | "pending_approval" | "cooling_off" | "active" | "disabled";
export type Command =
  | "challenge"
  | "attest"
  | "approve"
  | "activate"
  | "require_approval"
  | "expire"
  | "disable"
  | "set_default";

export type Step =
  | { readonly ok: true; readonly to: DestinationStatus }
  | { readonly ok: false; readonly state: DestinationStatus };

/** Where `command` moves a destination in `from` (approvals: how many are required after the attestation). */
export function transition(from: DestinationStatus, command: Command, o: { approvalsRequired?: number } = {}): Step {
  switch (command) {
    case "challenge":
      return from === "pending_verification" ? { ok: true, to: from } : { ok: false, state: from };
    case "attest":
      return from === "pending_verification"
        ? { ok: true, to: (o.approvalsRequired ?? 1) > 1 ? "pending_approval" : "cooling_off" }
        : { ok: false, state: from };
    case "approve":
      return from === "pending_approval" ? { ok: true, to: "cooling_off" } : { ok: false, state: from };
    case "activate":
      return from === "cooling_off" ? { ok: true, to: "active" } : { ok: false, state: from };
    case "require_approval":
      return from === "cooling_off" ? { ok: true, to: "pending_approval" } : { ok: false, state: from };
    case "expire":
      return from === "pending_verification" || from === "pending_approval"
        ? { ok: true, to: "disabled" }
        : { ok: false, state: from };
    case "disable":
      return from === "disabled" ? { ok: false, state: from } : { ok: true, to: "disabled" };
    case "set_default":
      return from === "active" ? { ok: true, to: "active" } : { ok: false, state: from };
  }
}

/**
 * Approvals needed (lld/identity.md §5): 2 when the account has ≥ 2 owner/admin members, else 1
 * (the creator). Stage 1 ships the single-approver flow (two approvers arrive with members in Stage 2).
 */
export function approvalsRequired(ownerAdminMembers: number, twoApproverRule: boolean): number {
  return twoApproverRule && ownerAdminMembers >= 2 ? 2 : 1;
}

/** Live mode (lld/identity.md §5): KYB approved, an active live destination, account active. */
export function liveEnabled(a: { kyb_status: string; status: string }, hasActiveLiveDestination: boolean): boolean {
  return a.kyb_status === "approved" && hasActiveLiveDestination && a.status === "active";
}

/** What is missing before live mode (`GET /v1/account/requirements`). */
export function missingRequirements(
  a: { kyb_status: string; status: string },
  hasActiveLiveDestination: boolean,
): ("kyb" | "destination" | "account_status")[] {
  return [
    ...(a.kyb_status === "approved" ? [] : (["kyb"] as const)),
    ...(hasActiveLiveDestination ? [] : (["destination"] as const)),
    ...(a.status === "active" ? [] : (["account_status"] as const)),
  ];
}

export type SigningStandard = "nep413" | "eip191" | "solana" | "bip322";

/**
 * How a destination proves ownership (lld/identity.md §8.2, §20): NEAR accounts (named or implicit) sign
 * NEP-413; EVM addresses and `0x…` Intents accounts sign EIP-191; Solana addresses sign the raw message
 * bytes (ed25519, `solana`); Bitcoin P2WPKH/P2TR addresses sign BIP-322 "simple" (`bip322`).
 */
export function signingStandard(
  type: "chain_address" | "intents_account",
  family: string,
  addressNorm: string,
): SigningStandard {
  if (/^0x[0-9a-f]{40}$/.test(addressNorm)) return "eip191";
  if (type === "intents_account" || family === "near") return "nep413";
  if (family === "evm") return "eip191";
  if (family === "solana") return "solana";
  return "bip322";
}

/**
 * Standards identity verifies (Stage 4, §20: all four). Stage 1 verified NEP-413 and EIP-191 only and
 * refused live Solana/Bitcoin destinations; that refusal is lifted.
 */
export const VERIFIABLE_STANDARDS: readonly SigningStandard[] = ["nep413", "eip191", "solana", "bip322"];

/** Bitcoin address types (kit `chains` validates the checksum; this reads the type). */
export type BitcoinAddressType = "p2wpkh" | "p2tr" | "p2wsh" | "p2pkh" | "p2sh" | "other";

/**
 * Type of a Bitcoin mainnet address already validated by kit `chains` (lld/identity.md §20): `bc1q` +
 * 20-byte program (42 chars) = P2WPKH, `bc1q` + 32 bytes (62) = P2WSH, `bc1p` + 32 bytes (62) = P2TR,
 * base58 `1…` = P2PKH, `3…` = P2SH; anything else (other witness versions or program sizes) = `other`.
 * Case-insensitive (bech32 is single-case; kit refuses mixed case).
 */
export function bitcoinAddressType(address: string): BitcoinAddressType {
  const a = address.toLowerCase();
  if (a.startsWith("bc1q")) return a.length === 42 ? "p2wpkh" : a.length === 62 ? "p2wsh" : "other";
  if (a.startsWith("bc1p")) return a.length === 62 ? "p2tr" : "other";
  if (a.startsWith("bc1")) return "other";
  if (address.startsWith("1")) return "p2pkh";
  if (address.startsWith("3")) return "p2sh";
  return "other";
}

/**
 * Bitcoin settlement destinations (§20): P2WPKH and P2TR only, in both modes — BIP-322 "simple" cannot
 * prove ownership of P2SH/P2WSH (the script is unknown from the address) or legacy P2PKH (needs the
 * legacy message format).
 */
export function bitcoinDestinationAllowed(address: string): boolean {
  const t = bitcoinAddressType(address);
  return t === "p2wpkh" || t === "p2tr";
}

/** The `address_invalid` message for a refused Bitcoin address type (§20). */
export const BITCOIN_DESTINATION_HINT = "Use a native SegWit (bc1q…) or Taproot (bc1p…) address";

export const CHALLENGE_TTL_MS = 10 * 60_000;
export const NEP413_RECIPIENT = "nearpay.money";

/** The exact message a destination key signs (lld/identity.md §8.2). */
export function attestationMessage(m: {
  account: string;
  livemode: boolean;
  assetId: string;
  chain: string;
  address: string;
  nonceHex: string;
  expiresAt: Date;
}): string {
  return [
    "NearPay settlement destination",
    `Account: ${m.account}`,
    `Mode: ${m.livemode ? "live" : "test"}`,
    `Asset: ${m.assetId}`,
    `Network: ${m.chain}`,
    `Address: ${m.address}`,
    `Nonce: ${m.nonceHex}`,
    `Expires: ${m.expiresAt.toISOString()}`,
  ].join("\n");
}

/** USD micros → `UsdAmount` minor units (cents, rounded up: a minimum must not be understated). */
export function usdMicrosToCents(micros: number): number {
  return Math.ceil(micros / 10_000);
}
